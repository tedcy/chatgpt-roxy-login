# -*- coding: utf-8 -*-
"""Roxy Local API transport, throttling, retry, and safe diagnostics."""
from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import requests

from config import roxybrowser as _cfg
from core.roxybrowser_domains.shared import (
    RoxyCreateBusyError,
    RoxyRateLimitError,
    _MAX_RETRY_AFTER_SECONDS,
    _RATE_LIMIT_DELAYS,
)


logger = logging.getLogger("core.roxybrowser_client")


def _active_rate_limit_delays() -> tuple[float, ...]:
    """Honor the historical facade patch point used by local tests/tools."""
    import sys

    facade = sys.modules.get("core.roxybrowser_client")
    configured = getattr(facade, "_RATE_LIMIT_DELAYS", _RATE_LIMIT_DELAYS)
    try:
        values = tuple(float(value) for value in configured)
    except (TypeError, ValueError):
        return _RATE_LIMIT_DELAYS
    return values or _RATE_LIMIT_DELAYS


def _api_rate_settings() -> tuple[float, int]:
    per_minute = max(
        0.0,
        float(getattr(_cfg, "ROXY_API_RATE_LIMIT_PER_MINUTE", 90) or 0.0),
    )
    max_in_flight = max(
        1,
        int(getattr(_cfg, "ROXY_API_MAX_IN_FLIGHT", 25) or 25),
    )
    return per_minute, max_in_flight


class _RoxyApiRequestGate:
    """Process-wide FIFO start-rate limiter for the Roxy Local API.

    Browser page traffic does not pass through this gate. Management requests
    start at a smooth process-wide rate while slow responses may overlap.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._waiters: deque[object] = deque()
        self._in_flight = 0
        self._last_started_at = 0.0
        self._not_before = 0.0
        self._configured_per_minute = 0.0
        self._max_in_flight = 1
        self._rate_limit_events = 0
        self._retry_successes = 0
        self._last_rate_limit_at: str | None = None

    @contextmanager
    def slot(self, per_minute: float, max_in_flight: int):
        ticket = object()
        rate = max(0.0, float(per_minute or 0.0))
        capacity = max(1, int(max_in_flight or 1))
        interval = 60.0 / rate if rate > 0 else 0.0
        queued_at = time.monotonic()
        slot_info: dict[str, int] = {}
        with self._condition:
            self._configured_per_minute = rate
            self._max_in_flight = capacity
            self._waiters.append(ticket)
            try:
                while True:
                    now = time.monotonic()
                    ready_at = max(self._not_before, self._last_started_at + interval)
                    is_head = bool(self._waiters) and self._waiters[0] is ticket
                    if is_head and self._in_flight < capacity and now >= ready_at:
                        self._waiters.popleft()
                        self._in_flight += 1
                        self._last_started_at = now
                        slot_info.update({
                            "wait_ms": max(0, int((now - queued_at) * 1000)),
                            "in_flight": self._in_flight,
                        })
                        self._condition.notify_all()
                        break
                    if is_head and self._in_flight < capacity:
                        timeout = max(0.01, min(0.25, ready_at - now))
                    else:
                        timeout = 0.25
                    self._condition.wait(timeout=timeout)
            except BaseException:
                try:
                    self._waiters.remove(ticket)
                except ValueError:
                    pass
                self._condition.notify_all()
                raise
        try:
            yield slot_info
        finally:
            with self._condition:
                self._in_flight = max(0, self._in_flight - 1)
                self._condition.notify_all()

    def record_rate_limit(self, delay: float) -> None:
        with self._condition:
            self._rate_limit_events += 1
            self._last_rate_limit_at = (
                datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
            self._not_before = max(self._not_before, time.monotonic() + max(0.0, delay))
            self._condition.notify_all()

    def record_retry_success(self) -> None:
        with self._condition:
            self._retry_successes += 1

    def snapshot(self) -> dict:
        with self._condition:
            retry_after = max(0.0, self._not_before - time.monotonic())
            configured_per_minute, max_in_flight = _api_rate_settings()
            return {
                "state": "cooldown" if retry_after > 0 else "ready",
                "retry_after_ms": int(retry_after * 1000),
                "configured_per_minute": configured_per_minute,
                "max_in_flight": max_in_flight,
                "in_flight": self._in_flight,
                "rate_limit_events": self._rate_limit_events,
                "retry_successes": self._retry_successes,
                "last_rate_limit_at": self._last_rate_limit_at,
                "waiting": len(self._waiters),
            }

    def reset_for_tests(self) -> None:
        with self._condition:
            self._waiters.clear()
            self._in_flight = 0
            self._last_started_at = 0.0
            self._not_before = 0.0
            self._configured_per_minute = 0.0
            self._max_in_flight = 1
            self._rate_limit_events = 0
            self._retry_successes = 0
            self._last_rate_limit_at = None
            self._condition.notify_all()


_API_REQUEST_GATE = _RoxyApiRequestGate()

def _strip_slashes(value: str) -> str:
    return str(value or "").strip().strip("/")


def _join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _is_create_busy_message(value: object) -> bool:
    text = str(value or "")
    return "正在创建中" in text and "请稍等" in text


def _is_rate_limit_message(value: object) -> bool:
    text = str(value or "").strip().lower()
    return any(
        marker in text
        for marker in (
            "请求过频",
            "请求频繁",
            "too many requests",
            "rate limit",
            "rate-limit",
        )
    )


def _bounded_retry_after(value: object) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            seconds = (parsed - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    return min(_MAX_RETRY_AFTER_SECONDS, max(0.0, seconds))


def _response_retry_after(response: object, payload: object) -> float | None:
    headers = getattr(response, "headers", None)
    if headers is not None:
        try:
            header_value = headers.get("Retry-After")
        except Exception:
            header_value = None
        parsed = _bounded_retry_after(header_value)
        if parsed is not None:
            return parsed
    candidates = [payload]
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        candidates.append(payload["data"])
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        for key in ("retryAfter", "retry_after", "retryAfterSeconds"):
            if key not in candidate:
                continue
            parsed = _bounded_retry_after(candidate.get(key))
            if parsed is not None:
                return parsed
    return None


def _jittered_backoff(delay: float) -> float:
    base = max(0.0, float(delay or 0.0))
    if base <= 0:
        return 0.0
    return max(0.0, base * random.uniform(0.9, 1.1))


def _safe_api_endpoint(path: object) -> str:
    """Return a fixed management endpoint label without IDs or query data."""
    normalized = urlparse(str(path or "")).path.strip().lower()
    browser_names = {
        "create",
        "open",
        "detail",
        "random_env",
        "mdf",
        "close",
        "delete",
        "list",
        "list_v3",
        "workspace",
        "connection_info",
    }
    parts = [part for part in normalized.split("/") if part]
    if len(parts) >= 2 and parts[0] == "browser" and parts[1] in browser_names:
        return f"/browser/{parts[1]}"
    return "/roxy-api"


def _safe_roxy_diagnostic(value: object) -> str:
    """Render an API error without proxy credentials, SID values or raw bodies."""

    from core.proxy_sid import redact_proxy_metadata

    if isinstance(value, BaseException):
        value = str(value)
    safe = redact_proxy_metadata(value)
    if isinstance(safe, (dict, list, tuple)):
        return json.dumps(safe, ensure_ascii=False)
    return str(safe or "")


def _sanitized_roxy_exception(exc: Exception) -> Exception:
    """Preserve requests exception classes while removing sensitive details."""

    if not isinstance(exc, requests.RequestException):
        return exc
    safe_message = _safe_roxy_diagnostic(exc)
    try:
        return type(exc)(safe_message)
    except Exception:  # pragma: no cover - defensive for custom subclasses
        return requests.RequestException(safe_message)


def get_roxy_api_runtime_status() -> dict:
    """Return safe process-local API throttle counters for the Web UI."""
    return _API_REQUEST_GATE.snapshot()


def reset_roxy_api_request_gate_for_tests() -> None:
    _API_REQUEST_GATE.reset_for_tests()

class RoxyTransportMixin:
    def __init__(
        self,
        api_base: str | None = None,
        token: str | None = None,
        *,
        safe_logging: bool = False,
    ):
        self.api_base = (api_base or _cfg.ROXY_API_BASE).strip()
        self.token = (token if token is not None else _cfg.ROXY_API_TOKEN).strip()
        # Manual windows must not put Profile IDs, debugger endpoints or
        # transport diagnostics into the ordinary application log. Existing
        # registration callers keep the historical diagnostics by default.
        self.safe_logging = bool(safe_logging)
        self.http = requests.Session()
        if self.token:
            # 官方文档要求所有接口请求头必须加 token。这里同时兼容 token / Authorization。
            self.http.headers.update({
                "token": self.token,
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        if isinstance(exc, RoxyRateLimitError):
            return True
        if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
            return True
        text = str(exc or "").lower()
        return (
            "timeout" in text
            or "timed out" in text
            or "connection" in text
            or "temporarily" in text
            or re.search(r"\bhttp 5\d\d\b", text) is not None
            # Roxy's structured error envelope reports upstream failures as
            # ``status code 500`` (rather than the transport-style ``HTTP
            # 500`` string).  Treat only 5xx status-code forms as transient;
            # client-side 4xx validation errors must remain terminal.
            or re.search(r"\bstatus\s+code\s+5\d\d\b", text) is not None
            or re.search(r"\bcode\s*[:=]\s*5\d\d\b", text) is not None
            or "http 429" in text
        )

    @classmethod
    def is_transient_api_error(cls, exc: BaseException) -> bool:
        return isinstance(exc, Exception) and cls._is_retryable_error(exc)

    def request(self, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None) -> dict:
        url = _join_url(self.api_base, path)
        method_u = method.upper()
        endpoint_label = _safe_api_endpoint(path)
        rate_limit_delays = _active_rate_limit_delays()
        # create 超时后服务端可能已创建环境，直接重试可能产生孤儿环境；默认不重试 create。
        is_create = str(path or "").rstrip("/").endswith("/create") or "browser/create" in str(path or "")
        generic_max_attempts = 1 if is_create else max(1, int(getattr(_cfg, "ROXY_API_RETRIES", 3) or 3))
        base_delay = max(0.5, float(getattr(_cfg, "ROXY_API_RETRY_DELAY", 2) or 2))
        rate_per_minute, max_in_flight = _api_rate_settings()
        last_exc: Exception | None = None
        generic_failures = 0
        rate_limit_failures = 0
        total_attempts = 0

        def mark_rate_limit_before_release(
            exc: RoxyRateLimitError,
            *,
            retry_after: float | None = None,
        ) -> RoxyRateLimitError:
            """Install the process-wide cooldown before this request releases the gate."""
            failure_number = rate_limit_failures + 1
            fallback = rate_limit_delays[
                min(failure_number - 1, len(rate_limit_delays) - 1)
            ]
            delay = (
                retry_after
                if retry_after is not None
                else _jittered_backoff(fallback)
            )
            _API_REQUEST_GATE.record_rate_limit(delay)
            setattr(exc, "_roxy_gate_recorded", True)
            setattr(exc, "_roxy_retry_delay", delay)
            return exc

        while True:
            total_attempts += 1
            try:
                request_log_target = endpoint_label if self.safe_logging else url
                logger.debug(
                    "[Roxy] %s %s param_keys=%s body_keys=%s attempt=%s",
                    method,
                    request_log_target,
                    sorted((params or {}).keys()),
                    sorted((json_body or {}).keys()),
                    total_attempts,
                )
                with _API_REQUEST_GATE.slot(
                    rate_per_minute,
                    max_in_flight,
                ) as gate_info:
                    if int(gate_info.get("wait_ms") or 0) >= 1000:
                        logger.info(
                            "[Roxy] API 门禁等待完成：endpoint=%s wait_ms=%s in_flight=%s",
                            endpoint_label,
                            gate_info.get("wait_ms"),
                            gate_info.get("in_flight"),
                        )
                    resp = self.http.request(
                        method_u,
                        url,
                        params=params or None,
                        json=json_body if json_body is not None else None,
                        timeout=max(5, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)),
                    )
                    text = resp.text or ""
                    try:
                        payload = resp.json()
                    except Exception:
                        payload = {"raw": text}
                    if resp.status_code == 429:
                        raise mark_rate_limit_before_release(
                            RoxyRateLimitError(
                                f"Roxy API 请求过频 {method_u} {endpoint_label}，请稍后再试"
                            ),
                            retry_after=_response_retry_after(resp, payload),
                        )
                    if not (200 <= resp.status_code < 300):
                        safe_text = _safe_roxy_diagnostic(text)
                        raise RuntimeError(
                            f"Roxy API 请求失败 {method_u} {endpoint_label} "
                            f"HTTP {resp.status_code}: {safe_text[:500]}"
                        )
                    if isinstance(payload, dict):
                        code = payload.get("code")
                        ok = payload.get("ok")
                        success = payload.get("success")
                        explicit_success = ok is True or success is True
                        explicit_failure = ok is False or success is False
                        bad_code = code not in (None, 0, 200, "0", "200")
                        if not explicit_success and (bad_code or explicit_failure):
                            msg = payload.get("msg") or payload.get("message") or payload.get("error") or json.dumps(payload, ensure_ascii=False)[:500]
                            if is_create and _is_create_busy_message(msg):
                                raise RoxyCreateBusyError(
                                    f"Roxy API 返回失败 {method_u} {path}: 正在创建中，请稍等！"
                                )
                            if _is_rate_limit_message(msg):
                                raise mark_rate_limit_before_release(
                                    RoxyRateLimitError(
                                        f"Roxy API 请求过频 {method_u} {endpoint_label}，请稍后再试"
                                    ),
                                    retry_after=_response_retry_after(resp, payload),
                                )
                            safe_msg = _safe_roxy_diagnostic(msg)
                            raise RuntimeError(
                                f"Roxy API 返回失败 {method_u} {endpoint_label}: "
                                f"{safe_msg[:500]}"
                            )
                if rate_limit_failures:
                    _API_REQUEST_GATE.record_retry_success()
                if total_attempts > 1:
                    logger.info("[Roxy] API 重试成功：%s %s attempt=%s", method_u, endpoint_label, total_attempts)
                return payload if isinstance(payload, dict) else {"data": payload}
            except RoxyRateLimitError as exc:
                last_exc = exc
                rate_limit_failures += 1
                can_retry = rate_limit_failures <= len(rate_limit_delays)
                fallback = rate_limit_delays[
                    min(rate_limit_failures - 1, len(rate_limit_delays) - 1)
                ]
                recorded_delay = getattr(exc, "_roxy_retry_delay", None)
                delay = float(
                    recorded_delay
                    if recorded_delay is not None
                    else _jittered_backoff(fallback)
                )
                # Every rejected response is counted, including the terminal
                # fourth attempt and a non-retryable create request.  A custom
                # transport raising this exception directly is counted here;
                # normal HTTP/structured responses were recorded while the
                # request gate was still held, preventing a cooldown race.
                if not bool(getattr(exc, "_roxy_gate_recorded", False)):
                    _API_REQUEST_GATE.record_rate_limit(delay)
                if not can_retry:
                    raise
                logger.warning(
                    "[Roxy] API 请求过频，将在 %.1fs 后重试：%s %s attempt=%s/%s",
                    delay,
                    method_u,
                    endpoint_label,
                    rate_limit_failures,
                    len(rate_limit_delays) + 1,
                )
            except Exception as exc:
                last_exc = exc
                generic_failures += 1
                retryable = self._is_retryable_error(exc)
                if generic_failures >= generic_max_attempts or not retryable:
                    sanitized_exc = _sanitized_roxy_exception(exc)
                    if sanitized_exc is exc:
                        raise
                    raise sanitized_exc from None
                delay = _jittered_backoff(base_delay * generic_failures)
                logger.warning(
                    "[Roxy] API 请求失败，将在 %.1fs 后重试：%s %s attempt=%s/%s error=%s",
                    delay,
                    method_u,
                    endpoint_label,
                    generic_failures,
                    generic_max_attempts,
                    _safe_roxy_diagnostic(exc),
                )
                time.sleep(delay)
        raise last_exc or RuntimeError(
            f"Roxy API 请求失败 {method_u} {endpoint_label}"
        )

    def try_request(self, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None) -> tuple[bool, dict | str]:
        """宽松请求：用于探测不同 Roxy 版本接口，失败不抛出。"""
        try:
            return True, self.request(method, path, params=params, json_body=json_body)
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
