# -*- coding: utf-8 -*-
"""Long-lived, user-controlled visible Roxy windows for account operations.

This module is deliberately separate from the normal Session refresh path.
It owns one visible browser/Profile lease per account, performs the smallest
possible automatic login hand-off, and then stops automating so the operator
can use the browser.  No credential or target URL is exposed by its public
state projections.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from core import account_operation_log, db
from core.chatgpt_plan import (
    check_account_promos,
    normalize_promo_check_region,
    token_claims,
)
from core.chatgpt_session_refresh import (
    ChatGPTSessionRefreshError,
    _build_roxy_login_candidate,
    _cleanup_refresh_profile,
    _find_session_in_windows,
    _registration_password,
    _restore_saved_session_to_driver,
    _safe_session_restore_reason,
    _wait_for_visible_login,
    normalize_token,
    save_roxy_login_candidate_for_account,
    save_driver_session_for_account,
    validate_session_identity,
)
from core.openai_auth import AccountUnusableError
from core.roxy_chatgpt_contract_trace import RoxyChatGPTContractTracer


logger = logging.getLogger(__name__)

_MAX_TARGET_URL_LENGTH = 8192
_WINDOW_POLL_SECONDS = 2.0
_PROFILE_CHECK_SECONDS = 8.0
_SESSION_LOG_TRIGGERS = frozenset({"roxy_window", "turb_browser"})
_PROMO_PROBE_INVALID_CODES = frozenset({
    "token_expired",
    "token_invalidated",
})
_PROMO_PROBE_SAFE_CODES = frozenset({
    "promo_check_token_missing",
    "promo_check_network_config_error",
    "promo_check_network_error",
    "promo_check_http_error",
    "promo_check_non_json_response",
    "promo_check_response_invalid",
    "promo_check_unexpected",
    "promo_region_invalid",
})
_ROXY_FRESH_VALIDATION_CODES = frozenset({
    "token_expired",
    "session_exchange_no_rotation",
    "session_login_liveness_failed",
    "session_refresh_empty",
    "session_browser_cookie_capture_failed",
    "account_token_update_conflict",
    "account_missing",
    "session_identity_mismatch",
    "session_identity_email_mismatch",
    "session_identity_user_mismatch",
    "session_identity_account_mismatch",
})
_ACTIVE_STATES = frozenset({
    "queued",
    "opening",
    "restoring_session",
    "automatic_login",
    "waiting_user",
    "ready",
    "closing",
})


def _access_token_state(token: object) -> str:
    """Return a safe local JWT state label for diagnostics only.

    This is never used as the authoritative login decision.  The Roxy path
    uses the existing ``check_account_promos`` request for that decision; the
    label only makes races/expired values visible in the account log.
    """

    value = normalize_token(str(token or ""))
    if not value:
        return "unknown"
    try:
        expired = token_claims(value).get("token_expired")
    except Exception:
        expired = None
    if expired is True:
        return "expired"
    if expired is False:
        return "valid"
    return "unknown"


def _safe_roxy_validation_reason(value: object) -> str:
    code = str(value or "").strip().lower()
    if code in _ROXY_FRESH_VALIDATION_CODES:
        return code
    return "fresh_login_validation_failed"


class RoxyManualWindowError(RuntimeError):
    def __init__(self, error_code: str, message: str = "") -> None:
        self.error_code = str(error_code or "roxy_window_failed")
        self.user_message = str(message or self.error_code)
        super().__init__(self.user_message)


def validate_target_url(value: object) -> str:
    """Validate a one-shot browser target without resolving or contacting it."""

    if value is None or value == "":
        raw_input = ""
    elif isinstance(value, str):
        raw_input = value
    else:
        raise RoxyManualWindowError(
            "roxy_window_target_url_invalid",
            "目标 URL 格式无效",
        )
    if len(raw_input) > _MAX_TARGET_URL_LENGTH:
        raise RoxyManualWindowError(
            "roxy_window_target_url_invalid",
            "目标 URL 过长",
        )
    raw = raw_input.strip()
    if not raw:
        return ""
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise RoxyManualWindowError(
            "roxy_window_target_url_invalid",
            "目标 URL 格式无效",
        )
    try:
        parsed = urlsplit(raw)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        # Accessing .port validates malformed numeric ports as well.
        _ = parsed.port
    except ValueError as exc:
        raise RoxyManualWindowError(
            "roxy_window_target_url_invalid",
            "目标 URL 格式无效",
        ) from exc
    scheme = str(parsed.scheme or "").strip().lower()
    if not host or parsed.username is not None or parsed.password is not None:
        raise RoxyManualWindowError(
            "roxy_window_target_url_invalid",
            "目标 URL 格式无效",
        )
    # ``urlsplit`` is intentionally permissive.  Validate the hostname after
    # parsing so malformed labels (and control characters hidden in a Unicode
    # hostname) cannot reach the browser navigation call.
    try:
        ipaddress.ip_address(host)
        valid_host = True
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except (UnicodeError, ValueError):
            ascii_host = ""
        labels = ascii_host.split(".") if ascii_host else []
        valid_host = (
            bool(labels)
            and len(ascii_host) <= 253
            and all(
                0 < len(label) <= 63
                and not label.startswith("-")
                and not label.endswith("-")
                and re.fullmatch(r"[a-z0-9-]+", label) is not None
                for label in labels
            )
        )
    if not valid_host:
        raise RoxyManualWindowError(
            "roxy_window_target_url_invalid",
            "目标 URL 格式无效",
        )
    if scheme == "https":
        return raw
    if scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}:
        return raw
    raise RoxyManualWindowError(
        "roxy_window_target_url_invalid",
        "目标 URL 仅允许 HTTPS 或本机 HTTP",
    )


@dataclass
class _WindowContext:
    account_id: int
    run_id: str
    browser_driver: str = "roxy"
    browser_lease: object | None = field(default=None, repr=False)
    local_browser_ref: dict | None = field(default=None, repr=False)
    target_url: str = field(default="", repr=False)
    raw_trace_enabled: bool = False
    auto_login_enabled: bool = True
    target_only: bool = False
    otp_only_login: bool = False
    session_log_enabled: bool = field(default=False, repr=False)
    session_log_ticket: object | None = field(default=None, repr=False)
    stop_event: threading.Event = field(default_factory=threading.Event, repr=False)
    client: object | None = field(default=None, repr=False)
    opened: object | None = field(default=None, repr=False)
    driver: object | None = field(default=None, repr=False)
    tracer: object | None = field(default=None, repr=False)
    raw_tracer: object | None = field(default=None, repr=False)
    dom_recorder: object | None = field(default=None, repr=False)
    thread: threading.Thread | None = field(default=None, repr=False)
    auth_handle: str | None = field(default=None, repr=False)
    # A fresh-login result is not safe to persist from the close hook until
    # the strict rotation/liveness/identity gate has passed.  This prevents a
    # user closing a window immediately after a failed validation from
    # accidentally committing the browser's unverified AT.
    fresh_login_attempted: bool = field(default=False, repr=False)
    fresh_login_validated: bool = field(default=False, repr=False)
    target_opened: bool = False
    strict_target: bool = False
    target_validator: Callable[[str], object] | None = field(
        default=None,
        repr=False,
    )
    lifecycle_observer: Callable[[dict], object] | None = field(
        default=None,
        repr=False,
    )
    proxy_country_override: str | None = field(default=None, repr=False)
    proxy_override: str | None = field(default=None, repr=False)


class RoxyManualWindowManager:
    """Process-local owner of visible Profile leases and browser drivers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._contexts: dict[int, _WindowContext] = {}

    def open(
        self,
        account_id: int,
        target_url: object = "",
        *,
        raw_trace: bool = False,
        auto_login: bool = True,
        target_only: bool = False,
        otp_only: bool = False,
        operation_log_trigger: str = "roxy_window",
        strict_target: bool = False,
        target_validator: Callable[[str], object] | None = None,
        lifecycle_observer: Callable[[dict], object] | None = None,
        proxy_country_override: str | None = None,
        window_driver: str = "roxy",
        proxy: object = None,
    ) -> dict:
        if window_driver not in {"roxy", "headed_chrome"}:
            raise RoxyManualWindowError("manual_window_driver_unsupported", "人工窗口驱动配置无效")
        if isinstance(account_id, bool):
            raise RoxyManualWindowError(
                "account_id_invalid", "账号 ID 必须是整数"
            )
        try:
            account_id = int(account_id)
        except (TypeError, ValueError) as exc:
            raise RoxyManualWindowError(
                "account_id_invalid", "账号 ID 必须是整数"
            ) from exc
        if account_id <= 0:
            raise RoxyManualWindowError("account_id_invalid", "账号 ID 无效")
        if not isinstance(raw_trace, bool):
            raise RoxyManualWindowError(
                "roxy_window_raw_trace_invalid",
                "原始网络抓包开关必须是布尔值",
            )
        if not isinstance(auto_login, bool):
            raise RoxyManualWindowError(
                "roxy_window_auto_login_invalid",
                "自动登录开关必须是布尔值",
            )
        if not isinstance(target_only, bool):
            raise RoxyManualWindowError(
                "roxy_window_target_only_invalid",
                "仅目标页模式必须是布尔值",
            )
        if not isinstance(otp_only, bool):
            raise RoxyManualWindowError(
                "roxy_window_otp_only_invalid",
                "OTP 登录模式必须是布尔值",
            )
        if not isinstance(operation_log_trigger, str):
            raise RoxyManualWindowError(
                "roxy_window_log_trigger_invalid",
                "会话刷新日志触发来源无效",
            )
        normalized_log_trigger = operation_log_trigger.strip().lower()
        if normalized_log_trigger not in _SESSION_LOG_TRIGGERS:
            raise RoxyManualWindowError(
                "roxy_window_log_trigger_invalid",
                "会话刷新日志触发来源无效",
            )
        if not isinstance(strict_target, bool):
            raise RoxyManualWindowError(
                "roxy_window_strict_target_invalid",
                "严格目标页开关必须是布尔值",
            )
        if target_validator is not None and not callable(target_validator):
            raise RoxyManualWindowError(
                "roxy_window_target_validator_invalid",
                "目标页校验器无效",
            )
        if lifecycle_observer is not None and not callable(lifecycle_observer):
            raise RoxyManualWindowError(
                "roxy_window_lifecycle_observer_invalid",
                "窗口生命周期观察器无效",
            )
        normalized_proxy_country = str(proxy_country_override or "").strip().upper()
        if normalized_proxy_country not in {"", "US"} and not (
            target_only and re.fullmatch(r"[A-Z]{2}", normalized_proxy_country)
        ):
            raise RoxyManualWindowError(
                "roxy_window_proxy_country_invalid",
                "Roxy 代理国家无效",
            )
        from core.manual_window_proxy import normalize_proxy, PROXY_INVALID, PROXY_INVALID_MESSAGE
        try:
            normalized_proxy = normalize_proxy(proxy)
        except ValueError:
            raise RoxyManualWindowError(PROXY_INVALID, PROXY_INVALID_MESSAGE) from None
        normalized_url = validate_target_url(target_url)
        if target_only and not normalized_url:
            raise RoxyManualWindowError(
                "roxy_window_target_url_required",
                "仅目标页模式必须提供目标 URL",
            )
        if strict_target and not normalized_url:
            raise RoxyManualWindowError(
                "roxy_window_target_url_required",
                "严格目标页模式必须提供目标 URL",
            )
        claim = db.claim_account_roxy_window(
            account_id,
            target_url_configured=bool(normalized_url),
            window_driver=window_driver,
        )
        if not claim.get("accepted"):
            return {
                key: value
                for key, value in claim.items()
                if key != "run_id"
            }
        ctx = _WindowContext(
            account_id=account_id,
            run_id=str(claim.get("run_id") or ""),
            browser_driver=window_driver,
            target_url=normalized_url,
            raw_trace_enabled=raw_trace,
            auto_login_enabled=auto_login,
            target_only=target_only,
            otp_only_login=otp_only,
            strict_target=strict_target,
            target_validator=target_validator,
            lifecycle_observer=lifecycle_observer,
            proxy_country_override=normalized_proxy_country or None,
            proxy_override=normalized_proxy or None,
        )
        if auto_login and not target_only:
            try:
                ctx.session_log_ticket = account_operation_log.begin_run(
                    account_id,
                    "session_refresh",
                    trigger=normalized_log_trigger,
                )
                ctx.session_log_enabled = ctx.session_log_ticket is not None
            except Exception:
                # The account operation log is diagnostic only.  A transient
                # filesystem/locking failure must never prevent the visible
                # window from opening or the existing login flow from running.
                logger.warning(
                    "[SessionRefresh][Roxy] 会话专属日志初始化失败："
                    "account_id=%s reason=operation_log_init_failed",
                    account_id,
                )
        with self._lock:
            self._contexts[account_id] = ctx
        try:
            thread = threading.Thread(
                target=self._run,
                args=(ctx,),
                name=f"roxy-manual-window-{account_id}",
                daemon=True,
            )
            ctx.thread = thread
            thread.start()
        except Exception:
            if ctx.session_log_ticket is not None:
                try:
                    account_operation_log.rollback_run(ctx.session_log_ticket)
                except Exception:
                    logger.warning(
                        "[SessionRefresh][Roxy] 会话专属日志回滚失败："
                        "account_id=%s reason=operation_log_rollback_failed",
                        account_id,
                    )
            with self._lock:
                self._contexts.pop(account_id, None)
            db.finish_account_roxy_window(
                account_id,
                ctx.run_id,
                status="failed",
                error_code="roxy_window_thread_start_failed",
            )
            return {
                "accepted": False,
                "busy": False,
                "error_code": "roxy_window_thread_start_failed",
                "error": "浏览器窗口任务启动失败",
            }
        return {
            "accepted": True,
            "busy": False,
            "account_id": account_id,
            "status": "queued",
            "driver": window_driver,
            "target_url_configured": bool(normalized_url),
        }

    @staticmethod
    def _notify_lifecycle(
        ctx: _WindowContext,
        event: str,
        **details: object,
    ) -> None:
        observer = ctx.lifecycle_observer
        if observer is None:
            return
        payload = {
            "event": str(event or "state"),
            "status": str(details.get("status") or ""),
            "stage": str(details.get("stage") or ""),
            "error_code": str(details.get("error_code") or ""),
            "target_opened": bool(ctx.target_opened),
            "stop_requested": bool(ctx.stop_event.is_set()),
        }
        try:
            observer(payload)
        except Exception:
            logger.warning(
                "[Roxy人工窗口] 生命周期观察器失败："
                "account_id=%s reason=lifecycle_observer_failed",
                ctx.account_id,
            )

    def close(self, account_id: int) -> dict:
        if isinstance(account_id, bool):
            raise RoxyManualWindowError(
                "account_id_invalid", "账号 ID 必须是整数"
            )
        try:
            account_id = int(account_id)
        except (TypeError, ValueError) as exc:
            raise RoxyManualWindowError(
                "account_id_invalid", "账号 ID 必须是整数"
            ) from exc
        if account_id <= 0:
            raise RoxyManualWindowError("account_id_invalid", "账号 ID 无效")
        with self._lock:
            ctx = self._contexts.get(account_id)
        if ctx is not None:
            ctx.stop_event.set()
            db.update_account_roxy_window(
                account_id,
                ctx.run_id,
                status="closing",
                stage="closing",
            )
            return {
                "accepted": True,
                "account_id": account_id,
                "status": "closing",
                "driver": ctx.browser_driver,
            }

        # After a WebUI restart, only the safe internal Profile reference is
        # available.  Close it without reattaching Selenium or restoring a
        # session; the next pool reconciliation can reclaim it.
        row = db.get_account(account_id)
        if not row:
            return {
                "accepted": False,
                "error_code": "account_not_found",
                "error": "账号不存在",
            }
        status = str(row.get("roxy_window_status") or "").strip().lower()
        if status not in _ACTIVE_STATES and status != "interrupted":
            return {
                "accepted": True,
                "account_id": account_id,
                "status": "closed",
                "already_closed": True,
                "driver": row.get("roxy_window_driver") or "roxy",
            }
        if row.get("roxy_window_driver") == "headed_chrome":
            from core.manual_window_browser import close_local_browser

            reference = row.get("roxy_window_local_browser_ref")
            if reference and not close_local_browser(reference):
                return {"accepted": False, "driver": "headed_chrome",
                        "error_code": "roxy_window_close_unconfirmed",
                        "error": "本机浏览器窗口关闭状态暂时无法确认"}
            try:
                finished = db.finish_account_roxy_window(
                    account_id, str(row.get("roxy_window_run_id") or ""), status="closed",
                )
            except Exception:
                finished = False
            return {"accepted": bool(finished), "account_id": account_id,
                    "status": "closed" if finished else "interrupted", "driver": "headed_chrome",
                    **({} if finished else {"error_code": "roxy_window_close_persist_failed"})}
        profile_id = str(row.get("roxy_window_profile_id") or "").strip()
        run_id = str(row.get("roxy_window_run_id") or "").strip()
        if not profile_id or not run_id:
            db.finish_account_roxy_window(
                account_id,
                run_id,
                status="closed",
                error_code=None,
            )
            return {
                "accepted": True,
                "account_id": account_id,
                "status": "closed",
            }
        from core.roxy_profile_pool import get_roxy_profile_pool

        pool = get_roxy_profile_pool()
        # Reserve before the management API call.  Otherwise an allocator can
        # lease the same restart-orphaned Profile between our DB read and the
        # close request, causing this endpoint to close another task's window.
        if not pool.reserve_external(profile_id):
            return {
                "accepted": False,
                "busy": True,
                "error_code": "roxy_window_profile_busy",
                "error": "该 Roxy 环境正在被其他任务使用",
            }
        try:
            from core.roxybrowser_client import RoxyBrowserClient

            client = RoxyBrowserClient(safe_logging=True)
            client.close_profile(profile_id)
            state = client._profile_open_state_strict(profile_id)
        except Exception:
            state = None
        if state is not False:
            return {
                "accepted": False,
                "error_code": "roxy_window_close_unconfirmed",
                "error": "Roxy 窗口关闭状态暂时无法确认",
            }
        try:
            finished = db.finish_account_roxy_window(
                account_id,
                run_id,
                status="closed",
            )
        except Exception:
            finished = False
        if not finished:
            # Keep the reservation fail-closed.  Releasing it before the DB
            # ownership record is cleared would recreate the restart race.
            return {
                "accepted": False,
                "error_code": "roxy_window_close_persist_failed",
                "error": "浏览器窗口已关闭，但状态保存失败",
            }
        pool.release_external(profile_id)
        return {
            "accepted": True,
            "account_id": account_id,
            "status": "closed",
        }

    def status(self) -> dict:
        windows = []
        for item in db.list_roxy_window_states():
            status = str(item.get("roxy_window_status") or "").strip().lower()
            if not status:
                continue
            windows.append({
                "account_id": int(item.get("id") or 0),
                "driver": item.get("roxy_window_driver") or "roxy",
                "status": status,
                "stage": item.get("roxy_window_stage"),
                "error_code": item.get("roxy_window_error_code"),
                "message": item.get("roxy_window_message"),
                "started_at": item.get("roxy_window_started_at"),
                "ready_at": item.get("roxy_window_ready_at"),
                "target_url_configured": bool(
                    item.get("roxy_window_target_url_configured")
                ),
            })
        return {"ok": True, "windows": windows}

    def automatic_session_log_active(self, account_id: int) -> bool:
        """Return whether an automatic window is still in its login phase.

        The operation-log API historically derives ``running`` from the
        background refresh status field.  A visible Roxy window deliberately
        does not claim that field (doing so would block the normal refresh
        queue), so expose this process-local diagnostic instead.  Manual
        windows never create a Session-refresh run and therefore always
        return ``False`` here.
        """

        try:
            account_id = int(account_id)
        except (TypeError, ValueError, OverflowError):
            return False
        with self._lock:
            ctx = self._contexts.get(account_id)
        if ctx is None or not ctx.auto_login_enabled or not ctx.session_log_enabled:
            return False
        try:
            row = db.get_account(account_id) or {}
            status = str(row.get("roxy_window_status") or "").strip().lower()
        except Exception:
            return False
        return status in {
            "queued",
            "opening",
            "restoring_session",
            "automatic_login",
            "waiting_user",
            "closing",
        }

    def _set_state(self, ctx: _WindowContext, **kwargs) -> bool:
        if ctx.dom_recorder is not None and ctx.driver is not None:
            try:
                ctx.dom_recorder.observe(
                    ctx.driver,
                    stage=str(kwargs.get("stage") or "window"),
                    event="state_change",
                    force=bool(kwargs.get("status") in {"failed", "interrupted"}),
                )
            except Exception:
                pass
        try:
            changed = db.update_account_roxy_window(
                ctx.account_id,
                ctx.run_id,
                **kwargs,
            )
            if changed:
                self._notify_lifecycle(
                    ctx,
                    "state",
                    status=kwargs.get("status"),
                    stage=kwargs.get("stage"),
                    error_code=kwargs.get("error_code"),
                )
            return changed
        except Exception:
            logger.warning(
                "[Roxy人工窗口] 状态写入失败：account_id=%s reason=state_persist_failed",
                ctx.account_id,
            )
            return False

    @staticmethod
    def _country_for_account(account: dict) -> str | None:
        from core.operation_country import MAINTENANCE_COUNTRY
        return MAINTENANCE_COUNTRY

    @staticmethod
    def _check_driver_alive(ctx: _WindowContext) -> bool:
        driver = ctx.driver
        if driver is None:
            return False
        try:
            handles = list(getattr(driver, "window_handles", []) or [])
            return bool(handles)
        except Exception:
            return False

    @staticmethod
    def _probe_access_token_with_promos(account: dict) -> dict:
        """Probe the stored AT through the same kernel as the 查优惠 action.

        The result is deliberately reduced to fixed, credential-free fields.
        A successful promotion response proves that the token was accepted by
        the service; transport/rate-limit failures remain ``unknown`` and do
        not force a fresh login.
        """

        token = normalize_token(account.get("access_token") or "")
        raw_region = str(account.get("promo_check_region") or "").strip().upper()
        try:
            region = normalize_promo_check_region(raw_region)
        except ValueError:
            region = "US"

        try:
            raw_result = check_account_promos(
                token,
                region=region,
            )
        except Exception:
            raw_result = {
                "ok": False,
                "error_code": "promo_check_unexpected",
                "http_status": None,
                "attempt_count": 0,
            }
        result = raw_result if isinstance(raw_result, dict) else {}
        ok = bool(result.get("ok"))
        try:
            http_status = int(result.get("http_status"))
            if not 100 <= http_status <= 599:
                http_status = None
        except (TypeError, ValueError, OverflowError):
            http_status = None
        try:
            attempt_count = max(0, min(2, int(result.get("attempt_count") or 0)))
        except (TypeError, ValueError, OverflowError):
            attempt_count = 0
        error_code = str(
            result.get("error_code") or result.get("auth_error_code") or ""
        ).strip().lower()
        # Treat an explicit authentication rejection as authoritative even if
        # a malformed/mocked response also claims ``ok=true``. The normal
        # promo kernel never emits that contradiction, but fail closed here so
        # an expired AT can never take the restore branch by accident.
        if error_code in _PROMO_PROBE_INVALID_CODES:
            state = "invalid"
            reason = error_code
        elif http_status == 401:
            state = "invalid"
            reason = "promo_check_http_401"
        elif ok:
            state = "valid"
            reason = "promo_check_valid"
        else:
            state = "unknown"
            reason = (
                error_code
                if error_code in _PROMO_PROBE_SAFE_CODES
                else "promo_check_unknown"
            )
        return {
            "state": state,
            "reason": reason,
            "http_status": http_status,
            "attempt_count": attempt_count,
            "region": region,
        }

    def _try_restore_session(self, ctx: _WindowContext, account: dict) -> dict | None:
        """Restore the saved browser Session using the historical Roxy path.

        This deliberately remains a small, visible-window helper rather than
        calling the shared background-refresh wrapper.  The latter performs an
        additional probe/state transition intended for bounded refresh jobs;
        the long-lived turb/OPLL window must preserve the old
        restore-then-OTP hand-off order.
        """

        def log_miss(reason: str) -> None:
            logger.info(
                "[SessionRefresh][Roxy] restore_result=miss account_id=%s reason=%s",
                ctx.account_id,
                _safe_session_restore_reason(reason),
            )

        email = str(account.get("email") or "").strip()
        stored_token = normalize_token(account.get("access_token") or "")
        logger.info(
            "[SessionRefresh][Roxy] restore_probe stored_token_state=%s account_id=%s",
            _access_token_state(stored_token),
            ctx.account_id,
        )
        if not email:
            log_miss("account_email_missing")
            return None
        if ctx.driver is None:
            log_miss("session_restore_failed")
            return None
        try:
            from core.chatgpt_session_store import get_session
            from core.roxy_registration import _page_warmup, _safe_get

            record = get_session(email, account_id=ctx.account_id)
            if not record:
                log_miss("session_record_missing")
                return None
            _restore_saved_session_to_driver(ctx.driver, record)
            _safe_get(
                ctx.driver,
                "https://chatgpt.com/",
                timeout=45,
                attempts=2,
                accept_hosts=("chatgpt.com", "auth.openai.com"),
            )
            _page_warmup(ctx.driver, reason="manual_window_session_restore")
            info = _find_session_in_windows(ctx.driver)
            token = normalize_token((info or {}).get("accessToken") or "")
            if not info or not token:
                log_miss("session_not_published")
                return None
            returned_state = _access_token_state(token)
            token_changed = token != stored_token
            logger.info(
                "[SessionRefresh][Roxy] restore_probe returned_token_state=%s "
                "token_changed=%s account_id=%s",
                returned_state,
                str(token_changed).lower(),
                ctx.account_id,
            )
            if returned_state == "expired":
                log_miss("token_expired")
                return None
            try:
                validate_session_identity(account, info, token)
            except ChatGPTSessionRefreshError:
                log_miss("session_identity_mismatch")
                return None
            logger.info(
                "[SessionRefresh][Roxy] restore_result=restored account_id=%s",
                ctx.account_id,
            )
            return info
        except ChatGPTSessionRefreshError as exc:
            if exc.error_code in {
                "session_window_close_requested",
                "roxy_window_browser_closed",
            }:
                raise
            log_miss(exc.error_code)
            return None
        except Exception:
            log_miss("session_restore_failed")
            return None

    def _wait_for_user_session(self, ctx: _WindowContext, account: dict) -> dict:
        """Wait indefinitely after an automatic-login obstacle."""

        self._set_state(
            ctx,
            status="waiting_user",
            stage="waiting_user",
        )
        while not ctx.stop_event.wait(1.0):
            if not self._check_driver_alive(ctx):
                raise ChatGPTSessionRefreshError(
                    "roxy_window_browser_closed",
                    "浏览器窗口已关闭",
                )
            info = _find_session_in_windows(ctx.driver)
            token = normalize_token((info or {}).get("accessToken") or "")
            if not info or not token:
                continue
            try:
                validate_session_identity(account, info, token)
                return info
            except ChatGPTSessionRefreshError as exc:
                self._set_state(
                    ctx,
                    status="waiting_user",
                    stage="waiting_user",
                    error_code=exc.error_code,
                )
        raise ChatGPTSessionRefreshError(
            "session_window_close_requested",
            "已请求关闭浏览器窗口",
        )

    def _persist_session(self, ctx: _WindowContext, account: dict, info: dict) -> None:
        save_driver_session_for_account(account, ctx.driver, info)

    def _run_headed_fresh_login(self, ctx: _WindowContext, account: dict) -> dict:
        """Run the pinned headed auth kernel inside this Roxy Profile.

        This method is reached only after the saved Session restore path has
        missed.  It deliberately does not fall back to Selenium when the CDP
        adapter cannot attach: the visible window is handed to the operator by
        the caller with a fixed error code instead.
        """

        from core.roxy_headed_registration import (
            run_roxy_headed_login_on_profile,
        )
        from core.roxy_registration import _safe_get

        password = ""
        if not ctx.otp_only_login:
            try:
                password = _registration_password(account)
            except Exception:
                password = ""
        secret = str(account.get("totp_secret") or "").strip()
        try:
            from core.auth_factors import resolve_login_policy

            mailbox_access = resolve_login_policy(account).mailbox_access
        except Exception:
            mailbox_access = True
        def login():
            return run_roxy_headed_login_on_profile(
                account=account,
                opened=ctx.opened,
                driver=ctx.driver,
                saved_openai_password=password,
                mfa_totp_secret=secret,
                otp_only=ctx.otp_only_login,
                stop_check=ctx.stop_event.is_set,
                stage_callback=lambda stage: self._set_raw_trace_stage(ctx, stage),
                low_traffic_enabled=False,
                mailbox_access=bool(mailbox_access),
                **({"allow_any_proxy_country": True} if getattr(ctx, "proxy_override", None) else {}),
            )
        if getattr(ctx, "browser_driver", "roxy") == "headed_chrome":
            from core.manual_window_browser import run_local_login
            session_info = run_local_login(login)
        else:
            session_info = login()
        # The headed worker used a page in the same remote Context.  Anchor
        # the owner Selenium session on ChatGPT before the strict liveness and
        # snapshot gates inspect it; this does not open any user target URL.
        _safe_get(
            ctx.driver,
            "https://chatgpt.com/",
            timeout=45,
            attempts=2,
            accept_hosts=("chatgpt.com", "auth.openai.com"),
        )
        return session_info

    def _run_automatic_fresh_login(
        self,
        ctx: _WindowContext,
        account: dict,
        *,
        use_headed: bool,
    ) -> dict:
        """Run one selected fresh-login kernel and preserve the visible hand-off.

        The headed and Selenium implementations share the same error/hand-off
        policy.  Keeping that policy here prevents a failure in either kernel
        from accidentally starting the other one or exposing an exception
        message in the window state.
        """

        try:
            if use_headed:
                return self._run_headed_fresh_login(ctx, account)
            return _wait_for_visible_login(
                ctx.driver,
                account,
                account_id=ctx.account_id,
                allow_manual_wait=True,
                manual_wait_timeout=None,
                on_manual_wait=lambda: self._set_state(
                    ctx,
                    status="waiting_user",
                    stage="waiting_user",
                ),
                stop_event=ctx.stop_event,
                otp_only=ctx.otp_only_login,
            )
        except AccountUnusableError as exc:
            self._set_state(
                ctx,
                status="waiting_user",
                stage="waiting_user",
                error_code=str(
                    getattr(exc, "error_code", "account_deactivated")
                ),
            )
            return self._wait_for_user_session(ctx, account)
        except ChatGPTSessionRefreshError as exc:
            if exc.error_code in {
                "session_window_close_requested",
                "roxy_window_browser_closed",
            }:
                raise
            self._set_state(
                ctx,
                status="waiting_user",
                stage="waiting_user",
                error_code=exc.error_code,
            )
            return self._wait_for_user_session(ctx, account)
        except Exception as exc:
            if ctx.stop_event.is_set():
                raise ChatGPTSessionRefreshError(
                    "session_window_close_requested",
                    "已请求关闭浏览器窗口",
                )
            if not self._check_driver_alive(ctx):
                raise ChatGPTSessionRefreshError(
                    "roxy_window_browser_closed",
                    "浏览器窗口已关闭",
                )
            # The headed adapter exposes a fixed ``code`` attribute.  The
            # Selenium path deliberately keeps its historical generic code.
            error_code = (
                str(getattr(exc, "code", "") or "").strip().lower()
                if use_headed
                else "roxy_window_automatic_login_failed"
            )
            if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", error_code):
                error_code = "roxy_window_automatic_login_failed"
            logger.warning(
                "[Roxy人工窗口] 自动登录未完成，转人工接管：account_id=%s reason=%s",
                ctx.account_id,
                error_code,
            )
            self._set_state(
                ctx,
                status="waiting_user",
                stage="waiting_user",
                error_code=error_code,
            )
            return self._wait_for_user_session(ctx, account)

    def _persist_fresh_login(self, ctx: _WindowContext, account: dict, info: dict) -> None:
        """Persist a fresh browser login through the strict rotation gate."""

        candidate = _build_roxy_login_candidate(
            account,
            login_email=str(account.get("email") or "").strip().lower(),
            driver=ctx.driver,
            session_info=info,
        )
        save_roxy_login_candidate_for_account(account, candidate)
        logger.info(
            "[SessionRefresh][Roxy] fresh_login_validation token_changed=true "
            "liveness=passed identity=matched account_id=%s",
            ctx.account_id,
        )

    def _open_target_tab(self, ctx: _WindowContext) -> None:
        if not ctx.target_url or ctx.driver is None:
            return
        driver = ctx.driver
        target_url = ctx.target_url
        try:
            ctx.auth_handle = getattr(driver, "current_window_handle", None)
        except Exception:
            ctx.auth_handle = None
        try:
            new_handle = None
            before_handles = set(getattr(driver, "window_handles", []) or [])
            switch_to = getattr(driver, "switch_to", None)
            if switch_to is not None and hasattr(switch_to, "new_window"):
                new_handle = switch_to.new_window("tab")
            if not new_handle:
                for candidate in list(getattr(driver, "window_handles", []) or []):
                    if candidate not in before_handles:
                        new_handle = candidate
                        break
            if not new_handle:
                driver.execute_script("window.open('about:blank', '_blank');")
                for candidate in list(getattr(driver, "window_handles", []) or []):
                    if candidate not in before_handles:
                        new_handle = candidate
                        break
            if not new_handle:
                raise RuntimeError("roxy_window_target_tab_open_failed")
            driver.switch_to.window(new_handle)
            driver.get(target_url)
            if ctx.target_validator is not None:
                current_url = str(getattr(driver, "current_url", "") or "")
                if not current_url:
                    raise RoxyManualWindowError(
                        "roxy_window_target_navigation_failed",
                        "目标支付页面未返回可验证地址",
                    )
                ctx.target_validator(current_url)
            if not self._check_driver_alive(ctx):
                raise RoxyManualWindowError(
                    "roxy_window_target_navigation_failed",
                    "目标支付页面打开后浏览器已关闭",
                )
            ctx.target_opened = True
            self._notify_lifecycle(
                ctx,
                "target_opened",
                status="ready",
                stage="payment_page_open",
            )
        except Exception as exc:
            if ctx.strict_target:
                if isinstance(exc, RoxyManualWindowError):
                    raise
                raise RoxyManualWindowError(
                    "roxy_window_target_navigation_failed",
                    "目标支付页面导航失败",
                ) from exc
            self._set_state(
                ctx,
                status="ready",
                stage="ready",
                error_code="roxy_window_target_navigation_failed",
            )
            if ctx.auth_handle:
                try:
                    driver.switch_to.window(ctx.auth_handle)
                except Exception:
                    pass
        finally:
            # The target URL is one-shot payment context.  Keep it only until
            # the navigation attempt has consumed it.
            ctx.target_url = ""

    def _wait_until_closed(self, ctx: _WindowContext) -> None:
        last_profile_check = 0.0
        while not ctx.stop_event.wait(_WINDOW_POLL_SECONDS):
            if not self._check_driver_alive(ctx):
                return
            now = time.monotonic()
            if now - last_profile_check < _PROFILE_CHECK_SECONDS:
                continue
            last_profile_check = now
            try:
                if ctx.client is not None and ctx.opened is not None:
                    if ctx.client.profile_is_closed(ctx.opened.profile_id):
                        # Roxy's management list can lag the browser process
                        # for a few seconds after launch.  Selenium is the
                        # authoritative liveness signal while the visible
                        # window still has a live handle; do not tear down a
                        # window solely because the remote Profile snapshot
                        # says it is closed.
                        if not self._check_driver_alive(ctx):
                            return
            except Exception:
                # Unknown management state must not close or release a live
                # lease. Selenium liveness remains the first signal.
                continue

    def _capture_before_close(self, ctx: _WindowContext, account: dict) -> None:
        if ctx.target_only:
            return
        if ctx.driver is None or not self._check_driver_alive(ctx):
            return
        if ctx.fresh_login_attempted and not ctx.fresh_login_validated:
            logger.info(
                "[SessionRefresh][Roxy] close_persist_skipped "
                "reason=fresh_login_validation_pending account_id=%s",
                ctx.account_id,
            )
            return
        info = _find_session_in_windows(ctx.driver)
        token = normalize_token((info or {}).get("accessToken") or "")
        if not info or not token:
            return
        try:
            validate_session_identity(account, info, token)
            self._persist_session(ctx, account, info)
        except ChatGPTSessionRefreshError as exc:
            self._set_state(
                ctx,
                status="ready",
                stage="ready",
                error_code=exc.error_code,
            )

    @staticmethod
    def _set_raw_trace_stage(ctx: _WindowContext, stage: str) -> None:
        tracer = ctx.raw_tracer
        if tracer is None:
            return
        try:
            tracer.set_stage(stage)
        except Exception:
            logger.warning(
                "[RoxyRawTrace] 人工窗口采样阶段更新失败："
                "account_id=%s reason=roxy_raw_trace_write_failed",
                ctx.account_id,
            )

    def _start_raw_trace(self, ctx: _WindowContext) -> None:
        if not ctx.raw_trace_enabled:
            return
        try:
            from core.roxy_raw_network_trace import RoxyRawNetworkTracer

            tracer = RoxyRawNetworkTracer(
                debugger_address=str(
                    getattr(ctx.opened, "debugger_address", "") or ""
                ),
                enabled=True,
                task_kind="manual_window",
            )
            ctx.raw_tracer = tracer
            if not tracer.start():
                raise RoxyManualWindowError(
                    "roxy_raw_trace_start_failed",
                    "原始网络抓包启动失败",
                )
            logger.info(
                "[RoxyRawTrace] 人工窗口原始网络采样已启动："
                "account_id=%s trace_id=%s",
                ctx.account_id,
                tracer.trace_id,
            )
            self._set_raw_trace_stage(ctx, "profile_session")
        except RoxyManualWindowError:
            raise
        except Exception as exc:
            raise RoxyManualWindowError(
                "roxy_raw_trace_start_failed",
                "原始网络抓包启动失败",
            ) from exc

    @staticmethod
    def _stop_raw_trace(ctx: _WindowContext) -> None:
        tracer = ctx.raw_tracer
        if tracer is None:
            return
        trace_id = str(getattr(tracer, "trace_id", "") or "")
        try:
            summary = tracer.stop(network_usage=None)
            logger.info(
                "[RoxyRawTrace] 人工窗口原始网络采样已封存："
                "account_id=%s trace_id=%s state=%s errors=%s",
                ctx.account_id,
                trace_id,
                str((summary or {}).get("state") or "unknown"),
                len((summary or {}).get("error_codes") or []),
            )
        except Exception:
            logger.warning(
                "[RoxyRawTrace] 人工窗口原始网络采样收尾失败："
                "account_id=%s trace_id=%s reason=roxy_raw_trace_stop_failed",
                ctx.account_id,
                trace_id,
            )
        finally:
            ctx.raw_tracer = None

    def _cleanup(self, ctx: _WindowContext) -> bool:
        if ctx.tracer is not None:
            try:
                ctx.tracer.stop()
            except Exception:
                pass
        if ctx.raw_tracer is not None:
            try:
                ctx.raw_tracer.begin_browser_shutdown()
            except Exception:
                pass
        if ctx.browser_driver == "headed_chrome":
            from core.manual_window_browser import close_manual_chrome
            cleanup_ok = close_manual_chrome(ctx)
            self._stop_raw_trace(ctx)
            return cleanup_ok
        if ctx.driver is not None:
            try:
                ctx.driver.quit()
            except Exception:
                pass
        self._stop_raw_trace(ctx)
        if ctx.client is None or ctx.opened is None:
            return True
        try:
            _cleanup_refresh_profile(ctx.client, ctx.opened)
            if not bool(getattr(ctx.opened, "pooled", False)):
                try:
                    rows = ctx.client.list_profiles()
                    if not any(
                        ctx.client.profile_id_from_row(row)
                        == str(ctx.opened.profile_id)
                        for row in rows
                    ):
                        return True
                except Exception:
                    pass
            state = ctx.client._profile_open_state_strict(ctx.opened.profile_id)
            return state is False
        except Exception:
            return False

    def _run(self, ctx: _WindowContext) -> None:
        """Run the worker inside the existing per-account Session log.

        ``begin_run`` is intentionally performed before the worker thread is
        submitted so the first log record and the active run id are present
        when the authentication kernel starts.  Entering the handler is
        diagnostic only; if a logging sink cannot be installed, run the
        exact same worker without it rather than changing browser behavior.
        """

        if not ctx.session_log_enabled:
            self._run_impl(ctx)
            return

        try:
            log_context = account_operation_log.task_log_context(
                ctx.account_id,
                "session_refresh",
            )
            log_context.__enter__()
        except Exception:
            logger.warning(
                "[SessionRefresh][Roxy] 会话专属日志上下文启动失败："
                "account_id=%s reason=operation_log_context_failed",
                ctx.account_id,
            )
            self._run_impl(ctx)
            return

        try:
            self._run_impl(ctx)
        finally:
            try:
                log_context.__exit__(None, None, None)
            except Exception:
                logger.warning(
                    "[SessionRefresh][Roxy] 会话专属日志上下文收尾失败："
                    "account_id=%s reason=operation_log_context_close_failed",
                    ctx.account_id,
                )

    def _run_impl(self, ctx: _WindowContext) -> None:
        terminal_status = "closed"
        terminal_error = None
        terminal_error_type = ""
        account = None
        fresh_login_used = False
        try:
            self._set_state(ctx, status="opening", stage="opening")
            account = db.get_account(ctx.account_id)
            if not account:
                raise RoxyManualWindowError("account_not_found", "账号不存在")
            from core.roxy_registration import (
                RoxyIdentityResetError,
                _center_browser_window,
                _reset_pooled_profile_identity,
            )
            from core.manual_window_browser import open_manual_browser

            open_manual_browser(self, ctx, account)
            if ctx.stop_event.is_set():
                raise ChatGPTSessionRefreshError(
                    "session_window_close_requested",
                    "已请求关闭浏览器窗口",
                )
            try:
                from core.roxy_dom_failure_diagnostic import create_recorder

                ctx.dom_recorder = create_recorder(
                    ctx.driver,
                    task_kind="manual_window",
                    account_id=ctx.account_id,
                )
                ctx.dom_recorder.observe(
                    ctx.driver,
                    stage="opening",
                    event="browser_ready",
                    force=True,
                )
            except Exception:
                ctx.dom_recorder = None
            _center_browser_window(ctx.driver, headless=False)
            try:
                ctx.driver.set_page_load_timeout(90)
            except Exception:
                pass
            try:
                _reset_pooled_profile_identity(ctx.driver)
            except RoxyIdentityResetError as exc:
                raise RoxyManualWindowError(
                    "roxy_window_identity_cleanup_failed",
                    "浏览器身份数据清理失败",
                ) from exc
            if ctx.stop_event.is_set():
                raise ChatGPTSessionRefreshError(
                    "session_window_close_requested",
                    "已请求关闭浏览器窗口",
                )
            if ctx.target_only:
                self._set_state(
                    ctx,
                    status="opening",
                    stage="opening",
                )
                self._open_target_tab(ctx)
                self._set_state(ctx, status="ready", stage="ready")
                self._wait_until_closed(ctx)
                if not ctx.stop_event.is_set():
                    terminal_error = "roxy_window_browser_closed"
                return
            self._start_raw_trace(ctx)
            if ctx.stop_event.is_set():
                raise ChatGPTSessionRefreshError(
                    "session_window_close_requested",
                    "已请求关闭浏览器窗口",
                )

            def persist_account_unusable(code: str, _metadata: dict) -> None:
                try:
                    db.mark_account_unusable(
                        acc_id=ctx.account_id,
                        error_code=str(code or "account_deactivated"),
                        evidence_source="roxy_manual_window",
                    )
                except Exception:
                    pass

            try:
                ctx.tracer = RoxyChatGPTContractTracer(
                    ctx.driver,
                    debugger_address=getattr(ctx.opened, "debugger_address", None),
                    task_kind="manual_window",
                    account_id=ctx.account_id,
                    old_access_token=str(account.get("access_token") or ""),
                    account_unusable_callback=persist_account_unusable,
                )
                ctx.tracer.set_stage("manual_window_login")
                ctx.tracer.start()
            except Exception:
                ctx.tracer = None

            if not ctx.auto_login_enabled:
                # Explicit manual mode never reads saved credentials or
                # requests an OTP.  The browser remains available while the
                # operator navigates and signs in; the same identity checks
                # below protect the account before any Session is persisted.
                self._set_raw_trace_stage(ctx, "login_page")
                session_info = self._wait_for_user_session(ctx, account)
            else:
                # Read the backend hint immediately before choosing the
                # restore path.  Plan/promo checks may finish while the
                # browser/Profile is being prepared; the latest persisted
                # value must win over the account snapshot taken at open.
                probe_account = db.get_account(ctx.account_id)
                if not probe_account:
                    raise RoxyManualWindowError("account_not_found", "账号不存在")
                account = probe_account
                self._set_state(ctx, status="restoring_session", stage="restoring_session")
                self._set_raw_trace_stage(ctx, "profile_session")
                promo_probe = self._probe_access_token_with_promos(probe_account)
                logger.info(
                    "[SessionRefresh][Roxy] promo_probe state=%s reason=%s "
                    "http_status=%s attempt_count=%s account_id=%s",
                    promo_probe.get("state") or "unknown",
                    promo_probe.get("reason") or "promo_check_unknown",
                    promo_probe.get("http_status")
                    if promo_probe.get("http_status") is not None
                    else "none",
                    int(promo_probe.get("attempt_count") or 0),
                    ctx.account_id,
                )
                latest_account = db.get_account(ctx.account_id)
                if not latest_account:
                    raise RoxyManualWindowError("account_not_found", "账号不存在")
                account = latest_account
                refresh_required = account.get("session_refresh_required") is True
                probe_invalid = promo_probe.get("state") == "invalid"
                restore_attempted = False
                if refresh_required:
                    logger.info(
                        "[SessionRefresh][Roxy] path=fresh_login "
                        "reason=session_refresh_required account_id=%s",
                        ctx.account_id,
                    )
                    session_info = None
                elif probe_invalid:
                    logger.info(
                        "[SessionRefresh][Roxy] path=fresh_login reason=%s account_id=%s",
                        promo_probe.get("reason") or "promo_check_http_401",
                        ctx.account_id,
                    )
                    session_info = None
                else:
                    restore_reason = (
                        "promo_check_valid"
                        if promo_probe.get("state") == "valid"
                        else "normal"
                    )
                    logger.info(
                        "[SessionRefresh][Roxy] path=restore_saved_session "
                        f"reason={restore_reason} account_id={ctx.account_id}",
                    )
                    restore_attempted = True
                    session_info = self._try_restore_session(ctx, account)
                if ctx.stop_event.is_set():
                    raise ChatGPTSessionRefreshError(
                        "session_window_close_requested",
                        "已请求关闭浏览器窗口",
                    )
                if session_info is None:
                    fresh_login_used = True
                    ctx.fresh_login_attempted = True
                    # The Profile was already cleaned immediately after it
                    # opened.  A normal restore miss needs the historical
                    # second cleanup (the restore attempt may have left
                    # identity residue); an explicit backend refresh hint did
                    # not attempt restoration, so do not clear it twice.
                    if restore_attempted:
                        try:
                            _reset_pooled_profile_identity(ctx.driver)
                        except RoxyIdentityResetError as exc:
                            raise RoxyManualWindowError(
                                "roxy_window_identity_cleanup_failed",
                                "浏览器身份数据清理失败",
                            ) from exc
                    self._set_state(ctx, status="automatic_login", stage="automatic_login")
                    self._set_raw_trace_stage(ctx, "login_page")
                    from config import roxybrowser as roxy_cfg

                    use_headed_login = ctx.browser_driver == "headed_chrome" or bool(
                        getattr(
                            roxy_cfg,
                            "ROXY_REGISTRATION_LOW_TRAFFIC_MODE",
                            False,
                        )
                    )
                    # Once selected, a headed failure is handed to the user;
                    # it is never retried through Selenium (or vice versa).
                    session_info = self._run_automatic_fresh_login(
                        ctx,
                        account,
                        use_headed=use_headed_login,
                    )
            if fresh_login_used and normalize_token(account.get("access_token") or ""):
                try:
                    self._persist_fresh_login(ctx, account, session_info)
                except ChatGPTSessionRefreshError as exc:
                    logger.warning(
                        "[SessionRefresh][Roxy] fresh_login_validation result=failed "
                        "token_changed=%s reason=%s account_id=%s",
                        str(
                            normalize_token((session_info or {}).get("accessToken") or "")
                            != normalize_token(account.get("access_token") or "")
                        ).lower(),
                        _safe_roxy_validation_reason(exc.error_code),
                        ctx.account_id,
                    )
                    raise
                else:
                    ctx.fresh_login_validated = True
            else:
                self._persist_session(ctx, account, session_info)
                if fresh_login_used:
                    # Accounts without a prior AT use the legacy persistence
                    # path; mark it validated only after that save succeeds so
                    # the close hook remains fail-closed on exceptions.
                    ctx.fresh_login_validated = True
            if ctx.session_log_enabled:
                saved_account = db.get_account(ctx.account_id) or {}
                logger.info(
                    "[SessionRefresh][Roxy] session_saved=true "
                    "refresh_required_cleared=%s account_id=%s",
                    str(saved_account.get("session_refresh_required") is not True).lower(),
                    ctx.account_id,
                )
            if ctx.tracer is not None:
                try:
                    ctx.tracer.observe_session_info(
                        session_info,
                        source="manual_window_login",
                    )
                    ctx.tracer.set_stage("manual_window_ready")
                except Exception:
                    pass
            self._set_raw_trace_stage(ctx, "other")
            if ctx.strict_target:
                self._set_state(
                    ctx,
                    status="opening",
                    stage="opening",
                )
            else:
                self._set_state(ctx, status="ready", stage="ready")
            self._open_target_tab(ctx)
            if ctx.strict_target:
                self._set_state(ctx, status="ready", stage="ready")
            self._wait_until_closed(ctx)
            if not ctx.stop_event.is_set():
                terminal_error = "roxy_window_browser_closed"
        except RoxyManualWindowError as exc:
            terminal_status = "closed" if ctx.stop_event.is_set() else "failed"
            terminal_error = None if terminal_status == "closed" else exc.error_code
            terminal_error_type = type(exc).__name__
            logger.warning(
                "[Roxy人工窗口] 任务结束：account_id=%s result=%s reason=%s",
                ctx.account_id,
                terminal_status,
                terminal_error or "closed_by_user",
            )
        except ChatGPTSessionRefreshError as exc:
            terminal_status = "closed" if ctx.stop_event.is_set() else "failed"
            terminal_error = None if terminal_status == "closed" else exc.error_code
            terminal_error_type = type(exc).__name__
            logger.warning(
                "[Roxy人工窗口] 登录流程结束：account_id=%s result=%s reason=%s",
                ctx.account_id,
                terminal_status,
                terminal_error or "closed_by_user",
            )
        except AccountUnusableError as exc:
            terminal_status = "closed" if ctx.stop_event.is_set() else "failed"
            terminal_error = (
                None
                if terminal_status == "closed"
                else str(getattr(exc, "error_code", "account_deactivated"))
            )
            terminal_error_type = type(exc).__name__
            logger.warning(
                "[Roxy人工窗口] 账号终态阻断：account_id=%s result=%s reason=%s",
                ctx.account_id,
                terminal_status,
                terminal_error or "closed_by_user",
            )
        except Exception as exc:
            terminal_status = "closed" if ctx.stop_event.is_set() else "failed"
            terminal_error = None if terminal_status == "closed" else "roxy_window_unexpected"
            terminal_error_type = type(exc).__name__
            logger.exception(
                "[Roxy人工窗口] 任务异常：account_id=%s reason=%s",
                ctx.account_id,
                terminal_error,
            )
        finally:
            if account is not None and ctx.stop_event.is_set():
                try:
                    self._capture_before_close(ctx, account)
                except Exception:
                    pass
            # User-requested close is a normal lifecycle outcome and must not
            # create a failure snapshot.  Startup/attach/auth failures do.
            if ctx.dom_recorder is not None and terminal_status == "failed":
                try:
                    ctx.dom_recorder.finalize(
                        ctx.driver,
                        terminal_status="failed",
                        error_code=terminal_error or "roxy_window_unexpected",
                        source_error_type=terminal_error_type,
                    )
                except Exception:
                    pass
            cleanup_ok = self._cleanup(ctx)
            if not cleanup_ok and ctx.opened is not None:
                terminal_status = "interrupted"
                if terminal_error != "roxy_raw_trace_start_failed":
                    terminal_error = "roxy_window_close_unconfirmed"
            profile_id = str(
                (getattr(ctx.opened, "profile_id", "") or "")
                if ctx.browser_driver == "roxy" else ""
            ).strip()
            if terminal_status == "interrupted" and profile_id:
                try:
                    from core.roxy_profile_pool import get_roxy_profile_pool

                    get_roxy_profile_pool().reserve_external(profile_id)
                except Exception:
                    logger.warning(
                        "[Roxy人工窗口] 中断环境隔离失败："
                        "account_id=%s reason=profile_reservation_failed",
                        ctx.account_id,
                    )
            try:
                persisted = db.finish_account_roxy_window(
                    ctx.account_id,
                    ctx.run_id,
                    status=terminal_status,
                    error_code=terminal_error,
                )
            except Exception:
                persisted = False
                logger.warning(
                    "[Roxy人工窗口] 终态写入失败：account_id=%s reason=terminal_state_persist_failed",
                    ctx.account_id,
                )
            if not persisted and profile_id:
                try:
                    latest = db.get_account(ctx.account_id) or {}
                    if str(
                        latest.get("roxy_window_profile_id") or ""
                    ).strip() == profile_id:
                        from core.roxy_profile_pool import get_roxy_profile_pool

                        get_roxy_profile_pool().reserve_external(profile_id)
                except Exception:
                    logger.warning(
                        "[Roxy人工窗口] 终态缺失环境隔离失败："
                        "account_id=%s reason=profile_reservation_failed",
                        ctx.account_id,
                    )
            self._notify_lifecycle(
                ctx,
                "terminal",
                status=terminal_status,
                stage=terminal_status,
                error_code=terminal_error,
            )
            with self._lock:
                self._contexts.pop(ctx.account_id, None)


_MANAGER = RoxyManualWindowManager()


def get_roxy_manual_window_manager() -> RoxyManualWindowManager:
    return _MANAGER


__all__ = [
    "RoxyManualWindowError",
    "RoxyManualWindowManager",
    "get_roxy_manual_window_manager",
    "validate_target_url",
]
