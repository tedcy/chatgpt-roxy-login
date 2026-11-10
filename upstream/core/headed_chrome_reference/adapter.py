"""Host adapter for the pinned local headed-Google-Chrome state machine."""

from __future__ import annotations

import importlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from config import twofa as _twofa_cfg
from config import roxybrowser as _browser_cfg
from core.account_export import save_account_data
from core.registration_password_state import bind_password_state, merge_auth_fields
from core.chatgpt_plan import token_claims
from core.chatgpt_session_store import (
    ChatGPTSessionStoreError,
    bind_account as bind_chatgpt_session_account,
    normalise_cookies,
    save_snapshot as save_chatgpt_session_snapshot,
)
from core.email_provider import (
    mark_registration_account_created,
    mark_registration_failed,
    prepare_otp_context,
    registration_failure_email_status,
    release_email,
    resolve_email_source,
    wait_for_otp,
)
from core.plan_check_route import RegistrationPlanRouteHint
from core.roxy_login_primitives import TotpSecretError, normalise_totp_secret
from core.proxy_sid import (
    mask_proxy_url,
    redact_proxy_metadata,
    select_default_proxy,
    validate_headed_chrome_proxy_country_runtime,
)

from .integrity import verify_vendored_source
from .traffic import HeadedChromeTrafficReporter
from .runtime_guard import RegistrationRuntime
from .completion import run_with_cleanup_result
from .password_diagnostics import PasswordInputObserver
from .password_confirmation import CandidatePasswordEvidence
from .password_entry_diagnostics import create_diagnostics
from .otp_transition import OtpProgress, wait_after_submit
from .response_guard import RegistrationResponseGuard, wait_for_create_transition, wait_auth_events
from .password_input import fill_signup_password, validate_before_submit
from .signup_mode import select_mode
from .flow_diagnostics import install as install_flow_diagnostics, capture as capture_submission
from .network_evidence import exception_reason
from . import email_form, profile_form
from .form_states import PASSWORD_ENTRY_PRESENT
from .form_readiness import FormNotReady, DocumentChanged
from .page_snapshot import evaluate_snapshot, AuthPageSnapshotTimeout, AuthPageSnapshotFailed, snapshot_purpose
from .diagnostics import (emit as diagnostic_emit, failure as diagnostic_failure,
                          step as diagnostic_step, worker_step, observe_close,
                          page_block, response as diagnostic_response,
                          request as diagnostic_request, trace_summary, log_text,
                          diagnostic_run)


logger = logging.getLogger(__name__)
_REFERENCE_LOCK = threading.RLock()
_REFERENCE_MODULE = None
_AUTH_TRANSITION_SECONDS = 15.0
_AUTH_POLL_SECONDS = 0.25
_AUTH_SNAPSHOT_SECONDS = 15.0
_AUTH_PAGE_SNAPSHOT = r"""() => {
    const usable = e => {
        const r = e.getBoundingClientRect(), s = getComputedStyle(e);
        return r.width > 0 && r.height > 0 && s.display !== 'none'
            && s.visibility !== 'hidden' && !e.disabled && !e.readOnly
            && e.getAttribute('aria-disabled') !== 'true';
    };
    const has = selector => [...document.querySelectorAll(selector)].some(usable);
    const path = location.pathname.replace(/\/$/, '');
    const heading = document.querySelector('h1')?.textContent || document.title;
    const expired = /session (?:has )?(?:expired|ended)|session is (?:invalid|no longer valid)|セッション(?:の有効期限が切れました|が終了しました)|会话(?:已过期|已结束|失效)/i.test(heading);
    let stage = 'other';
    if (expired) stage = 'session_expired';
    else if (/mfa|challenge|phone|captcha/.test(path)) stage = 'challenge';
    else if (path === '/about-you' || (document.querySelector('input[name="name"]')
             && has('input[name="name"]') && document.querySelector(
                 'input[name="birthday"], [autocomplete="bday"], [role="spinbutton"]')))
        stage = 'profile';
    else {
        const password = has('input[type="password"]');
        if (/password/.test(path)) {
            const otp = has('input[autocomplete="one-time-code"], input[name="code"], input[inputmode="numeric"], input[type="tel"]');
            stage = password && !otp ? 'password' : 'transitioning';
        } else if (password) stage = 'transitioning';
        else if (/email-verification|email-otp|email-code|verify-email/.test(path))
            stage = has('input[autocomplete="one-time-code"], input[name="code"], input[inputmode="numeric"], input[type="tel"]') ? 'email_otp' : 'transitioning';
    }
    const password_entry_present = (""" + PASSWORD_ENTRY_PRESENT + r""")();
    let diagnostic_controls = {};
    try {
        const otpInputs = [...document.querySelectorAll('input[autocomplete="one-time-code"], input[name="code"], input[inputmode="numeric"], input[type="tel"]')];
        const otpInput = otpInputs.find(usable);
        const otpForm = otpInput?.form || otpInputs[0]?.form;
        diagnostic_controls = {input: !!otpInput, form: !!otpForm,
            submit: !!otpForm && [...otpForm.querySelectorAll('button[type="submit"],input[type="submit"],button:not([type])')].some(usable)};
    } catch (_) { /* Diagnostic failures must not change the original stage. */ }
    return {stage, host: location.hostname, path, epoch: performance.timeOrigin, password_entry_present, diagnostic_controls};
}"""
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CACHE_ROOT = _PROJECT_ROOT / "data" / "headed_chrome_reference"
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]+){1,2}\b")
_OTP_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(access[_ -]?token|cookie|password|otp|totp|recovery[_ -]?code)"
    r"\s*[:=]\s*([^\s,;]+)"
)
_EMAIL_OTP_INVALID_CODES = frozenset(
    {
        "invalid_code",
        "invalid_email_code",
        "invalid_email_otp",
        "invalid_otp",
        "invalid_verification_code",
        "email_code_invalid",
        "email_otp_expired",
        "email_otp_invalid",
        "otp_expired",
        "otp_invalid",
        "verification_code_expired",
        "verification_code_invalid",
        "wrong_email_otp_code",
    }
)
_EMAIL_OTP_BLOCKED_CODES = frozenset(
    {
        "access_denied",
        "account_banned",
        "account_deactivated",
        "account_deleted",
        "auth_blocked",
        "captcha_required",
        "challenge_required",
        "csrf_failed",
        "forbidden",
        "identity_mismatch",
        "invalid_session",
        "rate_limited",
        "request_blocked",
        "sentinel_failed",
        "session_expired",
        "too_many_attempts",
        "unauthorized",
    }
)
_EMAIL_OTP_BLOCKED_MARKERS = (
    "account deactivated",
    "account deleted",
    "account banned",
    "access denied",
    "captcha",
    "challenge required",
    "rate limit",
    "too many",
    "unauthorized",
    "forbidden",
    "blocked",
    "session expired",
    "csrf",
    "sentinel",
)
_EMAIL_OTP_TEXT_MARKERS = (
    "otp",
    "verification code",
    "email code",
    "one-time code",
    "验证码",
    "驗證碼",
    "認証コード",
)
_EMAIL_OTP_INVALID_TEXT_MARKERS = (
    "invalid",
    "incorrect",
    "expired",
    "does not match",
    "not valid",
    "无效",
    "不正确",
    "過期",
    "不正",
)


class HeadedChromeRegistrationError(RuntimeError):
    def __init__(self, code: str):
        self.code = str(code or "headed_chrome_registration_failed")
        # Keep the error compatible with the shared Roxy/session refresh
        # boundary, which reads ``error_code`` from provider exceptions.
        self.error_code = self.code
        super().__init__(self.code)


def _normalise_response_code(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip(
        "_"
    )


def _email_otp_response_is_invalid(response: object) -> bool:
    """Recognise an OTP rejection without treating auth blocks as bad codes."""

    try:
        request = getattr(response, "request", None)
        method = str(getattr(request, "method", "") or "").upper()
        url = str(getattr(response, "url", "") or getattr(request, "url", "") or "")
        parsed = urlsplit(url)
        if (
            method != "POST"
            or str(parsed.hostname or "").lower() != "auth.openai.com"
            or not str(parsed.path or "").endswith("/api/accounts/email-otp/validate")
        ):
            return False
        status = int(getattr(response, "status", 0) or 0)
        if status not in {400, 401, 403, 422}:
            return False
        headers = getattr(response, "headers", {})
        if callable(headers):
            headers = headers()
        header_names = {
            str(key or "").strip().lower() for key in (headers or {})
        }
        blocked_headers = {
            "cf-mitigated",
            "cf-chl-bypass",
            "cf-chl-captcha-id",
            "retry-after",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
        }
        if header_names.intersection(blocked_headers):
            return False
        response_json = getattr(response, "json", None)
        try:
            payload = response_json() if callable(response_json) else {}
        except Exception:
            # Playwright can make the body unavailable after the response
            # observer has already seen the status.  A JSON 403 without a
            # body is still the normal invalid-code response unless the
            # headers identify a Cloudflare/rate-limit challenge.  Keep the
            # header gate below authoritative and do not require response
            # text to be readable before allowing the one safe resend.
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        error = payload.get("error")
        objects = [payload]
        if isinstance(error, dict):
            objects.append(error)
        elif isinstance(error, str):
            objects.append({"message": error})
        codes = {
            _normalise_response_code(item)
            for obj in objects
            for key in ("code", "error_code", "type", "kind")
            for item in (obj.get(key),)
            if item not in (None, "")
        }
        if codes & _EMAIL_OTP_BLOCKED_CODES:
            return False
        if codes & _EMAIL_OTP_INVALID_CODES:
            return True
        text = " ".join(
            str(obj.get(key) or "").strip().lower()
            for obj in objects
            for key in ("message", "detail", "reason")
        )
        if any(marker in text for marker in _EMAIL_OTP_BLOCKED_MARKERS):
            return False
        if bool(
            any(marker in text for marker in _EMAIL_OTP_TEXT_MARKERS)
            and any(marker in text for marker in _EMAIL_OTP_INVALID_TEXT_MARKERS)
        ):
            return True
        # The auth endpoint can return an empty/unreadable JSON body for an
        # ordinary rejected code.  A bare 403 is only retryable when it looks
        # like the JSON application response rather than a Cloudflare or
        # rate-limit challenge.  Terminal account codes were handled above.
        content_type = ""
        for key, value in (headers or {}).items():
            if str(key or "").strip().lower() == "content-type":
                content_type = str(value or "").lower()
                break
        return bool(
            status == 403
            and "application/json" in content_type
        )
    except Exception:
        return False


class _StopEvent:
    """Threading-Event compatible view over the registration stop callback."""

    def __init__(self, callback=None):
        self._callback = callback
        self._local = threading.Event()

    def _check(self) -> bool:
        if self._local.is_set():
            return True
        if self._callback is not None:
            result = self._callback()
            if result:
                self._local.set()
        return self._local.is_set()

    def is_set(self) -> bool:
        return self._check()

    def set(self) -> None:
        self._local.set()

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        while True:
            if self._check():
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            remaining = 0.2 if deadline is None else min(0.2, max(0.0, deadline - time.monotonic()))
            self._local.wait(remaining)


def _load_reference_module():
    global _REFERENCE_MODULE
    with _REFERENCE_LOCK:
        if _REFERENCE_MODULE is not None:
            return _REFERENCE_MODULE
        if not verify_vendored_source():
            raise HeadedChromeRegistrationError("headed_chrome_core_integrity_failed")
        try:
            reference = importlib.import_module(
                "core.headed_chrome_reference.vendor.app"
            )
        except Exception as exc:
            raise HeadedChromeRegistrationError(
                "headed_chrome_runtime_unavailable"
            ) from exc
        cache_root = _CACHE_ROOT.resolve()
        cache_root.mkdir(parents=True, exist_ok=True)
        reference.APP_DIR = cache_root
        reference.STATE_FILE = cache_root / "state.json"
        reference.STATE_DATA_DIR = cache_root
        reference.STATE_SESSION_DIR = cache_root / "sessions"
        reference.NETWORK_CAPTURE_DIR = cache_root / "network_captures"
        reference.AUTH_STATIC_DISK_CACHE_PATH = (
            cache_root / "auth-static-cache-v3.sqlite3"
        )
        _REFERENCE_MODULE = reference
        return reference


def _safe_log_text(value: object) -> str:
    text = str(redact_proxy_metadata(str(value or "")) or "")
    text = _JWT_RE.sub("[REDACTED]", text)
    text = _OTP_RE.sub("[REDACTED]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = re.sub(r"(?i)(页面内容|响应正文)\s*[:：].*$", r"\1=[REDACTED]", text)
    return text.strip()[:800]


def _session_identity(email: str, session_info: dict, access_token: str) -> dict:
    info = session_info if isinstance(session_info, dict) else {}
    user = info.get("user") if isinstance(info.get("user"), dict) else {}
    account = info.get("account") if isinstance(info.get("account"), dict) else {}
    claims = token_claims(access_token)
    emails = {
        str(item or "").strip().casefold()
        for item in (user.get("email"), claims.get("email"))
        if str(item or "").strip()
    }
    user_ids = {
        str(item or "").strip()
        for item in (user.get("id"), claims.get("user_id"))
        if str(item or "").strip()
    }
    account_ids = {
        str(item or "").strip()
        for item in (account.get("id"), claims.get("account_id"))
        if str(item or "").strip()
    }
    expected = str(email or "").strip().casefold()
    if not expected or emails != {expected} or len(user_ids) != 1 or len(account_ids) != 1:
        raise HeadedChromeRegistrationError(
            "registration_session_identity_mismatch"
        )
    return {
        "email": expected,
        "user_id": next(iter(user_ids)),
        "account_id": next(iter(account_ids)),
    }


def _browser_profile(worker) -> dict:
    fp = getattr(worker, "fingerprint", None)
    if fp is None:
        return {}
    return {
        "user_agent": str(getattr(fp, "user_agent", "") or ""),
        "accept_language": str(getattr(fp, "accept_language", "") or ""),
        "navigator_language": str(getattr(fp, "locale", "") or ""),
        "navigator_languages": list(getattr(fp, "languages", []) or []),
        "navigator_platform": str(getattr(fp, "platform", "") or ""),
        "user_agent_data_platform": "Windows",
        "timezone_iana": str(getattr(fp, "timezone", "") or ""),
        "screen_width": int(getattr(fp, "screen_width", 0) or 0),
        "screen_height": int(getattr(fp, "screen_height", 0) or 0),
        "device_pixel_ratio": float(
            getattr(fp, "device_scale_factor", 0) or 0
        ),
        "hardware_concurrency": int(
            getattr(fp, "hardware_concurrency", 0) or 0
        ),
        "device_memory": int(getattr(fp, "device_memory", 0) or 0),
    }


def _session_snapshot(
    *,
    email: str,
    result: dict,
    session_info: dict,
    worker,
) -> dict:
    try:
        storage_state = json.loads(str(result.get("storage_state_json") or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ChatGPTSessionStoreError("session_storage_state_invalid") from exc
    if not isinstance(storage_state, dict):
        raise ChatGPTSessionStoreError("session_storage_state_invalid")
    cookies = normalise_cookies(storage_state.get("cookies") or [])
    device_id = ""
    for item in cookies:
        if str(item.get("name") or "").lower() == "oai-did":
            device_id = str(item.get("value") or "")
            break
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "email": str(email or "").strip().lower(),
        "account_id": None,
        "cookies": cookies,
        "device_id": device_id,
        "browser_profile": _browser_profile(worker),
        "storage_state": storage_state,
        "session_expires_at": str(session_info.get("expires") or ""),
        "captured_at": now,
        "updated_at": now,
        "last_refresh_at": None,
        "status": "ready",
    }


def _plan_route_hint(selection) -> RegistrationPlanRouteHint:
    geo = dict(getattr(selection, "geo", {}) or {})
    country = str(
        geo.get("country") or getattr(selection, "actual_country", "") or ""
    ).strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        country = ""
    return RegistrationPlanRouteHint(
        proxy_url=str(getattr(selection, "proxy_url", "") or ""),
        validated_geo=geo,
        proxy_resolved=True,
        country=country,
        proxy_safe_label=str(getattr(selection, "safe_label", "") or ""),
    )


def _safe_codex_result(email: str, *, proxy: str, proxy_geo: dict) -> dict:
    try:
        from core.codex_oauth import run_codex_oauth

        return run_codex_oauth(email, proxy=proxy, proxy_geo=dict(proxy_geo or {}))
    except Exception:
        return {
            "status": "failed",
            "ok": False,
            "message": "codex_oauth_failed",
        }


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, TotpSecretError):
        return exc.error_code
    if type(exc).__name__ == "MfaRequiredError":
        return "headed_chrome_mfa_required"
    fixed = str(getattr(exc, "code", "") or "").strip().lower()
    if fixed:
        return fixed
    text = str(exc or "").lower()
    name = type(exc).__name__.lower()
    if "google chrome" in text and ("启动" in text or "launch" in text):
        return "headed_chrome_launch_failed"
    if "proxy" in name or "代理" in text or "err_tunnel" in text:
        return "headed_chrome_proxy_failed"
    if "identity" in text or "身份" in text:
        return "registration_session_identity_mismatch"
    if exception_reason(exc):
        return "headed_chrome_auth_network_error"
    if "session" in text or "accesstoken" in text:
        return "headed_chrome_session_missing"
    if "otp" in text or "验证码" in text:
        return "headed_chrome_otp_failed"
    if "timeout" in name or "超时" in text:
        return "headed_chrome_auth_timeout"
    return "headed_chrome_registration_failed"


def _email_otp_ready_timeout_seconds() -> float:
    """Read reloaded configuration once per readiness check."""
    try:
        value = int(str(getattr(_browser_cfg, "BROWSER_OTP_READY_TIMEOUT_SECONDS", 60)).strip())
    except (TypeError, ValueError, OverflowError):
        return 60.0
    return float(value) if 1 <= value <= 120 else 60.0


def _registration_worker_timeout_seconds() -> float:
    """Return a bounded headed-worker timeout without allowing an infinite run."""

    try:
        value = float(
            getattr(_browser_cfg, "REGISTRATION_WORKER_TIMEOUT_SECONDS", 900)
        )
    except (TypeError, ValueError, OverflowError):
        value = 900.0
    if value <= 0:
        value = 900.0
    return max(30.0, min(value, 7200.0))


def _is_transient_auth_navigation_error(exc: BaseException) -> bool:
    """Return whether an initial auth navigation may be retried safely.

    The retry is deliberately narrow: only browser navigation timeouts and
    Chromium's transient connection errors qualify.  Application errors,
    redirects, auth responses and proxy/configuration failures must still
    propagate to the existing registration boundary.
    """

    text = str(exc or "").strip().lower()
    name = type(exc).__name__.strip().lower()
    markers = (
        "net::err_timed_out",
        "net::err_connection_reset",
        "net::err_connection_closed",
        "net::err_network_changed",
        "navigation timeout",
        "page.goto: timeout",
    )
    if any(marker in text for marker in markers):
        return True
    return name in {"timeouterror", "playwrighttimeouterror"} or (
        "timeout" in name and "navigation" in text
    )


class _InitialAuthNavigationRetryPage:
    """Proxy one Playwright page navigation without changing its Context.

    The pinned vendor worker performs the first auth-page ``goto`` directly,
    so the host adapter cannot change that call without copying the vendor
    state machine.  This transparent proxy intercepts only that one target
    navigation and retries it once on a clearly transient browser error.
    """

    def __init__(self, page, owner) -> None:
        self._page = page
        self._owner = owner
        self._initial_navigation_pending = True

    def goto(self, url, *args, **kwargs):
        target = str(url or "")
        parsed = urlsplit(target)
        should_retry = bool(
            self._initial_navigation_pending
            and str(parsed.hostname or "").lower() == "auth.openai.com"
        )
        if not should_retry:
            return self._page.goto(url, *args, **kwargs)
        self._initial_navigation_pending = False
        try:
            return self._page.goto(url, *args, **kwargs)
        except Exception as exc:
            if not _is_transient_auth_navigation_error(exc):
                raise
            wait = getattr(self._owner, "_wait_or_stop", None)
            if callable(wait):
                wait(1.0)
            log = getattr(self._owner, "log", None)
            if callable(log):
                log(
                    "[认证] 初始授权页导航遇到临时网络超时，沿用同一 Profile 重试一次"
                )
            return self._page.goto(url, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._page, name)


def _current_provider_otp_reader_class(reference, stop_check=None):
    """Build the host mailbox adapter shared by local and Roxy Chrome."""

    class CurrentProviderOtpReader(reference.UrlOtpReader):
        def __init__(
            self,
            account,
            reader_log,
            _proxy_url="",
            stop_event=None,
            **_kwargs,
        ):
            self.account = account
            self.log = reader_log
            self.stop_event = stop_event
            self.fetch_count = 0

        def connect(self) -> None:
            if self.stop_event is not None and self.stop_event.is_set():
                raise HeadedChromeRegistrationError("registration_stopped")
            prepare_otp_context(self.account.email)
            self.log("[邮箱] 已建立当前项目独立取码基线")

        def mark_current_codes_seen(self) -> int:
            prepare_otp_context(self.account.email)
            return 0

        def wait_for_code(
            self,
            min_timestamp: float,
            timeout: int = 180,
            resend_callback=None,
            initial_delay: float = 0.0,
        ) -> str:
            del resend_callback
            delay = (
                max(10.0, float(initial_delay or 0.0))
                if self.fetch_count == 0
                else max(0.0, float(initial_delay or 0.0))
            )
            self.fetch_count += 1
            if self.stop_event is not None and self.stop_event.wait(delay):
                raise HeadedChromeRegistrationError("registration_stopped")
            code = wait_for_otp(
                self.account.email,
                after_ts=float(min_timestamp or 0.0),
                max_wait=max(1, int(timeout or 180)),
                stop_check=stop_check,
            )
            value = str(code or "").strip()
            if not re.fullmatch(r"\d{6}", value):
                raise HeadedChromeRegistrationError("headed_chrome_otp_failed")
            return value

        def close(self) -> None:
            return None

    return CurrentProviderOtpReader


def _worker_class(
    reference,
    expected_country: str,
    *,
    raw_trace=None,
    traffic_reporter: HeadedChromeTrafficReporter | None = None,
):
    class HeadedRegistrationWorker(reference.OpenAIRegistrationWorker):
        def _browser_chatgpt_json(self, page, path, **kwargs):
            # Observe the authenticated transport result without changing the pinned kernel.
            status = None
            class ObservedPage:
                def __getattr__(self, name):
                    return getattr(page, name)
                def evaluate(self, *args, **values):
                    nonlocal status
                    result = page.evaluate(*args, **values)
                    if isinstance(result, dict):
                        status = result.get('status')
                    return result
            watched = path.startswith('/backend-api/accounts/mfa')
            error_code = ('twofa_activate_failed' if path.endswith('/activate_enrollment') else
                          'twofa_enroll_failed' if path.endswith('/enroll') else 'twofa_remote_status_failed')
            try:
                data = super()._browser_chatgpt_json(ObservedPage() if watched else page, path, **kwargs)
                if watched and (data.get('error') or data.get('success') is False or data.get('ok') is False):
                    raise RuntimeError(error_code)
            except Exception:
                if not watched:
                    raise
                self._totp_error_code = error_code
                raise RuntimeError(error_code) from None
            posted = str(kwargs.get('method') or 'GET').upper() == 'POST'
            if path == '/backend-api/accounts/mfa/enroll' and status == 200 and posted:
                self._totp_enrollment_candidate = dict(data)
            elif path == '/backend-api/accounts/mfa/user/activate_enrollment' and status == 200 and posted:
                candidate = getattr(self, '_totp_enrollment_candidate', {})
                payload = kwargs.get('payload') or {}
                if (data.get('success') is True and candidate.get('secret')
                        and payload.get('factor_type') == 'totp'
                        and payload.get('session_id') == candidate.get('session_id')):
                    self._totp_activation_secret = str(candidate['secret']).strip()
            return data

        def _auth_page_snapshot(self, page, *, timeout=None):
            if timeout is not None:
                try:
                    # The initial-navigation proxy owns no separate Page or
                    # loop. Read its original Page; retain the same stop guard.
                    snapshot_page = page._page if isinstance(page, _InitialAuthNavigationRetryPage) else page
                    with snapshot_purpose('auth_page'):
                        state = evaluate_snapshot(snapshot_page, _AUTH_PAGE_SNAPSHOT,
                                                  timeout=timeout, check_stop=self._raise_if_stopped)
                    if isinstance(state, dict) and isinstance(state.get("stage"), str):
                        return state
                    raise AuthPageSnapshotFailed("snapshot_shape_invalid")
                except AuthPageSnapshotFailed as exc:
                    self._raise_if_stopped()
                    if not getattr(self, "_snapshot_diagnostic_logged", False):
                        diagnostic_failure(self.log, "auth_page_snapshot", exc)
                        self._snapshot_diagnostic_logged = True
                    return {"stage": "unavailable"}
            try:
                state = page.evaluate(_AUTH_PAGE_SNAPSHOT)
                if isinstance(state, dict) and isinstance(state.get("stage"), str):
                    return state
            except Exception as exc:
                # One structural error per attempt avoids polling log storms.
                if not getattr(self, "_snapshot_diagnostic_logged", False):
                    diagnostic_failure(self.log, "auth_page_snapshot", exc)
                    self._snapshot_diagnostic_logged = True
            return {"stage": "unavailable"}

        @staticmethod
        def _auth_page_key(state):
            return tuple(state.get(k) for k in ("host", "path", "epoch", "stage"))

        def _wait_for_password_transition(self, page):
            started = time.monotonic()
            previous = None
            state = {"stage": "unavailable"}
            result = "aborted"
            matching_pair = False
            timings = {"snapshot": [], "wait": []}
            slow_operations = 0
            slow_details = 0

            def timed(operation, callback):
                nonlocal slow_operations, slow_details
                before = time.monotonic()
                outcome = "raised"
                try:
                    value = callback()
                    outcome = "completed"
                    return value
                finally:
                    elapsed = max(0.0, time.monotonic() - before)
                    timings[operation].append(elapsed)
                    if elapsed >= 1.0:
                        slow_operations += 1
                        if slow_details < 5:
                            slow_details += 1
                            diagnostic_emit(self.log, "password_transition_slow",
                                            operation=operation, result=outcome,
                                            sample=len(timings[operation]),
                                            elapsed_ms=int(elapsed * 1000))

            self._password_mode_transition = True
            self.log("[AuthPage] stage=password_transition result=started")
            try:
                while time.monotonic() - started < _AUTH_TRANSITION_SECONDS:
                    self._raise_if_stopped()
                    remaining = _AUTH_TRANSITION_SECONDS - (time.monotonic() - started)
                    try:
                        state = timed("snapshot", lambda: self._auth_page_snapshot(page, timeout=max(0, remaining)))
                    except AuthPageSnapshotTimeout:
                        state = {"stage": "snapshot_timeout"}
                    key = self._auth_page_key(state)
                    matching_pair = state["stage"] == "password" and previous == key
                    remaining = _AUTH_TRANSITION_SECONDS - (time.monotonic() - started)
                    if remaining <= 0:
                        break
                    if matching_pair:
                        result = "stable"
                        self.log("[AuthPage] stage=password_transition result=stable elapsed_ms=%d"
                                 % ((time.monotonic() - started) * 1000))
                        return
                    previous = key if state["stage"] == "password" else None
                    timed("wait", lambda: self._wait_or_stop(min(_AUTH_POLL_SECONDS, remaining)))
                result = "timeout"
                self.log("[AuthPage] stage=password_transition result=timeout page=%s elapsed_ms=%d"
                         % (state["stage"], (time.monotonic() - started) * 1000))
                raise HeadedChromeRegistrationError("headed_chrome_auth_transition_timeout")
            except Exception as exc:
                if getattr(exc, "code", None) != "headed_chrome_auth_transition_timeout":
                    self.log("[AuthPage] stage=password_transition result=aborted page=%s elapsed_ms=%d"
                             % (state["stage"], (time.monotonic() - started) * 1000))
                raise
            finally:
                self._password_mode_transition = False
                diagnostic_emit(self.log, "password_transition_summary", result=result,
                                page=state["stage"], matching_pair=matching_pair,
                                budget_ms=int(_AUTH_TRANSITION_SECONDS * 1000),
                                elapsed_ms=int((time.monotonic() - started) * 1000),
                                samples=len(timings["snapshot"]),
                                snapshot_ms=int(sum(timings["snapshot"]) * 1000),
                                slowest_snapshot_ms=int(max(timings["snapshot"], default=0) * 1000),
                                waits=len(timings["wait"]),
                                wait_ms=int(sum(timings["wait"]) * 1000),
                                slowest_wait_ms=int(max(timings["wait"], default=0) * 1000),
                                slow_operations=slow_operations, slow_details=slow_details)

        def _require_email_otp_page(self, page, stage, *, begin=False):
            prepared = getattr(self, "_email_otp_decision_key", None)
            if begin and prepared is not None:
                self._email_otp_decision_key = None
                state = self._auth_page_snapshot(page, timeout=_AUTH_SNAPSHOT_SECONDS)
                if state.get("stage") == "session_expired":
                    raise HeadedChromeRegistrationError("headed_chrome_auth_session_expired")
                if state.get("stage") != "email_otp" or self._auth_page_key(state)[:3] != prepared:
                    raise HeadedChromeRegistrationError("headed_chrome_auth_page_changed")
                self._email_otp_page_key = self._auth_page_key(state)
                diagnostic_emit(self.log, "auth_page_ready", phase=stage, result="ready", reused=True)
                return
            timeout = _email_otp_ready_timeout_seconds()
            deadline = time.monotonic() + timeout
            previous = None
            samples = 0
            snapshot_seconds = 0.0
            slowest_snapshot = 0.0
            snapshot_timeouts = 0
            state = {"stage": "unavailable"}
            error_code = "headed_chrome_auth_page_ready_timeout"
            reason = "readiness_deadline"
            expected = getattr(self, "_email_otp_page_key", None)
            while True:
                self._raise_if_stopped()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sample_started = time.monotonic()
                try:
                    state = self._auth_page_snapshot(
                        page, timeout=min(_AUTH_SNAPSHOT_SECONDS, remaining))
                except AuthPageSnapshotTimeout:
                    snapshot_timeouts += 1
                    previous = None
                    state = {"stage": "snapshot_timeout"}
                sample_seconds = time.monotonic() - sample_started
                samples += 1
                snapshot_seconds += sample_seconds
                slowest_snapshot = max(slowest_snapshot, sample_seconds)
                key = self._auth_page_key(state)
                remaining = deadline - time.monotonic()
                self._raise_if_stopped()
                if state["stage"] == "session_expired":
                    error_code = "headed_chrome_auth_session_expired"
                    reason = "session_expired"
                    break
                if state["stage"] == "unavailable":
                    error_code = "headed_chrome_auth_page_snapshot_failed"
                    reason = "snapshot_unavailable"
                    break
                if state["stage"] == "snapshot_timeout":
                    if remaining <= 0:
                        break
                    self._wait_or_stop(min(_AUTH_POLL_SECONDS, remaining))
                    continue
                # Only tolerate DOM readiness on an OTP route. A known document
                # change must never adopt a new baseline after polling or filling.
                transitioning = state["stage"] == "transitioning" and state.get("path") in {
                    "/email-verification", "/email-otp", "/email-code", "/verify-email",
                }
                if getattr(self, "_password_mode_transition", False):
                    error_code = "headed_chrome_auth_page_changed"
                    reason = "password_transition_active"
                    break
                if not begin and expected is not None and key[:3] != expected[:3]:
                    error_code = "headed_chrome_auth_page_changed"
                    reason = "document_identity_changed"
                    break
                if state["stage"] != "email_otp" and not transitioning:
                    error_code = "headed_chrome_auth_page_changed"
                    reason = "unexpected_page_stage"
                    break
                if state["stage"] == "email_otp" and previous == key and remaining >= 0:
                    if begin:
                        self._email_otp_page_key = key
                    diagnostic_emit(self.log, "auth_page_ready", phase=stage, result="ready",
                                    elapsed_ms=int((timeout - remaining) * 1000),
                                    budget_ms=int(timeout * 1000), samples=samples,
                                    snapshot_ms=int(snapshot_seconds * 1000),
                                    slowest_snapshot_ms=int(slowest_snapshot * 1000),
                                    snapshot_timeouts=snapshot_timeouts)
                    return
                if remaining <= 0:
                    break
                previous = key if state["stage"] == "email_otp" else None
                self._wait_or_stop(min(_AUTH_POLL_SECONDS, remaining))
            page_block(self.log, stage, state, expected,
                       password_transition=bool(getattr(self, "_password_mode_transition", False)),
                       begin=begin, remaining=remaining,
                       elapsed_ms=(timeout - remaining) * 1000,
                       budget_ms=int(timeout * 1000),
                       samples=samples, snapshot_ms=int(snapshot_seconds * 1000),
                       slowest_snapshot_ms=int(slowest_snapshot * 1000),
                       snapshot_timeouts=snapshot_timeouts, reason=reason,
                       matching_pair=state["stage"] == "email_otp" and previous == key)
            self.log("[AuthPage] stage=%s page=%s result=blocked" % (stage, state["stage"]))
            raise HeadedChromeRegistrationError(error_code)

        def _click_continue(self, page):
            if getattr(self, "_email_otp_submission_active", False):
                self._require_email_otp_page(page, "before_submit")
            if getattr(self, "_password_fill_active", False):
                validate_before_submit(self, page, HeadedChromeRegistrationError)
            stage = 'otp' if getattr(self, '_email_otp_submission_active', False) else 'password' if getattr(self, '_password_fill_active', False) else 'profile' if getattr(self, '_profile_form_active', False) else None
            if stage:
                capture_submission(self, page, stage, 'before_click')
            try:
                result = super()._click_continue(page)
                if stage:
                    capture_submission(self, page, stage, 'after_click', bool(result))
                return result
            except Exception:
                if stage:
                    capture_submission(self, page, stage, 'click_failed', False)
                raise

        def _wait_or_stop(self, seconds):
            return wait_auth_events(self, seconds, super()._wait_or_stop)

        def _raise_if_stopped(self):
            runtime = getattr(self, "_registration_runtime", None)
            if runtime is not None:
                runtime.check()
            super()._raise_if_stopped()
            terminal = getattr(self, "_registration_terminal_code", None)
            if terminal:
                raise HeadedChromeRegistrationError(terminal)
            response_guard = getattr(self, "_registration_response_guard", None)
            if response_guard is not None:
                service_error = response_guard.failure_code()
                if service_error:
                    raise HeadedChromeRegistrationError(service_error)
            password_guard = getattr(self, "_password_wait_guard", None)
            if password_guard is not None:
                password_guard.check()
            guard = getattr(self, "_profile_wait_guard", None)
            if guard is not None:
                guard.check()

        def _fill_about_you_inputs(self, page, name, birthdate, birth_year, age):
            from core.registration_profile_diagnostic import ProfileWaitGuard, ProfileDiagnosticError, completed_age
            guard = ProfileWaitGuard(self.log, getattr(self, "_registration_dom_recorder", None))
            self._profile_wait_guard = guard
            guard.expected = {"name": name, "birthdate": birthdate}
            self._profile_segment_birthdate = None
            initial = guard.capture(page, "before_fill")
            try:
                today = initial["today"]
                age = str(completed_age(birthdate, today))
            except (TypeError, KeyError, ValueError) as exc:
                raise ProfileDiagnosticError("profile_submission_evidence_unavailable") from exc
            guard.expected.update(age=int(age), today=today, age_mode=initial.get("age_mode") is True)
            try:
                from core.registration_date_segments import fill_date_segments
                segmented = fill_date_segments(
                    page, birthdate,
                    lambda: self._fill_visible_input_by_keyboard(page, 0, name), self.log,
                    check_stop=self._raise_if_stopped,
                )
                result = None if segmented else super()._fill_about_you_inputs(page, name, birthdate, birth_year, age)
                if segmented:
                    self._profile_segment_birthdate = birthdate
            except Exception:
                guard.capture(page, "after_fill")
                raise
            guard.capture(page, "after_fill")
            if getattr(self, "_profile_form_active", False):
                profile_form.after_fill(self, page, time.monotonic)
            guard.validate_filled(page)
            return result

        def _about_you_values_ok(self, values, second_kind="birth_year"):
            valid = super()._about_you_values_ok(values, second_kind)
            guard = getattr(self, "_profile_wait_guard", None)
            if second_kind == "age" and guard is not None:
                return (valid and len(values) >= 2
                        and str(values[1]).strip() == str(guard.expected["age"]))
            return valid

        def _submit_about_you(self, page, timeout=90):
            if getattr(self, "_profile_form_active", False):
                profile_form.before_submit(self, page, time.monotonic)
                timeout = min(timeout, max(0, self._profile_submit_deadline-time.monotonic()))
            birthdate = getattr(self, "_profile_segment_birthdate", None)
            if birthdate is not None:
                from core.registration_date_segments import validate_date_segments
                validate_date_segments(page, birthdate, self.log, check_stop=self._raise_if_stopped)
            guard = getattr(self, "_profile_wait_guard", None)
            if guard is not None:
                guard.validate_filled(page)
            response_guard = getattr(self, "_registration_response_guard", None)
            if response_guard is not None:
                response_guard.reset_create()
            before_url = page.url
            try:
                return super()._submit_about_you(page, timeout=timeout)
            except Exception:
                self._raise_if_stopped()
                if response_guard is None or not response_guard.recovering_create():
                    raise
                return wait_for_create_transition(self, page, before_url, response_guard, HeadedChromeRegistrationError)

        def _fill_about_you(self, page):
            return profile_form.fill_profile(self, page, reference,
                                             HeadedChromeRegistrationError, time.monotonic)

        def _fill_email_if_visible(self, page):
            try:
                email_form.begin(self, page, time.monotonic)
                if getattr(self, "_email_submit_ambiguous", False):
                    return self._recover_stalled_email_if_due(page, timeout_seconds=5)
                return super()._fill_email_if_visible(page)
            except (FormNotReady, AuthPageSnapshotFailed, AuthPageSnapshotTimeout):
                email_form.deferred(self, "not_ready")
                return False
            except DocumentChanged:
                email_form.deferred(self, "document_changed")
                return False

        def _wait_email_input_hydrated(self, input_box, timeout_seconds=1):
            return email_form.hydrated(self)

        def _start_email_submission_wait(self, page_key):
            self._email_pending_start_key = page_key

        def _retry_email_form_submit(self, page):
            try:
                email_form.before_submit(self, page, time.monotonic)
            except (FormNotReady, AuthPageSnapshotFailed, AuthPageSnapshotTimeout, DocumentChanged):
                email_form.deferred(self, "submit_not_ready")
                return False
            if not email_form.click_submit(self, page):
                return False
            key = getattr(self, "_email_pending_start_key", None)
            if key is not None and getattr(self, "_email_submission_page_key", None) != key:
                super()._start_email_submission_wait(key)
            return True

        def _install_auth_flow_observer(self, context) -> None:
            super()._install_auth_flow_observer(context)
            if bool(
                getattr(self, "_email_otp_response_observer_installed", False)
            ):
                return
            on = getattr(context, "on", None)
            if not callable(on):
                return
            self._email_otp_response_observer_installed = True
            self._email_otp_invalid_response = False
            self._candidate_password_evidence = CandidatePasswordEvidence()
            if getattr(self, "_registration_response_guard", None) is None:
                self._registration_response_guard = RegistrationResponseGuard(
                    getattr(self, "log", None), getattr(self, "_headed_auth_page", None), clock=lambda: time.monotonic())

            def on_request(request):
                diagnostic_request(getattr(self, "log", None), request)
                self._registration_response_guard.request(request)
                if self._registration_response_guard.owns(request):
                    self._candidate_password_evidence.request(
                        request, str(getattr(self, "openai_password", "") or "")
                    )
                progress = getattr(self, "_email_otp_progress", None)
                if progress is not None and getattr(self, "_email_otp_submission_active", False):
                    progress.observe_request(request, self._email_otp_submission_page)
                guard = getattr(self, "_password_wait_guard", None)
                if guard is None or not self._registration_response_guard.current_request(request):
                    return
                parsed = urlsplit(str(request.url))
                if (request.method.upper() == "POST" and parsed.hostname == "auth.openai.com"
                        and parsed.path == "/api/accounts/user/register"):
                    guard.submitted()

            context.on("request", on_request)
            try:
                context.on("requestfailed", lambda request: diagnostic_request(getattr(self, "log", None), request, failed=True))
            except Exception as exc:
                diagnostic_failure(getattr(self, "log", None), "request_observer_install", exc)

            def on_response(response) -> None:
                diagnostic_response(getattr(self, "log", None), response)
                if self._registration_response_guard.owns(getattr(response, "request", None)):
                    self._candidate_password_evidence.response(response)
                if not self._registration_response_guard.current_request(getattr(response, "request", None)):
                    return
                progress = getattr(self, "_email_otp_progress", None)
                if progress is not None and progress.observe_response(response):
                    diagnostic_emit(getattr(self, "log", None), "otp_validation", result="accepted_waiting_navigation")
                terminal = self._registration_response_guard.observe(response)
                if not self._registration_response_guard.current_request(response.request):
                    return
                if terminal:
                    diagnostic_emit(getattr(self, "log", None), "otp_validation", result="account_terminal")
                    self._registration_terminal_code = terminal
                    return
                if _email_otp_response_is_invalid(response):
                    diagnostic_emit(getattr(self, "log", None), "otp_validation", result="invalid_code_response")
                    self._email_otp_invalid_response = True
                    return
                try:
                    request = getattr(response, "request", None)
                    method = str(getattr(request, "method", "") or "").upper()
                    parsed = urlsplit(
                        str(
                            getattr(response, "url", "")
                            or getattr(request, "url", "")
                            or ""
                        )
                    )
                    if (
                        method == "POST"
                        and str(parsed.hostname or "").lower() == "auth.openai.com"
                        and str(parsed.path or "").endswith("/api/accounts/user/register")
                    ):
                        guard = getattr(self, "_password_wait_guard", None)
                        if guard is not None:
                            guard.response(response.status, response.headers)
                except Exception:
                    return

            try:
                context.on("response", on_response)
            except Exception:
                self._email_otp_response_observer_installed = False

        def _has_visible_password(self, page) -> bool:
            visible = bool(super()._has_visible_password(page))
            guard = getattr(self, "_password_wait_guard", None)
            if guard is None:
                return visible
            guard.page = page
            guard.check()
            # The official frontend retries fetch 5xx itself. An extra click here
            # can race it and submit the same credentials twice.
            return visible

        @worker_step("otp_submit")
        def _submit_email_code_once(self, page, code: str) -> None:
            # The response observer belongs to the current submission only;
            # otherwise a rejected first code could poison the one allowed
            # resend attempt.
            self._email_otp_invalid_response = False
            self._email_otp_progress = OtpProgress()
            self._email_otp_submission_page = page
            self._require_email_otp_page(page, "after_poll")
            self._email_otp_submission_active = True
            self._email_otp_expected = code
            result = 'failed'
            try:
                capture_submission(self, page, 'otp', 'before_input')
                value = super()._submit_email_code_once(page, code)
                result = 'completed'
                return value
            finally:
                capture_submission(self, page, 'otp', 'after_submit', result)
                self._email_otp_expected = None
                self._email_otp_submission_active = False

        @worker_step("otp_poll_and_submit")
        def _submit_email_code(self, page, min_timestamp: float) -> None:
            # A challenge can appear between the vendor's classification and
            # dispatch. Never submit a mailbox code into an unidentified MFA form.
            if self._is_mfa_route(page):
                diagnostic_emit(self.log, "mfa_required", reason="challenge_not_email_otp",
                                saved_totp_present=bool(getattr(self, "mfa_totp_secret", "")))
                raise HeadedChromeRegistrationError("headed_chrome_mfa_required")
            self._require_email_otp_page(page, "before_poll", begin=True)
            try:
                diagnostic = getattr(self, "_password_entry_dom_diagnostics", None)
                if diagnostic is not None:
                    diagnostic.otp_ready(page, self._email_otp_page_key, check_stop=self._raise_if_stopped)
                return self._submit_email_code_guarded(page, min_timestamp)
            finally:
                self._email_otp_page_key = None

        def _submit_email_code_guarded(self, page, min_timestamp: float) -> None:
            """Give the shared mailbox path one safe resend on a poll timeout.

            The pinned worker only wires its resend callback for the vendor's
            URL-mail reader.  The host adapter replaces that reader with the
            project's provider bridge, so an HME/provider timeout used to end
            the registration without ever clicking the visible resend
            control.  Keep this bounded to one retry and refresh the provider
            baseline before requesting a new message.
            """
            if bool(getattr(self, "_host_email_otp_resend_used", False)):
                return super()._submit_email_code(page, min_timestamp)
            try:
                return super()._submit_email_code(page, min_timestamp)
            except Exception as exc:
                provider_code = str(
                    getattr(exc, "error_code", "")
                    or getattr(exc, "code", "")
                    or ""
                ).strip().lower()
                invalid_otp_error = getattr(
                    reference,
                    "InvalidEmailOtpError",
                    None,
                )
                invalid_otp_response = bool(
                    isinstance(invalid_otp_error, type)
                    and isinstance(exc, invalid_otp_error)
                )
                if not isinstance(exc, TimeoutError) and provider_code not in {
                    "otp_timeout",
                    "headed_chrome_otp_failed",
                } and not invalid_otp_response:
                    raise
                self._require_email_otp_page(page, "before_resend")
                self._host_email_otp_resend_used = True
                reader = getattr(self, "otp_reader", None)
                mark_seen = getattr(reader, "mark_current_codes_seen", None)
                if callable(mark_seen):
                    mark_seen()
                resend = getattr(self, "_resend_email_otp", None)
                if not callable(resend) or not resend(page):
                    raise
                self.log(
                    "邮箱验证码%s，已在同一页面重发一次后继续取码"
                    % ("被拒绝" if invalid_otp_response else "等待超时")
                )
                self._require_email_otp_page(page, "before_retry_poll")
                return super()._submit_email_code(page, time.time())

        def _resend_email_otp(self, page) -> bool:
            """Keep the vendor selectors and add a language-neutral resend fallback."""

            if super()._resend_email_otp(page):
                return True
            try:
                result = page.evaluate(
                    r"""() => {
                        const visible = el => {
                            if (!el) return false;
                            const rect = el.getBoundingClientRect();
                            const style = getComputedStyle(el);
                            return rect.width > 0 && rect.height > 0
                                && style.visibility !== 'hidden'
                                && style.display !== 'none';
                        };
                        const fold = value => String(value || '')
                            .normalize('NFD')
                            .replace(/[\u0300-\u036f]/g, '')
                            .replace(/\s+/g, ' ')
                            .trim()
                            .toLowerCase();
                        const resend = /resend|send again|send a new|try again|gui lai|gửi lại|reenviar|enviar novamente|renvoyer|erneut senden|erneut schicken|再送信|重新发送|重新發送|重发|重發|再发送|再發送|再次发送|再次發送/;
                        const exclude = /continue|verify|submit|confirm|next|继续|繼續|提交|确认|確認|xác nhận|tiep tuc|tiếp tục|xac nhan|继续/;
                        const candidates = Array.from(document.querySelectorAll(
                            'button, [role="button"], a'
                        )).filter(visible).filter(el => {
                            if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
                            const text = fold([
                                el.textContent,
                                el.getAttribute('aria-label'),
                                el.getAttribute('title'),
                                el.getAttribute('data-testid'),
                            ].filter(Boolean).join(' '));
                            return resend.test(text) && !exclude.test(text);
                        });
                        const target = candidates[0];
                        if (!target) return false;
                        target.scrollIntoView({block: 'center', inline: 'center'});
                        target.click();
                        return true;
                    }"""
                )
                if result:
                    self.log("已通过本地化页面控件重发邮箱验证码")
                    return True
            except Exception:
                pass
            return False

        @worker_step("otp_validation_wait")
        def _wait_after_otp_submit(self, page, timeout: int = 60) -> None:
            return wait_after_submit(self, page, reference, HeadedChromeRegistrationError, timeout)

        @worker_step("browser_launch")
        def _new_browser_context(self, p, proxy, storage_state=None):
            runtime = getattr(self, "_registration_runtime", None)
            if runtime is not None:
                runtime.attach(p)
            from core.headed_window_visibility import launch_visibility, hide_playwright_browser
            requested_headless = bool(getattr(self, "headless", False))
            launch_headless, hide_window = launch_visibility(requested_headless)
            self.headless = launch_headless
            try:
                browser, context = super()._new_browser_context(p, proxy, storage_state)
            finally:
                self.headless = requested_headless
            self._active_registration_browser = browser
            self._active_registration_context = context
            self._flow_diagnostics = install_flow_diagnostics(self, context)
            try:
                transport = (
                    getattr(
                        getattr(getattr(browser, "_impl_obj", None), "_connection", None),
                        "_transport",
                        None,
                    )
                )
                driver_process = getattr(transport, "_proc", None)
                self._registration_driver_pid = int(
                    getattr(driver_process, "pid", 0) or 0
                )
            except (TypeError, ValueError, OverflowError):
                self._registration_driver_pid = 0
            if hide_window:
                try:
                    hide_playwright_browser(browser)
                except Exception:
                    browser.close()
                    raise
            try:
                from core.roxy_dom_failure_diagnostic import RoxyFailureDomRecorder
                self._registration_dom_recorder = RoxyFailureDomRecorder(task_kind="registration")
                self._registration_dom_context = context
            except Exception:
                self.log("[FailureDOM] reason=registration_dom_start_failed")
            if raw_trace is not None and context is not None:
                try:
                    self._headed_raw_trace_context = context
                    started = raw_trace.start(context)
                    if started:
                        activity = getattr(raw_trace, 'timing_summary', None)
                        if callable(activity):
                            self._registration_trace_activity = activity
                        self._password_entry_dom_diagnostics = create_diagnostics(
                            raw_trace, started=started, log=self.log)
                        self.log("[RawTrace] 有头 Chrome 原始网络采样已启动")
                    else:
                        self.log(
                            "[RawTrace] 有头 Chrome 原始网络采样不可用，注册继续："
                            "reason=roxy_raw_trace_start_failed"
                        )
                except Exception:
                    self.log(
                        "[RawTrace] 有头 Chrome 原始网络采样启动异常，注册继续："
                        "reason=roxy_raw_trace_start_failed"
                    )
            return browser, context

        def _set_auth_traffic_stage(self, stage: str) -> None:
            result = super()._set_auth_traffic_stage(stage)
            guard = getattr(self, "_password_wait_guard", None)
            if guard is not None and stage in {"Session 确认", "基础资料提交", "邮箱验证码提交"}:
                guard.completed = True
            if raw_trace is not None:
                try:
                    raw_trace.set_stage(stage)
                except Exception:
                    pass
            return result

        @worker_step("session_extract")
        def _extract_session_info(self, context):
            runtime = getattr(self, "_registration_runtime", None)
            if runtime is not None:
                runtime.check()
            result = super()._extract_session_info(context)
            if runtime is not None:
                runtime.capture_result(result)
            self._headed_raw_session_extracted = True
            return result

        def _has_chatgpt_session(self, page):
            runtime = getattr(self, "_registration_runtime", None)
            if runtime is not None:
                runtime.check()
            return super()._has_chatgpt_session(page)

        def _close_browser(self, context, browser) -> None:
            runtime = getattr(self, "_registration_runtime", None)
            if runtime is not None:
                runtime.begin_cleanup()
            try:
                if runtime is not None and runtime.code:
                    self.log("[Cleanup] stage=browser result=skipped reason=registration_terminated")
                    return
                return self._close_browser_live(context, browser)
            finally:
                if runtime is not None:
                    runtime.end_cleanup()
                if context is getattr(self, "_active_registration_context", None):
                    self._active_registration_context = None
                if browser is getattr(self, "_active_registration_browser", None):
                    self._active_registration_browser = None

        @worker_step("browser_cleanup")
        def _close_browser_live(self, context, browser) -> None:
            if (context is getattr(self, "_registration_dom_context", None)
                and not getattr(self, "_headed_raw_session_extracted", False)):
                try:
                    recorder = self._registration_dom_recorder
                    for page in list(getattr(context, "pages", []) or []):
                        if not page.is_closed():
                            recorder.observe(page, stage="failure", event="before_close", force=True)
                    with diagnostic_step(self.log, "failure_dom_finalize", getattr(self, "_registration_runtime", None)):
                        metadata = recorder.finalize(error_code="headed_chrome_registration_failed")
                    if metadata.get("state") != "saved":
                        raise RuntimeError("registration_dom_not_saved")
                    self.log(f"[FailureDOM] diagnostic_id={recorder.diagnostic_id}")
                except Exception:
                    self.log("[FailureDOM] reason=registration_dom_finalize_failed")
            if (
                raw_trace is not None
                and context is getattr(self, "_headed_raw_trace_context", None)
            ):
                try:
                    state = (
                        "complete"
                        if bool(getattr(self, "_headed_raw_session_extracted", False))
                        else "partial"
                    )
                    usage = (
                        traffic_reporter.snapshot(state)
                        if traffic_reporter is not None
                        else None
                    )
                    with diagnostic_step(self.log, "raw_trace_stop", getattr(self, "_registration_runtime", None)):
                        summary = raw_trace.stop(network_usage=usage)
                    trace_summary(self.log, summary)
                    self.log(
                        "[RawTrace] 有头 Chrome 原始网络采样已封存："
                        f"state={summary.get('state', 'unknown')} "
                        f"errors={len(summary.get('error_codes') or [])}"
                    )
                except Exception:
                    self.log(
                        "[RawTrace] 有头 Chrome 原始网络采样收尾失败，注册继续："
                        "reason=roxy_raw_trace_stop_failed"
                    )
            try:
                runtime = getattr(self, "_registration_runtime", None)
                return super()._close_browser(
                    observe_close(context, self.log, "context_close", runtime),
                    observe_close(browser, self.log, "browser_close", runtime),
                )
            finally:
                if context is getattr(self, "_active_registration_context", None):
                    self._active_registration_context = None
                if browser is getattr(self, "_active_registration_browser", None):
                    self._active_registration_browser = None

        def _create_openai_signin_url(self, context, page=None) -> str:
            if not str(getattr(self, "openai_password", "") or "").strip():
                self._auth_screen_hint = "signup"
                self.log("[认证] 新邮箱请求注册入口，页面就绪后优先选择密码注册")
                return self._create_provider_auth_url(
                    context, "signup", "密码注册页", page
                )
            return super()._create_openai_signin_url(context, page)

        def _set_auth_route(self, route: str) -> None:
            normalized = str(route or "").strip()
            if (
                normalized == "existing_email_otp_login"
                and str(getattr(self, "_last_authorize_page_type", "") or "")
                .strip()
                .lower()
                == "email_otp_verification"
                and not bool(getattr(self, "_account_create_confirmed", False))
            ):
                normalized = "pending_email_otp"
            return super()._set_auth_route(normalized)

        def _finalize_deferred_email_otp_route(self) -> None:
            if str(getattr(self, "auth_route", "") or "") != "pending_email_otp":
                return
            if bool(getattr(self, "is_new_account", False)) or bool(
                getattr(self, "_account_create_confirmed", False)
            ):
                super()._set_auth_route("new_passwordless_signup")
                self.log("[认证] 已确认新账号无密码注册")
                return
            super()._set_auth_route("existing_email_otp_login")
            self.log("[认证] 已确认已有账号邮箱验证码登录")

        @worker_step("auth_flow")
        def _register(self, page, context) -> None:
            self._headed_auth_page = page
            self._registration_response_guard = RegistrationResponseGuard(self.log, page, clock=lambda: time.monotonic())
            diagnostic = getattr(self, '_flow_diagnostics', None)
            try:
                if diagnostic is None:
                    return self._register_preserving_error(page, context)
                with diagnostic.reads():
                    result = self._register_preserving_error(page, context)
                    diagnostic.terminal(page, None)
                    return result
            except Exception as exc:
                if diagnostic is not None:
                    diagnostic.terminal(page, exc)
                runtime = getattr(self, "_registration_runtime", None)
                if runtime is not None:
                    runtime.check_cancellation()
                code = (getattr(self, "_registration_terminal_code", None)
                        or self._registration_response_guard.failure_code(force=True)
                        or (diagnostic.error_code(exc) if diagnostic is not None else None))
                if code and not getattr(exc, "code", None):
                    exc = HeadedChromeRegistrationError(code)
                self._headed_auth_error = exc
                raise exc
            finally:
                self._headed_auth_page = None

        @staticmethod
        def _is_mfa_route(page):
            path = urlsplit(str(getattr(page, "url", "") or "")).path.lower()
            return path == "/mfa-challenge" or path.startswith(("/mfa-challenge/", "/mfa/"))

        def _register_preserving_error(self, page, context) -> None:
            self.log("[认证] 进入有头 Chrome 注册状态机")
            # The pinned worker performs its first auth-page navigation
            # directly.  Wrap only the non-protocol entry page so a transient
            # Chromium timeout gets one same-Profile retry; protocol handoff
            # keeps its existing tolerant navigation path unchanged.
            bootstrap = getattr(self, "_protocol_otp_bootstrap", None) or {}
            if bootstrap:
                result = super()._register(page, context)
            else:
                result = super()._register(
                    _InitialAuthNavigationRetryPage(page, self),
                    context,
                )
            self._finalize_deferred_email_otp_route()
            return result

        @worker_step("mfa_enrollment")
        def _ensure_totp_mfa(self, context) -> None:
            password = str(getattr(self, "openai_password", "") or "").strip()
            password_state = str(
                getattr(self, "openai_password_state", "") or ""
            ).strip()
            if not password or password_state != "confirmed":
                self.log("[MFA] 当前账号未确认创建密码，已跳过 2FA 绑定")
                return
            return super()._ensure_totp_mfa(context)

        @worker_step("proxy_probe")
        def _prepare_fingerprint_for_proxy(self, proxy, label):
            try:
                health = super()._prepare_fingerprint_for_proxy(proxy, label)
            except getattr(reference, 'ProxyExitCheckError', ()) as exc:
                try:
                    from .proxy_probe_evidence import proxy_probe_evidence
                    diagnostic_emit(self.log, 'registration_proxy_precheck', result='failed', **proxy_probe_evidence(exc))
                except Exception:
                    pass
                raise
            observed = str(getattr(health, "country", "") or "").strip().upper()
            if expected_country and observed != expected_country:
                raise HeadedChromeRegistrationError(
                    "headed_chrome_proxy_country_drift"
                )
            return health

        def _choose_existing_email_otp(
            self, page, *, allow_generic: bool = False
        ) -> bool:
            selectors = [
                'button:has-text("Email me a code")',
                'button:has-text("Continue with email")',
                'button:has-text("Continue with a code")',
                'button:has-text("Use email code")',
                'button:has-text("Send code")',
                'button:has-text("发送验证码")',
                'button:has-text("邮箱验证码")',
                'button:has-text("使用邮箱")',
                '[role="button"]:has-text("Email me a code")',
                '[role="button"]:has-text("Continue with email")',
                '[role="button"]:has-text("Send code")',
            ]
            for selector in selectors:
                target = page.locator(selector).first
                try:
                    if target.is_visible(timeout=500) and target.is_enabled(timeout=500):
                        target.click(timeout=5000)
                        self._set_auth_route("existing_email_otp_login")
                        self.log("[认证] 已有账号无本地密码，已切换邮箱验证码登录")
                        return True
                except Exception:
                    continue
            try:
                box = page.evaluate(
                    r"""({allowGeneric}) => {
                        const visible = el => {
                            if (!el) return false;
                            const r = el.getBoundingClientRect();
                            const s = getComputedStyle(el);
                            return r.width > 0 && r.height > 0
                                && s.visibility !== 'hidden' && s.display !== 'none';
                        };
                        const specific = /email.{0,24}(code|otp)|(?:code|otp).{0,24}email|邮箱.{0,12}(验证码|动态码)|(?:验证码|动态码).{0,12}邮箱|メール.{0,20}コード|コード.{0,20}メール/i;
                        const generic = /^(continue|next|继续|下一步|続行)$/i;
                        const exclude = /password|密码|密碼|パスワード|forgot|reset|google|apple|microsoft|phone|sms/i;
                        const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
                            .filter(visible)
                            .filter(el => !el.disabled && el.getAttribute('aria-disabled') !== 'true')
                            .map(el => ({el, text: `${el.textContent || ''} ${el.getAttribute('aria-label') || ''}`.replace(/\s+/g, ' ').trim()}))
                            .filter(item => !exclude.test(item.text))
                            .filter(item => specific.test(item.text) || (allowGeneric && generic.test(item.text)));
                        const item = candidates[0];
                        if (!item) return null;
                        item.el.scrollIntoView({block: 'center', inline: 'center'});
                        const r = item.el.getBoundingClientRect();
                        return {x: r.left + r.width / 2, y: r.top + r.height / 2};
                    }""",
                    {"allowGeneric": bool(allow_generic)},
                )
            except Exception:
                box = None
            if not box:
                return False
            page.mouse.click(float(box["x"]), float(box["y"]))
            self._set_auth_route("existing_email_otp_login")
            self.log("[认证] 已有账号无本地密码，已通过真实鼠标切换邮箱验证码登录")
            return True

        def _select_password_auth_mode_if_visible(self, page) -> bool:
            guard = getattr(self, "_profile_wait_guard", None)
            if urlsplit(str(page.url)).path == "/about-you" and (guard is None or guard.submitted_at is None):
                try:
                    profile_form.prepare(self, page, time.monotonic)
                except DocumentChanged:
                    self._profile_dispatch_ready = None
                    return True
                except FormNotReady:
                    raise HeadedChromeRegistrationError("headed_chrome_profile_form_not_ready") from None
                return False
            return select_mode(self, page, HeadedChromeRegistrationError,
                               timeout=_email_otp_ready_timeout_seconds(), clock=time.monotonic)

        def _select_password_auth_mode_once(self, page, *, snapshot=None) -> bool:
            state = snapshot or self._auth_page_snapshot(page, timeout=_AUTH_SNAPSHOT_SECONDS)
            if state["stage"] == "password":
                return False
            password_present = bool(
                str(getattr(self, "openai_password", "") or "").strip()
            )
            if (
                not password_present
                and str(getattr(self, "auth_route", "") or "")
                == "existing_password_login"
                and self._choose_existing_email_otp(page, allow_generic=True)
            ):
                return True
            if super()._select_password_auth_mode_if_visible(page):
                self._wait_for_password_transition(page)
                return True
            if (
                not password_present
                and str(getattr(self, "auth_route", "") or "")
                == "existing_password_login"
            ):
                return False
            page_key = "|".join(
                (
                    str(getattr(page, "url", "") or ""),
                    str(getattr(self, "_last_authorize_page_type", "") or ""),
                )
            )
            if page_key == str(
                getattr(self, "_hidden_password_mode_selection_page_key", "") or ""
            ):
                return False
            try:
                selected = page.evaluate(
                    r"""() => {
                        const visible = el => {
                            if (!el) return false;
                            const r = el.getBoundingClientRect();
                            const s = getComputedStyle(el);
                            return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                        };
                        const include = /continue with password|use password|sign up with password|create password|password instead|password signup|mit passwort fortfahren|passwort verwenden|mit passwort registrieren|passwort erstellen|stattdessen passwort|registrieren mit passwort|密码注册|使用密码|使用密碼|パスワードを使用|パスワードで続行|パスワードで続ける/i;
                        const vietnamese = /tiep tuc voi mat khau|tiep tuc bang mat khau|su dung mat khau|dang nhap bang mat khau/i;
                        const exclude = /forgot|reset|password reset|passwort vergessen|passwort zurücksetzen|anmelden|einloggen|忘记|忘記|重置|找回|ログイン|log in|sign in/i;
                        const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
                            .filter(el => !el.disabled && el.getAttribute('aria-disabled') !== 'true')
                            .map(el => {
                                const text = `${el.textContent || ''} ${el.getAttribute('aria-label') || ''} ${el.getAttribute('title') || ''} ${el.getAttribute('data-testid') || ''}`.replace(/\s+/g, ' ').trim();
                                const folded = text.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
                                return {el, text, folded};
                            })
                            .filter(item => (include.test(item.text) || vietnamese.test(item.folded)) && !exclude.test(item.text));
                        const item = candidates[0];
                        if (!item) return null;
                        if (visible(item.el)) {
                            item.el.scrollIntoView({block: 'center', inline: 'center'});
                            const r = item.el.getBoundingClientRect();
                            return {method: 'mouse', visible: true, x: r.left + r.width / 2, y: r.top + r.height / 2};
                        }
                        const href = item.el instanceof HTMLAnchorElement ? item.el.href : '';
                        if (href && !href.startsWith('javascript:')) {
                            window.location.assign(href);
                            return {method: 'href', visible: false};
                        }
                        item.el.click();
                        return {method: 'click', visible: false};
                    }"""
                )
            except Exception:
                selected = None
            if not selected:
                return False
            if bool(selected.get("visible")):
                try:
                    page.mouse.click(float(selected["x"]), float(selected["y"]))
                except Exception:
                    return False
            self._hidden_password_mode_selection_page_key = page_key
            self.log(
                "[认证] 已选择本地化密码登录入口"
                if password_present and bool(selected.get("visible"))
                else "[认证] 已选择隐藏的密码登录入口"
                if password_present
                else "[认证] 已选择本地化密码注册入口"
                if bool(selected.get("visible"))
                else "[认证] 已选择隐藏的密码注册入口"
            )
            self._wait_for_password_transition(page)
            return True

        def _type_password_trusted(self, input_box, value: str) -> bool:
            observed = PasswordInputObserver(input_box, self.log)
            result = super()._type_password_trusted(observed, value)
            self._password_input_failed = observed.failed and not result
            if observed.failed:
                diagnostic_emit(self.log, "password_input_outcome",
                                result="fallback_succeeded" if result else "failed")
            return result

        def _force_fill_locator(self, locator, value: str) -> bool:
            if isinstance(locator, PasswordInputObserver):
                locator = locator.fallback()
            return super()._force_fill_locator(locator, value)

        @worker_step("password_step")
        def _fill_password_step(self, page) -> None:
            route = self._password_page_route(page)
            if route == "new_password_signup" and getattr(self, "_password_wait_guard", None) is None:
                from core.registration_password_guard import PasswordSubmissionGuard
                self._password_wait_guard = PasswordSubmissionGuard(
                    page, self.log, getattr(self, "_registration_dom_recorder", None)
                )
            if route != "existing_password_login" or str(
                self.openai_password or ""
            ).strip():
                result = (fill_signup_password(self, page, super()._fill_password_step, HeadedChromeRegistrationError)
                          if route == "new_password_signup" else super()._fill_password_step(page))
                guard = getattr(self, "_password_wait_guard", None)
                if guard is not None:
                    guard.fill_returned()
                return result
            if self._choose_existing_email_otp(page):
                return
            try:
                page.go_back(wait_until="domcontentloaded", timeout=30000)
            except Exception:
                pass
            if self._choose_existing_email_otp(page, allow_generic=True):
                return
            raise HeadedChromeRegistrationError(
                "headed_chrome_existing_login_unavailable"
            )

    return HeadedRegistrationWorker


@diagnostic_run
def run_headed_chrome_registration(
    *,
    email: str,
    name: str = "",
    birthday: str = "",
    proxy: str | None = None,
    otp_code: str | None = None,
    batch_dir: Path | None = None,
    proxy_country: str | None = None,
    stop_check=None,
    traffic_snapshot_callback: Callable[[dict], None] | None = None,
    saved_openai_password: str = "",
    saved_openai_password_state: str = "pending_registration",
    saved_totp_secret: str = "",
    auth_persist_callback: Callable[[dict], None] | None = None,
    raw_trace_sampled: bool = False,
    raw_trace_job_id: int | None = None,
    cancellation_event=None,
) -> dict:
    """Run only the pinned local Chrome path; never fall back to another driver."""

    del name, birthday, otp_code
    target_email = str(email or "").strip().lower()
    if not target_email:
        return {
            "success": False,
            "email": target_email,
            "error": "headed_chrome_email_invalid",
        }
    try:
        reference = _load_reference_module()
    except Exception as exc:
        diagnostic_failure(lambda message: logger.warning(message, extra={"registration_job_id": raw_trace_job_id}),
                           "reference_load", exc)
        raise
    stop_event = _StopEvent(stop_check)
    worker = None
    chain = None
    reporter = HeadedChromeTrafficReporter(traffic_snapshot_callback)
    raw_trace = None
    if bool(raw_trace_sampled):
        try:
            from core.roxy_raw_network_trace import (
                HEADED_CHROME_TASK_KIND,
                PlaywrightRawNetworkTracer,
            )

            raw_trace = PlaywrightRawNetworkTracer(
                job_id=raw_trace_job_id,
                enabled=True,
                task_kind=HEADED_CHROME_TASK_KIND,
            )
        except Exception:
            raw_trace = None
            logger.warning(
                "[RawTrace] 有头 Chrome 原始网络采样初始化失败，注册继续："
                "reason=roxy_raw_trace_start_failed"
            )

    def finalize_raw_trace(state: str) -> None:
        if raw_trace is None:
            return
        try:
            if bool(getattr(raw_trace, "_stopped", False)):
                return
            with diagnostic_step(log_reference, "raw_trace_finalize"):
                summary = raw_trace.stop(network_usage=reporter.snapshot(state))
            trace_summary(log_reference, summary)
            logger.info(
                "[RawTrace] 有头 Chrome 原始网络采样已封存：state=%s errors=%s",
                summary.get("state", "unknown"),
                len(summary.get("error_codes") or []),
            )
        except Exception:
            logger.warning(
                "[RawTrace] 有头 Chrome 原始网络采样收尾失败，注册继续："
                "reason=roxy_raw_trace_stop_failed"
            )
    auth_fields: dict[str, str] = {}
    mfa_fields: dict[str, str] = {}
    create_started = False
    create_acknowledged = False
    existing_account_detected = False
    identity_pending = False
    session_saved = False
    result_payload: dict | None = None
    pending_account_id: int | None = None

    def log_reference(message: str) -> None:
        text = log_text(message, _safe_log_text)
        if text:
            logger.info("[HeadedChrome] %s", text,
                        extra={"registration_job_id": raw_trace_job_id})

    def persist_auth(fields: dict) -> None:
        nonlocal pending_account_id
        clean = {
            str(key): str(value)
            for key, value in dict(fields or {}).items()
            if key
            in {
                "openai_password",
                "openai_password_state",
                "auth_route",
                "account_creation_state",
            }
            and value not in (None, "")
        }
        merge_auth_fields(auth_fields, clean)
        if auth_persist_callback is not None:
            try:
                persisted = auth_persist_callback(dict(clean))
            except Exception as exc:
                raise HeadedChromeRegistrationError(
                    "headed_chrome_pending_credentials_persist_failed"
                ) from exc
            if (
                not isinstance(persisted, bool)
                and isinstance(persisted, int)
                and persisted > 0
            ):
                pending_account_id = int(persisted)

    def persist_mfa(fields: dict) -> None:
        clean = {
            str(key): str(value)
            for key, value in dict(fields or {}).items()
            if key
            in {
                "mfa_totp_secret",
                "mfa_recovery_code",
                "mfa_enrollment_state",
                "mfa_enrolled_at",
            }
            and value not in (None, "")
        }
        mfa_fields.update(clean)

    phase = "saved_credentials_persist"
    try:
        saved_totp_secret = (
            normalise_totp_secret(saved_totp_secret)
            if str(saved_totp_secret or "").strip() else ""
        )
        if str(saved_openai_password or "").strip():
            persist_auth(
                {
                    "openai_password": str(saved_openai_password).strip(),
                    "openai_password_state": (
                        "confirmed" if saved_openai_password_state == "confirmed"
                        else "pending_registration"
                    ),
                }
            )
        phase = "proxy_selection"
        if proxy_country:
            country = validate_headed_chrome_proxy_country_runtime(proxy_country)
        else:
            country = ""
        if proxy is None:
            selection = select_default_proxy(
                country=country or None,
                check_stop=stop_check,
            )
        else:
            from core.proxy_sid import ProxySelection

            selection = ProxySelection(
                proxy_url=str(proxy or ""),
                source="explicit",
                safe_label=mask_proxy_url(proxy),
                validated=False,
                expected_country=country,
            )
        upstream_proxy = str(getattr(selection, "proxy_url", "") or "").strip()
        if not upstream_proxy:
            raise HeadedChromeRegistrationError("headed_chrome_proxy_missing")
        expected_country = str(
            country
            or getattr(selection, "actual_country", "")
            or getattr(selection, "expected_country", "")
            or ""
        ).strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", expected_country):
            raise HeadedChromeRegistrationError(
                "headed_chrome_proxy_country_missing"
            )

        CurrentProviderOtpReader = _current_provider_otp_reader_class(
            reference,
            stop_check,
        )

        account = reference.MailAccount(
            email=target_email,
            password="",
            client_id="",
            refresh_token="",
            raw=target_email,
            account_type="unknown",
            mailbox_email=target_email,
            pickup_url="",
            mfa_totp_secret=saved_totp_secret,
        )
        phase = "proxy_chain_start"
        with reference.ProxyChainServer(
            "",
            upstream_proxy,
            log_reference,
            traffic_callback=reporter.on_bytes,
            force_server=True,
        ) as chain:
            reporter.attach(chain)
            reporter.on_bytes(0)
            worker_type = _worker_class(
                reference,
                expected_country,
                raw_trace=raw_trace,
                traffic_reporter=reporter,
            )
            phase = "worker_construct"
            worker = worker_type(
                account,
                bool(_browser_cfg.REGISTRATION_HEADLESS),
                reference.ProxyConfig(
                    local_proxy="",
                    dynamic_proxy=upstream_proxy,
                    chain_url=chain.url,
                ),
                log_reference,
                otp_reader_factory=CurrentProviderOtpReader,
                mfa_totp_secret=saved_totp_secret,
                mfa_persist_callback=persist_mfa,
                enable_mfa_enrollment=bool(
                    getattr(_twofa_cfg, "ENABLE_2FA", False)
                ),
                stop_event=stop_event,
            )
            worker.protocol_prefix_before_otp = False
            worker.hybrid_protocol_after_otp = False
            worker.openai_password = str(saved_openai_password or "")
            if worker.openai_password:
                worker.openai_password_state = auth_fields["openai_password_state"]
            worker.auth_persist_callback = persist_auth
            worker.browser_traffic_callback = lambda _delta: None
            worker.browser_traffic_forward_to_account = False
            worker.stop_event = stop_event
            runtime = RegistrationRuntime(
                worker, timeout=_registration_worker_timeout_seconds(),
                cancellation_event=cancellation_event, log=log_reference,
            )
            worker._registration_runtime = runtime
            runtime.start()
            phase = "worker_run"
            result_payload = run_with_cleanup_result(worker, runtime)
            phase = "post_cleanup_check"
            runtime.check_result()
            # The pinned worker closes its Context after extracting Session;
            # this idempotent fallback also covers compatible test doubles or
            # a future reference-core implementation that omits that hook.
            finalize_raw_trace("complete")
            create_started = bool(
                getattr(worker, "_user_register_seen", False)
                or getattr(worker, "_account_create_confirmed", False)
            )
            create_acknowledged = bool(
                getattr(worker, "_account_create_confirmed", False)
            )
            identity_pending = str(getattr(worker, "auth_route", "") or "") in {
                "pending_email_otp",
                "new_password_signup",
            }
            existing_account_detected = str(
                getattr(worker, "auth_route", "") or ""
            ) in {"existing_password_login", "existing_email_otp_login"}

        if not isinstance(result_payload, dict):
            raise HeadedChromeRegistrationError(
                "headed_chrome_session_missing"
            )
        result_payload.update(auth_fields)
        result_payload.update(mfa_fields)
        access_token = str(result_payload.get("access_token") or "").strip()
        if not access_token:
            raise HeadedChromeRegistrationError("headed_chrome_session_missing")
        try:
            session_info = json.loads(
                str(result_payload.get("session_json") or "{}")
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise HeadedChromeRegistrationError(
                "headed_chrome_session_missing"
            ) from exc
        if not isinstance(session_info, dict):
            raise HeadedChromeRegistrationError("headed_chrome_session_missing")
        phase = "session_identity"
        identity = _session_identity(target_email, session_info, access_token)
        create_acknowledged = True
        identity_pending = False
        mark_registration_account_created(target_email)

        try:
            snapshot = _session_snapshot(
                email=target_email,
                result=result_payload,
                session_info=session_info,
                worker=worker,
            )
            phase = "session_save"
            with diagnostic_step(log_reference, phase):
                save_chatgpt_session_snapshot(snapshot)
            session_saved = True
            logger.info("[HeadedChrome] stage=session_snapshot result=saved")
        except ChatGPTSessionStoreError as exc:
            logger.warning(
                "[HeadedChrome] stage=session_snapshot result=failed error_code=%s",
                exc.error_code,
            )

        phase = "codex_followup"
        codex_result = _safe_codex_result(
            target_email,
            proxy=upstream_proxy,
            proxy_geo=dict(getattr(selection, "geo", {}) or {}),
        )
        password = str(
            result_payload.get("openai_password")
            or auth_fields.get("openai_password")
            or saved_openai_password
            or ""
        )
        # Identity has already been checked against the Session and token.
        evidence = getattr(worker, "_candidate_password_evidence", None)
        if evidence is not None and evidence.confirms(password):
            result_payload["openai_password_state"] = "confirmed"
        totp_secret = str(
            result_payload.get("mfa_totp_secret")
            or mfa_fields.get("mfa_totp_secret")
            or saved_totp_secret
            or ""
        ) or None
        registration_path = str(
            result_payload.get("auth_route")
            or auth_fields.get("auth_route")
            or "headed_chrome"
        )
        extra = {
            "user": session_info.get("user"),
            "account": session_info.get("account"),
            "expires": session_info.get("expires"),
            "device_id": snapshot.get("device_id") if session_saved else None,
            "browser_profile": _browser_profile(worker),
            "registration_driver": "headed_chrome",
            "registration_state": "complete",
            "registration_path": registration_path,
            "registration_password": password,
            "mfa_recovery_code": str(
                result_payload.get("mfa_recovery_code")
                or mfa_fields.get("mfa_recovery_code")
                or ""
            ),
            "codex": codex_result,
        }
        bind_password_state(
            extra, password, str(result_payload.get("openai_password_state") or "")
        )
        phase = "account_save"
        extra['mfa_enrollment_state'] = mfa_fields.get('mfa_enrollment_state')
        extra['mfa_enrolled_at'] = mfa_fields.get('mfa_enrolled_at')
        account_id = save_account_data(
            email=target_email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(target_email),
            proxy_used=str(getattr(selection, "safe_label", "") or "") or None,
            batch_dir=batch_dir,
            registration_plan_route_hint=_plan_route_hint(selection),
            extra=extra,
        )
        from core.totp_confirmation import persist_registration_evidence
        persist_registration_evidence(account_id, target_email, totp_secret,
                                      getattr(worker, '_totp_activation_secret', None),
                                      error_code=getattr(worker, '_totp_error_code', None))
        if session_saved:
            try:
                bind_chatgpt_session_account(target_email, account_id)
            except Exception as exc:
                diagnostic_failure(log_reference, "session_bind", exc)
                logger.warning(
                    "[HeadedChrome] stage=session_bind result=failed error_code=session_bind_failed"
                )
        codex_ok = bool(
            codex_result.get("ok") or codex_result.get("status") == "skipped"
        )
        network_usage = reporter.snapshot("complete")
        logger.info(
            "[HeadedChrome] stage=complete result=%s account_id=%s",
            "success" if codex_ok else "partial",
            account_id,
        )
        return {
            "success": codex_ok,
            "email": target_email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "registration_path": registration_path,
            "codex": codex_result,
            "network_usage": network_usage,
            "error": None if codex_ok else "codex_oauth_incomplete",
        }
    except Exception as exc:
        diagnostic_failure(log_reference, phase, exc)
        diagnostic_emit(log_reference, "registration_failure_state",
                        session_extracted=bool(getattr(worker, "_headed_raw_session_extracted", False)),
                        result_returned=isinstance(result_payload, dict), session_saved=session_saved)
        finalize_raw_trace("partial")
        runtime = getattr(worker, "_registration_runtime", None)
        # Cleanup must not mask an earlier auth failure or a rejected candidate.
        terminal = (None if runtime is not None and runtime.abort_source == "cleanup_deadline"
                    else getattr(worker, "_registration_terminal_code", None))
        error_code = terminal or _error_code(exc)
        callback_account_id = getattr(
            auth_persist_callback, "latest_account_id", None
        )
        if (
            pending_account_id is None
            and not isinstance(callback_account_id, bool)
            and isinstance(callback_account_id, int)
            and callback_account_id > 0
        ):
            pending_account_id = int(callback_account_id)
        if error_code in {"account_deactivated", "account_deleted", "account_banned"}:
            from core import db
            db.mark_account_unusable(email=target_email, error_code=error_code,
                                     evidence_source="registration_email_otp_validate")
        failed_usage = reporter.snapshot(
            "partial", error_code="headed_chrome_registration_interrupted"
        )
        if traffic_snapshot_callback is not None:
            try:
                traffic_snapshot_callback(failed_usage)
            except Exception:
                pass
        if stop_check is not None:
            stop_check()
        if worker is not None:
            create_started = create_started or bool(
                getattr(worker, "_user_register_seen", False)
                or getattr(worker, "_account_create_confirmed", False)
            )
            create_acknowledged = create_acknowledged or bool(
                getattr(worker, "_account_create_confirmed", False)
            )
            auth_route = str(getattr(worker, "auth_route", "") or "")
            identity_pending = identity_pending or auth_route in {
                "pending_email_otp",
                "new_password_signup",
            }
            existing_account_detected = existing_account_detected or auth_route in {
                "existing_password_login",
                "existing_email_otp_login",
            }
        if pending_account_id is None:
            mark_registration_failed(
                target_email,
                create_started=create_started,
                create_acknowledged=(
                    create_acknowledged
                    and error_code != "registration_session_identity_mismatch"
                ),
                error=error_code,
                existing_account_detected=existing_account_detected,
                identity_pending=identity_pending,
            )
            try:
                status = registration_failure_email_status(
                    target_email,
                    create_started=create_started,
                    create_acknowledged=create_acknowledged,
                    existing_account_detected=existing_account_detected,
                    identity_pending=identity_pending,
                    email_source=resolve_email_source(target_email),
                )
                if error_code == "registration_session_identity_mismatch":
                    status = (
                        "quarantined"
                        if resolve_email_source(target_email) == "icloud_hme"
                        else "failed"
                    )
                release_email(
                    target_email,
                    status=status,
                    note=f"headed_chrome_failed:{error_code}",
                )
            except Exception:
                logger.warning(
                    "[HeadedChrome] stage=email_release result=failed error_code=email_release_failed"
                )
        else:
            logger.info(
                "[HeadedChrome] stage=email_release result=preserved reason=pending_credentials"
            )
        logger.warning(
            "[HeadedChrome] stage=complete result=failed error_code=%s",
            error_code,
        )
        failed_result = {
            "success": False,
            "email": target_email,
            "error": error_code,
            "error_code": error_code,
            "network_usage": failed_usage,
        }
        if pending_account_id is not None:
            failed_result["account_id"] = pending_account_id
        return failed_result


__all__ = [
    "HeadedChromeRegistrationError",
    "run_headed_chrome_registration",
]
