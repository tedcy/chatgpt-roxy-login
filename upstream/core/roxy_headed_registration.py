"""Run the pinned headed-Chrome auth state machine inside a Roxy Profile.

Roxy remains the sole owner of the browser process, persistent profile,
fingerprint, proxy and TLS stack.  Playwright attaches to the existing default
context only for the registration state machine and disconnects before the
normal Roxy post-registration work continues.
"""

from __future__ import annotations

import inspect
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from config import roxybrowser as _cfg
from config import twofa as _twofa_cfg
from core.account_export import save_account_data
from core.chatgpt_session_store import (
    ChatGPTSessionStoreError,
    bind_account as bind_chatgpt_session_account,
    save_snapshot as save_chatgpt_session_snapshot,
)
from core.email_provider import (
    mark_registration_account_created,
    mark_registration_failed,
    registration_failure_email_status,
    release_email,
    resolve_email_source,
)
from core.headed_chrome_reference.adapter import (
    HeadedChromeRegistrationError,
    _StopEvent,
    _current_provider_otp_reader_class,
    _error_code as _headed_error_code,
    _load_reference_module,
    _safe_log_text,
    _session_identity,
    _worker_class,
)
from core.plan_check_route import registration_plan_route_hint_from_opened
from core.roxy_chatgpt_contract_trace import RoxyChatGPTContractTracer
from core.roxy_traffic_meter import RoxyTrafficMeter, empty_network_usage
from core.roxybrowser_client import RoxyBrowserClient, RoxyOpenResult


logger = logging.getLogger(__name__)


ROXY_HEADED_OPEN_ARGS = (
    "--disable-background-networking",
    "--disable-breakpad",
    "--disable-client-side-phishing-detection",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-notifications",
    "--disable-pings",
    "--disable-sync",
    "--dns-prefetch-disable",
    "--metrics-recording-only",
    "--no-first-run",
    "--disable-features="
    "MediaRouter,OptimizationHints,OptimizationGuideModelDownloading,"
    "Translate,AutofillServerCommunication,Prerender2,SpeculationRules,"
    "SpeculationRulesPrefetchProxy,PreloadingHeuristicsMLModel,"
    "InterestFeedContentSuggestions,NetworkTimeServiceQuerying",
)


_ROXY_AUTOMATION_MASK_JS = r"""(() => {
  try {
    if (navigator.webdriver !== undefined) {
      Object.defineProperty(Navigator.prototype, 'webdriver', {
        configurable: true,
        get: () => undefined
      });
    }
  } catch (_) {}
})();"""


_FINGERPRINT_JS = r"""() => {
  let timezone = '';
  try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (_) {}
  let webglVendor = '';
  let webglRenderer = '';
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) {
        webglVendor = String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '');
        webglRenderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '');
      }
    }
  } catch (_) {}
  return {
    user_agent: navigator.userAgent || '',
    locale: navigator.language || '',
    languages: Array.isArray(navigator.languages) ? navigator.languages : [],
    timezone,
    inner_width: window.innerWidth || 0,
    inner_height: window.innerHeight || 0,
    outer_width: window.outerWidth || 0,
    outer_height: window.outerHeight || 0,
    screen_width: (window.screen && window.screen.width) || 0,
    screen_height: (window.screen && window.screen.height) || 0,
    device_scale_factor: window.devicePixelRatio || 0,
    hardware_concurrency: navigator.hardwareConcurrency || 0,
    device_memory: navigator.deviceMemory || 0,
    platform: navigator.platform || '',
    vendor: navigator.vendor || '',
    max_touch_points: navigator.maxTouchPoints || 0,
    webdriver: navigator.webdriver === undefined ? 'undefined' : String(navigator.webdriver),
    webgl_vendor: webglVendor,
    webgl_renderer: webglRenderer,
  };
}"""


_STABLE_FINGERPRINT_FIELDS = (
    "user_agent",
    "locale",
    "languages",
    "timezone",
    "screen_width",
    "screen_height",
    "device_scale_factor",
    "hardware_concurrency",
    "device_memory",
    "platform",
    "vendor",
    "max_touch_points",
    "webdriver",
    "webgl_vendor",
    "webgl_renderer",
)


class RoxyHeadedRegistrationError(HeadedChromeRegistrationError):
    """A fixed, credential-free failure from the Roxy-headed adapter."""


class _MailboxAccessDeniedOtpReader:
    """Fail closed if the reference worker tries to open mailbox OTP."""

    def __init__(self, *args, **kwargs):
        raise RoxyHeadedRegistrationError("auth_email_challenge_required")


def _page_is_closed(page: object) -> bool:
    try:
        value = getattr(page, "is_closed", False)
        if callable(value):
            value = value()
        return bool(value)
    except Exception:
        return False


_DOM_DIAGNOSTIC_HOSTS = frozenset(
    {
        "auth.openai.com",
        "chatgpt.com",
        "www.chatgpt.com",
        "openai.com",
        "www.openai.com",
        "platform.openai.com",
    }
)


def _page_is_openai_first_party(page: object) -> bool:
    try:
        value = ""
        for attribute in ("current_url", "url"):
            value = getattr(page, attribute, "")
            if callable(value):
                value = value()
            if value:
                break
        return str(urlsplit(str(value or "")).hostname or "").lower() in _DOM_DIAGNOSTIC_HOSTS
    except Exception:
        return False


def _is_stale_cdp_interception_error(method: object, exc: BaseException) -> bool:
    """Recognize only the benign race where Fetch already consumed a request."""
    command = str(method or "").strip().lower()
    if command not in {
        "fetch.continuerequest",
        "fetch.fulfillrequest",
        "fetch.failrequest",
    }:
        return False
    text = str(exc or "").lower()
    return "invalid interceptionid" in text


def _guard_stale_cdp_interception(worker, session) -> None:
    """Make the vendored Fetch callback idempotent without editing the vendor."""
    if session is None or bool(getattr(session, "_turb_cdp_send_guarded", False)):
        return
    original_send = getattr(session, "send", None)
    if not callable(original_send):
        return

    def guarded_send(method, params=None):
        try:
            return original_send(method, params)
        except Exception as exc:
            if not _is_stale_cdp_interception_error(method, exc):
                raise
            count = int(getattr(session, "_turb_cdp_stale_interceptions", 0) or 0) + 1
            try:
                session._turb_cdp_stale_interceptions = count
            except Exception:
                pass
            if count == 1:
                try:
                    worker.log(
                        "[traffic] CDP 拦截请求已失效，忽略重复继续："
                        "reason=stale_interception"
                    )
                except Exception:
                    pass
            return {}

    try:
        session._turb_cdp_original_send = original_send
        session.send = guarded_send
        session._turb_cdp_send_guarded = True
    except Exception:
        try:
            del session._turb_cdp_original_send
        except Exception:
            pass


def _guard_stale_cdp_sessions(worker) -> None:
    for session in list(getattr(worker, "_low_traffic_cdp_sessions", []) or []):
        _guard_stale_cdp_interception(worker, session)


def _normalise_fingerprint_projection(value: object) -> dict:
    source = value if isinstance(value, dict) else {}
    languages = [
        str(item or "").strip()
        for item in list(source.get("languages") or [])
        if str(item or "").strip()
    ]

    def integer(name: str, minimum: int = 0) -> int:
        try:
            return max(minimum, int(float(source.get(name) or 0)))
        except (TypeError, ValueError, OverflowError):
            return minimum

    try:
        scale = round(float(source.get("device_scale_factor") or 0), 4)
    except (TypeError, ValueError, OverflowError):
        scale = 0.0
    return {
        "user_agent": str(source.get("user_agent") or "").strip(),
        "locale": str(source.get("locale") or "").strip(),
        "languages": languages,
        "timezone": str(source.get("timezone") or "").strip(),
        "inner_width": integer("inner_width"),
        "inner_height": integer("inner_height"),
        "outer_width": integer("outer_width"),
        "outer_height": integer("outer_height"),
        "screen_width": integer("screen_width"),
        "screen_height": integer("screen_height"),
        "device_scale_factor": scale,
        "hardware_concurrency": integer("hardware_concurrency"),
        "device_memory": integer("device_memory"),
        "platform": str(source.get("platform") or "").strip(),
        "vendor": str(source.get("vendor") or "").strip(),
        "max_touch_points": integer("max_touch_points"),
        "webdriver": str(source.get("webdriver") or "").strip(),
        "webgl_vendor": str(source.get("webgl_vendor") or "").strip(),
        "webgl_renderer": str(source.get("webgl_renderer") or "").strip(),
    }


def _fingerprint_projection_matches(before: dict, after: dict) -> bool:
    left = _normalise_fingerprint_projection(before)
    right = _normalise_fingerprint_projection(after)
    return all(left.get(name) == right.get(name) for name in _STABLE_FINGERPRINT_FIELDS)


def _selenium_fingerprint_projection(driver) -> dict:
    try:
        driver.get("about:blank")
        value = driver.execute_script(f"return ({_FINGERPRINT_JS})();")
    except Exception as exc:
        raise RoxyHeadedRegistrationError(
            "roxy_headed_fingerprint_unavailable"
        ) from exc
    projection = _normalise_fingerprint_projection(value)
    if not projection.get("user_agent") or not projection.get("locale"):
        raise RoxyHeadedRegistrationError("roxy_headed_fingerprint_unavailable")
    return projection


def _device_fingerprint(reference, projection: dict):
    value = _normalise_fingerprint_projection(projection)
    locale = str(value.get("locale") or "").strip()
    user_agent = str(value.get("user_agent") or "").strip()
    timezone = str(value.get("timezone") or "").strip()
    if not user_agent or not locale or not timezone:
        raise RoxyHeadedRegistrationError("roxy_headed_fingerprint_unavailable")
    languages = list(value.get("languages") or []) or [locale]
    return reference.DeviceFingerprint(
        user_agent=user_agent,
        locale=locale,
        languages=languages,
        timezone=timezone,
        viewport_width=max(1, int(value.get("inner_width") or value.get("screen_width") or 1)),
        viewport_height=max(1, int(value.get("inner_height") or value.get("screen_height") or 1)),
        screen_width=max(1, int(value.get("screen_width") or 1)),
        screen_height=max(1, int(value.get("screen_height") or 1)),
        outer_width=max(1, int(value.get("outer_width") or value.get("screen_width") or 1)),
        outer_height=max(1, int(value.get("outer_height") or value.get("screen_height") or 1)),
        device_scale_factor=max(0.1, float(value.get("device_scale_factor") or 1.0)),
        hardware_concurrency=max(1, int(value.get("hardware_concurrency") or 1)),
        device_memory=max(1, int(value.get("device_memory") or 1)),
        platform=str(value.get("platform") or ""),
        vendor=str(value.get("vendor") or "Google Inc."),
        max_touch_points=max(0, int(value.get("max_touch_points") or 0)),
    )


def _roxy_proxy_health(reference, opened: RoxyOpenResult, expected_country: str):
    geo = dict(getattr(opened, "task_proxy_geo", {}) or {})
    actual_country = str(
        geo.get("country") or geo.get("country_code") or ""
    ).strip().upper()
    expected = str(expected_country or "").strip().upper()
    if expected and actual_country != expected:
        logger.warning(
            "[CountryPolicy] operation=browser_auth required_country=%s actual_country=%s source=task outcome=rejected",
            expected if len(expected) == 2 and expected.isascii() and expected.isalpha() else "invalid",
            actual_country if len(actual_country) == 2 and actual_country.isascii() and actual_country.isalpha() else "unknown",
        )
    if expected and not actual_country:
        raise RoxyHeadedRegistrationError("roxy_headed_proxy_country_unverified")
    if expected and actual_country != expected:
        raise RoxyHeadedRegistrationError("roxy_headed_proxy_country_drift")
    return reference.ProxyHealthResult(
        True,
        ip=str(geo.get("ip") or ""),
        country=actual_country,
        region=str(geo.get("region") or ""),
        city=str(geo.get("city") or ""),
        timezone=str(geo.get("timezone") or ""),
        org=str(geo.get("org") or ""),
        chatgpt_status=0,
    )


def _stage_name(value: object) -> str:
    text = str(value or "").strip().lower()
    if any(marker in text for marker in ("mfa状态", "mfa status", "mfa_info", "mfa info")):
        return "twofa_status"
    if any(marker in text for marker in ("mfa绑定", "mfa enroll", "mfa/enroll", "totp enrollment")):
        return "twofa_enroll"
    if any(marker in text for marker in ("mfa激活", "mfa activate", "activate_enrollment")):
        return "twofa_activate"
    if any(marker in text for marker in ("mfa复核", "mfa verify", "mfa verification")):
        return "twofa_verify"
    if any(marker in text for marker in ("csrf", "oauth 入口", "chromium", "出口定位")):
        return "login_page"
    if any(marker in text for marker in ("邮箱分流", "email submit", "邮箱提交")):
        return "email_submit"
    if any(marker in text for marker in ("密码", "password")):
        return "password"
    if any(marker in text for marker in ("验证码", "otp")):
        return "otp"
    if any(marker in text for marker in ("基础资料", "about", "callback", "session")):
        return "profile_session"
    if "mfa" in text:
        return "profile_session"
    return "other"


def _browser_csrf_and_device(worker, context, page) -> tuple[str, str]:
    if page is None:
        raise RoxyHeadedRegistrationError("roxy_headed_browser_transport_failed")
    reference = worker._roxy_reference
    cookie_urls = [reference.CHATGPT_BASE_URL, "https://openai.com"]

    def cookie_values() -> tuple[str, str]:
        csrf_value = ""
        device_id = ""
        try:
            cookies = context.cookies(cookie_urls)
        except Exception:
            cookies = []
        for cookie in cookies:
            name = str(cookie.get("name") or "")
            if name == "__Host-next-auth.csrf-token":
                csrf_value = unquote(str(cookie.get("value") or "")).split("|", 1)[0]
            elif name == "oai-did":
                device_id = str(cookie.get("value") or "")
        return csrf_value, device_id

    csrf_value, device_id = cookie_values()
    if csrf_value:
        worker._auth_csrf_via_browser = True
        return csrf_value, device_id

    csrf_url = f"{reference.CHATGPT_BASE_URL}/api/auth/csrf"
    for attempt in range(1, 4):
        worker._raise_if_stopped()
        payload = {}
        status = 0
        try:
            response = page.goto(
                csrf_url,
                wait_until="commit",
                timeout=60000,
            )
            if response is not None:
                status = int(getattr(response, "status", 0) or 0)
                try:
                    candidate = response.json()
                except Exception:
                    candidate = {}
                if isinstance(candidate, dict):
                    payload = candidate
        except Exception:
            if not str(getattr(page, "url", "") or "").startswith(
                reference.CHATGPT_BASE_URL
            ):
                if attempt >= 3:
                    raise RoxyHeadedRegistrationError(
                        "roxy_headed_browser_transport_failed"
                    )

        csrf_value = str(payload.get("csrfToken") or "").strip()
        if not csrf_value:
            try:
                result = page.evaluate(
                    """async () => {
                      const response = await fetch('/api/auth/csrf', {
                        method: 'GET', credentials: 'include', cache: 'no-store',
                        headers: {accept: 'application/json'}
                      });
                      let payload = {};
                      try { payload = await response.json(); } catch (_) {}
                      return {ok: response.ok, status: response.status,
                              csrfToken: String(payload.csrfToken || '')};
                    }"""
                )
            except Exception:
                result = {}
            csrf_value = str((result or {}).get("csrfToken") or "").strip()
            status = int((result or {}).get("status", status) or status)
        cookie_csrf, cookie_device = cookie_values()
        csrf_value = csrf_value or cookie_csrf
        device_id = device_id or cookie_device
        if csrf_value:
            worker._auth_csrf_via_browser = True
            worker.log("[auth] 已通过 Roxy Chromium 浏览器通道获取 CSRF")
            return csrf_value, device_id
        if attempt < 3:
            worker.log(
                "[auth] Roxy Chromium CSRF 暂不可用，保持同一 Profile 后重试"
            )
            if attempt == 2:
                # A stale Fetch/Network interception can leave a live Roxy
                # page returning 200 without exposing the CSRF JSON to the
                # attached Playwright page.  Re-arm only the adapter-owned
                # CDP filters; the browser, profile and proxy remain intact.
                try:
                    _teardown_reference_low_traffic(worker, context)
                    reinstall = getattr(worker, "_install_low_traffic_cdp", None)
                    if callable(reinstall):
                        reinstall(context)
                        worker.log("[auth] 已重装 Roxy CDP 流量过滤后重试 CSRF")
                except Exception:
                    worker.log("[auth] Roxy CDP 流量过滤重装失败，继续重试 CSRF")
            worker._wait_or_stop(2.0 if status != 403 else 5.0)

    raise RoxyHeadedRegistrationError("roxy_headed_csrf_failed")


def _teardown_reference_low_traffic(worker, context) -> bool:
    failed = False
    guard_context = getattr(worker, "_turb_cdp_guard_context", None)
    guard_listener = getattr(worker, "_turb_cdp_guard_listener", None)
    if guard_context is None:
        guard_context = context
    if callable(guard_listener):
        try:
            guard_context.remove_listener("page", guard_listener)
        except Exception:
            failed = True
    original_new_cdp_session = getattr(
        worker, "_turb_cdp_original_new_cdp_session", None
    )
    if callable(original_new_cdp_session):
        try:
            guard_context.new_cdp_session = original_new_cdp_session
        except Exception:
            failed = True
    attach = getattr(worker, "_attach_low_traffic_cdp_page", None)
    if callable(attach):
        try:
            context.remove_listener("page", attach)
        except Exception:
            failed = True
    for session in list(getattr(worker, "_low_traffic_cdp_sessions", []) or []):
        original_send = getattr(session, "_turb_cdp_original_send", None)
        try:
            try:
                session.send("Fetch.disable")
            except Exception:
                failed = True
            try:
                session.send("Network.setBlockedURLs", {"urls": []})
            except Exception:
                failed = True
            try:
                session.detach()
            except Exception:
                failed = True
        finally:
            if callable(original_send):
                try:
                    session.send = original_send
                except Exception:
                    failed = True
            for name in (
                "_turb_cdp_original_send",
                "_turb_cdp_send_guarded",
                "_turb_cdp_stale_interceptions",
            ):
                try:
                    delattr(session, name)
                except Exception:
                    pass
    worker._low_traffic_cdp_sessions = []
    worker._attach_low_traffic_cdp_page = None
    worker._turb_cdp_guard_context = None
    worker._turb_cdp_guard_listener = None
    worker._turb_cdp_original_new_cdp_session = None
    return not failed


def _roxy_worker_class(
    reference,
    *,
    expected_country: str,
    opened: RoxyOpenResult,
    before_fingerprint: dict,
    stage_callback,
    automation_mask_enabled: bool = True,
    login_only: bool = False,
    dom_recorder=None,
    otp_observer=None,
    low_traffic_enabled: bool = True,
):
    base = _worker_class(reference, expected_country)

    class RoxyHeadedWorker(base):
        def _install_low_traffic_cdp(self, context) -> None:
            if not low_traffic_enabled:
                return
            original_new_cdp_session = getattr(context, "new_cdp_session", None)
            if (
                callable(original_new_cdp_session)
                and not callable(
                    getattr(self, "_turb_cdp_original_new_cdp_session", None)
                )
            ):
                def guarded_new_cdp_session(page):
                    session = original_new_cdp_session(page)
                    _guard_stale_cdp_interception(self, session)
                    return session

                try:
                    context.new_cdp_session = guarded_new_cdp_session
                    self._turb_cdp_guard_context = context
                    self._turb_cdp_original_new_cdp_session = original_new_cdp_session
                except Exception:
                    self._turb_cdp_guard_context = None
                    self._turb_cdp_original_new_cdp_session = None
            result = super()._install_low_traffic_cdp(context)
            _guard_stale_cdp_sessions(self)
            if callable(
                getattr(self, "_turb_cdp_original_new_cdp_session", None)
            ):
                return result
            on_page = getattr(self, "_turb_cdp_guard_listener", None)
            if callable(on_page):
                return result
            context_on = getattr(context, "on", None)
            if not callable(context_on):
                return result

            def guard_page(_page) -> None:
                _guard_stale_cdp_sessions(self)

            try:
                context_on("page", guard_page)
                self._turb_cdp_guard_context = context
                self._turb_cdp_guard_listener = guard_page
            except Exception:
                self._turb_cdp_guard_context = None
                self._turb_cdp_guard_listener = None
            return result

        def _dom_observe_page(
            self,
            page,
            *,
            stage: str,
            event: str,
            force: bool = False,
            result: str = "",
            source_error_type: str = "",
        ) -> None:
            recorder = getattr(self, "_dom_recorder", None) or dom_recorder
            if recorder is None or page is None:
                return
            try:
                recorder.observe_page(
                    page,
                    stage=stage,
                    event=event,
                    force=force,
                    result=result,
                    source_error_type=source_error_type,
                )
            except Exception:
                pass

        def _dom_observe_context(
            self,
            *,
            stage: str,
            event: str,
            force: bool = False,
            result: str = "",
            source_error_type: str = "",
        ) -> None:
            recorder = getattr(self, "_dom_recorder", None) or dom_recorder
            if recorder is None:
                return
            context = getattr(self, "_roxy_connected_context", None)
            if context is None:
                context = getattr(self, "_dom_context", None)
            try:
                pages = list(getattr(context, "pages", []) or [])
            except Exception:
                pages = []
            pages = [page for page in pages if _page_is_openai_first_party(page)]
            active_page = getattr(self, "_dom_active_page", None)
            if active_page in pages:
                pages = [page for page in pages if page is not active_page]
                pages.append(active_page)
            if pages:
                try:
                    recorder.observe_pages(
                        pages,
                        stage=stage,
                        event=event,
                        force=force,
                        result=result,
                        source_error_type=source_error_type,
                    )
                except Exception:
                    pass
            else:
                active_page = getattr(self, "_dom_active_page", None)
                if _page_is_openai_first_party(active_page):
                    self._dom_observe_page(
                        active_page,
                        stage=stage,
                        event=event,
                        force=force,
                        result=result,
                        source_error_type=source_error_type,
                    )

        def _otp_mark(self, kind: str, result: str = "", *, stage: str = "email_otp") -> None:
            observer = otp_observer
            if observer is None:
                return
            try:
                if kind == "challenge":
                    observer.mark_challenge_page(stage=stage)
                elif kind == "mailbox":
                    observer.mark_mailbox_poll(result, stage=stage)
                elif kind == "submit":
                    observer.mark_submit_result(result, stage=stage)
            except Exception:
                pass

        def _register(self, page, context) -> None:
            self._dom_active_page = page
            self._dom_context = context
            self._dom_observe_page(
                page,
                stage="authentication",
                event="auth_flow_start",
                force=True,
            )
            try:
                return super()._register(page, context)
            except Exception as exc:
                self._dom_observe_context(
                    stage="failure",
                    event="auth_flow_exception",
                    result="failed",
                    source_error_type=type(exc).__name__,
                    force=True,
                )
                raise
            finally:
                self._dom_observe_context(
                    stage="authentication",
                    event="auth_flow_end",
                    force=True,
                )

        def _recover_auth_page_if_closed(self, page, context, action: str):
            recovered = super()._recover_auth_page_if_closed(page, context, action)
            self._dom_active_page = recovered
            self._dom_observe_page(
                recovered,
                stage="authentication",
                event="page_recovered",
                force=True,
            )
            return recovered

        def _fill_password_step(self, page) -> None:
            evidence = getattr(self, '_login_evidence', None)
            if evidence is not None:
                evidence.password_submitted = True
                evidence.password_verified = False
            self._dom_active_page = page
            self._dom_observe_page(
                page,
                stage="password",
                event="password_action_start",
                force=True,
            )
            try:
                result = super()._fill_password_step(page)
            except Exception as exc:
                self._dom_observe_page(
                    page,
                    stage="password",
                    event="password_action_exception",
                    result="failed",
                    source_error_type=type(exc).__name__,
                    force=True,
                )
                raise
            self._dom_observe_page(
                page,
                stage="password",
                event="password_action_success",
                result="success",
                force=True,
            )
            return result

        def _submit_email_code(self, page, min_timestamp: float) -> None:
            self._dom_active_page = page
            self._otp_mark("challenge", stage="email_otp")
            self._otp_mark("mailbox", "waiting", stage="email_otp")
            self._dom_observe_page(
                page,
                stage="email_otp",
                event="email_otp_action_start",
                force=True,
            )
            try:
                result = super()._submit_email_code(page, min_timestamp)
            except Exception as exc:
                self._otp_mark("mailbox", "error", stage="email_otp")
                self._otp_mark("submit", "failed", stage="email_otp")
                self._dom_observe_page(
                    page,
                    stage="email_otp",
                    event="email_otp_action_exception",
                    result="failed",
                    source_error_type=type(exc).__name__,
                    force=True,
                )
                raise
            self._dom_observe_page(
                page,
                stage="email_otp",
                event="email_otp_action_success",
                result="success",
                force=True,
            )
            self._otp_mark("mailbox", "received", stage="email_otp")
            self._otp_mark("submit", "accepted", stage="email_otp")
            return result

        def _submit_mfa_email_code(self, page, min_timestamp: float) -> None:
            self._dom_active_page = page
            self._otp_mark("challenge", stage="mfa")
            self._otp_mark("mailbox", "waiting", stage="mfa")
            self._dom_observe_page(
                page,
                stage="mfa",
                event="mfa_email_action_start",
                force=True,
            )
            try:
                result = super()._submit_mfa_email_code(page, min_timestamp)
            except Exception as exc:
                self._otp_mark("mailbox", "error", stage="mfa")
                self._otp_mark("submit", "failed", stage="mfa")
                self._dom_observe_page(
                    page,
                    stage="mfa",
                    event="mfa_email_action_exception",
                    result="failed",
                    source_error_type=type(exc).__name__,
                    force=True,
                )
                raise
            self._dom_observe_page(
                page,
                stage="mfa",
                event="mfa_email_action_success",
                result="success",
                force=True,
            )
            self._otp_mark("mailbox", "received", stage="mfa")
            self._otp_mark("submit", "accepted", stage="mfa")
            return result

        def _prepare_fingerprint_for_proxy(self, proxy, label):
            del proxy, label
            health = _roxy_proxy_health(reference, opened, expected_country)
            self.current_proxy_health = health
            self.fingerprint = _device_fingerprint(reference, before_fingerprint)
            self.log("[代理] 复用 Roxy 已校验代理和浏览器指纹")
            return health

        def _use_compact_auth_window(self) -> None:
            # Roxy owns window geometry as part of its fingerprint.
            return None

        def _new_isolated_registration_browser_context(self, p, proxy):
            del proxy
            endpoint = str(getattr(opened, "debugger_address", "") or "").strip()
            if endpoint:
                if not endpoint.startswith(("http://", "https://", "ws://", "wss://")):
                    endpoint = f"http://{endpoint}"
            else:
                endpoint = str(getattr(opened, "ws_endpoint", "") or "").strip()
            if not endpoint:
                raise RoxyHeadedRegistrationError("roxy_headed_cdp_unavailable")
            try:
                parameters = inspect.signature(
                    p.chromium.connect_over_cdp
                ).parameters
            except Exception:
                parameters = {}
            if "no_defaults" not in parameters:
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_playwright_incompatible"
                )
            try:
                browser = p.chromium.connect_over_cdp(
                    endpoint,
                    timeout=30000,
                    no_defaults=True,
                )
            except TypeError as exc:
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_playwright_incompatible"
                ) from exc
            except Exception as exc:
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_cdp_unavailable"
                ) from exc
            try:
                contexts = list(browser.contexts or [])
                if not contexts:
                    raise RoxyHeadedRegistrationError(
                        "roxy_headed_default_context_missing"
                    )
                context = contexts[0]
                if automation_mask_enabled:
                    try:
                        # Carry the existing Roxy/Selenium one-property
                        # automation mask to Playwright-created pages.  This
                        # is deliberately not the headed-Chrome fingerprint
                        # injector: Roxy remains authoritative for every
                        # identity-bearing browser field.
                        context.add_init_script(_ROXY_AUTOMATION_MASK_JS)
                    except Exception as exc:
                        raise RoxyHeadedRegistrationError(
                            "roxy_headed_automation_mask_failed"
                        ) from exc
                probe = context.new_page()
                try:
                    probe.goto("about:blank", wait_until="commit", timeout=10000)
                    after = _normalise_fingerprint_projection(
                        probe.evaluate(_FINGERPRINT_JS)
                    )
                finally:
                    try:
                        probe.close()
                    except Exception:
                        pass
                if not _fingerprint_projection_matches(before_fingerprint, after):
                    opened.profile_cache_discard = True
                    raise RoxyHeadedRegistrationError(
                        "roxy_headed_fingerprint_changed"
                    )
                self.fingerprint = _device_fingerprint(reference, after)
                self._roxy_connected_browser = browser
                self._roxy_connected_context = context
                self._dom_context = context
                self._roxy_reference = reference
                self._install_low_traffic_cdp(context)
                self.log("[RoxyHeaded] 已连接 Roxy 默认 Context，指纹保持一致")
                return browser, context
            except Exception:
                # ``connect_over_cdp`` attaches to the Roxy-owned browser. A
                # Playwright Browser.close() here closes the remote Chromium
                # instead of merely releasing this adapter's transport.
                try:
                    _teardown_reference_low_traffic(self, context)
                except Exception:
                    pass
                raise

        def _create_openai_signin_url(self, context, page=None) -> str:
            # A visible Roxy fresh-login must always enter the existing-account
            # route.  The registration adapter normally selects signup when no
            # password is present; doing that here could create a new account
            # instead of authenticating the requested one.
            if login_only:
                self._auth_screen_hint = "login"
                return self._create_provider_auth_url(
                    context,
                    "login",
                    "登录页",
                    page,
                )
            return super()._create_openai_signin_url(context, page)

        def _password_page_route(self, page) -> str:
            route = super()._password_page_route(page)
            if login_only and route == "new_password_signup":
                # A login-only Roxy window must never turn an unexpected
                # signup route into account creation, even if the provider
                # ignores the requested screen_hint.
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_login_unexpected_signup"
                )
            return route

        def _about_you_submit_retryable(self, page, exc: Exception) -> bool:
            message = str(exc or "")
            if "未产生业务提交请求" not in message:
                return False
            if any(
                marker in message
                for marker in (
                    "业务提交请求被代理连接中断",
                    "提交接口返回错误",
                    "Sentinel 验证失败",
                )
            ):
                return False
            try:
                return bool(
                    "about-you" in str(getattr(page, "url", "") or "").lower()
                    or self._has_about_you_form(page)
                )
            except Exception:
                return False

        def _reload_about_you_for_retry(self, page) -> bool:
            try:
                if not self._has_about_you_form(page):
                    return False
                # A stale Fetch/Network interception can leave the React form
                # interactive while suppressing the business submit event.
                # Keep the normal path in low-traffic mode, but release this
                # adapter-owned filter before the bounded recovery reload so
                # the page can rebuild its handlers and submit normally.
                context = (
                    getattr(self, "_roxy_connected_context", None)
                    or getattr(self, "_dom_context", None)
                )
                if context is not None:
                    try:
                        clean = _teardown_reference_low_traffic(self, context)
                        self.log(
                            f"基础资料恢复前已解除本次 Context 低流量拦截: clean={clean}"
                        )
                    except Exception:
                        self.log("基础资料恢复前解除低流量拦截失败，继续 reload")
                page.reload(wait_until="domcontentloaded", timeout=60000)
                self._wait_for_about_you_inputs(page)
                return bool(self._has_about_you_form(page))
            except Exception as exc:
                self.log(f"基础资料提交恢复失败: {str(exc)[:160]}")
                return False

        def _force_about_you_submit_recovery(self, page) -> bool:
            """Recover the current React-Aria date-picker form once.

            The pinned worker historically verifies only ``input`` values.
            The current about-you page can render the birthday as
            ``role=spinbutton`` segments, leaving the visible name input in
            the DOM while the form remains invalid.  Refill the same form
            through the vendor's existing field kernel, then submit once with
            the adapter-owned low-traffic interception released.
            """
            try:
                context = (
                    getattr(self, "_roxy_connected_context", None)
                    or getattr(self, "_dom_context", None)
                )
                if context is not None:
                    _teardown_reference_low_traffic(self, context)
                name, birthdate = reference.random_profile()
                birth_year = str(str(birthdate).split("-", 1)[0])
                age = str(
                    max(
                        18,
                        datetime.now(timezone.utc).year - int(birth_year),
                    )
                )
                self._fill_about_you_inputs(
                    page,
                    name,
                    birthdate,
                    birth_year,
                    age,
                )
                self._click_finish_creating_account(page) or self._click_continue(page)
                started = time.monotonic()
                while time.monotonic() - started < 35.0:
                    if self._about_you_submit_done(page, str(page.url or "")):
                        return True
                    self._wait_or_stop(0.25)
            except Exception:
                return False
            return False

        def _fill_about_you(self, page) -> None:
            self._dom_active_page = page
            self._dom_observe_page(
                page,
                stage="profile",
                event="profile_action_start",
                force=True,
            )
            if login_only:
                self._dom_observe_page(
                    page,
                    stage="profile",
                    event="profile_action_exception",
                    result="failed",
                    source_error_type="RoxyHeadedRegistrationError",
                    force=True,
                )
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_login_unexpected_signup"
                )
            retry_count = 0
            while True:
                try:
                    result = super()._fill_about_you(page)
                    break
                except Exception as exc:
                    if (
                        retry_count < 1
                        and self._about_you_submit_retryable(page, exc)
                    ):
                        retry_count += 1
                        if self._force_about_you_submit_recovery(page):
                            self.log("基础资料 React-Aria 字段恢复提交成功")
                            break
                        self.log(
                            "基础资料未产生业务提交请求，reload 后重试一次"
                        )
                        self._dom_observe_page(
                            page,
                            stage="profile",
                            event="profile_action_retry",
                            result="retry",
                            source_error_type=type(exc).__name__,
                            force=True,
                        )
                        if self._reload_about_you_for_retry(page):
                            continue
                    self._dom_observe_page(
                        page,
                        stage="profile",
                        event="profile_action_exception",
                        result="failed",
                        source_error_type=type(exc).__name__,
                        force=True,
                    )
                    raise
            self._dom_observe_page(
                page,
                stage="profile",
                event="profile_action_success",
                result="success",
                force=True,
            )
            return result

        def _ensure_totp_mfa(self, context) -> None:
            if login_only:
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_login_enrollment_forbidden"
                )
            return super()._ensure_totp_mfa(context)

        def _submit_authenticator_mfa_code(self, page) -> None:
            self._dom_active_page = page
            self._dom_observe_page(
                page,
                stage="mfa",
                event="mfa_action_start",
                force=True,
            )
            if login_only:
                # Reuse the shared committed-secret validator so the visible
                # and headed kernels expose the same fixed failure codes.
                try:
                    from core.chatgpt_session_refresh import _totp_secret_for_login

                    _totp_secret_for_login(
                        {"totp_secret": self.mfa_totp_secret}
                    )
                except Exception as exc:
                    self._dom_observe_page(
                        page,
                        stage="mfa",
                        event="mfa_action_exception",
                        result="failed",
                        source_error_type=type(exc).__name__,
                        force=True,
                    )
                    code = str(getattr(exc, "error_code", "") or "").strip()
                    if code in {
                        "session_login_totp_secret_missing",
                        "session_login_totp_secret_invalid",
                    }:
                        raise RoxyHeadedRegistrationError(code) from exc
                    raise RoxyHeadedRegistrationError(
                        "session_login_totp_failed"
                    ) from exc
            try:
                result = super()._submit_authenticator_mfa_code(page)
            except Exception as exc:
                self._dom_observe_page(
                    page,
                    stage="mfa",
                    event="mfa_action_exception",
                    result="failed",
                    source_error_type=type(exc).__name__,
                    force=True,
                )
                # The vendored worker intentionally exposes a generic
                # MfaRequiredError.  Normalize every failure at this host
                # boundary so the visible and background Roxy paths share the
                # same safe error code and never leak page text.
                stop_event = getattr(self, "stop_event", None)
                try:
                    if stop_event is not None and stop_event.is_set():
                        raise RoxyHeadedRegistrationError(
                            "session_window_close_requested"
                        ) from exc
                except RoxyHeadedRegistrationError:
                    raise
                except Exception:
                    pass
                raise RoxyHeadedRegistrationError(
                    "session_login_totp_failed"
                ) from exc
            self._dom_observe_page(
                page,
                stage="mfa",
                event="mfa_action_success",
                result="success",
                force=True,
            )
            return result

        def _get_chatgpt_csrf_and_device(self, context, page=None):
            return _browser_csrf_and_device(self, context, page)

        def _create_auth_entry_url(
            self,
            context,
            screen_hint,
            label,
            page=None,
            force_browser_channel=False,
        ):
            del force_browser_channel
            if page is None:
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_browser_transport_failed"
                )
            return super()._create_auth_entry_url(
                context,
                screen_hint,
                label,
                page,
                force_browser_channel=True,
            )

        def _browser_auth_entry_url(self, page, request_url, form, label):
            del label
            if not str(getattr(page, "url", "") or "").startswith(
                reference.CHATGPT_BASE_URL
            ):
                page.goto(
                    f"{reference.CHATGPT_BASE_URL}/api/auth/csrf",
                    wait_until="commit",
                    timeout=30000,
                )
            try:
                result = page.evaluate(
                    """async ({url, form}) => {
                      const body = new URLSearchParams();
                      for (const [name, value] of Object.entries(form)) body.set(name, value);
                      const response = await fetch(url, {
                        method: 'POST', credentials: 'include',
                        headers: {accept: 'application/json',
                                  'content-type': 'application/x-www-form-urlencoded'},
                        body: body.toString(),
                      });
                      let payload = {};
                      try { payload = await response.json(); } catch (_) {}
                      return {ok: response.ok, status: response.status,
                              url: String(payload.url || '')};
                    }""",
                    {"url": request_url, "form": form},
                )
            except Exception as exc:
                raise RoxyHeadedRegistrationError(
                    "roxy_headed_signin_failed"
                ) from exc
            signin_url = str((result or {}).get("url") or "").strip()
            if not bool((result or {}).get("ok")) or not signin_url:
                raise RoxyHeadedRegistrationError("roxy_headed_signin_failed")
            return signin_url

        def _set_auth_traffic_stage(self, stage: str) -> None:
            result = super()._set_auth_traffic_stage(stage)
            self._dom_observe_context(
                stage=_stage_name(stage),
                event="stage_change",
            )
            try:
                stage_callback(_stage_name(stage))
            except Exception:
                pass
            return result

        def _close_browser(self, context, browser) -> None:
            recorder = getattr(self, "_dom_recorder", None) or dom_recorder
            if recorder is not None and context is not None:
                try:
                    pages = list(getattr(context, "pages", []) or [])
                    open_pages = [
                        candidate
                        for candidate in pages
                        if not _page_is_closed(candidate)
                        and _page_is_openai_first_party(candidate)
                    ]
                    active_page = getattr(self, "_dom_active_page", None)
                    if active_page in open_pages:
                        open_pages = [
                            candidate
                            for candidate in open_pages
                            if candidate is not active_page
                        ] + [active_page]
                    if open_pages:
                        recorder.set_final_source(open_pages[-1])
                    recorder.observe_pages(
                        open_pages,
                        stage="cleanup",
                        event="browser_cleanup",
                        force=True,
                    )
                except Exception:
                    pass
            if browser is getattr(self, "_roxy_connected_browser", None):
                clean = _teardown_reference_low_traffic(self, context)
                if not clean:
                    self.log(
                        "[RoxyHeaded] 低流量过滤清理未完全确认："
                        "reason=roxy_headed_filter_cleanup_failed"
                    )
                # This is a CDP attachment to a Roxy-owned browser. Do not
                # call Browser.close(): it sends Browser.close to the remote
                # Chromium and can turn a successful registration into a
                # cleanup failure. Exiting sync_playwright() releases the
                # local transport after interception state is removed.
                self._roxy_connected_browser = None
                self._roxy_connected_context = None
                return None
            return super()._close_browser(context, browser)

    return RoxyHeadedWorker


def _session_info_from_headed_result(result: object) -> dict:
    """Convert the reference worker result to the host Session projection."""

    payload = result if isinstance(result, dict) else {}
    raw_json = str(payload.get("session_json") or "{}").strip()
    try:
        session_info = json.loads(raw_json)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RoxyHeadedRegistrationError(
            "roxy_headed_session_missing"
        ) from exc
    if not isinstance(session_info, dict):
        raise RoxyHeadedRegistrationError("roxy_headed_session_missing")
    token = str(
        session_info.get("accessToken")
        or payload.get("access_token")
        or ""
    ).strip()
    if not token:
        raise RoxyHeadedRegistrationError("roxy_headed_session_missing")
    session_info["accessToken"] = token
    return session_info


def run_roxy_headed_login(
    *,
    account: dict,
    opened: RoxyOpenResult,
    driver,
    saved_openai_password: str = "",
    mfa_totp_secret: str = "",
    otp_only: bool = False,
    stop_check=None,
    stage_callback=None,
    defer_email_otp_context: bool = False,
    mailbox_access: bool = True,
    low_traffic_enabled: bool = True,
    task_country: str = "US",
    allow_any_proxy_country: bool = False,
) -> dict:
    """Run only the pinned headed login state machine in an open Roxy Profile.

    The caller owns the Roxy lease and Selenium driver.  This adapter attaches
    Playwright to ``browser.contexts[0]`` via CDP, executes the reference
    password/email-OTP/authenticator-MFA state machine, returns an in-memory
    ``/api/auth/session`` projection, and disconnects without closing Roxy.
    No registration persistence, MFA enrollment, Codex or plan work is run.
    """

    # This public adapter is also called directly by the manual-window and
    # low-traffic Roxy paths.  Do not rely on those callers to have already
    # applied the neutral auth facade: a committed password+TOTP account must
    # be mailbox-free even when this function is entered on its own.
    try:
        from core.auth_factors import load_chatgpt_auth_factors, resolve_login_policy

        direct_policy = resolve_login_policy(account or {})
        mailbox_access = direct_policy.mailbox_access
        if direct_policy.password_totp:
            direct_factors = load_chatgpt_auth_factors(account or {})
            saved_openai_password = direct_factors.password
            mfa_totp_secret = direct_factors.totp_secret
            otp_only = False
            mailbox_access = False
            defer_email_otp_context = True
    except Exception:
        # Factor-loading errors retain the historical caller error path.  A
        # failed read must never be treated as proof of password+TOTP.
        pass

    target_email = str((account or {}).get("email") or "").strip().lower()
    if not target_email:
        raise RoxyHeadedRegistrationError("roxy_headed_email_invalid")
    if opened is None or driver is None:
        raise RoxyHeadedRegistrationError("roxy_headed_cdp_unavailable")

    try:
        from core.roxy_dom_failure_diagnostic import get_recorder

        dom_recorder = get_recorder(driver)
    except Exception:
        dom_recorder = None
    try:
        from core.roxy_otp_observer import ensure_observer

        otp_observer = ensure_observer(driver, task_kind="registration")
    except Exception:
        otp_observer = None

    def headed_stage(value: str) -> None:
        if callable(stage_callback):
            stage_callback(value)
        if dom_recorder is not None:
            try:
                _observe_headed_pages(
                    stage=str(value or "login"),
                    event="stage_change",
                )
            except Exception:
                pass

    reference = _load_reference_module()
    stop_event = _StopEvent(stop_check)
    before_fingerprint = _selenium_fingerprint_projection(driver)
    geo = dict(getattr(opened, "task_proxy_geo", {}) or {})
    from core.operation_country import maintenance_country
    expected_country = "" if allow_any_proxy_country else maintenance_country(task_country)
    worker_type = _roxy_worker_class(
        reference,
        expected_country=expected_country,
        opened=opened,
        before_fingerprint=before_fingerprint,
        stage_callback=headed_stage,
        # Reapply Roxy/Selenium's existing single-property webdriver mask to
        # Playwright-created pages; no headed-Chrome fingerprint emulation is
        # installed.
        automation_mask_enabled=True,
        login_only=True,
        low_traffic_enabled=low_traffic_enabled,
        dom_recorder=dom_recorder,
        otp_observer=otp_observer,
    )

    def log_reference(message: str) -> None:
        safe = _safe_log_text(message)
        if safe:
            logger.info("[RoxyHeaded] %s", safe)

    password = "" if otp_only else str(saved_openai_password or "")
    secret = str(mfa_totp_secret or "").strip()
    if not mailbox_access:
        defer_email_otp_context = True
    try:
        mail_account = reference.MailAccount(
            email=target_email,
            password="",
            client_id="",
            refresh_token="",
            raw=target_email,
            account_type="unknown",
            mailbox_email=target_email,
            pickup_url="",
            mfa_totp_secret=secret,
        )
        worker = worker_type(
            mail_account,
            False,
            reference.ProxyConfig(
                local_proxy="",
                dynamic_proxy=str(
                    getattr(opened, "task_proxy_upstream_url", "")
                    or getattr(opened, "task_proxy_url", "")
                    or ""
                ),
                chain_url="",
            ),
            log_reference,
            otp_reader_factory=(
                _current_provider_otp_reader_class(reference, stop_check)
                if mailbox_access
                else _MailboxAccessDeniedOtpReader
            ),
            mfa_totp_secret=secret,
            # This is an existing-account login adapter.  Enrollment belongs
            # to the dedicated 2FA service and must never run here.
            enable_mfa_enrollment=False,
            stop_event=stop_event,
        )
        worker._dom_recorder = dom_recorder
    except Exception as exc:
        raise RoxyHeadedRegistrationError(
            "roxy_headed_worker_unavailable"
        ) from exc

    worker.fingerprint = _device_fingerprint(reference, before_fingerprint)
    worker.protocol_prefix_before_otp = False
    worker.hybrid_protocol_after_otp = False
    worker.openai_password = password
    worker.openai_password_state = "confirmed" if password else ""
    from core.login_evidence import BrowserLoginEvidence
    worker._login_evidence = BrowserLoginEvidence()
    worker.auth_persist_callback = None
    worker.browser_traffic_callback = None
    worker.browser_traffic_forward_to_account = False

    browser = None
    context = None
    page = None
    result = None
    preserved_pages: list[object] = []
    login_succeeded = False
    runtime_cleanup_done = False

    def _observe_headed_pages(
        *,
        stage: str,
        event: str,
        force: bool = False,
        result: str = "",
        source_error_type: str = "",
    ) -> None:
        """Sample the Playwright auth page(s), then fall back to Selenium.

        The Selenium handle can remain focused on a different CDP target
        after Auth0 opens a popup or the reference worker recovers a closed
        page.  Prefer every currently open Playwright page so the terminal
        snapshot describes the controls the worker actually saw.
        """
        if dom_recorder is None:
            return
        pages = []
        if context is not None:
            try:
                pages = list(getattr(context, "pages", []) or [])
            except Exception:
                pages = []
        pages = [candidate for candidate in pages if _page_is_openai_first_party(candidate)]
        if page in pages:
            pages = [candidate for candidate in pages if candidate is not page]
            pages.append(page)
        sampled = dom_recorder.observe_pages(
            pages,
            stage=stage,
            event=event,
            force=force,
            result=result,
            source_error_type=source_error_type,
        ) if pages else None
        if sampled is None and driver is not None and _page_is_openai_first_party(driver):
            dom_recorder.observe(
                driver,
                stage=stage,
                event=event,
                force=force,
                result=result,
                source_error_type=source_error_type,
            )

    def cleanup_reference_runtime() -> None:
        """Release Playwright-owned resources while its runtime is still live.

        ``sync_playwright()`` disconnects all attached objects when its context
        exits.  The CDP Fetch/Network filters must therefore be disabled before
        that exit; doing it afterwards can leave a Roxy page permanently
        paused.  The helper is idempotent because both the inner and outer
        exception paths call it.
        """

        nonlocal runtime_cleanup_done
        if runtime_cleanup_done:
            return
        runtime_cleanup_done = True
        if dom_recorder is not None:
            try:
                open_pages = []
                if context is not None:
                    open_pages = [
                        candidate
                        for candidate in list(getattr(context, "pages", []) or [])
                        if not _page_is_closed(candidate)
                        and _page_is_openai_first_party(candidate)
                    ]
                if page in open_pages:
                    open_pages = [candidate for candidate in open_pages if candidate is not page]
                    open_pages.append(page)
                if open_pages:
                    # Keep the last page as the preferred terminal source for
                    # the outer Selenium-owned finalizer after CDP disconnect.
                    dom_recorder.set_final_source(open_pages[-1])
                elif page is not None:
                    dom_recorder.set_final_source(page)
                _observe_headed_pages(
                    stage="authentication",
                    event="final_page",
                    force=True,
                )
            except Exception:
                pass
        # The reference extractor may create short-lived JSON pages.  Close
        # only pages created by this adapter after a successful login; on a
        # failure leave the auth page visible for operator takeover.  A context
        # that started empty keeps the worker page so the Roxy window never
        # ends up tab-less.
        if login_succeeded and context is not None:
            try:
                current_pages = list(getattr(context, "pages", []) or [])
                keep_pages = set(preserved_pages)
                if not keep_pages and page is not None:
                    keep_pages.add(page)
                for candidate in current_pages:
                    if candidate in keep_pages:
                        continue
                    try:
                        candidate.close()
                    except Exception:
                        pass
                for candidate in current_pages:
                    if candidate in keep_pages:
                        try:
                            candidate.bring_to_front()
                        except Exception:
                            pass
                        break
            except Exception:
                pass
        try:
            if getattr(worker, "otp_reader", None) is not None:
                worker.otp_reader.close()
        except Exception:
            pass
        try:
            worker._close_auth_static_local_session()
        except Exception:
            pass
        if context is not None and browser is not None:
            try:
                # This call must happen before sync_playwright exits so the
                # low-traffic CDP sessions can disable Fetch and detach.
                worker._close_browser(context, browser)
            except Exception:
                # Cleanup is deliberately best-effort.  The caller still owns
                # the Roxy Profile and can hand the visible page to the user.
                opened.profile_cache_discard = True

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            worker._playwright_runtime = playwright
            try:
                if stop_event.is_set():
                    raise RoxyHeadedRegistrationError(
                        "session_window_close_requested"
                    )
                worker._prepare_fingerprint_for_proxy(worker.register_proxy, "认证")
                worker._use_compact_auth_window()
                # Avoid opening a mailbox channel for the common password+TOTP
                # route.  If the page later asks for email OTP the reference
                # worker starts the same provider lazily.
                if mailbox_access and not defer_email_otp_context and not (
                    str(getattr(worker, "openai_password", "") or "").strip()
                    and str(getattr(worker, "mfa_totp_secret", "") or "").strip()
                ):
                    worker._preconnect_otp_reader()
                browser, context = worker._new_isolated_registration_browser_context(
                    playwright,
                    worker.register_proxy,
                )
                worker._dom_context = context
                # The Selenium owner has already cleared the pooled identity.
                # Do not clear cookies again here: doing so would race Selenium
                # and could erase a Session established by a concurrent Roxy tab.
                preserved_pages = list(getattr(context, "pages", []) or [])
                page = context.new_page()
                page.on('response', worker._login_evidence.observe_response)
                worker._register(page, context)
                result = worker._extract_session_info(context)
                session_info = _session_info_from_headed_result(result)
                login_succeeded = True
                logger.info(
                    "[RoxyHeaded] 现有 Profile 登录完成：mfa_secret_present=%s",
                    str(bool(secret)).lower(),
                )
                return worker._login_evidence.session(session_info)
            finally:
                cleanup_reference_runtime()
    except RoxyHeadedRegistrationError:
        raise
    except Exception as exc:
        try:
            stopped = bool(stop_check and stop_check())
        except Exception:
            stopped = False
        code = _headed_error_code(exc)
        if stopped or type(exc).__name__ == "TaskStoppedError":
            code = "session_window_close_requested"
        elif code in {
            "roxy_headed_totp_failed",
            "headed_chrome_totp_failed",
            "session_login_totp_failed",
        } or type(exc).__name__ == "MfaRequiredError" or any(
            marker in str(exc).lower() for marker in ("mfa", "totp", "authenticator")
        ):
            code = "session_login_totp_failed"
        raise RoxyHeadedRegistrationError(code) from exc
    finally:
        # Covers failures before sync_playwright() is entered and keeps the
        # cleanup idempotent if an outer caller interrupts this function.
        cleanup_reference_runtime()
        try:
            worker._playwright_runtime = None
        except Exception:
            pass


# A descriptive alias keeps the call site explicit while allowing older
# internal integrations to use the shorter helper name.
run_roxy_headed_login_on_profile = run_roxy_headed_login


def _open_roxy_profile(
    client: RoxyBrowserClient,
    *,
    proxy: str | None,
    proxy_country: str | None,
    proxy_wire_scope,
    stop_check,
) -> RoxyOpenResult:
    kwargs = {"browser_args": ROXY_HEADED_OPEN_ARGS,
              "headless": bool(_cfg.REGISTRATION_HEADLESS)}
    if proxy is not None:
        kwargs["task_proxy"] = proxy
    if proxy_country:
        kwargs["proxy_country"] = proxy_country
    if proxy_wire_scope is not None:
        kwargs["proxy_wire_scope"] = proxy_wire_scope
    if stop_check is not None:
        kwargs["stop_check"] = stop_check
    return client.open_profile(**kwargs)


def run_roxy_headed_registration(
    *,
    email: str,
    name: str = "",
    birthday: str = "",
    proxy: str | None = None,
    otp_code: str | None = None,
    batch_dir: Path | None = None,
    proxy_country: str | None = None,
    proxy_wire_scope=None,
    raw_trace_sampled: bool = False,
    raw_trace_job_id: int | None = None,
    stop_check=None,
    saved_openai_password: str = "",
    auth_persist_callback=None,
    traffic_snapshot_callback=None,
) -> dict:
    """Run headed auth in the Roxy-owned default context without fallback."""

    del name, birthday, otp_code, traffic_snapshot_callback
    # This Roxy adapter may reuse the pinned browser engine internally, but it
    # is deliberately not the headed-Chrome recovery state machine.  Ignore
    # the legacy callback at this boundary so an out-of-band caller cannot
    # create a password-only ``pending_credentials`` account shell.
    del auth_persist_callback
    from core import roxy_registration as legacy

    target_email = str(email or "").strip().lower()
    if not target_email:
        return {
            "success": False,
            "email": target_email,
            "error": "roxy_headed_email_invalid",
            "error_code": "roxy_headed_email_invalid",
        }

    client = RoxyBrowserClient()
    opened = None
    driver = None
    worker = None
    traffic_meter = None
    contract_tracer = None
    raw_trace = None
    dom_recorder = None
    reference = _load_reference_module()
    stop_event = _StopEvent(stop_check)
    traffic_enabled = bool(getattr(_cfg, "ROXY_TRAFFIC_METERING", True))
    network_usage = empty_network_usage(
        "disabled" if not traffic_enabled else "unavailable"
    )
    if traffic_enabled:
        network_usage["error_code"] = "meter_not_started"
    result = None
    result_payload = None
    auth_fields: dict[str, str] = {}
    mfa_fields: dict[str, str] = {}
    create_started = False
    create_acknowledged = False
    existing_account_detected = False
    identity_pending = False
    session_saved = False
    previous_stop_check = getattr(legacy._STOP_CHECK_CONTEXT, "callback", None)
    legacy._STOP_CHECK_CONTEXT.callback = stop_check

    def check_stop() -> None:
        if stop_check is not None:
            stop_check()

    def log_reference(message: str) -> None:
        text = _safe_log_text(message)
        if text:
            logger.info("[RoxyHeaded] %s", text)

    def persist_auth(fields: dict) -> None:
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
        auth_fields.update(clean)

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

    def set_stage(stage: str) -> None:
        legacy._set_traffic_stage(traffic_meter, stage, raw_trace)
        if dom_recorder is not None and driver is not None:
            try:
                dom_recorder.observe(
                    driver,
                    stage=str(stage or "other"),
                    event="stage_change",
                )
            except Exception:
                pass
        if contract_tracer is not None:
            try:
                contract_tracer.set_stage(stage)
            except Exception:
                pass

    try:
        if str(saved_openai_password or "").strip():
            persist_auth(
                {
                    "openai_password": str(saved_openai_password).strip(),
                    "openai_password_state": "confirmed",
                }
            )
        opened = _open_roxy_profile(
            client,
            proxy=proxy,
            proxy_country=proxy_country,
            proxy_wire_scope=proxy_wire_scope,
            stop_check=stop_check,
        )
        if not opened.debugger_address and not opened.ws_endpoint:
            raise RoxyHeadedRegistrationError("roxy_headed_cdp_unavailable")
        driver = legacy._build_driver(opened)
        try:
            from core.roxy_otp_observer import ensure_observer

            otp_observer = ensure_observer(driver, task_kind="registration")
        except Exception:
            otp_observer = None
        try:
            from core.roxy_dom_failure_diagnostic import create_recorder

            dom_recorder = create_recorder(
                driver,
                task_kind="registration",
            )
            dom_recorder.observe(
                driver,
                stage="opening",
                event="browser_ready",
                force=True,
            )
        except Exception:
            dom_recorder = None
        driver.set_page_load_timeout(int(_cfg.ROXY_SELENIUM_TIMEOUT))
        if bool(getattr(opened, "pooled", False)):
            try:
                legacy._reset_pooled_profile_identity(driver)
            except legacy.RoxyIdentityResetError:
                opened.profile_cache_discard = True
                raise
        before_fingerprint = _selenium_fingerprint_projection(driver)

        try:
            traffic_meter = RoxyTrafficMeter(
                driver,
                debugger_address=opened.debugger_address,
                enabled=traffic_enabled,
            )
            started = traffic_meter.start()
            logger.info(
                "[Roxy流量] HTTP 流量计量%s",
                "已启动" if started else "不可用，注册继续",
            )
        except Exception:
            traffic_meter = None
            network_usage = empty_network_usage("unavailable")
            network_usage["error_code"] = "meter_start_failed"
            logger.warning("[Roxy流量] HTTP 流量计量启动失败，注册继续")

        if raw_trace_sampled:
            try:
                from core.roxy_raw_network_trace import RoxyRawNetworkTracer

                raw_trace = RoxyRawNetworkTracer(
                    debugger_address=opened.debugger_address,
                    job_id=raw_trace_job_id,
                    enabled=True,
                )
                if raw_trace.start():
                    logger.info(
                        "[RoxyRawTrace] 原始网络采样已启动：trace_id=%s",
                        raw_trace.trace_id,
                    )
                else:
                    logger.warning(
                        "[RoxyRawTrace] 原始网络采样不可用，注册继续："
                        "reason=roxy_raw_trace_start_failed"
                    )
            except Exception:
                raw_trace = None
                logger.warning(
                    "[RoxyRawTrace] 原始网络采样启动异常，注册继续："
                    "reason=roxy_raw_trace_start_failed"
                )

        if bool(getattr(_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", False)):
            try:
                contract_tracer = RoxyChatGPTContractTracer(
                    driver,
                    debugger_address=opened.debugger_address,
                    task_kind="registration",
                )
                contract_tracer.start()
            except Exception:
                contract_tracer = None
                logger.warning(
                    "[RoxyTrace] 注册脱敏契约追踪启动失败，注册继续："
                    "reason=trace_start_unexpected"
                )

        expected_country = str(
            proxy_country
            or dict(getattr(opened, "task_proxy_geo", {}) or {}).get("country")
            or dict(getattr(opened, "task_proxy_geo", {}) or {}).get("country_code")
            or ""
        ).strip().upper()
        worker_type = _roxy_worker_class(
            reference,
            expected_country=expected_country,
            opened=opened,
            before_fingerprint=before_fingerprint,
            stage_callback=set_stage,
            automation_mask_enabled=legacy._browser_actions_enabled(),
            dom_recorder=dom_recorder,
            otp_observer=otp_observer,
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
            mfa_totp_secret="",
        )
        otp_reader = _current_provider_otp_reader_class(reference, stop_check)
        worker = worker_type(
            account,
            False,
            reference.ProxyConfig(
                local_proxy="",
                dynamic_proxy=str(
                    getattr(opened, "task_proxy_upstream_url", "")
                    or getattr(opened, "task_proxy_url", "")
                    or ""
                ),
                chain_url="",
            ),
            log_reference,
            otp_reader_factory=otp_reader,
            mfa_persist_callback=persist_mfa,
            enable_mfa_enrollment=bool(
                getattr(_twofa_cfg, "ENABLE_2FA", False)
            ),
            stop_event=stop_event,
        )
        worker._dom_recorder = dom_recorder
        worker.fingerprint = _device_fingerprint(reference, before_fingerprint)
        worker.protocol_prefix_before_otp = False
        worker.hybrid_protocol_after_otp = False
        worker.openai_password = str(saved_openai_password or "")
        if worker.openai_password:
            worker.openai_password_state = "confirmed"
        worker.auth_persist_callback = persist_auth
        worker.browser_traffic_callback = lambda _delta: None
        worker.browser_traffic_forward_to_account = False

        logger.info(
            "[RoxyHeaded] 注册开始：engine=headed_chrome profile=active"
        )
        result_payload = worker.run()
        after_fingerprint = _selenium_fingerprint_projection(driver)
        if not _fingerprint_projection_matches(
            before_fingerprint,
            after_fingerprint,
        ):
            opened.profile_cache_discard = True
            raise RoxyHeadedRegistrationError(
                "roxy_headed_fingerprint_changed"
            )
        worker.fingerprint = _device_fingerprint(
            reference,
            after_fingerprint,
        )
        create_started = bool(
            getattr(worker, "_user_register_seen", False)
            or getattr(worker, "_account_create_confirmed", False)
        )
        create_acknowledged = bool(
            getattr(worker, "_account_create_confirmed", False)
        )
        route = str(getattr(worker, "auth_route", "") or "")
        identity_pending = route in {"pending_email_otp", "new_password_signup"}
        existing_account_detected = route in {
            "existing_password_login",
            "existing_email_otp_login",
        }
        if not isinstance(result_payload, dict):
            raise RoxyHeadedRegistrationError("headed_chrome_session_missing")
        result_payload.update(auth_fields)
        result_payload.update(mfa_fields)
        access_token = str(result_payload.get("access_token") or "").strip()
        if not access_token:
            raise RoxyHeadedRegistrationError("headed_chrome_session_missing")
        try:
            session_info = json.loads(
                str(result_payload.get("session_json") or "{}")
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RoxyHeadedRegistrationError(
                "headed_chrome_session_missing"
            ) from exc
        if not isinstance(session_info, dict):
            raise RoxyHeadedRegistrationError("headed_chrome_session_missing")
        _session_identity(target_email, session_info, access_token)
        create_acknowledged = True
        identity_pending = False
        mark_registration_account_created(target_email)
        if contract_tracer is not None:
            contract_tracer.observe_session_info(
                session_info,
                source="registration_session",
            )

        snapshot = {}
        try:
            # Capture through Selenium after Playwright disconnects so the
            # persisted browser profile is the actual Roxy projection (which
            # may be Windows or macOS), never headed_chrome's synthetic
            # Windows profile representation.
            snapshot = legacy.capture_driver_snapshot(
                driver,
                email=target_email,
                session_info=session_info,
            )
            save_chatgpt_session_snapshot(snapshot)
            session_saved = True
            logger.info("[RoxyHeaded][Session] ChatGPT Web Session 已保存")
        except ChatGPTSessionStoreError as exc:
            logger.warning(
                "[RoxyHeaded][Session] 会话保存失败，不影响注册结果：reason=%s",
                exc.error_code,
            )
        check_stop()

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "ENABLE_CODEX_AUTO=False，跳过 Codex",
        }
        try:
            from config import codex as _codex_cfg

            if bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False)):
                from core.roxy_codex_oauth import run_roxy_codex_oauth

                set_stage("codex_oauth")
                check_stop()
                logger.info(
                    "[RoxyHeaded][Codex] 复用当前 Roxy 窗口执行 Codex 授权"
                )
                codex_result = run_roxy_codex_oauth(
                    target_email,
                    reuse_existing_profile=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    force=True,
                    clear_existing_state=True,
                )
            else:
                logger.info(
                    "[RoxyHeaded][Codex] ENABLE_CODEX_AUTO=False，跳过 Codex OAuth"
                )
        except Exception:
            codex_result = {
                "status": "failed",
                "ok": False,
                "message": "codex_oauth_failed",
            }

        set_stage("other")
        network_usage = legacy._stop_traffic_meter(traffic_meter, network_usage)
        traffic_meter = None
        from core.proxy_sid import mask_proxy_url

        password = str(
            result_payload.get("openai_password")
            or auth_fields.get("openai_password")
            or saved_openai_password
            or ""
        )
        totp_secret = str(
            result_payload.get("mfa_totp_secret")
            or mfa_fields.get("mfa_totp_secret")
            or ""
        ) or None
        registration_path = str(
            result_payload.get("auth_route")
            or auth_fields.get("auth_route")
            or "headed_chrome"
        )
        account_id = save_account_data(
            email=target_email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(target_email),
            proxy_used=(
                str(getattr(opened, "proxy_safe_label", "") or "")
                or mask_proxy_url(proxy)
                or None
            ),
            batch_dir=batch_dir,
            registration_plan_route_hint=(
                registration_plan_route_hint_from_opened(
                    opened,
                    proxy_wire_scope=proxy_wire_scope,
                )
                if proxy_wire_scope is not None
                else registration_plan_route_hint_from_opened(opened)
            ),
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "device_id": snapshot.get("device_id") if session_saved else None,
                "browser_profile": snapshot.get("browser_profile") if session_saved else None,
                "roxybrowser": {
                    "profile_id": opened.profile_id,
                    "open_result": opened.raw,
                },
                "registration_driver": "roxy",
                "registration_engine": "headed_chrome",
                "registration_state": "complete",
                "registration_password": password,
                "registration_path": registration_path,
                "mfa_recovery_code": str(
                    result_payload.get("mfa_recovery_code")
                    or mfa_fields.get("mfa_recovery_code")
                    or ""
                ),
                "mfa_enrollment_state": mfa_fields.get('mfa_enrollment_state'),
                "mfa_enrolled_at": mfa_fields.get('mfa_enrolled_at'),
                "codex": codex_result,
            },
        )
        from core.totp_confirmation import persist_registration_evidence
        persist_registration_evidence(account_id, target_email, totp_secret,
                                      getattr(worker, '_totp_activation_secret', None),
                                      error_code=getattr(worker, '_totp_error_code', None))
        if session_saved:
            try:
                bind_chatgpt_session_account(target_email, account_id)
            except Exception:
                logger.warning(
                    "[RoxyHeaded][Session] 会话关联失败：reason=session_bind_failed"
                )
        codex_ok = bool(
            codex_result.get("ok") or codex_result.get("status") == "skipped"
        )
        result = {
            "success": codex_ok,
            "email": target_email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "registration_path": registration_path,
            "codex": codex_result,
            "error": None if codex_ok else "codex_oauth_incomplete",
        }
        logger.info(
            "[RoxyHeaded] 注册结束：result=%s account_id=%s",
            "success" if codex_ok else "partial",
            account_id,
        )
        return result
    except Exception as exc:
        try:
            from core.registration_service import StopRequested
        except Exception:
            StopRequested = ()
        if StopRequested and isinstance(exc, StopRequested):
            raise
        error_code = _headed_error_code(exc)
        dom_error_code = (
            error_code
            if error_code.startswith(("registration_", "roxy_headed_"))
            else "registration_failed"
        )
        if dom_recorder is not None and error_code != "session_window_close_requested":
            try:
                from core.roxy_dom_failure_diagnostic import finalize_recorder

                finalize_recorder(
                    dom_recorder,
                    driver,
                    terminal_status="failed",
                    error_code=dom_error_code,
                    source_error_type=type(exc).__name__,
                )
            except Exception:
                pass
        if proxy_wire_scope is not None and error_code.startswith(
            "proxy_wire_meter_"
        ):
            proxy_wire_scope.record_failure(error_code)
        network_usage = legacy._stop_traffic_meter(traffic_meter, network_usage)
        traffic_meter = None
        if worker is not None:
            create_started = create_started or bool(
                getattr(worker, "_user_register_seen", False)
                or getattr(worker, "_account_create_confirmed", False)
            )
            create_acknowledged = create_acknowledged or bool(
                getattr(worker, "_account_create_confirmed", False)
            )
            route = str(getattr(worker, "auth_route", "") or "")
            identity_pending = route in {
                "pending_email_otp",
                "new_password_signup",
            }
            existing_account_detected = route in {
                "existing_password_login",
                "existing_email_otp_login",
            }
        identity_mismatch = error_code == "registration_session_identity_mismatch"
        if identity_mismatch and opened is not None:
            opened.profile_cache_discard = True
        mark_registration_failed(
            target_email,
            create_started=create_started,
            create_acknowledged=create_acknowledged and not identity_mismatch,
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
            if identity_mismatch:
                status = (
                    "quarantined"
                    if resolve_email_source(target_email) == "icloud_hme"
                    else "failed"
                )
            release_email(
                target_email,
                status=status,
                note=f"roxy_headed_failed:{error_code}",
            )
        except Exception:
            logger.warning(
                "[RoxyHeaded] 邮箱释放失败：reason=email_release_failed"
            )
        logger.warning(
            "[RoxyHeaded] 注册失败：error_code=%s",
            error_code,
        )
        result = {
            "success": False,
            "email": target_email,
            "error": error_code,
            "error_code": error_code,
        }
        return result
    finally:
        if contract_tracer is not None:
            try:
                contract_tracer.stop()
            except Exception:
                logger.warning(
                    "[RoxyTrace] 注册脱敏契约追踪停止失败："
                    "reason=trace_stop_unexpected"
                )
        if traffic_meter is not None:
            network_usage = legacy._stop_traffic_meter(
                traffic_meter,
                network_usage,
            )
        network_usage = legacy._attach_profile_cache_context(
            network_usage,
            opened,
        )
        if proxy_wire_scope is not None:
            try:
                proxy_wire_scope.attach_browser_http(network_usage)
                network_usage = proxy_wire_scope.checkpoint()
            except Exception:
                logger.warning(
                    "[ProxyWire] 浏览器诊断合并失败："
                    "reason=proxy_wire_meter_snapshot_failed"
                )
                network_usage = proxy_wire_scope.snapshot()
        if result is not None:
            result["network_usage"] = network_usage
        if raw_trace is not None and driver and not legacy._effective_keep_browser_open():
            try:
                raw_trace.begin_browser_shutdown()
            except Exception:
                pass
        if driver and not legacy._effective_keep_browser_open():
            legacy._quit_driver_for_shutdown(driver)
        if raw_trace is not None:
            try:
                raw_usage = network_usage
                if proxy_wire_scope is not None:
                    try:
                        raw_usage = proxy_wire_scope.snapshot()
                    except Exception:
                        pass
                summary = raw_trace.stop(network_usage=raw_usage)
                logger.info(
                    "[RoxyRawTrace] 原始网络采样已封存：trace_id=%s state=%s errors=%s",
                    raw_trace.trace_id,
                    summary.get("state", "unknown"),
                    len(summary.get("error_codes") or []),
                )
            except Exception:
                logger.warning(
                    "[RoxyRawTrace] 原始网络采样收尾失败："
                    "reason=roxy_raw_trace_stop_failed"
                )
        if not legacy._effective_keep_browser_open():
            try:
                client.cleanup_profile(opened)
            except Exception:
                logger.warning(
                    "[Roxy] Profile 清理未确认：reason=profile_cleanup_failed"
                )
        if previous_stop_check is None:
            try:
                delattr(legacy._STOP_CHECK_CONTEXT, "callback")
            except AttributeError:
                pass
        else:
            legacy._STOP_CHECK_CONTEXT.callback = previous_stop_check


__all__ = [
    "ROXY_HEADED_OPEN_ARGS",
    "RoxyHeadedRegistrationError",
    "run_roxy_headed_login",
    "run_roxy_headed_login_on_profile",
    "run_roxy_headed_registration",
]
