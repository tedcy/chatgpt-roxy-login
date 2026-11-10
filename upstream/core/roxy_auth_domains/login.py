"""Shared existing-account Roxy authentication login implementation.

Loaded into :mod:`core.chatgpt_session_refresh` globals to preserve public
names and test seams while keeping login mechanics outside refresh business
logic.
"""
from __future__ import annotations
from textwrap import dedent

_SOURCE = dedent(r'''
import re
import unicodedata

def _record_login_dom_event(driver, *, stage: str, event: str, result: str = "", force: bool = False) -> None:
    try:
        from core.roxy_dom_failure_diagnostic import record_dom_event

        record_dom_event(
            driver,
            stage=stage,
            event=event,
            result=result,
            force=force,
        )
    except Exception:
        pass

def _registration_password(account: dict) -> str:
    """Compatibility wrapper around the shared factor reader."""
    try:
        from core.auth_factors import load_chatgpt_auth_factors

        return load_chatgpt_auth_factors(account).password
    except Exception:
        return ""


def _read_browser_session_once(driver) -> dict | None:
    try:
        current = str(getattr(driver, "current_url", "") or "")
        host = str(urlparse(current).hostname or "").lower()
        if host != "chatgpt.com" and not host.endswith(".chatgpt.com"):
            return None
        result = driver.execute_async_script(
            """
            const done = arguments[0];
            fetch('/api/auth/session', {credentials:'include', cache:'no-store'})
              .then(r => r.json())
              .then(j => done({ok:true,data:j}))
              .catch(() => done({ok:false}));
            """
        ) or {}
        data = result.get("data") if result.get("ok") else None
        return data if isinstance(data, dict) and data.get("accessToken") else None
    except Exception:
        return None


def _find_session_in_windows(driver) -> dict | None:
    # Session polling must not use Selenium window switching: doing so changes
    # the visible tab and can make a manually controlled Roxy window flicker.
    # Prefer a read-only CDP request against an existing ChatGPT target.
    try:
        capabilities = getattr(driver, "capabilities", {}) or {}
        chrome_options = (
            capabilities.get("goog:chromeOptions")
            or capabilities.get("chromeOptions")
            or {}
        )
        debugger_address = str(chrome_options.get("debuggerAddress") or "").strip()
    except Exception:
        debugger_address = ""
    if debugger_address:
        try:
            from core.headed_auth_watch import read_chatgpt_session

            current_handle = getattr(driver, "current_window_handle", None)
            found = read_chatgpt_session(
                debugger_address,
                preferred_target_id=current_handle,
            )
            if found:
                return found
        except Exception:
            pass
    # CDP may be unavailable for a remote or non-Chrome driver. Inspect only
    # Selenium's current tab as a safe fallback; never enumerate by switching.
    return _read_browser_session_once(driver)


def _browser_session_business_ready(driver, account: dict, session_info: dict) -> bool:
    """Confirm that a published browser Session can reach accounts/check.

    NextAuth's ``/api/auth/session`` endpoint can briefly expose a stale
    access token after its cookie has been rejected by ChatGPT's business
    APIs.  Treat that token as a login *hint*, never as a successful restore.
    The probe returns only a boolean and intentionally keeps response details
    out of logs and task payloads.
    """

    try:
        token = normalize_token((session_info or {}).get("accessToken") or "")
        if not token:
            return False
        validate_session_identity(account, session_info, token)
        result = check_account_plan_in_driver(driver, token, timeout=12)
        return bool(isinstance(result, dict) and result.get("ok"))
    except Exception:
        return False


def _is_password_reset_page(driver) -> bool:
    """Return whether the official Add Password flow reached its new-password
    document.

    The route is hosted by Auth0 and therefore cannot publish ChatGPT's normal
    ``/api/auth/session`` payload yet.  Restrict detection to the exact
    reset-password path plus two visible password inputs so an unrelated
    ``/reset`` link cannot short-circuit ordinary Session refresh.
    """

    try:
        current = str(getattr(driver, "current_url", "") or "")
        parsed = urlparse(current)
        if parsed.scheme != "https" or parsed.hostname not in {
            "auth.openai.com",
            "chatgpt.com",
        }:
            return False
        if not str(parsed.path or "").lower().startswith("/reset-password/"):
            return False
        state = driver.execute_script(
            r"""
            const visible = el => !!el &&
              !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
              getComputedStyle(el).visibility !== 'hidden' &&
              getComputedStyle(el).display !== 'none' && !el.disabled && !el.readOnly;
            return [...document.querySelectorAll('input')].filter(visible)
              .filter(el => String(el.type || '').toLowerCase() === 'password' ||
                /password/i.test(String(el.name || '') + ' ' + String(el.id || '') +
                  ' ' + String(el.autocomplete || ''))).length >= 2;
            """
        )
        return bool(state)
    except Exception:
        return False


def _password_reset_operation_session(account: dict) -> dict:
    """Build an internal identity marker for a reset-password document.

    ``ensure_roxy_session_on_driver`` still performs its normal identity
    validation.  The marker only supplies the already-known account token and
    identity while the official Auth0 page owns the password mutation; it is
    never serialized or returned by an API.
    """

    token = normalize_token(account.get("access_token") or "")
    if not token:
        raise ChatGPTSessionRefreshError(
            "session_refresh_empty",
            "密码页面已打开但本地账号身份不完整",
        )
    return {
        "accessToken": token,
        "user": {
            "email": str(account.get("email") or "").strip().lower(),
            "id": str(account.get("user_id") or "").strip(),
        },
        "account": {"id": str(account.get("account_id") or "").strip()},
        "_turb_password_reset_ready": True,
    }


def _submit_saved_password(driver, password: str) -> bool:
    from core.roxy_browser_kernel import submit_login_password
    from core.roxy_registration import _human_click, _human_type_text

    return submit_login_password(
        driver,
        password,
        human_type=_human_type_text,
        human_click=_human_click,
        label="session_refresh_password",
    )


def _submit_email_otp_once(driver, email: str, after_ts: float) -> bool:
    from core.email_provider import prepare_otp_context, wait_for_otp
    from core.roxy_codex_oauth import (
        _click_if_present,
        _install_email_otp_validate_hook,
        _wait_after_email_otp_submit,
        _wait_for_email_otp_input,
        _wait_for_fresh_email_otp,
    )
    from core.roxy_browser_kernel import click_resend_email_otp
    from core.roxy_otp_observer import ensure_observer, mark_mailbox, mark_submit
    from core.roxy_registration import (
        _clear_otp_inputs,
        _ensure_email_otp_value_before_submit,
        _is_email_verification_page,
        _type_otp,
    )

    from core.otp_retry_policy import (
        OtpResendResult,
        OtpRetryConfig,
        OtpSubmitResult,
        run_email_otp_retry,
    )

    current_after_ts = float(after_ts or time.time())
    try:
        observer = ensure_observer(
            driver,
            task_kind="session_refresh",
            account_id=getattr(driver, "_turb_roxy_account_id", None),
        )
        if observer is not None:
            observer.install_browser_hooks(driver)
    except Exception:
        observer = None

    def resend_once() -> str:
        """Re-baseline and click one explicit resend action in this browser."""

        baseline: list[float] = []

        def before_send() -> None:
            prepare_otp_context(email)
            baseline.append(time.time())

        try:
            action = click_resend_email_otp(
                driver,
                timeout=25,
                strict=True,
                before_send=before_send,
            )
        except Exception:
            return ""
        status = str((action or {}).get("status") or "").strip().lower()
        if status in {"logged_in", "profile"}:
            return "terminal"
        return "resent" if status == "resent" and bool(baseline) else ""

    last_wait_error: list[BaseException] = []

    def wait_code(after: float, used_codes: set[str]) -> str:
        if observer is not None:
            try:
                observer.drain_browser_hooks(driver, stage="email_otp")
            except Exception:
                pass
        mark_mailbox(driver, "waiting", stage="email_otp")
        try:
            code = _wait_for_fresh_email_otp(
                wait_for_otp,
                email,
                after_ts=after,
                used_codes=used_codes,
                timeout=90,
            )
        except Exception as exc:
            last_wait_error[:] = [exc]
            provider_code = str(getattr(exc, "error_code", "") or "").strip().lower()
            mark_mailbox(
                driver,
                "timeout" if provider_code == "otp_timeout" else "error",
                stage="email_otp",
            )
            raise
        mark_mailbox(driver, "received", stage="email_otp")
        return str(code or "")

    def submit_code(code: str, _attempt: int) -> OtpSubmitResult:
        _wait_for_email_otp_input(driver, timeout=30)
        _record_login_dom_event(
            driver,
            stage="email_otp",
            event="email_otp_input",
            force=True,
        )
        # The server reports terminal account state through the structured
        # email-otp/validate response.  Install the same hook as Codex before
        # the submit so a deactivated/deleted/banned account cannot fall
        # through to the generic manual-login timeout.
        _install_email_otp_validate_hook(driver)
        _clear_otp_inputs(driver)
        _type_otp(driver, code)
        _ensure_email_otp_value_before_submit(driver, code)
        _record_login_dom_event(
            driver,
            stage="email_otp",
            event="email_otp_submit",
            result="waiting",
            force=True,
        )
        clicked = _click_if_present(
            driver,
            [
                "button[type='submit']",
                "//button[contains(., 'Continue')]",
                "//button[contains(., '继续')]",
                "//button[contains(., 'Verify')]",
                "//button[contains(., '验证')]",
            ],
            timeout=8,
        )
        if not clicked:
            mark_submit(driver, "failed", stage="email_otp")
            _record_login_dom_event(
                driver,
                stage="email_otp",
                event="email_otp_submit",
                result="failed",
                force=True,
            )
            return OtpSubmitResult("failed", reason="email_otp_submit_failed")
        outcome = _wait_after_email_otp_submit(
            driver,
            timeout=45,
            accepted_predicate=_is_authenticator_mfa_page,
        )
        mark_submit(
            driver,
            "accepted" if outcome == "accepted" else "invalid" if outcome == "invalid" else "unconfirmed",
            stage="email_otp",
        )
        _record_login_dom_event(
            driver,
            stage="email_otp",
            event="email_otp_transition",
            result="success" if outcome == "accepted" else "failed",
            force=True,
        )
        if str(outcome).startswith("deactivated:"):
            raw_code = str(outcome).split(":", 1)[1]
            error_code = detect_account_unusable_text(raw_code) or "account_deactivated"
            raise AccountUnusableError(
                f"账号已废（{error_code}）",
                error_code=error_code,
            )
        if outcome == "accepted":
            return OtpSubmitResult("accepted")
        if outcome == "invalid":
            return OtpSubmitResult("invalid", reason="otp_invalid")
        return OtpSubmitResult("unconfirmed", reason="otp_submission_unconfirmed")

    def trigger_resend(_attempt: int, _reason: str) -> OtpResendResult:
        status = resend_once()
        if status == "terminal":
            return OtpResendResult("terminal", reason="session_published")
        if status == "resent":
            return OtpResendResult("sent", after_ts=time.time())
        return OtpResendResult("failed", reason="otp_resend_unavailable")

    def handle_unretryable(exc: BaseException, _reason: str):
        # Preserve the historical helper contract: provider errors that are
        # not timeout errors are raised to the caller for its existing mapping.
        raise exc

    result = run_email_otp_retry(
        config=OtpRetryConfig(
            max_attempts=2,
            max_resends=1,
            retry_wait_reasons=frozenset({"otp_timeout"}),
            retry_submit_reasons=frozenset({"otp_invalid"}),
            deduplicate_codes=True,
            retry_unconfirmed=True,
        ),
        initial_after_ts=current_after_ts,
        wait_code=wait_code,
        submit_code=submit_code,
        trigger_resend=trigger_resend,
        classify_error=lambda exc: str(
            getattr(exc, "error_code", "") or "otp_unavailable"
        ).strip().lower()
        or "otp_unavailable",
        stop_check=lambda: None,
        can_resend=lambda _attempt, _reason: _is_email_verification_page(driver),
        handle_error=handle_unretryable,
    )
    if result.status == "accepted":
        return True
    if result.status == "terminal":
        return True
    if last_wait_error and result.reason == "otp_timeout":
        # The old implementation re-raised the provider timeout when its
        # single resend was unavailable or the second poll timed out.
        raise last_wait_error[0]
    return False


_VISIBLE_ACCOUNT_UNUSABLE_SOURCES = frozenset({
    "role_alert",
    "aria_live_assertive",
    "data_error",
    "testid_error",
    "page_heading",
})


def _detect_visible_account_unusable_state(url: str, state: object) -> str:
    """Return a terminal account code only from trusted, explicit error UI."""
    try:
        host = (urlparse(str(url or "")).hostname or "").lower()
    except Exception:
        return ""
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in (
        "chatgpt.com",
        "auth.openai.com",
    )):
        return ""
    if not isinstance(state, dict):
        return ""
    # Authentication error pages can render the canonical machine code in a
    # plain ``div``/``p`` instead of an alert node.  The browser probe returns
    # only the matched fixed token, never the surrounding page text.
    machine_codes = state.get("machine_codes")
    if isinstance(machine_codes, list):
        for raw_code in machine_codes[:3]:
            error_code = str(raw_code or "").strip().lower()
            if error_code in {
                "account_deactivated",
                "account_deleted",
                "account_banned",
            }:
                return error_code
    nodes = state.get("nodes")
    if not isinstance(nodes, list):
        return ""
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if str(node.get("source") or "") not in _VISIBLE_ACCOUNT_UNUSABLE_SOURCES:
            continue
        text = " ".join(str(node.get("text") or "").split())
        if not text or len(text) > 600:
            continue
        error_code = detect_account_unusable_text(text)
        if error_code:
            return error_code
    return ""


def _read_visible_account_unusable_code(driver) -> str:
    """Inspect small visible error nodes without reading or logging page body."""
    try:
        url = str(driver.current_url or "")
    except Exception:
        return ""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in (
        "chatgpt.com",
        "auth.openai.com",
    )):
        return ""
    try:
        state = driver.execute_script(
            r"""
            const visible = el => !!el
              && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
              && getComputedStyle(el).visibility !== 'hidden'
              && getComputedStyle(el).display !== 'none';
            const nodes = [];
            const seen = new Set();
            const add = (el, source) => {
              if (!visible(el) || seen.has(el)) return;
              const text = String(el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
              const rect = el.getBoundingClientRect();
              if (!text || text.length > 600 || rect.height > 260
                  || el === document.body || el === document.documentElement) return;
              seen.add(el);
              nodes.push({source, text});
            };
            const selectors = [
              ['role_alert', '[role="alert"]'],
              ['aria_live_assertive', '[aria-live="assertive"]'],
              ['data_error', '[data-error="true"], [data-state="error"]'],
              ['testid_error', '[data-testid*="error" i]'],
              ['page_heading', 'main h1, main h2'],
            ];
            for (const [source, selector] of selectors) {
              for (const el of document.querySelectorAll(selector)) add(el, source);
            }
            const machineCodes = [];
            try {
              const root = document.body || document.documentElement;
              const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
              let textNode = null;
              let visited = 0;
              while ((textNode = walker.nextNode()) && visited < 2048) {
                visited += 1;
                const parent = textNode.parentElement;
                if (!parent || !visible(parent) ||
                    ['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE'].includes(parent.tagName)) continue;
                const text = String(textNode.nodeValue || '').trim().toLowerCase();
                if (!text || text.length > 240) continue;
                const match = text.match(
                  /(?:^|[^a-z0-9_])(account_deactivated|account_deleted|account_banned)(?:$|[^a-z0-9_])/
                );
                if (match && !machineCodes.includes(match[1])) machineCodes.push(match[1]);
                if (machineCodes.length >= 3) break;
              }
            } catch (e) {}
            return {nodes, machine_codes: machineCodes};
            """
        ) or {}
    except Exception:
        return ""
    error_code = _detect_visible_account_unusable_state(url, state)
    if error_code:
        logger.warning(
            "[SessionRefresh][Roxy] 登录页识别账号已废：reason=%s",
            error_code,
        )
    return error_code


def _raise_if_visible_account_unusable(driver) -> None:
    error_code = _read_visible_account_unusable_code(driver)
    if error_code:
        raise AccountUnusableError(
            f"账号已废（{error_code}）",
            error_code=error_code,
        )


def _authenticator_mfa_page_state(driver) -> dict:
    """Return a small, credential-free projection of an authenticator MFA page.

    OpenAI uses the same ``/mfa-challenge`` route for email and authenticator
    challenges.  A route or a generic numeric input alone is therefore not
    sufficient: the authenticator marker must be visible and an email marker
    must not win.  The projection intentionally contains only booleans and a
    bounded location string; page text is never written to a log.
    """

    try:
        url = str(getattr(driver, "current_url", "") or "")
    except Exception:
        url = ""
    try:
        parsed = urlparse(url)
        host = str(parsed.hostname or "").lower()
        path = str(parsed.path or "").lower()
        query = str(parsed.query or "").lower()
    except Exception:
        host, path, query = "", "", ""
    if not (
        host == "auth.openai.com"
        or host.endswith(".auth.openai.com")
        or host == "chatgpt.com"
        or host.endswith(".chatgpt.com")
    ):
        return {"route": False, "candidate": False, "authenticator": False}
    route = "/mfa-challenge" in path or "/mfa/" in path or "mfa-challenge" in query
    if not route:
        return {"route": False, "candidate": False, "authenticator": False}

    state = {}
    try:
        state = driver.execute_script(
            r"""
            return (() => {
              const visible = el => !!el &&
                !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
                getComputedStyle(el).visibility !== 'hidden' &&
                getComputedStyle(el).display !== 'none' &&
                !el.disabled && !el.readOnly;
              const text = String(document.body?.innerText || document.body?.textContent || '')
                .replace(/\s+/g, ' ').slice(0, 2400);
              const inputs = [...document.querySelectorAll('input')]
                .filter(visible)
                .map(el => ({
                  type: String(el.getAttribute('type') || '').toLowerCase(),
                  name: String(el.getAttribute('name') || '').toLowerCase(),
                  id: String(el.getAttribute('id') || '').toLowerCase(),
                  autocomplete: String(el.getAttribute('autocomplete') || '').toLowerCase(),
                  inputmode: String(el.getAttribute('inputmode') || '').toLowerCase(),
                  aria: String(el.getAttribute('aria-label') || '').toLowerCase(),
                  placeholder: String(el.getAttribute('placeholder') || '').toLowerCase(),
                }));
              return {title: String(document.title || '').slice(0, 400), text, inputs};
            })();
            """
        ) or {}
    except Exception:
        state = {}
    if not isinstance(state, dict):
        state = {}
    text = " ".join(
        str(value or "")
        for value in (state.get("title"), state.get("text"))
    ).lower()
    inputs = state.get("inputs") if isinstance(state.get("inputs"), list) else []
    input_text = " ".join(
        " ".join(str(item.get(key) or "") for key in (
            "type", "name", "id", "autocomplete", "inputmode", "aria", "placeholder",
        ))
        for item in inputs
        if isinstance(item, dict)
    ).lower()
    auth_markers = (
        "authenticator app",
        "authentication app",
        "verification app",
        "authenticator code",
        "one-time password",
        "time-based one-time",
        "totp",
        "认证器",
        "身份验证器",
        "身份驗證器",
        "验证器应用",
        "驗證器應用",
        "認証アプリ",
        "ワンタイム認証",
        "認証コードアプリ",
        # Vietnamese authenticator challenge.  Keep these app-specific: the
        # generic phrase "mã xác minh" is also used by email OTP messages.
        "ứng dụng xác thực",
        "trình xác thực",
        "mã từ ứng dụng xác thực",
        "xác thực hai bước",
    )
    email_markers = (
        "check your email",
        "email code",
        "code sent to your email",
        "email verification",
        "邮箱验证码",
        "邮箱验证",
        "電子郵件驗證碼",
        "メールを確認",
        "メールに送信",
        "メールで受け取ったコード",
        "kiểm tra email",
        "mã được gửi đến email",
        "mã xác minh qua email",
    )
    def has_marker(value, markers):
        raw = str(value or "").casefold()
        folded = unicodedata.normalize("NFD", raw)
        folded = "".join(
            char for char in folded if not unicodedata.combining(char)
        ).replace("đ", "d")
        for marker in markers:
            candidate = str(marker or "").casefold()
            candidate_folded = unicodedata.normalize("NFD", candidate)
            candidate_folded = "".join(
                char for char in candidate_folded
                if not unicodedata.combining(char)
            ).replace("đ", "d")
            if candidate in raw or candidate_folded in folded:
                return True
        return False

    explicit_auth_marker = has_marker(text, auth_markers)
    auth_marker = explicit_auth_marker or has_marker(
        input_text, ("authenticator", "totp")
    ) or "factor=totp" in query
    email_marker = (
        has_marker(text, email_markers)
        or has_marker(input_text, ("email", "e-mail"))
        or "factor=email" in query
    )
    # A page explicitly naming an authenticator is authoritative when an
    # implementation also leaves a generic "email" attribute on a hidden
    # control.  A pure email challenge is never treated as TOTP.
    if email_marker and not explicit_auth_marker and not has_marker(
        input_text, ("authenticator", "totp")
    ):
        auth_marker = False
    code_inputs = 0
    generic_inputs = 0
    for item in inputs:
        if not isinstance(item, dict):
            continue
        attrs = " ".join(str(item.get(key) or "") for key in (
            "type", "name", "id", "autocomplete", "inputmode", "aria", "placeholder",
        )).lower()
        if any(marker in attrs for marker in ("email", "phone", "search", "password")):
            continue
        generic_inputs += 1
        if any(marker in attrs for marker in (
            "one-time", "otp", "totp", "code", "numeric", "verification", "authenticator",
        )) or str(item.get("inputmode") or "").lower() == "numeric":
            code_inputs += 1
    if auth_marker and code_inputs == 0 and 1 <= generic_inputs <= 8:
        # Some Auth0 builds render six plain text boxes with no semantic
        # attributes.  On an explicitly identified authenticator route these
        # visible controls are safe to treat as the code inputs.
        code_inputs = generic_inputs
    return {
        "route": True,
        "candidate": bool(auth_marker),
        "authenticator": bool(auth_marker and code_inputs > 0),
        "email": bool(email_marker),
        "input_count": code_inputs,
        "path": path,
    }


def _is_authenticator_mfa_page(driver) -> bool:
    return bool(_authenticator_mfa_page_state(driver).get("authenticator"))


def _totp_secret_for_login(account: dict) -> str:
    """Compatibility wrapper around the shared committed-TOTP reader."""
    from core.roxy_login_primitives import TotpSecretError
    from core.auth_factors import read_committed_totp_secret

    try:
        return read_committed_totp_secret(account)
    except TotpSecretError as exc:
        message = (
            "认证器 MFA 需要已保存的 TOTP 密钥"
            if exc.error_code == "session_login_totp_secret_missing"
            else "已保存的 TOTP 密钥格式无效"
        )
        raise ChatGPTSessionRefreshError(exc.error_code, message) from exc


def _wait_for_totp_window(stop_event: threading.Event | None) -> None:
    """Avoid submitting a code during the last two seconds of its period."""
    from core.roxy_login_primitives import TotpWindowInterrupted
    from core.roxy_browser_kernel import wait_for_totp_window

    try:
        wait_for_totp_window(stop_event, clock=time)
    except TotpWindowInterrupted as exc:
        raise ChatGPTSessionRefreshError(
            "session_window_close_requested",
            "已请求关闭 Roxy 窗口",
        ) from exc


def _authenticator_mfa_error_present(driver) -> bool:
    try:
        state = driver.execute_script(
            r"""
            return (() => {
              const visible = el => !!el &&
                !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
                getComputedStyle(el).visibility !== 'hidden' &&
                getComputedStyle(el).display !== 'none';
              const selectors = '[role="alert"], [aria-live="assertive"], [data-testid*="error" i], main p, main div';
              return [...document.querySelectorAll(selectors)].filter(visible).slice(0, 30)
                .map(el => String(el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim())
                .filter(text => text && text.length <= 400).join('\n');
            })();
            """
        )
    except Exception:
        return False
    text = str(state or "").lower()
    return bool(re.search(
        r"incorrect|invalid|expired|try again|验证码不正确|验证码无效|验证失败|驗證碼不正確|コードが正しく|無効なコード",
        text,
    ))


def _submit_authenticator_mfa_code(
    driver,
    account: dict,
    *,
    stop_event: threading.Event | None = None,
) -> dict | None:
    """Submit one authenticator code and wait for a safe post-MFA state."""

    from core.roxy_registration import (
        _human_click,
        _human_type_text,
        _visible,
    )
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    import pyotp

    secret = _totp_secret_for_login(account)
    _record_login_dom_event(
        driver,
        stage="mfa",
        event="mfa_action_start",
        force=True,
    )
    _wait_for_totp_window(stop_event)
    try:
        code = pyotp.TOTP(secret).now()
    except Exception as exc:
        raise ChatGPTSessionRefreshError(
            "session_login_totp_secret_invalid",
            "已保存的 TOTP 密钥格式无效",
        ) from exc
    if not re.fullmatch(r"\d{6}", str(code or "")):
        raise ChatGPTSessionRefreshError(
            "session_login_totp_failed",
            "认证器动态码生成失败",
        )

    try:
        from core.roxy_login_primitives import LoginPrimitiveError
        from core.roxy_browser_kernel import fill_totp_inputs

        inputs = fill_totp_inputs(
            driver,
            str(code),
            visible=_visible,
            human_type=_human_type_text,
        )
        _record_login_dom_event(
            driver,
            stage="mfa",
            event="mfa_input",
            force=True,
        )
    except LoginPrimitiveError as exc:
        raise ChatGPTSessionRefreshError(
            "session_login_totp_failed",
            "认证器 MFA 动态码填写失败",
        ) from exc

    button = None
    try:
        button = driver.execute_script(
            r"""
            return (() => {
              const visible = el => !!el &&
                !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) &&
                getComputedStyle(el).visibility !== 'hidden' &&
                getComputedStyle(el).display !== 'none' && !el.disabled &&
                el.getAttribute('aria-disabled') !== 'true';
              const semantic = /continue|verify|submit|next|继续|验证|驗證|確認|確認する|続行/i;
              return [...document.querySelectorAll('button, input[type="submit"], [role="button"]')]
                .filter(visible)
                .find(el => semantic.test(`${el.textContent || ''} ${el.value || ''} ${el.getAttribute('aria-label') || ''}`)) || null;
            })();
            """
        )
    except Exception:
        button = None
    try:
        if button is not None:
            _human_click(driver, button, label="session_login_totp")
        else:
            inputs[-1].send_keys(Keys.ENTER)
    except Exception as exc:
        _record_login_dom_event(
            driver,
            stage="mfa",
            event="mfa_action_exception",
            result="failed",
            force=True,
        )
        raise ChatGPTSessionRefreshError(
            "session_login_totp_failed",
            "认证器 MFA 动态码提交失败",
        ) from exc
    logger.info(
        "[SessionRefresh][Roxy] 认证器 MFA 已提交：secret_present=true result=pending"
    )
    _record_login_dom_event(
        driver,
        stage="mfa",
        event="mfa_transition_waiting",
        result="waiting",
        force=True,
    )

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if stop_event is not None and stop_event.is_set():
            raise ChatGPTSessionRefreshError(
                "session_window_close_requested",
                "已请求关闭 Roxy 窗口",
            )
        try:
            if hasattr(driver, "window_handles") and not list(
                getattr(driver, "window_handles", []) or []
            ):
                raise ChatGPTSessionRefreshError(
                    "roxy_window_browser_closed",
                    "Roxy 窗口已关闭",
                )
        except ChatGPTSessionRefreshError:
            raise
        except Exception:
            raise ChatGPTSessionRefreshError(
                "roxy_window_browser_closed",
                "Roxy 窗口已关闭",
            ) from None
        session_info = _find_session_in_windows(driver)
        if session_info:
            logger.info(
                "[SessionRefresh][Roxy] 认证器 MFA 结果：result=accepted"
            )
            return session_info
        state = _authenticator_mfa_page_state(driver)
        if not state.get("candidate") or state.get("email"):
            logger.info(
                "[SessionRefresh][Roxy] 认证器 MFA 结果：result=advanced"
            )
            return None
        if _authenticator_mfa_error_present(driver):
            raise ChatGPTSessionRefreshError(
                "session_login_totp_failed",
                "认证器 MFA 动态码被服务器拒绝",
            )
        time.sleep(0.5)
    raise ChatGPTSessionRefreshError(
        "session_login_totp_failed",
        "认证器 MFA 提交后页面未完成跳转",
    )


def _wait_for_visible_login(
    driver,
    account: dict,
    *,
    account_id: int,
    allow_manual_wait: bool = True,
    manual_wait_timeout: float | None = _MANUAL_LOGIN_TIMEOUT,
    on_manual_wait: Callable[[], None] | None = None,
    stop_event: threading.Event | None = None,
    otp_only: bool = False,
    strict_password: bool = False,
    defer_email_otp_context: bool = False,
    mailbox_access: bool | None = None,
    post_login_add_password: bool = False,
    allow_password_reset_page: bool = False,
) -> dict:
    from core.email_provider import prepare_otp_context
    from core.roxy_registration import (
        _click_other_account_chooser_if_present,
        _click_passwordless_signup_if_present,
        _is_email_verification_page,
        _is_login_password_page,
        _maybe_accept,
        _page_warmup,
        _safe_get,
        _submit_email_and_wait_next,
        _submit_email_step,
        _type_email_address,
    )

    email = str(account.get("email") or "").strip()
    try:
        from core.auth_factors import resolve_login_policy

        login_policy = resolve_login_policy(account)
    except Exception:
        login_policy = None
    if login_policy is not None and login_policy.password_totp:
        # Do not let a legacy caller's ``mailbox_access=True`` override the
        # account-level password+TOTP rule at this lower-level entry point.
        mailbox_access = False
    else:
        mailbox_access = login_policy.mailbox_access if login_policy is not None else True
    mailbox_access = bool(mailbox_access)
    if not mailbox_access:
        # A password+TOTP login is not allowed to fall back to a deleted or
        # unavailable mailbox.  Keep the old strict-password behaviour for
        # password-only callers while making this boundary explicit.
        strict_password = True
        defer_email_otp_context = True
    # ``turb_browser`` payment windows can explicitly request the historical
    # mailbox-OTP path.  Do not even read the private registration password in
    # that mode; ordinary Session refresh and the account-page Roxy window keep
    # their existing password-first behaviour.
    if strict_password and otp_only:
        raise ChatGPTSessionRefreshError(
            "session_login_password_invalid",
            "严格密码验证不能使用邮箱验证码模式",
        )
    password = "" if otp_only else _registration_password(account)
    if strict_password and not password:
        raise ChatGPTSessionRefreshError(
            "session_login_password_invalid",
            "严格密码验证缺少候选密码",
        )
    # Incomplete committed factors can receive an OTP even before the password
    # page. Mailbox permission is independent of candidate verification.
    otp_context_prepared = False
    if mailbox_access and not defer_email_otp_context:
        prepare_otp_context(email)
        otp_context_prepared = True
    otp_after_ts = time.time()
    login_url = "https://chatgpt.com/auth/login"
    if post_login_add_password:
        login_url += "?post_login_add_password=true"
    _safe_get(
        driver,
        login_url,
        timeout=45,
        attempts=2,
        accept_hosts=("chatgpt.com", "auth.openai.com"),
    )
    _page_warmup(driver, reason="session_refresh_login")
    _maybe_accept(driver)
    # Reuse the registration kernel's controlled-input verification and SPA
    # transition wait.  A direct type+click can race React and leave the email
    # field cleared on the same /auth/login page without ever sending OTP.
    submitted_state = _submit_email_and_wait_next(
        driver,
        email,
        attempts=1,
        refresh_retries=1,
        refresh_interval=2.0,
        allow_existing_account=True,
    )
    if strict_password and str(submitted_state or "").strip().lower() == "otp":
        from core.password_login_choice import select_password_login
        from core.roxy_registration import _human_click

        if select_password_login(driver, _is_login_password_page, _human_click, stop_event):
            submitted_state = "login_password"
    if strict_password and str(submitted_state or "").strip().lower() not in {
        "login_password",
        "password",
    } and not (mailbox_access and str(submitted_state or '').strip().lower() == 'otp'):
        # A restored cookie can publish a Session before the password form is
        # rendered.  Strict pending-password recovery must never treat that
        # residual Session as proof that the candidate was accepted.
        raise ChatGPTSessionRefreshError(
            "session_login_password_invalid",
            "严格密码验证未进入密码页面",
        )

    def _check_stop_requested() -> None:
        if stop_event is not None and stop_event.is_set():
            raise ChatGPTSessionRefreshError(
                "session_window_close_requested",
                "已请求关闭 Roxy 窗口",
            )
        if stop_event is not None and hasattr(driver, "window_handles"):
            try:
                if not list(getattr(driver, "window_handles", []) or []):
                    raise ChatGPTSessionRefreshError(
                        "roxy_window_browser_closed",
                        "Roxy 窗口已关闭",
                    )
            except ChatGPTSessionRefreshError:
                raise
            except Exception:
                raise ChatGPTSessionRefreshError(
                    "roxy_window_browser_closed",
                    "Roxy 窗口已关闭",
                ) from None

    automatic_deadline = time.time() + 40
    otp_attempted = False
    password_attempted = False
    passwordless_attempted = False
    password_submitted_at = 0.0
    strict_password_submitted = False
    strict_email_challenge = False
    strict_email_verified = False
    password_transition_mark = 0
    chooser_retries = 0
    totp_challenge_key = ""
    totp_submitted = False
    totp_candidate_started = 0.0
    while time.time() < automatic_deadline:
        _check_stop_requested()
        if allow_password_reset_page and _is_password_reset_page(driver):
            # Current Auth0 builds finish the official Password Add
            # re-authentication on /reset-password/new-password before a new
            # ChatGPT Session is published.  Maintenance callers only need a
            # validated identity marker to keep this Driver alive; the page
            # itself owns Sentinel and the eventual password request.
            return _password_reset_operation_session(account)
        strict_otp_page = bool(strict_password and _is_email_verification_page(driver))
        if strict_otp_page:
            if not mailbox_access:
                raise ChatGPTSessionRefreshError(
                    "auth_email_challenge_required",
                    "远端要求额外邮箱验证，密码与认证器登录未完成",
                )
            strict_email_challenge = True
        session_info = _find_session_in_windows(driver)
        if session_info and (not strict_password or (
            (strict_password_submitted or strict_email_verified)
            and (not strict_email_challenge or strict_email_verified)
            and not _is_login_password_page(driver)
        )):
            from core.login_evidence import AuthenticatedSession
            from urllib.parse import urlsplit
            _raise_if_visible_account_unusable(driver)
            return AuthenticatedSession(
                session_info,
                password_verified=bool(password_submitted_at) and (
                    strict_email_verified
                    or urlsplit(str(getattr(driver, 'current_url', '') or '')).hostname == 'chatgpt.com'
                ),
                email_otp_verified=strict_email_verified,
            )
        if session_info and strict_password and not strict_password_submitted:
            # Ignore a pre-existing browser Session until this invocation has
            # actually submitted the candidate password below.
            session_info = None
        _raise_if_visible_account_unusable(driver)
        mfa_state = _authenticator_mfa_page_state(driver)
        if mfa_state.get("candidate"):
            try:
                from core.roxy_dom_failure_diagnostic import record_dom_event

                record_dom_event(
                    driver,
                    stage="mfa",
                    event="mfa_detected",
                    result="waiting",
                )
            except Exception:
                pass
            challenge_key = "|".join(
                (
                    str(mfa_state.get("path") or ""),
                    str(getattr(driver, "current_url", "") or "").split("?", 1)[0],
                )
            )
            if challenge_key != totp_challenge_key:
                totp_challenge_key = challenge_key
                totp_submitted = False
                totp_candidate_started = time.monotonic()
            if mfa_state.get("authenticator"):
                if not totp_submitted:
                    totp_submitted = True
                    session_info = _submit_authenticator_mfa_code(
                        driver,
                        account,
                        stop_event=stop_event,
                    )
                    if session_info:
                        return session_info
                    # The submitted challenge may have advanced directly to
                    # an email-MFA or callback page while retaining the same
                    # route for one render tick.  Re-arm the dispatcher so the
                    # next iteration can handle that page instead of treating
                    # it as a second authenticator attempt.
                    totp_challenge_key = ""
                    totp_submitted = False
                    totp_candidate_started = 0.0
                elif _authenticator_mfa_error_present(driver):
                    raise ChatGPTSessionRefreshError(
                        "session_login_totp_failed",
                        "认证器 MFA 动态码被服务器拒绝",
                    )
                time.sleep(0.5)
                continue
            if mfa_state.get("candidate"):
                # The MFA shell can render before its input controls. Keep
                # observing that same challenge instead of clicking an
                # unrelated chooser/submit control while React hydrates.
                if (
                    totp_candidate_started
                    and time.monotonic() - totp_candidate_started >= 15.0
                ):
                    raise ChatGPTSessionRefreshError(
                        "session_login_totp_failed",
                        "认证器 MFA 输入框加载超时",
                    )
                time.sleep(0.5)
                continue
        else:
            totp_challenge_key = ""
            totp_submitted = False
            totp_candidate_started = 0.0
        if strict_otp_page or (not strict_password and _is_email_verification_page(driver)):
            if strict_password:
                strict_email_challenge = True
                logger.info(
                    "[SessionRefresh][Roxy] 继续邮箱验证，密码证据单独核验：account_id=%s",
                    account_id,
                )
            try:
                from core.roxy_dom_failure_diagnostic import record_dom_event

                record_dom_event(
                    driver,
                    stage="email_otp",
                    event="email_otp_detected",
                    result="waiting",
                )
            except Exception:
                pass
            if not otp_context_prepared:
                # Password+TOTP callers do not touch the mailbox unless the
                # browser explicitly rendered an email challenge.  Prepare a
                # fresh provider baseline only at that confirmed boundary.
                prepare_otp_context(email)
                otp_after_ts = time.time()
                otp_context_prepared = True
            if not otp_attempted:
                otp_attempted = True
                if _submit_email_otp_once(driver, email, otp_after_ts):
                    strict_email_verified = True
                    # The OTP helper confirms that the verification page was
                    # accepted, but ChatGPT can publish /api/auth/session a few
                    # seconds later.  Keep the automatic (including headless)
                    # flow alive instead of falling through to the manual-login
                    # error immediately.  The OTP wait itself may already have
                    # consumed the original automatic deadline, so grant a fresh
                    # bounded Session-publish window from this point.
                    automatic_deadline = max(
                        automatic_deadline,
                        time.time() + _SESSION_AFTER_OTP_TIMEOUT,
                    )
                    logger.info(
                        "[SessionRefresh][Roxy] 邮箱 OTP 已接受，继续等待 Session：account_id=%s",
                        account_id,
                    )
        elif _is_login_password_page(driver):
            _record_login_dom_event(
                driver,
                stage="password",
                event="password_page_detected",
                result="waiting",
            )
            if password_submitted_at:
                mark = int(max(0.0, time.monotonic() - password_submitted_at) // 2.0)
                if mark > password_transition_mark:
                    password_transition_mark = mark
                    _record_login_dom_event(
                        driver,
                        stage="password",
                        event="password_transition_waiting",
                        result="waiting",
                        force=True,
                    )
            if not password_attempted:
                password_attempted = True
                if password:
                    if strict_password and mailbox_access and not otp_context_prepared:
                        # Establish the mailbox boundary before submitting the
                        # password: its response may immediately send an extra OTP.
                        prepare_otp_context(email)
                        otp_after_ts = time.time()
                        otp_context_prepared = True
                    if _submit_saved_password(driver, password):
                        password_submitted_at = time.monotonic()
                        strict_password_submitted = bool(strict_password)
                        # Do not classify a still-mounted password route as a
                        # failed login while Auth0 is rendering the next
                        # factor.  Grant a bounded post-submit window even if
                        # the email step consumed the original deadline.
                        automatic_deadline = max(
                            automatic_deadline,
                            time.time() + PASSWORD_SUBMIT_TRANSITION_TIMEOUT + 2.0,
                        )
                        try:
                            from core.roxy_dom_failure_diagnostic import record_dom_event

                            record_dom_event(
                                driver,
                                stage="password",
                                event="password_transition_waiting",
                                result="waiting",
                                force=True,
                            )
                        except Exception:
                            pass
                    else:
                        # A changed Auth0 form can reject the password
                        # selector even though the one-time-code path is
                        # still available.  Fall through to OTP once instead
                        # of handing a recoverable page to the operator.
                        if strict_password:
                            raise ChatGPTSessionRefreshError(
                                "session_login_password_invalid",
                                "候选登录密码未提交",
                            )
                        result = _click_passwordless_signup_if_present(driver)
                        passwordless_attempted = True
                        if not result.get("ok"):
                            break
                else:
                    result = _click_passwordless_signup_if_present(driver)
                    passwordless_attempted = True
                    if not result.get("ok"):
                        break
            elif (
                password
                and not passwordless_attempted
                and password_submitted_at
                and time.monotonic() - password_submitted_at
                >= PASSWORD_SUBMIT_TRANSITION_TIMEOUT
            ):
                # Keep the existing password-first policy, but automatically
                # switch to the supported email-code path when the submitted
                # password did not advance the page.
                if strict_password:
                    raise ChatGPTSessionRefreshError(
                        "session_login_password_invalid",
                        "候选登录密码未通过验证",
                    )
                result = _click_passwordless_signup_if_present(driver)
                passwordless_attempted = True
                if not result.get("ok"):
                    if strict_password:
                        raise ChatGPTSessionRefreshError(
                            "session_login_password_invalid",
                            "候选登录密码未推进登录页面",
                        )
                    logger.info(
                        "[SessionRefresh][Roxy] 保存密码未推进登录且无邮箱验证码入口：account_id=%s",
                        account_id,
                    )
        elif chooser_retries < 2:
            # The remembered-account chooser can appear again after the email
            # form is submitted.  Only the explicit "another account" action
            # is allowed; never click a stored account card.
            try:
                clicked = _click_other_account_chooser_if_present(driver)
            except Exception:
                clicked = False
            if clicked:
                chooser_retries += 1
                try:
                    _type_email_address(driver, email, timeout=8)
                    _submit_email_step(driver)
                    continue
                except Exception:
                    # Let the bounded loop decide whether this is a genuine
                    # CAPTCHA/unknown page and hand it to the operator.
                    pass
        time.sleep(0.6)

    if password_submitted_at and _is_login_password_page(driver):
        _record_login_dom_event(
            driver,
            stage="password",
            event="password_transition_timeout",
            result="failed",
            force=True,
        )

    # An automatic bulk task cannot hand an unknown login page to the
    # operator.  Fail explicitly instead of waiting five minutes; the window
    # may still be visible when ROXY_OPEN_HEADLESS is disabled.
    if not allow_manual_wait:
        logger.warning(
            "[SessionRefresh][Roxy] 自动登录未完成：account_id=%s "
            "reason=session_login_interaction_required",
            account_id,
        )
        raise ChatGPTSessionRefreshError(
            "session_login_interaction_required",
            "Roxy 刷新未能自动完成登录；如需人工处理，请关闭无头启动后单独刷新",
        )

    # Any CAPTCHA, unknown password flow, external IdP or delayed redirect is
    # deliberately handed to the visible browser instead of being guessed.
    if on_manual_wait is not None:
        on_manual_wait()
    else:
        db.mark_account_session_refresh_waiting(account_id)
    logger.info(
        "[SessionRefresh][Roxy] 等待用户在可见窗口完成登录：account_id=%s timeout=%s",
        account_id,
        "unlimited" if manual_wait_timeout is None else manual_wait_timeout,
    )
    deadline = (
        None
        if manual_wait_timeout is None
        else time.time() + max(0.0, float(manual_wait_timeout))
    )
    while deadline is None or time.time() < deadline:
        _check_stop_requested()
        session_info = _find_session_in_windows(driver)
        if session_info:
            return session_info
        _raise_if_visible_account_unusable(driver)
        time.sleep(1.0)
    raise ChatGPTSessionRefreshError(
        "session_login_timeout",
        "等待 Roxy 登录超时，请重试",
    )


def _cleanup_refresh_profile(client, opened) -> None:
    if not opened:
        return
    if bool(getattr(opened, "pooled", False)):
        client.cleanup_profile(opened)
        return
    try:
        client.close_profile(opened.profile_id)
    except Exception:
        pass
    try:
        from config import roxybrowser as roxy_cfg

        if (
            bool(getattr(opened, "created_by_run", False))
            and bool(getattr(roxy_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
            and bool(getattr(roxy_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True))
        ):
            client.delete_profile(opened.profile_id)
    except Exception:
        pass
''')

def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
