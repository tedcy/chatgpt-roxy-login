"""Small, stateless browser-login primitives shared by Roxy workflows.

The surrounding registration, refresh and OAuth modules deliberately keep
their own state machines.  This module only owns mechanics that must behave the
same everywhere: password control selection, TOTP secret validation/window
handling, and filling a visible authenticator challenge.
"""

from __future__ import annotations

import base64
import logging
import re
import time as _time
from collections.abc import Callable


logger = logging.getLogger(__name__)


def _record_dom_event(
    driver,
    *,
    stage: str,
    event: str,
    result: str = "",
    source_error_type: str = "",
    force: bool = False,
) -> None:
    """Best-effort bridge to the failure-only DOM recorder.

    The primitive is also used by lightweight test drivers and by callers that
    do not opt into diagnostics.  Keep the import lazy and swallow all
    recorder errors so browser authentication semantics never change.
    """
    try:
        from core.roxy_dom_failure_diagnostic import record_dom_event

        record_dom_event(
            driver,
            stage=stage,
            event=event,
            result=result,
            source_error_type=source_error_type,
            force=force,
        )
    except Exception:
        return


class LoginPrimitiveError(RuntimeError):
    """Fixed-code error raised by a primitive without page or secret details."""

    def __init__(self, error_code: str):
        self.error_code = str(error_code or "login_primitive_failed")
        super().__init__(self.error_code)


class TotpWindowInterrupted(LoginPrimitiveError):
    def __init__(self):
        super().__init__("session_window_close_requested")


class TotpSecretError(LoginPrimitiveError):
    pass


_PASSWORD_CONTROL_SCRIPT = r"""
const mode = String(arguments[0] || 'refresh');
const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
  && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
  && !el.disabled && !el.readOnly;
const passwordInputs = [...document.querySelectorAll('input')].filter(visible);
const input = passwordInputs.find(el => {
  const type = String(el.getAttribute('type') || '').toLowerCase();
  const name = String(el.getAttribute('name') || '').toLowerCase();
  const id = String(el.getAttribute('id') || '').toLowerCase();
  const autocomplete = String(el.getAttribute('autocomplete') || '').toLowerCase();
  const currentPassword = autocomplete.split(/\s+/).includes('current-password')
    || autocomplete.includes('current-password');
  const newPassword = autocomplete.split(/\s+/).includes('new-password')
    || autocomplete.includes('new-password');
  if (mode !== 'registration' && newPassword && !currentPassword) return false;
  if (type === 'password' || name.includes('password') || id.includes('password')) return true;
  return mode !== 'registration' && currentPassword;
});
if (!input) return {ok:false, reason:'missing_password_input'};
const scope = input.closest('form') || document;
const ir = input.getBoundingClientRect();
const candidates = [...scope.querySelectorAll('button,input[type="submit"],[role="button"]')]
  .filter(el => visible(el) && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true')
  .map((el, idx) => {
    const r = el.getBoundingClientRect();
    const below = r.top >= ir.bottom - 10;
    const attrs = [el.id, el.name, el.type, el.value,
      el.getAttribute('aria-label'), el.getAttribute('data-testid'),
      el.textContent].filter(Boolean).join(' ').toLowerCase();
    const semantic = /continue|log[ -]?in|sign[ -]?in|next|submit|继续|登录|登入|下一步/.test(attrs);
    return {el, idx, below, dist:Math.max(0, r.top - ir.bottom),
      score:(el.type === 'submit' ? 0 : 1) + (semantic ? 0 : 2)
        + (below ? 0 : 4) + (below ? Math.max(0, r.top - ir.bottom) / 10000 : 0)};
  });
if (mode === 'registration') {
  candidates.splice(0, candidates.length, ...candidates
    .filter(item => item.below)
    .sort((a,b) => a.dist - b.dist || a.idx - b.idx));
} else {
  candidates.sort((a,b) => a.score - b.score || a.idx - b.idx);
}
if (!candidates.length) return {ok:false, reason:'missing_password_submit'};
input.scrollIntoView({block:'center'});
return {ok:true, input, button:candidates[0].el};
"""

_PASSWORD_CONTROL_WAIT_TIMEOUT = 5.0
_PASSWORD_CONTROL_POLL_INTERVAL = 0.2
# Auth0 keeps the password route mounted while the submit request and the
# following MFA/session transition settle.  Callers must not switch to the
# passwordless fallback during this bounded window.
PASSWORD_SUBMIT_TRANSITION_TIMEOUT = 8.0


def submit_login_password(
    driver,
    password: str,
    *,
    human_type: Callable,
    human_click: Callable,
    label: str,
    strategy: str = "refresh",
    delay: Callable | None = None,
    control_wait_timeout: float = _PASSWORD_CONTROL_WAIT_TIMEOUT,
    control_poll_interval: float = _PASSWORD_CONTROL_POLL_INTERVAL,
) -> bool:
    """Find and submit a current-password form without exposing the password.

    Auth0/ChatGPT renders the password input and submit control in separate
    React commits.  A single DOM probe can therefore run in the small window
    between the password route appearing and the controls becoming usable.
    Retry only the *control discovery* phase for a short bounded interval;
    once typing or clicking starts we never replay the action, avoiding a
    duplicate password submission if the browser has already navigated.
    """
    if not password:
        return False

    try:
        wait_timeout = max(0.0, float(control_wait_timeout))
    except (TypeError, ValueError, OverflowError):
        wait_timeout = _PASSWORD_CONTROL_WAIT_TIMEOUT
    try:
        poll_interval = max(0.01, float(control_poll_interval))
    except (TypeError, ValueError, OverflowError):
        poll_interval = _PASSWORD_CONTROL_POLL_INTERVAL
    deadline = _time.monotonic() + wait_timeout
    attempts = 0
    last_reason = "missing_password_input"

    while True:
        attempts += 1
        _record_dom_event(
            driver,
            stage="password",
            event="password_control_probe",
        )
        try:
            result = driver.execute_script(
                _PASSWORD_CONTROL_SCRIPT,
                str(strategy or "refresh"),
            ) or {}
            if isinstance(result, dict) and result.get("ok"):
                input_element = result.get("input")
                button_element = result.get("button")
                if input_element is None or button_element is None:
                    last_reason = "password_controls_incomplete"
                else:
                    # Do not retry after this point: the input/click helpers
                    # may have already dispatched a real browser action before
                    # an underlying WebDriver call reports an error.
                    _record_dom_event(
                        driver,
                        stage="password",
                        event="password_action_start",
                    )
                    try:
                        human_type(driver, input_element, password, clear=True)
                    except Exception as exc:
                        _record_dom_event(
                            driver,
                            stage="password",
                            event="password_input_exception",
                            result="failed",
                            source_error_type=type(exc).__name__,
                            force=True,
                        )
                        _record_dom_event(
                            driver,
                            stage="password",
                            event="password_action_exception",
                            result="failed",
                            source_error_type=type(exc).__name__,
                            force=True,
                        )
                        logger.debug(
                            "密码控件操作失败: phase=input error=%s",
                            type(exc).__name__,
                        )
                        return False
                    try:
                        if delay is not None:
                            delay("form", minimum=0.4, maximum=1.4)
                        human_click(driver, button_element, label=label)
                    except Exception as exc:
                        _record_dom_event(
                            driver,
                            stage="password",
                            event="password_click_exception",
                            result="failed",
                            source_error_type=type(exc).__name__,
                            force=True,
                        )
                        _record_dom_event(
                            driver,
                            stage="password",
                            event="password_action_exception",
                            result="failed",
                            source_error_type=type(exc).__name__,
                            force=True,
                        )
                        logger.debug(
                            "密码控件操作失败: phase=action error=%s",
                            type(exc).__name__,
                        )
                        return False
                    _record_dom_event(
                        driver,
                        stage="password",
                        event="password_action_success",
                        result="success",
                        force=True,
                    )
                    _record_dom_event(
                        driver,
                        stage="password",
                        event="password_transition_waiting",
                        result="waiting",
                    )
                    return True
            elif isinstance(result, dict):
                last_reason = str(result.get("reason") or "password_controls_unavailable")[:80]
            else:
                last_reason = "password_controls_invalid"
        except Exception as exc:
            # Discovery failures are normally transient while the document is
            # being replaced.  Keep the reason fixed/safe and retry only until
            # the bounded discovery deadline.
            last_reason = type(exc).__name__[:80] or "password_control_probe_failed"

        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        _time.sleep(min(poll_interval, remaining))

    logger.debug(
        "密码控件等待超时: attempts=%s reason=%s",
        attempts,
        last_reason,
    )
    _record_dom_event(
        driver,
        stage="password",
        event="password_control_probe",
        result="failed",
        source_error_type=last_reason if last_reason and last_reason[0].isupper() else "",
        force=True,
    )
    return False


def normalise_totp_secret(value: object) -> str:
    """Validate and normalize the committed Base32 TOTP secret."""
    secret = re.sub(r"\s+", "", str(value or "")).upper()
    if not secret:
        raise TotpSecretError("session_login_totp_secret_missing")
    if not re.fullmatch(r"[A-Z2-7]+=*", secret):
        raise TotpSecretError("session_login_totp_secret_invalid")
    padding = "=" * ((8 - len(secret) % 8) % 8)
    try:
        decoded = base64.b32decode(secret + padding, casefold=True)
        if not decoded:
            raise ValueError("empty")
    except Exception as exc:
        raise TotpSecretError("session_login_totp_secret_invalid") from exc
    return secret


def wait_for_totp_window(
    stop_event,
    *,
    clock=_time,
    period: float = 30.0,
    safety_margin: float = 2.0,
) -> None:
    """Wait out the unsafe tail of a TOTP period, honoring cancellation."""
    remaining = float(period) - (float(clock.time()) % float(period))
    if remaining >= float(safety_margin):
        return
    delay = max(0.05, remaining + 0.25)
    if stop_event is not None:
        if stop_event.wait(delay):
            raise TotpWindowInterrupted()
    else:
        clock.sleep(delay)


def fill_totp_inputs(
    driver,
    code: str,
    *,
    visible: Callable,
    human_type: Callable,
) -> list[object]:
    """Fill one or six visible authenticator inputs and return them."""
    from selenium.webdriver.common.by import By

    inputs: list[object] = []
    selectors = (
        'input[autocomplete="one-time-code"]',
        'input[inputmode="numeric"]',
        'input[type="number"]',
        'input[type="tel"]',
        'input[name*="code" i]',
        'input[id*="code" i]',
        'input:not([type="hidden"]):not([type="email"]):not([type="password"])',
    )
    for selector in selectors:
        try:
            for item in driver.find_elements(By.CSS_SELECTOR, selector):
                if item not in inputs and visible(item):
                    inputs.append(item)
        except Exception:
            continue
    if not inputs:
        raise LoginPrimitiveError("session_login_totp_failed")
    try:
        if len(inputs) >= 6:
            for item, character in zip(inputs[:6], str(code)):
                human_type(driver, item, character, clear=True)
        else:
            human_type(driver, inputs[0], str(code), clear=True)
    except Exception as exc:
        raise LoginPrimitiveError("session_login_totp_failed") from exc
    return inputs


__all__ = [
    "LoginPrimitiveError",
    "TotpSecretError",
    "TotpWindowInterrupted",
    "fill_totp_inputs",
    "normalise_totp_secret",
    "PASSWORD_SUBMIT_TRANSITION_TIMEOUT",
    "submit_login_password",
    "wait_for_totp_window",
]
