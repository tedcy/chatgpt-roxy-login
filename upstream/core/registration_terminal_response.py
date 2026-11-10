"""Extract credential-free evidence from registration API responses."""
import re
import threading
from urllib.parse import urlsplit


_ENDPOINTS = {
    ("GET", "/api/accounts/authorize"): "authorize",
    ("GET", "/api/accounts/client_auth_session_dump"): "client_auth_session_dump",
    ("POST", "/api/accounts/user/register"): "user_register",
    ("GET", "/api/accounts/email-otp/send"): "email_otp_send",
    ("POST", "/api/accounts/email-otp/send"): "email_otp_send",
    ("POST", "/api/accounts/passwordless/send-otp"): "email_otp_send",
    ("POST", "/api/accounts/email-otp/validate"): "email_otp_validate",
    ("POST", "/api/accounts/create_account"): "create_account",
}
_SAFE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,79}$", re.I)
_ACCOUNT_TERMINAL_CODES = frozenset(
    {"account_deactivated", "account_deleted", "account_banned"}
)
_ENDPOINT_ORDER = (
    "authorize",
    "user_register",
    "email_otp_send",
    "email_otp_validate",
    "create_account",
    "client_auth_session_dump",
)
_THREAD_STATE = threading.local()


def reset_registration_response_diagnostics():
    _THREAD_STATE.responses = {
        name: {"responses": 0} for name in _ENDPOINT_ORDER
    }


def registration_response_diagnostics():
    states = getattr(_THREAD_STATE, "responses", None)
    if not isinstance(states, dict):
        reset_registration_response_diagnostics()
        states = _THREAD_STATE.responses
    return {name: dict(states.get(name) or {"responses": 0}) for name in _ENDPOINT_ORDER}


def _record_response_evidence(evidence):
    if not isinstance(evidence, dict):
        return
    endpoint = str(evidence.get("endpoint") or "")
    if endpoint not in _ENDPOINT_ORDER:
        return
    states = getattr(_THREAD_STATE, "responses", None)
    if not isinstance(states, dict):
        reset_registration_response_diagnostics()
        states = _THREAD_STATE.responses
    state = states[endpoint]
    state["responses"] = int(state.get("responses") or 0) + 1
    # A successful retry must not inherit the previous response's error fields.
    for key in ("status", "result", "error_code", "error_type"):
        state.pop(key, None)
        if key in evidence:
            state[key] = evidence[key]
    history = state.setdefault("history", [])
    history.append({k: evidence[k] for k in ("status", "result", "error_code", "error_type") if k in evidence})
    del history[:-4]


def registration_endpoint(url, method="POST"):
    try:
        parsed = urlsplit(str(url or ""))
        fixed_method = str(method or "").upper()
        if str(parsed.hostname or "").lower() != "auth.openai.com":
            return None
        return _ENDPOINTS.get((fixed_method, str(parsed.path or "")))
    except Exception:
        return None


def _safe_token(value):
    fixed = str(value or "").strip().lower()
    return fixed if _SAFE_TOKEN.fullmatch(fixed) else ""


def registration_response_evidence(response):
    """Return only endpoint/status/error classifications, never response text."""
    try:
        request = getattr(response, "request", None)
        method = str(getattr(request, "method", "") or "").upper()
        url = str(
            getattr(response, "url", "") or getattr(request, "url", "") or ""
        )
        endpoint = registration_endpoint(url, method)
        if endpoint is None:
            return None
        status = int(getattr(response, "status", 0) or 0)
        headers = {
            str(k).lower(): str(v).lower()
            for k, v in dict(getattr(response, "headers", {}) or {}).items()
        }
        challenged = headers.get("cf-mitigated") == "challenge"
        if challenged:
            result = "challenge"
        elif 200 <= status < 300:
            result = "accepted"
        elif 300 <= status < 400:
            result = "redirect"
        elif status:
            result = "rejected"
        else:
            result = "unknown"
        evidence = {"endpoint": endpoint, "status": status, "result": result}
        payload = {}
        if (
            not challenged
            and status >= 400
            and "application/json" in headers.get("content-type", "")
        ):
            try:
                candidate = response.json()
                payload = candidate if isinstance(candidate, dict) else {}
            except Exception:
                payload = {}
        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        error_code = _safe_token(error.get("code"))
        error_type = _safe_token(error.get("type"))
        if error_code:
            evidence["error_code"] = error_code
        if error_type:
            evidence["error_type"] = error_type
        terminal_code = ""
        if (
            endpoint == "email_otp_validate"
            and status in {401, 403}
            and error_code in _ACCOUNT_TERMINAL_CODES
        ):
            terminal_code = error_code
        elif (not challenged and endpoint != "client_auth_session_dump"
              and error_code in {"invalid_state", "invalid_session", "session_expired"}):
            terminal_code = "headed_chrome_auth_session_expired"
        elif endpoint == "create_account" and 400 <= status < 500 and not challenged:
            if error_code == "user_already_exists":
                # The canonical browser state machine owns one login recovery.
                evidence["result"] = "login_required"
            else:
                terminal_code = ("registration_disallowed" if error_code in {
                    "registration_disallowed", "registration_disallowed_too_young",
                } else "headed_chrome_account_create_rejected")
        if terminal_code:
            evidence["terminal_code"] = terminal_code
        return evidence
    except Exception:
        return None


def observe_registration_response(response, *, is_current=None):
    evidence = registration_response_evidence(response)
    # Reading a body pumps browser events: a newer attempt can arrive while
    # response.json() is pending. Recheck ownership before recording it.
    if is_current is not None and not is_current(response.request):
        return None
    _record_response_evidence(evidence)
    return evidence


def terminal_registration_code(response):
    evidence = observe_registration_response(response)
    return str((evidence or {}).get("terminal_code") or "") or None


def terminal_otp_code(response):
    # This is the observer hook used by the locked headed-registration adapter.
    # Keep the legacy name while allowing any explicit registration-terminal
    # response (including create_account) to stop the state machine promptly.
    return terminal_registration_code(response)
