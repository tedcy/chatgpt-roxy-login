"""Structural diagnostics only: never log exception messages, URLs or locals."""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
from pathlib import Path
import re
import time
import threading


_EXCEPTIONS = ContextVar("registration_diagnostic_exceptions", default=None)


@contextmanager
def exception_scope():
    """Keep exception identities alive only for this registration attempt."""
    scope = {"seen": {}, "lock": threading.RLock(), "active": True}
    token = _EXCEPTIONS.set(scope)
    try:
        yield
    finally:
        with scope["lock"]:
            scope["active"] = False
            scope["seen"].clear()
        _EXCEPTIONS.reset(token)


def diagnostic_run(method):
    @wraps(method)
    def observed(*args, **kwargs):
        with exception_scope():
            return method(*args, **kwargs)
    return observed


def _exception_chain(exc):
    seen = set()
    while isinstance(exc, BaseException) and id(exc) not in seen and len(seen) < 4:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ if exc.__cause__ is not None else (
            None if exc.__suppress_context__ else exc.__context__)


class DiagnosticMessage(str):
    """Internal structural event; never construct from external text or payloads."""


def log_text(value, redact):
    # A string prefix is NOT trusted. Only emit() produces this typed event.
    return str(value) if isinstance(value, DiagnosticMessage) else redact(value)


def _identifier(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.<>-]{0,95}", value) else "unknown"


def exception_summary(exc):
    """Bounded causes and code locations, without message/args/source/locals."""
    result, seen = [], set()
    while isinstance(exc, BaseException) and id(exc) not in seen and len(result) < 4:
        seen.add(id(exc))
        entry = {"type": _identifier(type(exc).__name__)}
        for name in ("errno", "winerror", "status_code"):
            value = getattr(exc, name, None)
            if type(value) is int and 0 <= value <= 65535:
                entry[name] = value
        # Recognize fixed network signals, never copy arbitrary message text.
        message = str(exc)
        markers = ("ERR_PROXY_CONNECTION_FAILED", "ERR_TUNNEL_CONNECTION_FAILED",
                   "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_TIMED_OUT",
                   "ERR_NAME_NOT_RESOLVED", "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT")
        entry["network_signals"] = [marker for marker in markers if marker in message]
        frames, tb = [], exc.__traceback__
        while tb is not None:
            code = tb.tb_frame.f_code
            frames.append({"file": _identifier(Path(code.co_filename).name),
                           "function": _identifier(code.co_name), "line": tb.tb_lineno})
            tb = tb.tb_next
        entry["frames"] = frames[-8:]
        result.append(entry)
        exc = exc.__cause__ if exc.__cause__ is not None else (
            None if exc.__suppress_context__ else exc.__context__)
    return result


def emit(log, event, **fields):
    """Callers pass fixed labels, numeric values and structural summaries only."""
    try:
        log(DiagnosticMessage("[Diagnostic] " + json.dumps({"event": event, **fields}, ensure_ascii=True, separators=(",", ":"))))
    except Exception:
        # Diagnostics must not change the business or cancellation outcome.
        pass


def failure(log, phase, exc):
    try:
        scope = _EXCEPTIONS.get()
        if scope is None:
            emit(log, "exception", phase=phase, causes=exception_summary(exc))
            return
        chain = list(_exception_chain(exc))
        causes, references = [], []
        with scope["lock"]:
            if not scope["active"]:
                emit(log, "exception", phase=phase, causes=exception_summary(exc))
                return
            known = scope["seen"]
            summaries = None
            for index, cause in enumerate(chain):
                prior = known.get(id(cause))
                if prior is not None:
                    references.append({"index": index, "exception_id": prior[1],
                                       "type": _identifier(type(cause).__name__)})
                    continue
                if summaries is None:
                    summaries = exception_summary(exc)
                reference = len(known) + 1
                known[id(cause)] = (cause, reference)
                causes.append({**summaries[index], "exception_id": reference})
        fields = {"phase": phase, "cause_refs": references}
        if causes:
            emit(log, "exception", **fields, causes=causes)
        else:
            emit(log, "exception_repeat", **fields)
    except Exception:
        emit(log, "exception", phase=phase, summary_unavailable=True)


@contextmanager
def step(log, phase, runtime=None):
    started = time.monotonic()
    previous = None
    if runtime is not None:
        with runtime.lock:
            previous = runtime.diagnostic_phase
            runtime.diagnostic_phase = (phase, started)
    emit(log, "step", phase=phase, result="started")
    outcome = "completed"
    try:
        yield
    except BaseException as exc:
        outcome = "raised"
        failure(log, phase, exc)
        raise
    finally:
        emit(log, "step", phase=phase, result=outcome,
             elapsed_ms=int((time.monotonic() - started) * 1000))
        if runtime is not None:
            with runtime.lock:
                runtime.diagnostic_phase = previous


class _ObservedClose:
    def __init__(self, wrapped, log, phase, runtime):
        self._wrapped, self._log, self._phase, self._runtime = wrapped, log, phase, runtime

    def __bool__(self):
        return bool(self._wrapped)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def close(self, *args, **kwargs):
        with step(self._log, self._phase, self._runtime):
            return self._wrapped.close(*args, **kwargs)


def observe_close(value, log, phase, runtime=None):
    return None if value is None else _ObservedClose(value, log, phase, runtime)


def worker_step(phase):
    def decorate(method):
        @wraps(method)
        def observed(self, *args, **kwargs):
            with step(getattr(self, "log", None), phase, getattr(self, "_registration_runtime", None)):
                return method(self, *args, **kwargs)
        return observed
    return decorate


def page_block(log, phase, state, expected, *, password_transition, begin, remaining, elapsed_ms, budget_ms,
               samples=0, snapshot_ms=0, slowest_snapshot_ms=0, matching_pair=False,
               snapshot_timeouts=0, reason=None):
    key = tuple(state.get(k) for k in ("host", "path", "epoch", "stage"))
    changed = [name for i, name in enumerate(("host", "path", "document_epoch"))
               if expected is not None and state.get("stage") not in {"unavailable", "snapshot_timeout"}
               and key[i] != expected[i]]
    if reason is not None:
        pass  # The guard owns the decision, including cancellable read timeouts.
    elif password_transition:
        reason = "password_transition_active"
    elif not begin and expected is not None and changed:
        reason = "document_identity_changed"
    elif state.get("stage") == "unavailable":
        reason = "snapshot_unavailable"
    elif not (state.get("stage") == "email_otp" or (
            state.get("stage") == "transitioning" and state.get("path") in {
                "/email-verification", "/email-otp", "/email-code", "/verify-email"})):
        reason = "unexpected_page_stage"
    elif remaining <= 0:
        reason = "readiness_deadline"
    else:
        reason = "unstable_page"
    known_stages = {"email_otp", "password", "transitioning", "profile", "challenge", "other", "unavailable", "snapshot_timeout", "session_expired"}
    emit(log, "auth_page_blocked", phase=phase, reason=reason,
         page=state.get("stage") if state.get("stage") in known_stages else "unknown",
         changed=changed, baseline_present=expected is not None, begin=bool(begin),
         elapsed_ms=int(elapsed_ms), budget_ms=int(budget_ms), samples=samples,
         snapshot_ms=snapshot_ms, slowest_snapshot_ms=slowest_snapshot_ms,
         matching_pair=matching_pair, snapshot_timeouts=snapshot_timeouts, result="blocked")


def response(log, response):
    """Read only endpoint identity and HTTP status; do not consume response bodies."""
    try:
        from core.registration_terminal_response import registration_endpoint
        request = response.request
        endpoint = registration_endpoint(response.url, request.method)
        status = response.status
        if endpoint and type(status) is int and 100 <= status <= 599:
            emit(log, "auth_http_response", endpoint=endpoint, status=status)
    except Exception:
        pass


def request(log, request, *, failed=False):
    try:
        from core.registration_terminal_response import registration_endpoint
        endpoint = registration_endpoint(request.url, request.method)
        if not endpoint:
            return
        fields = {"endpoint": endpoint}
        if failed:
            message = str(request.failure or "")
            fields["network_signals"] = [code for code in (
                "ERR_ABORTED", "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED",
                "ERR_TIMED_OUT", "ERR_NAME_NOT_RESOLVED", "ERR_TUNNEL_CONNECTION_FAILED",
                "ERR_PROXY_CONNECTION_FAILED", "ERR_EMPTY_RESPONSE") if code in message]
        emit(log, "auth_request_failed" if failed else "auth_request", **fields)
    except Exception:
        pass


def trace_summary(log, summary):
    try:
        known = {"roxy_raw_trace_" + suffix for suffix in (
            "attach_failed", "body_unavailable", "cdp_disconnected", "file_limit_reached",
            "index_failed", "sample_config_invalid", "start_failed", "stop_failed",
            "summary_failed", "target_attach_failed", "write_failed", "interrupted")}
        codes = summary.get("error_codes") or []
        safe = sorted({code for code in codes if isinstance(code, str) and code in known})
        emit(log, "raw_trace_summary", error_codes=safe,
             unknown_error_count=sum(not isinstance(code, str) or code not in known for code in codes))
    except Exception:
        pass
