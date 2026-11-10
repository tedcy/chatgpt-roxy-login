"""Small, transport-agnostic policy engine for email OTP retries.

Each business flow still owns its transport and page state machine.  The
policy only owns the repeated mechanics: attempt/resend budgets, safe error
classification, optional old-code de-duplication, baseline replacement and
stop checks. Callers receive fixed metadata through ``on_event`` and keep
their existing public error mappings. Fresh-code polling logs budgets only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import inspect
import logging
import time
from typing import Literal


logger = logging.getLogger(__name__)


OtpStatus = Literal[
    "accepted",
    "exhausted",
    "ambiguous",
    "unavailable",
    "terminal",
]
ResendStatus = Literal["sent", "ambiguous", "terminal", "unavailable", "failed"]


@dataclass(frozen=True, slots=True)
class OtpRetryConfig:
    """Per-flow retry policy; values are explicit instead of global."""

    max_attempts: int
    max_resends: int = 0
    retry_wait_reasons: frozenset[str] = frozenset({"otp_timeout"})
    retry_submit_reasons: frozenset[str] = frozenset({"otp_invalid"})
    deduplicate_codes: bool = False
    retry_unconfirmed: bool = False

    def __post_init__(self) -> None:
        if int(self.max_attempts) < 1:
            raise ValueError("max_attempts must be positive")
        if int(self.max_resends) < 0:
            raise ValueError("max_resends must not be negative")


@dataclass(frozen=True, slots=True)
class OtpResendResult:
    """Safe result returned by a transport-specific resend callback."""

    status: ResendStatus
    after_ts: float | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class OtpSubmitResult:
    """Safe result returned by a transport-specific submit callback."""

    status: Literal["accepted", "invalid", "unconfirmed", "terminal", "failed"]
    reason: str = ""


@dataclass(frozen=True, slots=True)
class OtpRetryEvent:
    """Fixed diagnostic fields; it intentionally contains no code or body."""

    event: Literal["wait", "submit", "resend"]
    attempt: int
    max_attempts: int
    resend_count: int
    reason: str = ""
    result: str = ""


@dataclass(frozen=True, slots=True)
class OtpRetryResult:
    """Terminal policy result without the OTP value or provider response."""

    status: OtpStatus
    attempts: int
    resend_count: int
    reason: str = ""


def _default_reason(exc: BaseException) -> str:
    value = str(
        getattr(exc, "error_code", "")
        or getattr(exc, "code", "")
        or ""
    ).strip().lower()
    return value or "otp_unavailable"


def _safe_reason(value: object) -> str:
    text = str(value or "").strip().lower()
    # Error codes are intentionally kept compact and punctuation-free.  This
    # prevents an exception message or response body from entering diagnostics.
    return text if text and text.isascii() and len(text) <= 80 and all(
        char.isalnum() or char in {"_", "-", "."} for char in text
    ) else "otp_unknown"


def _emit(on_event, event: OtpRetryEvent) -> None:
    if callable(on_event):
        try:
            on_event(event)
        except Exception:
            # Diagnostics must never change the OTP outcome.
            pass


def _result(
    status: OtpStatus,
    *,
    attempts: int,
    resend_count: int,
    reason: str = "",
) -> OtpRetryResult:
    return OtpRetryResult(
        status=status,
        attempts=int(attempts),
        resend_count=int(resend_count),
        reason=_safe_reason(reason),
    )


def run_email_otp_retry(
    *,
    config: OtpRetryConfig,
    initial_after_ts: float,
    wait_code: Callable[[float, set[str]], str],
    submit_code: Callable[[str, int], OtpSubmitResult | str],
    trigger_resend: Callable[[int, str], OtpResendResult] | None = None,
    prepare_baseline: Callable[[int, str], float] | None = None,
    classify_error: Callable[[BaseException], str] | None = None,
    handle_error: Callable[[BaseException, str], OtpRetryResult | None] | None = None,
    is_stop_error: Callable[[BaseException], bool] | None = None,
    propagate_error: Callable[[BaseException], bool] | None = None,
    stop_check: Callable[[], object] | None = None,
    initial_code: str | None = None,
    validate_code: Callable[[str], bool] | None = None,
    can_resend: Callable[[int, str], bool] | None = None,
    is_page_ready: Callable[[], object] | None = None,
    on_event: Callable[[OtpRetryEvent], None] | None = None,
) -> OtpRetryResult:
    """Run a bounded email OTP wait/submit/resend cycle.

    ``wait_code`` and ``submit_code`` are deliberately callbacks so protocol,
    Selenium, Roxy and email-change transports can keep their own behavior.
    Exceptions are reduced to fixed error codes before reaching the result.
    A caller may mark its stop exception with ``is_stop_error``; it is then
    re-raised unchanged so existing cancellation semantics are preserved.
    The optional propagate_error predicate likewise preserves explicitly
    classified terminal exceptions instead of reducing them to reason codes.
    """

    classify = classify_error or _default_reason
    validate = validate_code or (lambda value: len(value) == 6 and value.isdigit())
    used_codes: set[str] = set()
    after_ts = float(initial_after_ts or 0.0)
    current_code = str(initial_code or "").strip() or None
    attempts = 0
    resend_count = 0
    last_reason = ""

    def check_stop() -> None:
        if callable(stop_check):
            stop_check()

    def must_propagate(exc: BaseException) -> bool:
        return bool(
            (callable(is_stop_error) and is_stop_error(exc))
            or (callable(propagate_error) and propagate_error(exc))
        )

    def resend_or_finish(reason: str) -> OtpRetryResult | None:
        nonlocal after_ts, current_code, resend_count, last_reason
        last_reason = _safe_reason(reason)
        if resend_count >= int(config.max_resends) or not callable(trigger_resend):
            return _result(
                "exhausted",
                attempts=attempts,
                resend_count=resend_count,
                reason=last_reason,
            )
        if callable(can_resend):
            try:
                if not can_resend(attempts, last_reason):
                    return _result(
                        "unavailable",
                        attempts=attempts,
                        resend_count=resend_count,
                        reason="otp_resend_unavailable",
                    )
            except Exception as exc:
                if must_propagate(exc):
                    raise
                return _result(
                    "unavailable",
                    attempts=attempts,
                    resend_count=resend_count,
                    reason=_safe_reason(classify(exc)),
                )
        check_stop()
        try:
            outcome = trigger_resend(attempts, last_reason)
        except Exception as exc:
            if must_propagate(exc):
                raise
            outcome = OtpResendResult("failed", reason=_safe_reason(classify(exc)))
        if isinstance(outcome, dict):
            status = str(outcome.get("status") or "failed").lower()
            outcome_after_ts = outcome.get("after_ts")
            outcome_reason = outcome.get("reason")
        else:
            status = str(getattr(outcome, "status", "failed") or "failed").lower()
            outcome_after_ts = getattr(outcome, "after_ts", None)
            outcome_reason = getattr(outcome, "reason", "")
        reason_value = _safe_reason(outcome_reason or last_reason)
        _emit(
            on_event,
            OtpRetryEvent(
                event="resend",
                attempt=attempts,
                max_attempts=int(config.max_attempts),
                resend_count=resend_count + 1,
                reason=last_reason,
                result=status,
            ),
        )
        if status == "sent":
            resend_count += 1
            if outcome_after_ts is not None:
                after_ts = float(outcome_after_ts)
            elif callable(prepare_baseline):
                try:
                    after_ts = float(prepare_baseline(attempts, last_reason))
                except Exception as exc:
                    if must_propagate(exc):
                        raise
                    return _result(
                        "unavailable",
                        attempts=attempts,
                        resend_count=resend_count,
                        reason=_safe_reason(classify(exc)),
                    )
            current_code = None
            return None
        if status == "terminal":
            return _result(
                "terminal",
                attempts=attempts,
                resend_count=resend_count,
                reason=reason_value or "otp_terminal",
            )
        if status == "ambiguous":
            return _result(
                "ambiguous",
                attempts=attempts,
                resend_count=resend_count,
                reason=reason_value or "otp_resend_ambiguous",
            )
        return _result(
            "unavailable",
            attempts=attempts,
            resend_count=resend_count,
            reason=reason_value or "otp_resend_failed",
        )

    while attempts < int(config.max_attempts):
        check_stop()
        if callable(is_page_ready):
            try:
                if not bool(is_page_ready()):
                    return _result(
                        "unavailable",
                        attempts=attempts,
                        resend_count=resend_count,
                        reason="otp_page_not_ready",
                    )
            except Exception as exc:
                if must_propagate(exc):
                    raise
                reason = _safe_reason(classify(exc))
                if callable(handle_error):
                    handled = handle_error(exc, reason)
                    if handled is not None:
                        return handled
                return _result(
                    "unavailable",
                    attempts=attempts,
                    resend_count=resend_count,
                    reason=reason,
                )
        attempts += 1
        _emit(
            on_event,
            OtpRetryEvent(
                event="wait",
                attempt=attempts,
                max_attempts=int(config.max_attempts),
                resend_count=resend_count,
            ),
        )
        if current_code is None:
            try:
                current_code = str(wait_code(after_ts, used_codes) or "").strip() or None
            except Exception as exc:
                if must_propagate(exc):
                    raise
                reason = _safe_reason(classify(exc))
                last_reason = reason
                from core.otp_poll_guard import allow_guarded_wait_retry

                if reason not in config.retry_wait_reasons and not allow_guarded_wait_retry(reason):
                    if callable(handle_error):
                        handled = handle_error(exc, reason)
                        if handled is not None:
                            return handled
                    return _result(
                        "unavailable",
                        attempts=attempts,
                        resend_count=resend_count,
                        reason=reason,
                    )
                if attempts >= int(config.max_attempts):
                    return _result(
                        "exhausted",
                        attempts=attempts,
                        resend_count=resend_count,
                        reason=reason,
                    )
                retry_result = resend_or_finish(reason)
                if retry_result is not None:
                    return retry_result
                continue
        if not current_code or not validate(current_code):
            current_code = None
            last_reason = "otp_invalid"
            if "otp_invalid" not in config.retry_submit_reasons:
                return _result(
                    "unavailable",
                    attempts=attempts,
                    resend_count=resend_count,
                    reason=last_reason,
                )
            if attempts >= int(config.max_attempts):
                return _result(
                    "exhausted",
                    attempts=attempts,
                    resend_count=resend_count,
                    reason=last_reason,
                )
            retry_result = resend_or_finish(last_reason)
            if retry_result is not None:
                return retry_result
            continue
        if config.deduplicate_codes and current_code in used_codes:
            current_code = None
            last_reason = "otp_duplicate"
            if attempts >= int(config.max_attempts):
                return _result(
                    "exhausted",
                    attempts=attempts,
                    resend_count=resend_count,
                    reason=last_reason,
                )
            retry_result = resend_or_finish(last_reason)
            if retry_result is not None:
                return retry_result
            continue

        code_for_submit = current_code
        if config.deduplicate_codes:
            used_codes.add(code_for_submit)
        _emit(
            on_event,
            OtpRetryEvent(
                event="submit",
                attempt=attempts,
                max_attempts=int(config.max_attempts),
                resend_count=resend_count,
            ),
        )
        try:
            raw_outcome = submit_code(code_for_submit, attempts)
            outcome = (
                raw_outcome
                if isinstance(raw_outcome, OtpSubmitResult)
                else OtpSubmitResult(str(raw_outcome or "failed"))
            )
        except Exception as exc:
            if must_propagate(exc):
                raise
            reason = _safe_reason(classify(exc))
            last_reason = reason
            if reason not in config.retry_submit_reasons:
                if callable(handle_error):
                    handled = handle_error(exc, reason)
                    if handled is not None:
                        return handled
                return _result(
                    "unavailable",
                    attempts=attempts,
                    resend_count=resend_count,
                    reason=reason,
                )
            outcome = OtpSubmitResult("invalid", reason=reason)
        status = str(outcome.status or "failed").lower()
        reason = _safe_reason(outcome.reason or ("otp_invalid" if status == "invalid" else status))
        last_reason = reason
        if status == "accepted":
            return _result(
                "accepted",
                attempts=attempts,
                resend_count=resend_count,
            )
        if status == "terminal":
            return _result(
                "terminal",
                attempts=attempts,
                resend_count=resend_count,
                reason=reason,
            )
        if status == "unconfirmed" and not config.retry_unconfirmed:
            return _result(
                "ambiguous",
                attempts=attempts,
                resend_count=resend_count,
                reason="otp_submission_unconfirmed",
            )
        if status == "failed" and reason not in config.retry_submit_reasons:
            return _result(
                "unavailable",
                attempts=attempts,
                resend_count=resend_count,
                reason=reason,
            )
        if attempts >= int(config.max_attempts):
            return _result(
                "exhausted",
                attempts=attempts,
                resend_count=resend_count,
                reason=reason,
            )
        current_code = None
        retry_result = resend_or_finish(reason)
        if retry_result is not None:
            return retry_result

    return _result(
        "exhausted",
        attempts=attempts,
        resend_count=resend_count,
        reason=last_reason or "otp_exhausted",
    )


def wait_for_fresh_code(
    code_provider: Callable[..., str],
    key: str,
    *,
    after_ts: float,
    used_codes: set[str] | None = None,
    timeout: int = 90,
    poll_interval: float = 5.0,
    stop_check: Callable[[], object] | None = None,
) -> str:
    """Poll a provider until it returns a code not already submitted.

    This is the shared mailbox primitive used by browser login adapters.  It
    logs only budget metadata and never includes the key or code in logs or
    exception messages. Legacy providers remain callable, but cannot be
    preempted while blocked in synchronous I/O.
    """

    seen = {str(value) for value in (used_codes or set()) if str(value)}
    budget = max(1.0, float(timeout or 1))
    started = time.monotonic()
    deadline = started + budget
    try:
        parameters = inspect.signature(code_provider).parameters
    except (TypeError, ValueError):
        parameters = {}
    variadic = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values())

    def accepts(name):
        parameter = parameters.get(name)
        if parameter is not None:
            return parameter.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                      inspect.Parameter.KEYWORD_ONLY)
        return variadic

    bounded = accepts('max_wait')

    def check_deadline():
        if callable(stop_check):
            stop_check()
        if time.monotonic() >= deadline:
            raise RuntimeError("otp_timeout")

    outcome = 'failed'
    try:
        while True:
            check_deadline()
            remaining = deadline - time.monotonic()
            kwargs = {'after_ts': after_ts}
            if bounded:
                # Built-in providers use integer seconds. Never send zero:
                # legacy providers may interpret it as their default budget.
                if remaining < 1:
                    raise RuntimeError("otp_timeout")
                kwargs['max_wait'] = int(remaining)
            if accepts('stop_check'):
                kwargs['stop_check'] = check_deadline
            value = str(code_provider(key, **kwargs) or "").strip()
            check_deadline()
            if value and value not in seen:
                outcome = 'received'
                return value
            sleep_until = min(deadline, time.monotonic() + max(0.1, float(poll_interval or 0.1)))
            while time.monotonic() < sleep_until:
                check_deadline()
                time.sleep(max(0.0, min(0.25, sleep_until - time.monotonic())))
    finally:
        logger.info('[OtpWait] budget_seconds=%s elapsed_ms=%s provider_budget=%s result=%s',
                    budget, round((time.monotonic() - started) * 1000), bounded, outcome)


__all__ = [
    "OtpRetryConfig",
    "OtpResendResult",
    "OtpRetryEvent",
    "OtpRetryResult",
    "OtpSubmitResult",
    "run_email_otp_retry",
    "wait_for_fresh_code",
]
