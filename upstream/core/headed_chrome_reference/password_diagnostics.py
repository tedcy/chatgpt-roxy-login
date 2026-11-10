"""Observe password locator failures before the pinned worker swallows them."""

import time

from .diagnostics import emit, exception_summary


def _failure(log, mode, action, exc, elapsed_ms):
    # Playwright messages may contain the value being typed. Inspect only for
    # fixed signals; never copy messages, call arguments or locator reprs.
    fields = dict(mode=mode, action=action, elapsed_ms=elapsed_ms)
    try:
        message = str(exc).lower()
        markers = {
            "timeout": ("timeout", "timed out"),
            "target_closed": ("target page, context or browser has been closed", "target closed"),
            "element_detached": ("element was detached", "not attached to the dom"),
            "not_visible": ("element is not visible",),
            "not_enabled": ("element is not enabled", "element is disabled"),
            "not_editable": ("element is not editable", "element is readonly", "element is read-only"),
            "not_stable": ("element is not stable",),
            "pointer_intercepted": ("intercepts pointer events",),
            "strict_mode_violation": ("strict mode violation",),
            "context_destroyed": ("execution context was destroyed",),
        }
        fields["signals"] = [name for name, values in markers.items()
                             if any(value in message for value in values)]
        fields["causes"] = exception_summary(exc)
    except Exception:
        fields["summary_unavailable"] = True
    emit(log, "password_input_failure", **fields)


class PasswordInputObserver:
    """Delegate unchanged calls and rethrow the exact original exception."""

    def __init__(self, locator, log, mode="keyboard"):
        self._locator = locator
        self._log = log
        self._mode = mode
        self.failed = False

    def fallback(self):
        # Unwrap so fallback actions do not also produce keyboard events.
        return PasswordInputObserver(self._locator, self._log, "fallback")

    def __getattr__(self, name):
        method = getattr(self._locator, name)
        if name not in {"click", "press", "type", "fill", "evaluate"}:
            return method

        def observed(*args, **kwargs):
            action = name
            if name == "press":
                action = {"Control+A": "select_all", "Backspace": "clear"}.get(
                    args[0] if args else None, "press")
            started = time.monotonic()
            try:
                return method(*args, **kwargs)
            except Exception as exc:
                self.failed = True
                _failure(self._log, self._mode, action, exc,
                         int((time.monotonic() - started) * 1000))
                raise

        return observed
