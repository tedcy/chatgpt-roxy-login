"""Small, dependency-free helpers for cancellable OTP polling.

Registration jobs use a cooperative stop callback.  Historically the mailbox
adapters called ``time.sleep`` directly, which meant a stop request could not
be observed until the full OTP timeout elapsed.  Keep the helpers in a tiny
module so every adapter uses the same cancellation semantics without importing
the provider dispatcher (and creating an import cycle).
"""

from __future__ import annotations

import time
from typing import Callable


StopCheck = Callable[[], object]


def check_stop(stop_check: StopCheck | None) -> None:
    """Run a provider stop callback and raise the job's stop exception.

    The normal WebUI callback returns a boolean.  Protocol callers may use a
    callback that raises directly; that exception is intentionally allowed to
    propagate.  Supporting both forms keeps the helper compatible with CLI
    and test callers.
    """

    if not callable(stop_check):
        return
    if stop_check():
        # Import lazily: registration_service imports the email provider layer
        # and importing it at module load time would introduce a cycle.
        from core.registration_service import StopRequested

        raise StopRequested("注册任务已请求停止")


def sleep_with_stop(
    seconds: float,
    stop_check: StopCheck | None,
    *,
    quantum: float = 0.25,
    sleep_fn: Callable[[float], None] | None = None,
) -> None:
    """Sleep while checking for cancellation at a bounded interval."""

    delay = max(0.0, float(seconds))
    if delay <= 0:
        check_stop(stop_check)
        return
    sleeper = sleep_fn or time.sleep
    if not callable(stop_check):
        sleeper(delay)
        return

    deadline = time.monotonic() + delay
    step = max(0.05, float(quantum))
    while True:
        check_stop(stop_check)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        sleeper(min(step, remaining))
