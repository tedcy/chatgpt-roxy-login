"""Read-only snapshots bounded on the Page's owning Playwright event loop."""
from __future__ import annotations

import asyncio
import time
from contextlib import contextmanager
from contextvars import ContextVar

from playwright._impl._sync_base import SyncBase


class AuthPageSnapshotTimeout(TimeoutError):
    code = 'headed_chrome_auth_page_snapshot_timeout'


class AuthPageSnapshotFailed(RuntimeError):
    pass


_OBSERVER = ContextVar('registration_snapshot_observer', default=None)
_PURPOSE = ContextVar('registration_snapshot_purpose', default='other')


@contextmanager
def snapshot_purpose(value):
    fixed = value if value in {'auth_page', 'form_readiness', 'submission_diagnostic', 'signup_readiness'} else 'other'
    token = _PURPOSE.set(fixed)
    try:
        yield
    finally:
        _PURPOSE.reset(token)


@contextmanager
def snapshot_observer(callback):
    token = _OBSERVER.set(callback)
    try:
        yield
    finally:
        _OBSERVER.reset(token)


def evaluate_snapshot(page, expression, *, timeout, check_stop):
    """No worker thread, global patch, or unbounded evaluate fallback.

    Playwright's public synchronous evaluate has no timeout parameter. Keep the
    coroutine and its cancellation on the same loop used by that Page's _sync.
    Only read failures are wrapped; cancellation and business guards propagate.
    """
    check_stop()
    if not isinstance(page, SyncBase):
        raise AuthPageSnapshotFailed("unsupported_snapshot_page")
    started = time.monotonic()
    deadline = started + max(0.0, timeout)
    metrics = dict(budget_ms=int(max(0.0, timeout)*1000), cancel_ms=0, result='aborted',
                   purpose=_PURPOSE.get(), _started_monotonic=started,
                   dispatch_ms=0, evaluate_started=False, evaluate_done=False,
                   polls=0, max_poll_lag_ms=0, max_check_ms=0)

    def checked():
        before = time.monotonic()
        try:
            check_stop()
        finally:
            metrics['max_check_ms'] = max(metrics['max_check_ms'], int((time.monotonic()-before)*1000))

    async def evaluate():
        metrics['evaluate_started'] = True
        return await page._impl_obj.evaluate(expression)

    async def read():
        metrics['dispatch_ms'] = max(0, int((time.monotonic()-started)*1000))
        checked()
        if time.monotonic() >= deadline:
            raise AuthPageSnapshotTimeout()
        task = asyncio.create_task(evaluate())
        try:
            while True:
                checked()
                remaining = deadline - time.monotonic()
                if task.done():
                    if remaining < 0:
                        raise AuthPageSnapshotTimeout()
                    try:
                        return task.result()
                    except Exception as exc:
                        raise AuthPageSnapshotFailed("snapshot_read_failed") from exc
                if remaining <= 0:
                    raise AuthPageSnapshotTimeout()
                wait_budget = min(0.25, remaining)
                wait_started = time.monotonic()
                metrics['polls'] += 1
                await asyncio.wait({task}, timeout=wait_budget)
                lag_ms = max(0, int((time.monotonic()-wait_started-wait_budget)*1000))
                metrics['max_poll_lag_ms'] = max(metrics['max_poll_lag_ms'], lag_ms)
        finally:
            metrics['evaluate_done'] = task.done()
            cancel_started = time.monotonic()
            if not task.done():
                task.cancel()
            # Retrieve failures and drain cancellation before returning to sync
            # code. A late protocol reply has no route back into guard state.
            await asyncio.gather(task, return_exceptions=True)
            metrics['cancel_ms'] = max(0, int((time.monotonic()-cancel_started)*1000))

    try:
        value = page._sync(read())
        metrics.update(result='completed', state=value)
        return value
    except AuthPageSnapshotTimeout:
        metrics['result'] = 'timeout'
        raise
    except AuthPageSnapshotFailed:
        metrics['result'] = 'failed'
        raise
    finally:
        metrics['elapsed_ms'] = max(0, int((time.monotonic()-started)*1000))
        metrics['_ended_monotonic'] = time.monotonic()
        observer = _OBSERVER.get()
        if observer is not None:
            try:
                observer(metrics)
            except Exception:
                pass
