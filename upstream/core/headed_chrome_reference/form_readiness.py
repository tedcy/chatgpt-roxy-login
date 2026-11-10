"""Attempt-local, read-only form waits on the owning Playwright loop."""
import json
import time

from .page_snapshot import evaluate_snapshot, AuthPageSnapshotFailed, AuthPageSnapshotTimeout, snapshot_purpose


POLL_SECONDS = .25
READ_SECONDS = 15.0


class FormNotReady(TimeoutError):
    pass


class DocumentChanged(RuntimeError):
    pass


def document_key(state):
    return tuple(state.get(k) for k in ("host", "path", "epoch"))


def read_state(worker, page, script, *, deadline, args=None, clock=time.monotonic):
    worker._raise_if_stopped()
    remaining = deadline - clock()
    if remaining <= 0:
        raise FormNotReady()
    from .adapter import _InitialAuthNavigationRetryPage
    source = page._page if isinstance(page, _InitialAuthNavigationRetryPage) else page
    expression = script if args is None else "() => (" + script + ")(" + json.dumps(args) + ")"
    with snapshot_purpose('form_readiness'):
        result = evaluate_snapshot(source, expression, timeout=min(READ_SECONDS, remaining),
                                   check_stop=worker._raise_if_stopped)
    worker._raise_if_stopped()
    if clock() > deadline:
        raise FormNotReady()
    if not isinstance(result, dict):
        raise AuthPageSnapshotFailed("snapshot_shape_invalid")
    return result


class FormWait:
    def __init__(self, worker, page, timeout, *, clock=time.monotonic, baseline=None, pause=None):
        self.worker, self.page, self.clock = worker, page, clock
        self.started = clock()
        self.deadline = self.started + timeout
        self.baseline = baseline
        self.pause = pause or worker._wait_or_stop

    def read(self, script, args=None):
        return read_state(self.worker, self.page, script, deadline=self.deadline,
                          args=args, clock=self.clock)

    def wait(self, read, ready, *, signature=None, observe=None):
        previous = None
        while self.clock() < self.deadline:
            self.worker._raise_if_stopped()
            try:
                state = read(self.deadline)
            except (AuthPageSnapshotTimeout, AuthPageSnapshotFailed):
                state = {}
            key = document_key(state)
            if all(v is not None for v in key):
                if self.baseline is None:
                    self.baseline = key
                elif key != self.baseline:
                    raise DocumentChanged()
            if observe is not None:
                observe(state)
            match = (key, signature(state) if signature else None)
            accepted = all(v is not None for v in key) and ready(state)
            if self.clock() <= self.deadline and accepted and previous == match:
                return state
            previous = match if accepted else None
            remaining = self.deadline - self.clock()
            if remaining > 0:
                self.pause(min(POLL_SECONDS, remaining))
        raise FormNotReady()
