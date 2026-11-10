"""Task-owned cancellation and dead-dispatcher protection for Playwright sync.

Only objects belonging to one registration connection are adapted. Neither the
pinned registration source nor Playwright's classes are patched globally.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time

from .diagnostics import emit, step


class RegistrationRuntimeError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class DispatcherGuard:
    def __init__(self, binding):
        self.binding = binding

    def switch(self, *args, **kwargs):
        binding = self.binding
        if not binding.teardown:
            binding.check()
        elif binding.dispatcher.dead:
            return None
        try:
            result = binding.dispatcher.switch(*args, **kwargs)
        except Exception:
            if not binding.teardown and (
                binding.dispatcher.dead or binding.popen.poll() is not None
            ):
                binding.runtime.abort("headed_chrome_registration_failed", "driver_disconnected")
                binding.runtime.check()
            raise
        if not binding.teardown:
            binding.check()
        return result

    def __getattr__(self, name):
        return getattr(self.binding.dispatcher, name)


class ConnectionBinding:
    def __init__(self, runtime, connection):
        self.runtime = runtime
        self.connection = connection
        self.dispatcher = connection._dispatcher_fiber
        self.loop = connection._loop
        self.transport = connection._transport
        self.process = self.transport._proc
        # Retain the original Popen/Windows handle: a recycled numeric PID must
        # never become an eligible taskkill target.
        self.popen = self.process._transport.get_extra_info("subprocess")
        if self.popen is None or self.popen.pid != self.process.pid:
            raise RegistrationRuntimeError("headed_chrome_runtime_unavailable")
        args = self.popen.args
        if not isinstance(args, (list, tuple)) or "run-driver" not in args:
            raise RegistrationRuntimeError("headed_chrome_runtime_unavailable")
        self.original_stop = connection.stop_sync
        self.guard = DispatcherGuard(self)
        self.teardown = False
        self.finished = False
        self.kill_attempted = False
        self.abort_queued = False

    def install(self):
        objects = [self.connection, self.connection._root_object]
        objects.extend(list(self.connection._objects.values()))
        for obj in objects:
            if obj is None:
                continue
            obj._dispatcher_fiber = self.guard
            api = getattr(obj, "_pw_api_instance_", None)
            if api is not None:
                api._dispatcher_fiber = self.guard
        self.connection.stop_sync = self.stop_sync

    def check(self):
        self.runtime.check()
        transport_error = getattr(self.transport, "on_error_future", None)
        if (self.dispatcher.dead or self.popen.poll() is not None
                or (transport_error is not None and transport_error.done())):
            self.runtime.abort("headed_chrome_registration_failed", "driver_disconnected")
            self.runtime.check()

    def queue_abort(self):
        if self.abort_queued or self.finished or self.loop.is_closed():
            return
        self.abort_queued = True
        try:
            self.loop.call_soon_threadsafe(self._abort_on_owner_loop)
        except RuntimeError:
            pass

    def _abort_on_owner_loop(self):
        # Runs in the Playwright thread, never in the watchdog thread. Failing
        # protocol callbacks wakes the current sync call without cross-thread
        # greenlet switching or injecting an exception into a Python thread.
        self.connection.cleanup(self.runtime.code)
        try:
            self.transport.request_stop()
        except (AttributeError, OSError, RuntimeError):
            pass

    def terminate_owned_driver(self):
        if self.kill_attempted or self.popen.poll() is not None:
            return
        self.kill_attempted = True
        if self.process.pid != self.popen.pid:
            self.runtime.log("[Watchdog] stage=kill result=rejected reason=driver_identity_changed")
            return
        try:
            if os.name == "nt":
                result = subprocess.run(
                    ["taskkill", "/PID", str(self.popen.pid), "/T", "/F"],
                    capture_output=True, check=False, timeout=5,
                )
                ok = result.returncode == 0 or self.popen.poll() is not None
            else:
                self.popen.terminate()
                ok = True
            self.runtime.log("[Watchdog] stage=kill result=%s" % ("sent" if ok else "failed"))
        except (OSError, subprocess.SubprocessError):
            self.runtime.log("[Watchdog] stage=kill result=failed")

    def stop_sync(self):
        self.runtime.begin_cleanup()
        self.teardown = True
        try:
            if self.dispatcher.dead:
                # Resuming a dead greenlet cannot drain a newly created task.
                # The owning context manager cancels remaining local tasks and
                # closes its loop after this returns.
                self.connection.cleanup(self.runtime.code or "driver_disconnected")
                if self.popen.poll() is None:
                    self.terminate_owned_driver()
                return
            with step(self.runtime.log, "driver_stop", self.runtime):
                self.transport.request_stop()
                # Protocol callbacks can switch back to the sync caller before
                # transport.run() has exited. One switch is not a teardown barrier.
                # Drain ONLY this task's dispatcher; the watchdog bounds a stall.
                while not self.dispatcher.dead:
                    self.dispatcher.switch()
                self.loop.run_until_complete(self.transport.wait_until_stopped())
                self.connection.cleanup()
        finally:
            self.finished = True
            self.runtime.end_cleanup()


class RegistrationRuntime:
    POLL_SECONDS = 0.2
    GRACE_SECONDS = 2.0
    CLEANUP_SECONDS = 5.0

    def __init__(self, worker, *, timeout, cancellation_event=None, log=None):
        self.worker = worker
        self.timeout = float(timeout)
        self.cancellation_event = cancellation_event
        self.log = log or (lambda _message: None)
        self.code = None
        self.abort_source = None
        self.completed_result = None
        self.abort_started = None
        self.cleanup_deadline = None
        self.diagnostic_phase = None
        self.deadline = None
        self.bindings = []
        self.lock = threading.RLock()
        self.done = threading.Event()
        self.monitor = None

    def start(self):
        self.deadline = time.monotonic() + self.timeout
        self.monitor = threading.Thread(target=self._monitor, daemon=True,
                                        name="headed-chrome-registration-watchdog")
        self.monitor.start()

    def check(self):
        self.check_cancellation()
        if self.code:
            raise RegistrationRuntimeError(self.code)

    def check_cancellation(self):
        if self.cancellation_event is not None and self.cancellation_event.is_set():
            self.abort("registration_stopped", "manual")
        if self.abort_source == "manual":
            raise RegistrationRuntimeError(self.code)

    def capture_result(self, result):
        """Keep the in-memory result before vendor finally blocks close Chrome."""
        self.check()
        if isinstance(result, dict):
            self.completed_result = dict(result)

    def check_result(self):
        """Cleanup is not an authentication failure; real cancellation still wins."""
        self.check_cancellation()
        if self.code and not (self.abort_source == "cleanup_deadline"
                              and self.completed_result is not None):
            raise RegistrationRuntimeError(self.code)

    def abort(self, code, source):
        with self.lock:
            if self.code is not None:
                # An actual user's request may override a timeout, but our
                # internal stop event must never masquerade as manual cancel.
                if code == "registration_stopped":
                    self.code = code
                    self.abort_source = source
                    self.worker._registration_terminal_code = code
                return
            self.code = code
            self.abort_source = source
            self.abort_started = time.monotonic()
            self.worker._registration_terminal_code = code
            active = self.diagnostic_phase
            self.worker.stop_event.set()
            bindings = list(self.bindings)
        emit(self.log, "watchdog_abort", source=source,
             active_phase=active[0] if active else "unobserved",
             phase_elapsed_ms=int((time.monotonic() - active[1]) * 1000) if active else None,
             cleanup_budget_ms=int(self.CLEANUP_SECONDS * 1000))
        self.log("[Watchdog] stage=cancel source=%s error_code=%s" % (source, code))
        for binding in bindings:
            binding.queue_abort()

    def attach(self, playwright):
        self.check()
        try:
            connection = playwright._impl_obj._connection
            for binding in self.bindings:
                if binding.connection is connection:
                    return binding
            binding = ConnectionBinding(self, connection)
            binding.install()
            with self.lock:
                self.bindings.append(binding)
            self.check()
            return binding
        except RegistrationRuntimeError:
            raise
        except (AttributeError, TypeError) as exc:
            raise RegistrationRuntimeError("headed_chrome_runtime_unavailable") from exc

    def begin_cleanup(self):
        with self.lock:
            if self.cleanup_deadline is None:
                self.cleanup_deadline = time.monotonic() + self.CLEANUP_SECONDS

    def end_cleanup(self):
        with self.lock:
            self.cleanup_deadline = None

    def _monitor(self):
        while True:
            now = time.monotonic()
            if self.cancellation_event is not None and self.cancellation_event.is_set():
                self.abort("registration_stopped", "manual")
            elif not self.done.is_set() and now >= self.deadline:
                self.abort("headed_chrome_registration_timeout", "deadline")
            elif self.cleanup_deadline is not None and now >= self.cleanup_deadline:
                self.abort("headed_chrome_registration_timeout", "cleanup_deadline")
            with self.lock:
                bindings = list(self.bindings)
            if self.code:
                for binding in bindings:
                    binding.queue_abort()
                if now - self.abort_started >= self.GRACE_SECONDS:
                    for binding in bindings:
                        binding.terminate_owned_driver()
                    if self.done.is_set():
                        return
            if self.done.is_set() and (not self.code or all(b.popen.poll() is not None for b in bindings)):
                return
            self.done.wait(self.POLL_SECONDS) if not self.done.is_set() else time.sleep(self.POLL_SECONDS)

    def finish(self):
        self.done.set()
        if self.monitor is not None:
            self.monitor.join(timeout=self.GRACE_SECONDS + 5.5)
        if self.code:
            self.log("[Watchdog] stage=complete error_code=%s" % self.code)
