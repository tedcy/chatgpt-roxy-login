"""Non-terminal, paired DOM evidence for fully sampled registrations."""
from __future__ import annotations

import json
import math
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core import failure_dom_artifact as artifact
from core.roxy_dom_failure_diagnostic import (
    DEFAULT_DIAGNOSTIC_DIR, MAX_FILE_BYTES, _cleanup_old_files, _safe_route,
)
from .diagnostics import emit
from .page_snapshot import evaluate_snapshot, AuthPageSnapshotFailed, AuthPageSnapshotTimeout


READ_SECONDS = 2.0


def create_diagnostics(trace, *, started, log):
    """Freeze the diagnostic gate when this attempt's raw trace starts."""
    if not started or trace is None:
        return None
    try:
        from core.roxy_raw_network_trace import configured_raw_trace_sample_percent
        percent, error = configured_raw_trace_sample_percent()
        if error is not None or percent != 100:
            return None
        return PasswordEntryDomDiagnostics(log, job_id=trace.job_id, trace_id=trace.trace_id)
    except Exception:
        emit(log, "password_entry_dom", state="unavailable", reason="initialization_failed")
        return None


class _BoundedSource:
    def __init__(self, page, key, check_stop):
        self.page, self.key, self.check_stop = page, key, check_stop
        self.stop_error = None
        self.read_error = None

    def _check_stop(self):
        try:
            self.check_stop()
        except BaseException as exc:
            self.stop_error = exc
            raise

    def evaluate(self, expression):
        # The registration navigation proxy owns no separate Page or loop.
        # Import at read time because the adapter imports this module.
        from .adapter import _InitialAuthNavigationRetryPage
        page = self.page._page if isinstance(self.page, _InitialAuthNavigationRetryPage) else self.page
        # Check document identity inside the same page read as the export.
        expression = ("() => { const key = " + json.dumps(self.key) + ";"
                      "if (location.hostname !== key[0] || "
                      "location.pathname.replace(/\\/$/, '') !== key[1] || "
                      "performance.timeOrigin !== key[2]) "
                      "return {format:'rendered-dom-v1',error:'dom_document_changed'};"
                      "return (" + expression + "); }")
        try:
            raw = evaluate_snapshot(page, expression, timeout=READ_SECONDS,
                                    check_stop=self._check_stop)
        except AuthPageSnapshotTimeout:
            self.read_error = "dom_read_timeout"
            raise
        except AuthPageSnapshotFailed:
            self.read_error = "dom_read_failed"
            raise
        if isinstance(raw, dict) and raw.get("error") == "dom_document_changed":
            self.read_error = "dom_document_changed"
        return raw


class PasswordEntryDomDiagnostics:
    def __init__(self, log, *, job_id=None, trace_id=None, directory=None):
        self.log = log
        self.job_id = job_id if type(job_id) is int and job_id > 0 else None
        self.trace_id = trace_id if isinstance(trace_id, str) and re.fullmatch(r"[a-f0-9]{32}", trace_id) else None
        self.directory = Path(directory) if directory is not None else DEFAULT_DIAGNOSTIC_DIR
        self.incident_id = uuid.uuid4().hex
        self.failed_key = None
        self.failed_at = None
        self.ready_observed = False

    def recognition_failed(self, page, key, *, check_stop):
        if self.failed_key is not None:
            return
        self.failed_key = tuple(key[:3])
        self.failed_at = time.monotonic()
        self._save(page, "recognition_failed", check_stop)

    def otp_ready(self, page, key, *, check_stop):
        if self.failed_key is None or self.ready_observed:
            return
        self.ready_observed = True
        if key is None or tuple(key[:3]) != self.failed_key:
            self._emit("otp_ready_before_poll", state="skipped", reason="document_changed")
            return
        self._save(page, "otp_ready_before_poll", check_stop)

    def _emit(self, checkpoint, **fields):
        emit(self.log, "password_entry_dom", checkpoint=checkpoint,
             incident_id=self.incident_id, job_id=self.job_id, trace_id=self.trace_id,
             since_failure_ms=int((time.monotonic() - self.failed_at) * 1000), **fields)

    def _save(self, page, checkpoint, check_stop):
        check_stop()
        started = time.monotonic()
        diagnostic_id = uuid.uuid4().hex
        source = _BoundedSource(page, self.failed_key, check_stop)
        try:
            full_dom = artifact.capture(source, self.directory, diagnostic_id)
        except Exception:
            full_dom = dict(state="unavailable", file_name=None, complete=False,
                            error_code="dom_full_capture_or_write_failed")
        # The shared exporter is best effort. Recover cancellation caught by it.
        if source.stop_error is not None:
            raise source.stop_error
        check_stop()
        if source.read_error:
            full_dom["error_code"] = source.read_error
        elapsed_ms = int((time.monotonic() - started) * 1000)
        summary = self.directory / (diagnostic_id + ".json")
        temp = self.directory / ("." + diagnostic_id + ".tmp")
        try:
            epoch = self.failed_key[2]
            document = _safe_route("https://" + self.failed_key[0] + self.failed_key[1])
            document["epoch"] = epoch if type(epoch) in (int, float) and math.isfinite(epoch) else None
            payload = dict(schema_version=1, kind="registration_password_entry_miss",
                           diagnostic_id=diagnostic_id, incident_id=self.incident_id,
                           job_id=self.job_id, trace_id=self.trace_id, checkpoint=checkpoint,
                           captured_at=datetime.now(timezone.utc).isoformat(), document=document,
                           since_failure_ms=int((started - self.failed_at) * 1000),
                           read_budget_ms=int(READ_SECONDS * 1000), capture_elapsed_ms=elapsed_ms,
                           full_dom=full_dom)
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_FILE_BYTES:
                raise ValueError("diagnostic_size_limit")
            self.directory.mkdir(parents=True, exist_ok=True)
            temp.write_bytes(encoded)
            temp.replace(summary)
            self._prune(summary)
            self._emit(checkpoint, state="saved", diagnostic_id=diagnostic_id,
                       summary_file=str(summary.resolve()), dom_state=full_dom["state"],
                       dom_file=str((self.directory / full_dom["file_name"]).resolve()) if full_dom["file_name"] else None,
                       error_code=full_dom.get("error_code"),
                       elapsed_ms=int((time.monotonic() - started) * 1000))
        except Exception:
            self._emit(checkpoint, state="unavailable", reason="summary_write_failed",
                       diagnostic_id=diagnostic_id,
                       elapsed_ms=int((time.monotonic() - started) * 1000))
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass

    def _prune(self, summary):
        try:
            _cleanup_old_files(self.directory)
            _cleanup_old_files(self.directory, force=True, protected=summary)
            artifact.cleanup(self.directory, protected=summary)
        except Exception:
            pass
