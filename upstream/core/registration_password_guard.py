"""Bound the pending registration-password stage, not the whole auth flow."""
import time
from urllib.parse import urlsplit

from core.headed_chrome_reference.diagnostics import emit


class PasswordSubmissionTimeout(TimeoutError):
    code = "headed_chrome_password_submit_timeout"


class PasswordRequestNotObserved(PasswordSubmissionTimeout):
    code = "headed_chrome_password_request_not_observed"


class PasswordSubmissionGuard:
    def __init__(self, page, log, recorder=None, clock=time.monotonic):
        self.page, self.log, self.recorder, self.clock = page, log, recorder, clock
        self.started = None
        self.status = None
        self.retry_pending = False
        self.retries = 0
        self.completed = False
        self.fill_returned_at = None
        self.next_diagnostic = 0.0
        self.diagnostic_form = {}
        self.diagnostic_form_at = None

    def fill_returned(self):
        if self.fill_returned_at is None:
            self.fill_returned_at = self.clock()
            self._progress(force=True)

    def _progress(self, *, force=False):
        try:
            self._progress_once(force=force)
        except Exception:
            # Diagnostic failures never grant a retry or alter the auth outcome.
            pass

    def _progress_once(self, *, force=False):
        if self.fill_returned_at is None or self.completed:
            return
        now = self.clock()
        if not force and now < self.next_diagnostic:
            return
        self.next_diagnostic = now + 30
        # Never emit URLs, field values, validation text, or arbitrary DOM strings.
        path = urlsplit(str(self.page.url)).path
        route = path if path in {"/create-account/password", "/log-in/password",
                                 "/email-verification", "/about-you"} else "other"
        # check() is also called inside the owning asyncio loop's snapshot read.
        # Never enter synchronous Playwright I/O there; safe click checkpoints
        # supply cached, boolean-only form evidence.
        fields = {k: self.diagnostic_form[k] for k in (
            "password_visible", "password_filled", "password_valid",
            "invalid_field_present", "submit_visible", "submit_enabled")
            if type(self.diagnostic_form.get(k)) is bool}
        emit(self.log, "password_progress", route=route,
             elapsed_ms=int((now - self.fill_returned_at) * 1000),
             request_seen=self.started is not None, http_status=self.status,
             retry_count=self.retries, form=fields, form_cached=True,
             form_age_ms=None if self.diagnostic_form_at is None else max(0, int((now-self.diagnostic_form_at)*1000)))

    def submitted(self):
        if self.started is None:
            self.started = self.clock()
        self.status = None
        self.retry_pending = False

    def response(self, status, headers):
        self.status = int(status)
        headers = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        # A bare 4xx, CF HTML, or missing response is not retry permission.
        self.retry_pending = (
            self.status in {502, 503, 504}
            and "application/json" in headers.get("content-type", "")
            and headers.get("cf-mitigated") != "challenge"
        )

    def check(self):
        self._progress()
        if self.completed:
            return
        if self.started is None:
            if self.fill_returned_at is not None and self.clock() - self.fill_returned_at >= 30:
                raise PasswordRequestNotObserved("password_request_not_observed")
            return
        route = urlsplit(str(self.page.url))
        if (self.status is not None and 200 <= self.status < 300
                and route.hostname == "auth.openai.com"
                and route.path.rstrip("/") in {"/email-verification", "/about-you"}):
            self.completed = True
            return
        elapsed = self.clock() - self.started
        if elapsed < 60:
            return
        outcome = "submitted_unknown" if self.status is None else "response_without_progress"
        self.log(f"[PasswordDiagnostic] stage=password_submit elapsed_ms={int(elapsed * 1000)} "
                 f"retry_count={self.retries} http_status={self.status or 0} "
                 f"result={outcome} error_code={PasswordSubmissionTimeout.code}")
        # The synchronous terminal collector captures DOM after this guard has
        # unwound. Cancellation checks must not start browser I/O.
        raise PasswordSubmissionTimeout("password_submission_timeout")

    def take_retry(self):
        self.check()
        if self.completed or not self.retry_pending or self.retries >= 1:
            return False
        self.retries += 1
        self.submitted()  # Preserve the original deadline, clear response state.
        return True
