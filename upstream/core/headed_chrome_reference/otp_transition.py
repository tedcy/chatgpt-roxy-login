"""Wait for an OTP submission without confusing acceptance with navigation."""
from __future__ import annotations

import time

from core.registration_terminal_response import registration_endpoint
from .diagnostics import emit


class OtpProgress:
    """Evidence belongs to one submit, not to a previous code or another page."""

    def __init__(self):
        self.request = None
        self.accepted_at = None
        self.site_retry_pending = False

    def observe_request(self, request, page):
        try:
            if (registration_endpoint(request.url, request.method) != "email_otp_validate"
                    or request.frame != page.main_frame or self.accepted_at is not None):
                return
            if self.request is None:
                self.request = request
            elif self.site_retry_pending:
                previous = self.request.post_data
                if isinstance(previous, str) and request.post_data == previous:
                    self.request = request
                    self.site_retry_pending = False
        except Exception:
            pass

    def observe_response(self, response):
        try:
            if self.request is None or response.request is not self.request or self.accepted_at is not None:
                return False
            if not 200 <= response.status < 300:
                self.site_retry_pending = 500 <= response.status <= 599
                return False
            payload = response.json()
            session = payload.get("oai-client-auth-session") or {}
            if payload.get("error") or session.get("email_verified") is not True:
                return False
            self.accepted_at = time.monotonic()
            return True
        except Exception:
            return False


def wait_after_submit(worker, page, reference, error_type, timeout=60, navigation_timeout=30):
    progress = worker._email_otp_progress
    response_deadline = time.monotonic() + timeout
    while True:
        worker._raise_if_stopped()
        fatal = getattr(worker, "_fatal_auth_error", "")
        if fatal:
            raise RuntimeError(fatal)
        if getattr(worker, "_email_otp_invalid_response", False):
            worker._email_otp_invalid_response = False
            raise reference.InvalidEmailOtpError("邮箱验证码被服务器判定为无效")
        if worker._has_chatgpt_session(page):
            return
        chatgpt_page = worker._context_has_chatgpt_page(page)
        if not chatgpt_page:
            if "about-you" in page.url or worker._has_about_you_form(page):
                return
            if not ("email-verification" in page.url or worker._has_otp_input(page)):
                return
        accepted = progress.accepted_at
        if accepted is None:
            text = worker._page_text_summary(page).lower()
            if progress.accepted_at is None and any(marker in text for marker in (
                "incorrect code", "invalid code", "code is incorrect",
                "验证码不正确", "验证码无效", "驗證碼不正確", "驗證碼無效",
                "コードが正しく", "無効なコード",
            )):
                raise reference.InvalidEmailOtpError("邮箱验证码被服务器判定为无效")
        # Read again: Playwright calls above may have dispatched the response.
        worker._raise_if_stopped()
        if getattr(worker, "_email_otp_invalid_response", False):
            worker._email_otp_invalid_response = False
            raise reference.InvalidEmailOtpError("邮箱验证码被服务器判定为无效")
        accepted = progress.accepted_at
        deadline = response_deadline if accepted is None else accepted + navigation_timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if chatgpt_page:
                return  # The outer state machine still requires a real session.
            reason = "response_timeout" if accepted is None else "navigation_timeout"
            emit(worker.log, "otp_validation", result=reason)
            raise error_type("headed_chrome_otp_" + reason)
        # A blocking Python sleep starves Playwright route/response callbacks.
        page.wait_for_timeout(min(250, remaining * 1000))
