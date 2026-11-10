"""Observe the site's retries without replaying registration requests."""
from __future__ import annotations

import time

from core.registration_terminal_response import observe_registration_response, registration_endpoint
from .diagnostics import emit


class RegistrationResponseGuard:
    def __init__(self, log, page=None, clock=time.monotonic):
        self.log, self.page, self.clock = log, page, clock
        self.pending = {}
        self.create_result = None
        self.create_seen = False
        self.create_had_service_error = False
        self.requests = {}
        self.phase = 0
        self.generation = 0
        self.known_requests = {}

    def request(self, request):
        if not self.owns(request):
            return
        endpoint = registration_endpoint(getattr(request, "url", ""), getattr(request, "method", ""))
        if endpoint:
            if endpoint == "authorize":
                self.generation += 1
                self.pending.clear()
                self.requests.clear()
                self.phase = 0
                self.reset_create()
            self.requests[endpoint] = request
            self.known_requests[id(request)] = (request, self.generation)
            if len(self.known_requests) > 128:
                self.known_requests.pop(next(iter(self.known_requests)))

    def owns(self, request):
        if self.page is None:
            return True  # Compatibility for observers installed before page binding.
        try:
            return request.frame == self.page.main_frame
        except Exception:
            return False

    def current_request(self, request):
        if not self.owns(request):
            return False
        endpoint = registration_endpoint(getattr(request, "url", ""), getattr(request, "method", ""))
        if endpoint is None:
            return False
        known = self.known_requests.get(id(request))
        if known is None or known[0] is not request or known[1] != self.generation:
            return False
        if endpoint in self.requests and request is not self.requests[endpoint]:
            return False
        phase = {"authorize": 0, "user_register": 1, "email_otp_send": 2,
                 "email_otp_validate": 3, "create_account": 4}.get(endpoint)
        # The signup UI can send a passwordless OTP before switching to password.
        # This is still the same auth generation; later validation/create phases
        # continue to reject delayed password responses.
        if endpoint == "user_register" and self.phase == 2:
            return True
        return phase is None or phase >= self.phase

    def observe(self, response):
        if not self.current_request(getattr(response, "request", None)):
            return None
        evidence = observe_registration_response(response, is_current=self.current_request)
        if evidence is None:
            return None
        terminal = evidence.get("terminal_code")
        endpoint, status = evidence["endpoint"], evidence["status"]
        phase = {"authorize": 0, "user_register": 1, "email_otp_send": 2,
                 "email_otp_validate": 3, "create_account": 4}.get(endpoint)
        if phase is not None and 200 <= status < 400:
            self.phase = max(self.phase, phase)
            for name in list(self.pending):
                if name != endpoint:
                    self.pending.pop(name)
        if endpoint == "create_account":
            self.create_seen = True
            self.create_result = evidence
            if 500 <= status <= 599:
                self.create_had_service_error = True
        if evidence["result"] == "challenge":
            self.pending.pop(endpoint, None)
            return terminal
        # The site can use its cookie fallback when the dump fetch is unavailable.
        # A missing-session *page* is detected separately; this fetch alone is not fatal.
        if endpoint == "client_auth_session_dump":
            return terminal
        if 500 <= status <= 599:
            item = self.pending.setdefault(endpoint, {"started": self.clock(), "responses": 0})
            item["responses"] += 1
            item["status"] = status
            request = response.request
            try:
                navigation = request.is_navigation_request() is True
            except Exception:
                navigation = False
            item["navigation"] = navigation
            emit(self.log, "auth_service_error", endpoint=endpoint, status=status,
                 responses=item["responses"], waiting_for_site_retry=not navigation)
        else:
            self.pending.pop(endpoint, None)
        return terminal

    def failure_code(self, *, force=False):
        for endpoint, item in self.pending.items():
            # Document errors have no site fetch retry. Fetch errors get at most
            # 30 seconds for the site's own retry; we never submit another request.
            if force or item["navigation"] or item["responses"] >= 2 or self.clock() - item["started"] >= 30:
                return "headed_chrome_auth_service_unavailable"
        return None

    def recovering_create(self):
        result = self.create_result or {}
        return self.create_seen and (
            self.create_had_service_error or result.get("result") == "login_required")

    def reset_create(self):
        self.create_result = None
        self.create_seen = False
        self.create_had_service_error = False
        self.pending.pop("create_account", None)


def wait_for_create_transition(worker, page, before_url, guard, error_type):
    """Resume after the vendor sees an intermediate 5xx, without clicking again."""
    deadline = time.monotonic() + 30
    emit(worker.log, "account_create_wait", result="waiting_for_site_retry")
    while True:
        worker._raise_if_stopped()
        result = guard.create_result or {}
        if result.get("result") == "login_required":
            # Wait until the error page is actually rendered. The outer canonical
            # loop then performs its existing once-only login recovery.
            if worker._is_user_already_exists_error(page):
                emit(worker.log, "account_create_wait", result="continue_to_login")
                return True
        elif 200 <= result.get("status", 0) < 300 and worker._about_you_submit_done(page, before_url):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            code = ("headed_chrome_existing_login_unavailable" if result.get("result") == "login_required"
                    else "headed_chrome_account_create_navigation_timeout" if 200 <= result.get("status", 0) < 300
                    else "headed_chrome_auth_service_unavailable")
            raise error_type(code)
        page.wait_for_timeout(min(250, remaining * 1000))


def wait_auth_events(worker, seconds, fallback):
    page = getattr(worker, "_headed_auth_page", None)
    if page is None or page.is_closed():
        return fallback(seconds)
    deadline = time.monotonic() + max(0.0, seconds)
    while True:
        worker._raise_if_stopped()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        page.wait_for_timeout(min(250, remaining * 1000))
