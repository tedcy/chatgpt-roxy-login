"""Passive evidence for this attempt's candidate password login."""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit


class CandidatePasswordEvidence:
    def __init__(self):
        self.requests = {}
        self.accepted = ""

    @staticmethod
    def fingerprint(password):
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def request(self, request, password):
        url = urlsplit(str(getattr(request, "url", "") or ""))
        if url.hostname != "auth.openai.com" or request.method.upper() != "POST":
            return
        if url.path == "/api/accounts/authorize/continue":
            self.requests.clear()
            self.accepted = ""
        if url.path != "/api/accounts/password/verify":
            return
        self.accepted = ""
        self.requests.clear()
        try:
            body = json.loads(request.post_data or "{}")
        except (TypeError, ValueError):
            return
        if password and isinstance(body, dict) and body.get("password") == password:
            self.requests[id(request)] = (request, self.fingerprint(password))

    def response(self, response):
        request = getattr(response, "request", None)
        entry = self.requests.pop(id(request), None)
        if entry is None or entry[0] is not request:
            return
        if not 200 <= int(response.status) < 300:
            return
        try:
            body = response.json()
        except Exception:
            return
        if (not isinstance(body, dict) or body.get("error") or body.get("error_code")
                or body.get("success") is False or body.get("ok") is False):
            return
        self.accepted = entry[1]

    def confirms(self, password):
        return bool(password and self.accepted == self.fingerprint(password))
