"""Ephemeral, credential-free evidence from one authentication attempt."""
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LoginEvidence:
    password_verified: bool = False
    email_otp_verified: bool = False
    totp_verified: bool = False


class AuthenticatedSession(dict):
    """Session mapping whose evidence is not serialized as provider data."""

    def __init__(self, info, *, password_verified=False, email_otp_verified=False, totp_verified=False):
        super().__init__(info)
        self.login_evidence = LoginEvidence(
            bool(password_verified), bool(email_otp_verified), bool(totp_verified))


def password_was_verified(result) -> bool:
    evidence = getattr(result, 'login_evidence', None)
    return isinstance(evidence, LoginEvidence) and evidence.password_verified


class BrowserLoginEvidence:
    """Observe only this attempt's auth responses, never request secrets."""

    def __init__(self):
        self.password_submitted = False
        self.password_verified = False
        self.email_otp_verified = False
        self.totp_verified = False

    def observe_response(self, response):
        from urllib.parse import urlsplit
        try:
            url = urlsplit(response.url)
            if url.hostname != 'auth.openai.com' or response.request.method != 'POST':
                return
            if url.path not in {'/api/accounts/password/verify', '/api/accounts/email-otp/validate', '/api/accounts/mfa/verify'}:
                return
            data = response.json()
            accepted = (response.status == 200 and isinstance(data, dict) and not data.get('error')
                        and data.get('success') is not False and data.get('ok') is not False)
            if url.path.endswith('/password/verify') and self.password_submitted:
                self.password_verified = accepted
            elif url.path.endswith('/email-otp/validate'):
                self.email_otp_verified = accepted
            elif url.path.endswith('/mfa/verify'):
                payload = response.request.post_data_json
                if isinstance(payload, dict) and payload.get('type') == 'totp':
                    self.totp_verified = accepted
        except Exception:
            return

    def session(self, info):
        return AuthenticatedSession(info, password_verified=self.password_verified,
                                    email_otp_verified=self.email_otp_verified,
                                    totp_verified=self.totp_verified)
