"""Shared, credential-safe selection of ChatGPT authentication factors.

The existing tasks (session refresh, 2FA, password setup, Codex and email
change) all need the same small decision: whether the account has a saved
ChatGPT password and/or a committed TOTP secret.  This module keeps that
decision in one place without deciding how a caller should fall back.

Secrets are kept in memory only.  Dataclass repr is disabled for the secret
fields so accidental diagnostics cannot include them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from core import db
from core.roxy_login_primitives import normalise_totp_secret


AuthFactor = Literal["password_totp", "password", "email_otp", "invalid_totp"]


@dataclass(frozen=True, slots=True)
class LoginAuthPolicy:
    """Credential-free policy for one existing-account login.

    The policy deliberately contains only booleans and the factor label.  It
    is safe to pass through task/driver boundaries without exposing the
    password or TOTP secret held by :class:`ChatGPTAuthFactors`.
    """

    factor: AuthFactor
    mailbox_access: bool
    allow_email_otp: bool
    require_password: bool
    require_totp: bool

    @property
    def password_totp(self) -> bool:
        return self.factor == "password_totp"


def resolve_login_policy(account: Mapping[str, Any] | None) -> LoginAuthPolicy:
    """Resolve the shared existing-account login policy.

    A committed password and a validated committed TOTP are a strict
    password+authenticator login.  In that mode no caller may prepare or use
    a mailbox as a fallback. Incomplete committed credentials permit email
    OTP independently of any requirement to verify a candidate password.
    """

    saved_policy = (account or {}).get("_committed_login_policy")
    if isinstance(saved_policy, LoginAuthPolicy):
        return saved_policy
    factors = load_chatgpt_auth_factors(account)
    strict = factors.factor == "password_totp"
    return LoginAuthPolicy(
        factor=factors.factor,
        mailbox_access=not strict,
        allow_email_otp=not strict,
        require_password=strict,
        require_totp=strict,
    )


def project_login_password(account: Mapping[str, Any], password: str) -> dict:
    """Project a candidate without upgrading committed credential policy.

    This private credential-free snapshot belongs only to the login projection,
    never to a persisted account update.
    """
    result = dict(account)
    result["_committed_login_policy"] = resolve_login_policy(account)
    result["registration_password"] = password
    return result


@dataclass(frozen=True, slots=True)
class ChatGPTAuthFactors:
    """Resolved factors for an existing ChatGPT account.

    ``password`` and ``totp_secret`` deliberately do not participate in
    ``repr``.  Callers must not log or persist this object as a diagnostic.
    ``totp_secret`` is normalized only after validation and is never sourced
    from a pending enrollment value.
    """

    factor: AuthFactor
    password: str = field(default="", repr=False)
    totp_secret: str = field(default="", repr=False)

    @property
    def password_present(self) -> bool:
        return bool(self.password)

    @property
    def totp_present(self) -> bool:
        return bool(self.totp_secret)

    @property
    def totp_valid(self) -> bool:
        return self.factor == "password_totp"


def _account_password(account: Mapping[str, Any]) -> str:
    """Read only the private ChatGPT password accessor.

    The database helper understands the supported legacy layouts.  There is
    intentionally no fallback to ``account['password']`` because that field
    belongs to the mailbox provider, not ChatGPT.
    """

    try:
        value = db.account_registration_password(dict(account))
    except Exception:
        return ""
    return str(value or "").strip()


def load_chatgpt_auth_factors(account: Mapping[str, Any] | None) -> ChatGPTAuthFactors:
    """Return the committed ChatGPT login factors for ``account``.

    The result reports ``invalid_totp`` when a password exists but the
    committed TOTP value fails the shared validator.  Callers decide whether
    that is a hard error or whether an email OTP fallback is appropriate for
    their own flow; this helper never makes that policy decision.
    """

    row: Mapping[str, Any] = account if isinstance(account, Mapping) else {}
    password = _account_password(row)
    raw_secret = str(row.get("totp_secret") or "").strip()
    if not password:
        return ChatGPTAuthFactors("email_otp")
    if not raw_secret:
        return ChatGPTAuthFactors("password", password=password)
    try:
        secret = normalise_totp_secret(raw_secret)
    except Exception:
        return ChatGPTAuthFactors("invalid_totp", password=password)
    return ChatGPTAuthFactors(
        "password_totp",
        password=password,
        totp_secret=secret,
    )


def read_committed_totp_secret(account: Mapping[str, Any] | None) -> str:
    """Validate and return only the committed TOTP secret.

    This lower-level helper is used by the shared browser MFA primitive when a
    TOTP challenge is already visible, including accounts without a saved
    ChatGPT password.  It deliberately preserves the validator's fixed
    ``TotpSecretError`` codes for existing callers.
    """

    row: Mapping[str, Any] = account if isinstance(account, Mapping) else {}
    return normalise_totp_secret(row.get("totp_secret"))


__all__ = [
    "AuthFactor",
    "ChatGPTAuthFactors",
    "LoginAuthPolicy",
    "load_chatgpt_auth_factors",
    "resolve_login_policy",
    "read_committed_totp_secret",
]
