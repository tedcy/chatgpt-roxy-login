"""Shared contracts for authenticated ChatGPT Session candidates.

The refresh domain remains the owner of the historical persistence code for
now.  This module provides the neutral candidate types and the single public
validation entry point used by other maintenance flows; compatibility wrappers
below keep old imports and monkey-patching seams working while callers migrate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(slots=True)
class SessionTokenCandidate:
    """An uncommitted HTTP Session/token pair with secrets hidden from repr."""

    account_id: int
    email: str
    old_token_fingerprint: str
    new_token_fingerprint: str
    session_rotated: bool
    probe_count: int
    access_token: str = field(repr=False)
    expected_old_token: str = field(repr=False)
    session_info: dict = field(repr=False)
    snapshot: dict = field(repr=False)
    route: dict = field(repr=False)
    exchange_method: str = "http_session"
    login_evidence: Any = field(default=None, repr=False)


@dataclass(slots=True)
class RoxyLoginCandidate:
    """An identity-checked browser login that has not been persisted."""

    account_id: int
    login_email: str
    old_token_fingerprint: str
    new_token_fingerprint: str
    session_rotated: bool
    access_token: str = field(repr=False)
    expected_old_token: str = field(repr=False)
    session_info: dict = field(repr=False)
    snapshot: dict = field(repr=False)
    login_evidence: Any = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class SessionCommitPolicy:
    """Explicit safety requirements for a caller's Session commit."""

    require_nonexpired_token: bool = True
    require_token_change: bool = False
    require_backend_me: bool = False
    clear_refresh_required: bool = True
    source: str = "unknown"


def build_roxy_login_candidate(
    account: dict,
    *,
    login_email: str,
    driver,
    session_info: dict,
) -> RoxyLoginCandidate:
    """Build a strict browser candidate through the reviewed validator.

    The historical builder remains locked in the Roxy domain because it owns
    the browser-side ``/backend-api/me`` probe.  This neutral wrapper keeps
    headed maintenance off that private import path while preserving the
    exact validation and candidate shape.
    """

    # ``roxy_auth_domains.candidate`` is a source-domain wrapper whose
    # implementation is registered into the historical refresh facade.  It
    # intentionally does not expose the private builder as a module
    # attribute.  Resolve the already-loaded compatibility facade instead of
    # importing a symbol that cannot exist on the wrapper module.
    from core import chatgpt_session_refresh

    _build_roxy_login_candidate = getattr(
        chatgpt_session_refresh,
        "_build_roxy_login_candidate",
        None,
    )
    if not callable(_build_roxy_login_candidate):
        raise RuntimeError("roxy_login_candidate_builder_unavailable")

    return _build_roxy_login_candidate(
        account,
        login_email=login_email,
        driver=driver,
        session_info=session_info,
    )


def validate_session_identity(account: dict, session_info: dict, token: str) -> None:
    """Validate email, user ID and ChatGPT account ID against the local row."""

    from core.chatgpt_plan import token_claims
    from core.chatgpt_session_refresh import ChatGPTSessionRefreshError

    info = session_info if isinstance(session_info, dict) else {}
    user = info.get("user") if isinstance(info.get("user"), dict) else {}
    remote_account = (
        info.get("account") if isinstance(info.get("account"), dict) else {}
    )
    claims = token_claims(token or "")
    emails = {
        str(value or "").strip().lower()
        for value in (user.get("email"), claims.get("email"))
        if str(value or "").strip()
    }
    user_ids = {
        str(value or "").strip()
        for value in (user.get("id"), claims.get("user_id"))
        if str(value or "").strip()
    }
    account_ids = {
        str(value or "").strip()
        for value in (remote_account.get("id"), claims.get("account_id"))
        if str(value or "").strip()
    }
    expected_email = str(account.get("email") or "").strip().lower()
    from core.session_identity_diagnostic import identity_failure
    if not expected_email or not emails or emails != {expected_email}:
        identity_failure(account, source="session_token", code="session_identity_email_mismatch", session=info, claims=claims)
        raise ChatGPTSessionRefreshError(
            "session_identity_email_mismatch",
            "刷新得到的登录账号与本地账号不一致",
        )
    expected_user = str(account.get("user_id") or "").strip()
    if expected_user and user_ids != {expected_user}:
        identity_failure(account, source="session_token", code="session_identity_user_mismatch", session=info, claims=claims)
        raise ChatGPTSessionRefreshError(
            "session_identity_user_mismatch",
            "刷新得到的用户身份与本地账号不一致",
        )
    expected_account = str(account.get("account_id") or "").strip()
    if expected_account and account_ids != {expected_account}:
        identity_failure(account, source="session_token", code="session_identity_account_mismatch", session=info, claims=claims)
        raise ChatGPTSessionRefreshError(
            "session_identity_account_mismatch",
            "刷新得到的 ChatGPT 账户与本地账号不一致",
        )


def validate_session_candidate(
    account: dict,
    session_info: dict,
    token: str,
    *,
    policy: SessionCommitPolicy | None = None,
    backend_checker: Callable[[str], Any] | None = None,
) -> None:
    """Validate a candidate before any persistence side effect."""

    from core.chatgpt_plan import normalize_token, token_claims

    selected = policy or SessionCommitPolicy()
    normalized = normalize_token(token or "")
    if not normalized:
        from core.chatgpt_session_refresh import ChatGPTSessionRefreshError

        raise ChatGPTSessionRefreshError(
            "session_refresh_empty",
            "登录完成但未取得 access token",
        )
    if selected.require_nonexpired_token and token_claims(normalized).get("token_expired") is True:
        from core.chatgpt_session_refresh import ChatGPTSessionRefreshError

        raise ChatGPTSessionRefreshError(
            "token_expired",
            "登录完成但 access token 已过期",
        )
    validate_session_identity(account, session_info, normalized)
    if selected.require_token_change:
        old = normalize_token(account.get("access_token") or "")
        if old and old == normalized:
            from core.chatgpt_session_refresh import ChatGPTSessionRefreshError

            raise ChatGPTSessionRefreshError(
                "session_probe_same_token",
                "登录完成但 access token 未发生变化",
            )
    if selected.require_backend_me:
        if not callable(backend_checker) or not bool(backend_checker(normalized)):
            from core.chatgpt_session_refresh import ChatGPTSessionRefreshError

            raise ChatGPTSessionRefreshError(
                "session_business_invalid",
                "登录完成但后端 Session 验活失败",
            )


def save_roxy_login_candidate_for_account(account: dict, candidate: RoxyLoginCandidate) -> dict:
    """Compatibility entry point for the canonical Roxy candidate commit."""

    from core import chatgpt_session_refresh as _runtime

    _save = getattr(_runtime, "save_roxy_login_candidate_for_account", None)
    if not callable(_save):
        raise RuntimeError("roxy_login_candidate_saver_unavailable")

    return _save(account, candidate)


def save_driver_session_for_account(account: dict, driver, session_info: dict) -> dict:
    """Compatibility entry point for a verified browser Session commit."""

    from core import chatgpt_session_refresh as _runtime

    _save = getattr(_runtime, "save_driver_session_for_account", None)
    if not callable(_save):
        raise RuntimeError("driver_session_saver_unavailable")

    return _save(account, driver, session_info)


def commit_session_candidate(
    account: dict,
    candidate: SessionTokenCandidate | RoxyLoginCandidate,
    *,
    policy: SessionCommitPolicy | None = None,
) -> dict:
    """Commit a candidate through the existing CAS implementation.

    This dispatcher intentionally delegates to the established refresh-domain
    writers so revision, lock order, snapshots and refresh-marker semantics do
    not change during the extraction.
    """

    selected = policy or SessionCommitPolicy()
    validate_session_candidate(
        account,
        candidate.session_info,
        candidate.access_token,
        policy=selected,
    )
    if isinstance(candidate, RoxyLoginCandidate):
        return save_roxy_login_candidate_for_account(account, candidate)
    from core import chatgpt_session_refresh as _runtime

    commit_access_token_candidate = getattr(
        _runtime,
        "commit_access_token_candidate",
        None,
    )
    if not callable(commit_access_token_candidate):
        raise RuntimeError("access_token_candidate_committer_unavailable")
    return commit_access_token_candidate(candidate)


__all__ = [
    "SessionTokenCandidate",
    "RoxyLoginCandidate",
    "SessionCommitPolicy",
    "build_roxy_login_candidate",
    "validate_session_identity",
    "validate_session_candidate",
    "commit_session_candidate",
    "save_driver_session_for_account",
    "save_roxy_login_candidate_for_account",
]
