"""Public existing-account Roxy login runtime.

The implementation is still hosted by the session-refresh domain during the
compatibility migration.  Keeping this adapter independent gives 2FA,
password setup, Codex and email-change callers one stable interface without
duplicating Profile/Driver lifecycle code.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any

from core.session_candidate import RoxyLoginCandidate


@dataclass(frozen=True, slots=True)
class RoxyLoginOptions:
    login_email: str | None = None
    headless: bool | None = None
    proxy_country: str | None = None
    allow_manual_login: bool = True
    stop_event: Any = None
    task_kind: str = "session_refresh"
    allow_headed_auth: bool = True
    operation_only: bool = False
    restore_saved_session: bool = False
    reset_profile_identity: bool = True
    defer_email_otp_context: bool = False
    mailbox_access: bool | None = None
    allow_email_otp: bool | None = None
    strict_password: bool = False
    slot_already_acquired: bool = False
    stage_callback: Any = None
    excluded_profile_ids: Any = None
    login_function: Any = None
    profile_operation_lock: Any = None
    registration_route_hint: Any = field(default=None, repr=False)


def _kwargs(options: RoxyLoginOptions | None, extra: dict[str, Any]) -> dict[str, Any]:
    # ``dataclasses.asdict`` deep-copies stop Events, locks and test doubles;
    # keep those runtime objects by reference.
    values = (
        {item.name: getattr(options, item.name) for item in fields(options)}
        if options is not None
        else {}
    )
    values.update({key: value for key, value in extra.items() if value is not None})
    # ``allow_email_otp`` is part of the neutral facade's compatibility
    # options, but the Roxy candidate/login kernels accept only
    # ``mailbox_access``.  Convert it here at the actual driver boundary and
    # never forward an unknown keyword into the locked implementation.
    allow_email_otp = values.pop("allow_email_otp", None)
    if values.get("mailbox_access") is None and allow_email_otp is not None:
        values["mailbox_access"] = bool(allow_email_otp)
    return values


def open_existing_account_login(
    account: dict,
    *,
    options: RoxyLoginOptions | None = None,
    **kwargs,
):
    """Open a reusable login lease without committing its Session."""

    from core import chatgpt_session_refresh as _runtime

    return _runtime.open_roxy_login_candidate_lease(
        account,
        **_kwargs(options, kwargs),
    )


def run_existing_account_login(
    account: dict,
    *,
    options: RoxyLoginOptions | None = None,
    **kwargs,
) -> RoxyLoginCandidate:
    """Run one existing-account login and return an uncommitted candidate."""

    from core import chatgpt_session_refresh as _runtime

    return _runtime.run_roxy_login_candidate(
        account,
        **_kwargs(options, kwargs),
    )


def save_existing_account_login(account: dict, candidate: RoxyLoginCandidate) -> dict:
    from core import chatgpt_session_refresh as _runtime

    return _runtime.save_roxy_login_candidate_for_account(account, candidate)


def wait_for_visible_login(*args, **kwargs):
    """Delegate to the canonical shared factor state machine."""

    from core.chatgpt_session_refresh import _wait_for_visible_login

    values = dict(kwargs)
    allow_email_otp = values.pop("allow_email_otp", None)
    if values.get("mailbox_access") is None and allow_email_otp is not None:
        values["mailbox_access"] = bool(allow_email_otp)
    return _wait_for_visible_login(*args, **values)


def is_authenticator_mfa_page(*args, **kwargs):
    from core.chatgpt_session_refresh import _is_authenticator_mfa_page

    return _is_authenticator_mfa_page(*args, **kwargs)


def submit_authenticator_mfa_code(*args, **kwargs):
    from core.chatgpt_session_refresh import _submit_authenticator_mfa_code

    return _submit_authenticator_mfa_code(*args, **kwargs)


def submit_email_otp_once(*args, **kwargs):
    from core.chatgpt_session_refresh import _submit_email_otp_once

    return _submit_email_otp_once(*args, **kwargs)


__all__ = [
    "RoxyLoginOptions",
    "open_existing_account_login",
    "run_existing_account_login",
    "save_existing_account_login",
    "wait_for_visible_login",
    "is_authenticator_mfa_page",
    "submit_authenticator_mfa_code",
    "submit_email_otp_once",
]
