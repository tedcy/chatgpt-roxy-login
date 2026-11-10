"""Private confirmation metadata bound to one registration password candidate."""
from __future__ import annotations

import hashlib
import json

PENDING = "pending_registration"
CONFIRMED = "confirmed"


def can_resume_without_password(row: dict) -> bool:
    return row.get("email_source") == "icloud_hme" or (
        row.get("registration_driver") == "go_protocol"
        and row.get("registration_stage") in {
            "email_acquired", "account_created_pending_session", "identity_review_required"
        }
    )


def password_metadata(row: dict) -> dict:
    try:
        extra = json.loads(row.get("extra_json") or "{}")
    except (TypeError, ValueError):
        extra = {}
    return extra if isinstance(extra, dict) else {}


def bind_password_state(extra: dict, password: str, state: str) -> None:
    extra["registration_password_state"] = (
        CONFIRMED if password and state == CONFIRMED else PENDING
    )
    extra["registration_password_fingerprint"] = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


def read_password_state(row: dict, password: str) -> str:
    extra = password_metadata(row)
    fingerprint = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return (
        CONFIRMED
        if password and extra.get("registration_password_state") == CONFIRMED
        and extra.get("registration_password_fingerprint") == fingerprint
        else PENDING
    )


def merge_auth_fields(fields: dict, incoming: dict) -> None:
    """Changing a candidate must never inherit the previous confirmation."""
    if incoming.get("openai_password") and (
        incoming["openai_password"] != fields.get("openai_password")
    ):
        fields["openai_password_state"] = PENDING
    fields.update(incoming)
