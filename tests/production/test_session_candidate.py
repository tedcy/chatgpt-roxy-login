from __future__ import annotations

import base64
import json
import time

import pytest

from core.chatgpt_session_refresh import ChatGPTSessionRefreshError
from core.session_candidate import (
    SessionCommitPolicy,
    validate_session_candidate,
    validate_session_identity,
)


def _token(*, email: str, user_id: str = "user-1", account_id: str = "acct-1", exp=None) -> str:
    payload = {
        "https://api.openai.com/profile": {"email": email},
        "https://api.openai.com/auth": {
            "chatgpt_user_id": user_id,
            "chatgpt_account_id": account_id,
        },
    }
    if exp is not None:
        payload["exp"] = exp
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


def test_identity_validator_is_shared_and_checks_all_known_ids() -> None:
    account = {
        "email": "user@example.test",
        "user_id": "user-1",
        "account_id": "acct-1",
    }
    validate_session_identity(
        account,
        {
            "user": {"email": "user@example.test", "id": "user-1"},
            "account": {"id": "acct-1"},
        },
        _token(email="user@example.test"),
    )

    with pytest.raises(ChatGPTSessionRefreshError) as caught:
        validate_session_identity(
            account,
            {"user": {"email": "other@example.test"}, "account": {"id": "acct-1"}},
            _token(email="other@example.test"),
        )
    assert caught.value.error_code == "session_identity_email_mismatch"


def test_candidate_policy_rejects_expired_and_same_token() -> None:
    token = _token(email="user@example.test", exp=time.time() - 60)
    account = {"email": "user@example.test", "access_token": token}
    with pytest.raises(ChatGPTSessionRefreshError) as caught:
        validate_session_candidate(
            account,
            {"user": {"email": "user@example.test"}},
            token,
        )
    assert caught.value.error_code == "token_expired"

    fresh = _token(email="user@example.test", exp=time.time() + 600)
    with pytest.raises(ChatGPTSessionRefreshError) as caught:
        validate_session_candidate(
            {"email": "user@example.test", "access_token": fresh},
            {"user": {"email": "user@example.test"}},
            fresh,
            policy=SessionCommitPolicy(require_token_change=True),
        )
    assert caught.value.error_code == "session_probe_same_token"
