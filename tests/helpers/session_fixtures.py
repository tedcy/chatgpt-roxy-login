"""Reusable ChatGPT session-refresh test fixtures."""

import base64
import json


def _jwt(
    email="user@example.test",
    user_id="user-1",
    account_id="account-1",
    marker="new",
    exp=None,
):
    payload = {
        "https://api.openai.com/profile": {"email": email},
        "https://api.openai.com/auth": {
            "chatgpt_user_id": user_id,
            "chatgpt_account_id": account_id,
        },
        "marker": marker,
    }
    if exp is not None:
        payload["exp"] = exp
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"header.{encoded}.signature"


def _account(token=None):
    return {
        "id": 7,
        "email": "user@example.test",
        "user_id": "user-1",
        "account_id": "account-1",
        "access_token": token or _jwt(marker="old"),
    }

def _record():
    return {
        "email": "user@example.test",
        "account_id": 7,
        "cookies": [
            {
                "name": "__Secure-next-auth.session-token",
                "value": "session-secret",
                "domain": ".chatgpt.com",
                "path": "/",
            }
        ],
        "session_expires_at": "2099-01-01T00:00:00+00:00",
        "status": "ready",
    }


def _session_info(token=None, *, email="user@example.test"):
    return {
        "accessToken": token or _jwt(email=email, marker="new"),
        "user": {"email": email, "id": "user-1"},
        "account": {"id": "account-1", "planType": "plus"},
        "expires": "2099-01-01T00:00:00+00:00",
    }
