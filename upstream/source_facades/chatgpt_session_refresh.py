# -*- coding: utf-8 -*-
"""Refresh invalid ChatGPT access tokens from a stored Web session.

This module owns both the quiet server-side refresh used by plan checks and
the maintenance re-login task used when no usable Web session is available.
The owner is selected by ``SESSION_REFRESH_DRIVER``; browser callers may still
override visibility for bounded batch work. Cookie/token values are
deliberately excluded from all log lines and public task results.
"""
from __future__ import annotations
from core.task_concurrency import AdaptiveExecutor, RuntimeGate, QueueSlots, operation_limit, normalize_workers, query_default

import hashlib
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from collections.abc import Callable, Iterator
from urllib.parse import urlparse

from core import account_operation_log, action_progress, db
from core.chatgpt_plan import (
    check_account_plan,
    check_account_plan_in_driver,
    normalize_token,
    now_iso,
    plan_check_region_settings,
    resolve_plan_check_route,
    resolve_plan_check_region_route,
    token_claims,
)
from core.chatgpt_session_store import (
    apply_session_cookie_rotation,
    can_revalidate_session,
    ChatGPTSessionStoreError,
    capture_driver_snapshot,
    get_session,
    has_complete_session_cookie,
    has_session_cookie,
    hydrate_browser_session,
    mark_invalid,
    record_quiet_refresh,
    record_status,
    normalise_cookies,
    save_snapshot,
    snapshot_from_http_session,
)
from core.openai_auth import AccountUnusableError, detect_account_unusable_text
from core.session import BrowserSession
from core.roxy_chatgpt_contract_trace import RoxyChatGPTContractTracer
from core.task_queue_helpers import AdjustableConcurrencyGate as _AdjustableConcurrencyGate
from core.roxy_login_primitives import PASSWORD_SUBMIT_TRANSITION_TIMEOUT
from core.session_candidate import RoxyLoginCandidate, SessionTokenCandidate


logger = logging.getLogger(__name__)
_SESSION_REFRESH_DEFAULT_WORKERS = 15
_SESSION_REFRESH_MAX_WORKERS = operation_limit("session_refresh")
_SESSION_URL = "https://chatgpt.com/api/auth/session"
_SESSION_EXCHANGE_IMPLEMENTATION = "hidden_browser_runtime"
_MANUAL_LOGIN_TIMEOUT = 300
_SESSION_AFTER_OTP_TIMEOUT = 40
# Roxy may need a few render/network cycles to publish the restored
# ``/api/auth/session`` payload.  Twenty-four seconds was short enough to
# classify a session that was visibly restored as ``session_not_published``
# and unnecessarily fall back to a fresh email login.  Keep this bounded,
# but give the browser a full minute before taking that fallback.
_SAVED_SESSION_PROBE_TIMEOUT = 60
_SAFE_SESSION_RESTORE_REASONS = frozenset({
    "account_email_missing",
    "session_record_read_failed",
    "session_record_missing",
    "session_browser_cookie_restore_failed",
    "session_cookie_missing",
    "session_cookie_missing_after_refresh",
    "session_snapshot_invalid",
    "session_identity_mismatch",
    "session_not_published",
    "session_business_invalid",
    "session_restore_failed",
    "token_expired",
})


def _safe_session_restore_reason(value: object) -> str:
    """Map an internal restore exception to a fixed, non-sensitive code."""

    reason = str(value or "").strip().lower()
    return reason if reason in _SAFE_SESSION_RESTORE_REASONS else "session_restore_failed"


_AUTOMATIC_EXECUTOR = AdaptiveExecutor("session_refresh", thread_name_prefix="session-refresh-automatic",
    default=lambda: _ROXY_BROWSER_SLOTS.snapshot()["configured"] if hasattr(_ROXY_BROWSER_SLOTS, "snapshot") else _SESSION_REFRESH_DEFAULT_WORKERS)
# Headless and visible logins share this gate, including manual fallback.
# Window visibility must not introduce a second, serial concurrency limit.
_ROXY_BROWSER_SLOTS = RuntimeGate("session_refresh", _SESSION_REFRESH_DEFAULT_WORKERS)
_QUEUE_SLOTS = QueueSlots("session_refresh", 50)
_ACCOUNT_LOCKS_GUARD = threading.Lock()
_ACCOUNT_LOCKS: dict[int, threading.Lock] = {}


def _normalise_worker_count(value: object, *, default: int | None = None) -> int:
    fallback = _SESSION_REFRESH_DEFAULT_WORKERS if default is None else int(default)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(1, min(operation_limit("session_refresh"), parsed))


def configure_worker_limit(value: object = None) -> int:
    """Set and return the shared headless/visible login concurrency."""

    configured = _normalise_worker_count(value)
    setter = getattr(_ROXY_BROWSER_SLOTS, "set_limit", None)
    if callable(setter):
        return int(setter(configured))
    # Test doubles and older embedders may still provide a semaphore-shaped
    # object without a resizable limit; keep the hard cap behavior intact.
    return configured


def _effective_headless(headless: bool | None) -> bool:
    from config import roxybrowser as roxy_cfg

    return bool(
        getattr(roxy_cfg, "ROXY_OPEN_HEADLESS", False)
        if headless is None
        else headless
    )


class ChatGPTSessionRefreshError(RuntimeError):
    def __init__(self, error_code: str, message: str = ""):
        super().__init__(message or error_code)
        self.error_code = str(error_code or "session_refresh_failed")
        self.user_message = str(message or self.error_code)


# Maintenance authentication does not inherit an account's registration
# country; registration and plan-check routes keep their existing policy.
_MAINTENANCE_PROXY_COUNTRY = "US"


def _resolve_maintenance_us_route(*, check_stop=None) -> dict:
    """Select one validated US Sticky SID for a maintenance task."""
    try:
        route = resolve_plan_check_region_route(_MAINTENANCE_PROXY_COUNTRY)
    except Exception as exc:
        raise ChatGPTSessionRefreshError(
            "session_refresh_network_config_error",
            "US 维护代理不可用，无法刷新 Session",
        ) from exc
    if not str(route.get("proxy") or "").strip() or str(
        route.get("plan_region") or ""
    ).strip().upper() != _MAINTENANCE_PROXY_COUNTRY:
        raise ChatGPTSessionRefreshError(
            "session_refresh_network_config_error",
            "US 维护代理不可用，无法刷新 Session",
        )
    return dict(route)


_INTERACTIVE_LOGIN_ERROR_CODES = frozenset({
    "session_missing",
    "session_stale",
    "session_invalid",
    "session_auth_invalid",
    "session_refresh_empty",
    "session_refresh_stale_token",
    "refreshed_token_rejected",
    "session_probe_same_token",
    "session_exchange_no_rotation",
    "session_exchange_contract_mismatch",
    "session_exchange_identity_mismatch",
    "session_exchange_token_rejected",
    "session_browser_probe_login_required",
    "session_browser_probe_no_rotation",
    "session_browser_cookie_restore_failed",
    "session_cookie_missing",
    "session_cookie_missing_after_refresh",
    "session_snapshot_invalid",
    "session_email_missing",
})


def requires_interactive_login(error_code: str) -> bool:
    """Whether a quiet refresh failure proves that browser login is needed."""
    code = str(error_code or "")
    return code in _INTERACTIVE_LOGIN_ERROR_CODES or code.startswith(
        "session_identity_"
    )


def _account_lock(account_id: int) -> threading.Lock:
    key = int(account_id)
    with _ACCOUNT_LOCKS_GUARD:
        lock = _ACCOUNT_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _ACCOUNT_LOCKS[key] = lock
        return lock

from .session_refresh_domains import session, login, restore, probe, candidate, queue

for _domain_module in (session, login, restore, probe, candidate, queue):
    _domain_module.register(globals())
del _domain_module
