# -*- coding: utf-8 -*-
"""Local persistence for ChatGPT Web sessions.

The file intentionally lives below ``data/`` (which is Git-ignored) and is
kept separate from the registered-account export.  Callers may consume the
small status helpers, but cookie values must never be returned by WebUI APIs or
written to logs.
"""
from __future__ import annotations

import json
import os
import re
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.chatgpt_session_db import ChatGPTSessionSQLiteStore, SessionDbError


SCHEMA_VERSION = 1
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SESSION_DB_PATH = _PROJECT_ROOT / "data" / "chatgpt_sessions.db"
_LOCK = threading.RLock()
_SESSION_DB_LOCK = threading.RLock()
_SESSION_DB_INSTANCE: ChatGPTSessionSQLiteStore | None = None
_SESSION_DB_KEY: tuple[str, str] | None = None

_SESSION_COOKIE_PREFIXES = (
    "__Secure-next-auth.session-token",
    "__Host-next-auth.session-token",
    "next-auth.session-token",
    "__Secure-authjs.session-token",
    "__Host-authjs.session-token",
    "authjs.session-token",
)
_COOKIE_FIELDS = (
    "name",
    "value",
    "domain",
    "path",
    "expires",
    "secure",
    "httpOnly",
    "sameSite",
    "hostOnly",
)
_BROWSER_PROFILE_FIELDS = (
    "user_agent",
    "accept_language",
    "navigator_language",
    "navigator_languages",
    "navigator_platform",
    "user_agent_data_platform",
    "user_agent_data_brands",
    "user_agent_data_mobile",
    "timezone_iana",
    "timezone_offset_minutes",
    "screen_width",
    "screen_height",
    "device_pixel_ratio",
    "hardware_concurrency",
    "device_memory",
)
_FIXED_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_TOKEN_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{12}$")
_TRANSIENT_EDGE_COOKIE_NAMES = frozenset({
    "__cf_bm",
    "__cflb",
    "__cfseq",
    "__oailb",
    "__oai_lb",
    "__oai_dc",
    "oai-lb",
    "_cfuvid",
    "_dd_s",
    "cf_clearance",
    "cf_chl_rc_i",
    "cf_chl_rc_m",
    "cf_chl_rc_ni",
})
_STORAGE_STATE_MAX_BYTES = 16 * 1024 * 1024


def is_transient_edge_cookie_name(name: str) -> bool:
    value = str(name or "").strip().lower()
    return value in _TRANSIENT_EDGE_COOKIE_NAMES or value.startswith("cf_chl_")


class ChatGPTSessionStoreError(RuntimeError):
    """A persisted Web session is missing or structurally invalid."""

    def __init__(self, error_code: str):
        super().__init__(str(error_code or "chatgpt_session_store_error"))
        self.error_code = str(error_code or "chatgpt_session_store_error")


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _normalise_email(email: str) -> str:
    return str(email or "").strip().lower()


def _session_db_path() -> Path:
    configured = str(os.getenv("TURB_CHATGPT_SESSION_DB_PATH") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return _SESSION_DB_PATH




def _session_backend() -> ChatGPTSessionSQLiteStore:
    global _SESSION_DB_INSTANCE, _SESSION_DB_KEY
    path = _session_db_path()
    key = str(path)
    with _SESSION_DB_LOCK:
        if _SESSION_DB_INSTANCE is None or _SESSION_DB_KEY != key:
            _SESSION_DB_INSTANCE = ChatGPTSessionSQLiteStore(
                path,
                record_status=record_status,
                has_session_cookie=has_session_cookie,
                quiet_normalizer=_normalise_quiet_refresh,
            )
            _SESSION_DB_KEY = key
        return _SESSION_DB_INSTANCE


def initialize_session_store() -> dict:
    try:
        return _session_backend().initialize()
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc










def _is_session_cookie_name(name: str) -> bool:
    value = str(name or "")
    return any(
        value == prefix or value.startswith(prefix + ".")
        for prefix in _SESSION_COOKIE_PREFIXES
    )


def _session_cookie_base(name: str) -> str | None:
    value = str(name or "")
    for prefix in _SESSION_COOKIE_PREFIXES:
        if value == prefix:
            return prefix
        if value.startswith(prefix + ".") and value[len(prefix) + 1 :].isdigit():
            return prefix
    return None


def _normalise_cookie(raw: Any) -> dict | None:
    if isinstance(raw, dict):
        source = raw
        get_value = source.get
    else:
        get_value = lambda key, default=None: getattr(raw, key, default)
    name = str(get_value("name", "") or "").strip()
    value = str(get_value("value", "") or "")
    domain = str(get_value("domain", "") or "").strip().lower()
    if not name or not value:
        return None
    if domain and not (
        domain.lstrip(".") == "chatgpt.com"
        or domain.lstrip(".").endswith(".chatgpt.com")
        or domain.lstrip(".") == "auth.openai.com"
        or domain.lstrip(".").endswith(".auth.openai.com")
    ):
        return None
    result = {
        "name": name,
        "value": value,
        "domain": domain or ".chatgpt.com",
        "path": str(get_value("path", "/") or "/"),
        "secure": bool(get_value("secure", True)),
        "httpOnly": bool(
            get_value("httpOnly", get_value("httponly", get_value("http_only", False)))
        ),
    }
    expires = get_value("expires", get_value("expiry", None))
    if expires not in (None, "", -1):
        try:
            result["expires"] = float(expires)
        except (TypeError, ValueError):
            pass
    same_site = str(get_value("sameSite", get_value("samesite", "")) or "").strip()
    if same_site:
        result["sameSite"] = same_site
    if not isinstance(raw, dict) and hasattr(raw, "has_nonstandard_attr"):
        result["httpOnly"] = raw.has_nonstandard_attr("HttpOnly")
        same_site = raw.get_nonstandard_attr("SameSite")
        if same_site:
            result["sameSite"] = same_site
    if isinstance(raw, dict) and "hostOnly" in raw:
        result["hostOnly"] = bool(raw["hostOnly"])
    elif not isinstance(raw, dict) and hasattr(raw, "domain_specified"):
        result["hostOnly"] = not raw.domain_specified
    return {key: result[key] for key in _COOKIE_FIELDS if key in result}


def normalise_cookies(cookies: Iterable[Any]) -> list[dict]:
    """Return deterministic, OpenAI-scoped cookie records without logging values."""
    by_key: dict[tuple[str, str, str], dict] = {}
    for raw in cookies or []:
        item = _normalise_cookie(raw)
        if not item:
            continue
        key = (item["name"], item.get("domain") or "", item.get("path") or "/")
        by_key[key] = item
    return [by_key[key] for key in sorted(by_key)]


def has_session_cookie(cookies: Iterable[dict]) -> bool:
    return any(_is_session_cookie_name(item.get("name") or "") for item in cookies or [])


def _complete_session_cookie_family(cookies: Iterable[dict]) -> list[dict]:
    """Return one complete unchunked/chunked Session Cookie family."""
    families: dict[str, list[dict]] = {}
    for item in normalise_cookies(cookies or []):
        base = _session_cookie_base(item.get("name") or "")
        if base:
            families.setdefault(base, []).append(item)
    for base in _SESSION_COOKIE_PREFIXES:
        family = families.get(base) or []
        exact = [item for item in family if item.get("name") == base]
        chunks = [item for item in family if item.get("name") != base]
        if chunks:
            by_index = {
                int(str(item.get("name") or "").rsplit(".", 1)[-1]): item
                for item in chunks
            }
            if set(by_index) == set(range(len(by_index))):
                return [by_index[index] for index in range(len(by_index))]
        if exact:
            return [exact[0]]
    return []


def has_complete_session_cookie(cookies: Iterable[dict]) -> bool:
    return bool(_complete_session_cookie_family(cookies))


def _normalise_browser_profile(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return {}
    profile: dict[str, Any] = {}
    for key in _BROWSER_PROFILE_FIELDS:
        value = raw.get(key)
        if value in (None, ""):
            continue
        if key == "navigator_languages":
            if isinstance(value, (list, tuple)):
                profile[key] = [str(item) for item in value if str(item or "").strip()][:10]
            continue
        if key == "user_agent_data_brands":
            if isinstance(value, list):
                brands = []
                for item in value[:10]:
                    if not isinstance(item, dict):
                        continue
                    brand = str(item.get("brand") or "").strip()
                    version = str(item.get("version") or "").strip()
                    if brand and version:
                        brands.append({"brand": brand, "version": version})
                if brands:
                    profile[key] = brands
            continue
        if key in {
            "timezone_offset_minutes",
            "screen_width",
            "screen_height",
            "hardware_concurrency",
        }:
            try:
                profile[key] = int(value)
            except (TypeError, ValueError):
                continue
            continue
        if key in {"device_pixel_ratio", "device_memory"}:
            try:
                profile[key] = float(value)
            except (TypeError, ValueError):
                continue
            continue
        if key == "user_agent_data_mobile":
            profile[key] = bool(value)
            continue
        profile[key] = str(value)
    return profile


def _normalise_quiet_refresh(raw: Any) -> dict | None:
    """Keep only bounded, non-secret diagnostics for one quiet refresh attempt."""
    if not isinstance(raw, dict):
        return None
    stage = str(raw.get("stage") or "").strip().lower()
    outcome = str(raw.get("outcome") or "").strip().lower()
    if not _FIXED_CODE_RE.fullmatch(stage) or not _FIXED_CODE_RE.fullmatch(outcome):
        return None
    result: dict[str, Any] = {
        "attempted_at": str(raw.get("attempted_at") or _now_iso()),
        "stage": stage,
        "outcome": outcome,
        "token_changed": bool(raw.get("token_changed")),
        "session_rotated": bool(raw.get("session_rotated")),
    }
    method = str(raw.get("exchange_method") or "unknown").strip().lower()
    if method not in {"http_session", "hidden_roxy", "roxy_login", "unknown"}:
        method = "unknown"
    result["exchange_method"] = method
    for key in ("old_token_fingerprint", "new_token_fingerprint"):
        value = str(raw.get(key) or "").strip().lower()
        if _TOKEN_FINGERPRINT_RE.fullmatch(value):
            result[key] = value
    try:
        status = int(raw.get("http_status"))
    except (TypeError, ValueError):
        status = 0
    if 100 <= status <= 599:
        result["http_status"] = status
    return result


def capture_http_snapshot(
    env,
    *,
    email: str,
    session_info: dict,
    account_id: int | None = None,
) -> dict:
    """Capture a curl-based ChatGPT session using the same safe schema.

    This helper is intentionally transport-agnostic and never logs or returns
    cookie values outside the snapshot passed directly to ``save_snapshot``.
    """
    try:
        session = getattr(env, "session", env)
        jar = getattr(getattr(session, "cookies", None), "jar", None)
        cookies = normalise_cookies(list(jar or []))
    except Exception as exc:
        raise ChatGPTSessionStoreError("session_cookie_capture_failed") from exc
    if not has_session_cookie(cookies):
        raise ChatGPTSessionStoreError("session_cookie_missing")
    profile = _normalise_browser_profile(
        getattr(env, "browser_profile", None) or {}
    )
    device_id = str(getattr(env, "device_id", "") or "")
    if not device_id:
        for cookie in cookies:
            if str(cookie.get("name") or "").strip().lower() == "oai-did":
                device_id = str(cookie.get("value") or "")
                break
    return {
        "email": _normalise_email(email),
        "account_id": int(account_id) if account_id is not None else None,
        "cookies": cookies,
        "device_id": device_id,
        "browser_profile": profile,
        "session_expires_at": str((session_info or {}).get("expires") or ""),
        "captured_at": _now_iso(),
        "updated_at": _now_iso(),
        "last_refresh_at": None,
        "status": "ready",
    }


def capture_driver_snapshot(
    driver,
    *,
    email: str,
    session_info: dict,
    account_id: int | None = None,
) -> dict:
    """Capture a Selenium session without exposing cookie values to callers' logs."""
    try:
        raw = driver.execute_cdp_cmd("Network.getAllCookies", {}) or {}
        cookies = normalise_cookies(raw.get("cookies") or [])
    except Exception as exc:
        raise ChatGPTSessionStoreError("session_cookie_capture_failed") from exc
    if not has_session_cookie(cookies):
        raise ChatGPTSessionStoreError("session_cookie_missing")

    try:
        profile = driver.execute_script(
            """
            const data = navigator.userAgentData || {};
            const langs = Array.isArray(navigator.languages) ? navigator.languages : [];
            let timezone = '';
            try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (_) {}
            return {
              user_agent: navigator.userAgent || '',
              accept_language: langs.join(',') || navigator.language || '',
              navigator_language: navigator.language || '',
              navigator_languages: langs,
              navigator_platform: navigator.platform || '',
              user_agent_data_platform: data.platform || '',
              user_agent_data_brands: Array.isArray(data.brands) ? data.brands : [],
              user_agent_data_mobile: !!data.mobile,
              timezone_iana: timezone,
              timezone_offset_minutes: new Date().getTimezoneOffset(),
              screen_width: (window.screen && window.screen.width) || 0,
              screen_height: (window.screen && window.screen.height) || 0,
              device_pixel_ratio: window.devicePixelRatio || 0,
              hardware_concurrency: navigator.hardwareConcurrency || 0,
              device_memory: navigator.deviceMemory || 0,
            };
            """
        ) or {}
    except Exception:
        profile = {}
    device_id = ""
    for cookie in cookies:
        if cookie.get("name") == "oai-did":
            device_id = str(cookie.get("value") or "")
            break
    return {
        "email": _normalise_email(email),
        "account_id": int(account_id) if account_id is not None else None,
        "cookies": cookies,
        "device_id": device_id,
        "browser_profile": _normalise_browser_profile(profile),
        "session_expires_at": str((session_info or {}).get("expires") or ""),
        "captured_at": _now_iso(),
        "updated_at": _now_iso(),
        "last_refresh_at": None,
        "status": "ready",
    }


def _validate_snapshot(snapshot: dict) -> dict:
    if not isinstance(snapshot, dict):
        raise ChatGPTSessionStoreError("session_snapshot_invalid")
    email = _normalise_email(snapshot.get("email") or "")
    cookies = [
        item
        for item in normalise_cookies(snapshot.get("cookies") or [])
        if not is_transient_edge_cookie_name(item.get("name") or "")
    ]
    if not email:
        raise ChatGPTSessionStoreError("session_email_missing")
    if not has_session_cookie(cookies):
        raise ChatGPTSessionStoreError("session_cookie_missing")
    result = {
        "email": email,
        "account_id": snapshot.get("account_id"),
        "cookies": cookies,
        "device_id": str(snapshot.get("device_id") or ""),
        "browser_profile": _normalise_browser_profile(
            snapshot.get("browser_profile")
            or {
                # Backward compatibility with snapshots produced during early
                # development of schema v1.
                "user_agent": snapshot.get("user_agent"),
                "accept_language": snapshot.get("accept_language"),
            }
        ),
        "session_expires_at": str(snapshot.get("session_expires_at") or ""),
        "captured_at": str(snapshot.get("captured_at") or _now_iso()),
        "updated_at": _now_iso(),
        "last_refresh_at": snapshot.get("last_refresh_at"),
        "status": str(snapshot.get("status") or "ready"),
        "status_reason": str(snapshot.get("status_reason") or "").strip() or None,
    }
    quiet_refresh = _normalise_quiet_refresh(snapshot.get("last_quiet_refresh"))
    if quiet_refresh:
        result["last_quiet_refresh"] = quiet_refresh
    storage_state = snapshot.get("storage_state")
    if storage_state is not None:
        if not isinstance(storage_state, dict):
            raise ChatGPTSessionStoreError("session_storage_state_invalid")
        try:
            encoded_storage_state = json.dumps(
                storage_state,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ChatGPTSessionStoreError(
                "session_storage_state_invalid"
            ) from exc
        if len(encoded_storage_state) > _STORAGE_STATE_MAX_BYTES:
            raise ChatGPTSessionStoreError("session_storage_state_too_large")
        result["storage_state"] = deepcopy(storage_state)
    if result["account_id"] is not None:
        try:
            result["account_id"] = int(result["account_id"])
        except (TypeError, ValueError):
            result["account_id"] = None
    return result


def save_snapshot(snapshot: dict, *, refreshed: bool = False) -> dict:
    record = _validate_snapshot(snapshot)
    try:
        return _session_backend().save(record, refreshed=refreshed)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def bind_account(email: str, account_id: int) -> bool:
    key = _normalise_email(email)
    try:
        return _session_backend().bind(key, int(account_id))
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def stage_session_rekey(
    old_email: str,
    new_email: str,
    snapshot: dict,
) -> dict:
    """Stage a verified Session under ``new_email`` without deleting the old key."""

    source = _normalise_email(old_email)
    target = _normalise_email(new_email)
    candidate = dict(snapshot or {})
    candidate["email"] = target
    record = _validate_snapshot(candidate)
    try:
        return _session_backend().stage_rekey(source, target, record)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def get_session(email: str, *, account_id: int | None = None) -> dict | None:
    key = _normalise_email(email)
    try:
        record = _session_backend().get(key)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc
    if not isinstance(record, dict):
        return None
    if account_id is not None:
        expected_id = int(account_id)
        stored_id = record.get("account_id")
        if stored_id not in (None, "", expected_id):
            try:
                if int(stored_id) != expected_id:
                    return None
            except (TypeError, ValueError):
                return None
    return deepcopy(record)


def _parse_expiry(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def record_status(record: dict | None) -> str:
    if not isinstance(record, dict):
        return "missing"
    stored_status = str(record.get("status") or "ready").strip().lower()
    if stored_status in {"invalid", "stale"}:
        return stored_status
    cookies = normalise_cookies(record.get("cookies") or [])
    if not has_session_cookie(cookies):
        return "invalid"
    expires_at = _parse_expiry(record.get("session_expires_at"))
    if expires_at is not None and datetime.now(timezone.utc) >= expires_at:
        return "stale"
    return "ready"


def can_revalidate_session(record: dict | None) -> bool:
    """Allow one network check for legacy locally-rejected Cookie records.

    Old versions only wrote ``status=invalid`` and retained the Cookie.  A
    missing reason therefore does not prove that ChatGPT rejected the remote
    Session.  New explicit failures always carry a reason and are not retried.
    """
    if not isinstance(record, dict):
        return False
    if record_status(record) not in {"invalid", "stale"}:
        return False
    if str(record.get("status_reason") or "").strip():
        return False
    return has_complete_session_cookie(record.get("cookies") or [])


def safe_status_map(*, email: str | None = None) -> dict[str, dict]:
    """Read one indexed status, or all statuses for account-list projections."""
    try:
        return _session_backend().status_map(email=email)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def record_quiet_refresh(
    email: str,
    *,
    stage: str,
    outcome: str,
    old_token_fingerprint: str,
    new_token_fingerprint: str = "",
    token_changed: bool = False,
    session_rotated: bool = False,
    http_status: int | None = None,
    status: str | None = None,
    exchange_method: str = "unknown",
) -> bool:
    """Persist one sanitised quiet-refresh result without storing token values."""
    old_fingerprint = str(old_token_fingerprint or "").strip().lower()
    new_fingerprint = str(new_token_fingerprint or "").strip().lower()
    if not _TOKEN_FINGERPRINT_RE.fullmatch(old_fingerprint) or (
        new_fingerprint and not _TOKEN_FINGERPRINT_RE.fullmatch(new_fingerprint)
    ):
        raise ChatGPTSessionStoreError("session_refresh_diagnostic_invalid")
    diagnostic = _normalise_quiet_refresh({
        "attempted_at": _now_iso(),
        "stage": stage,
        "outcome": outcome,
        "old_token_fingerprint": old_fingerprint,
        "new_token_fingerprint": new_fingerprint,
        "token_changed": token_changed,
        "session_rotated": session_rotated,
        "http_status": http_status,
        "exchange_method": exchange_method,
    })
    if not diagnostic:
        raise ChatGPTSessionStoreError("session_refresh_diagnostic_invalid")
    key = _normalise_email(email)
    def update(record: dict) -> bool:
        record["last_quiet_refresh"] = diagnostic
        fixed_status = str(status or "").strip().lower()
        if fixed_status in {"ready", "stale", "invalid"}:
            record["status"] = fixed_status
            if fixed_status == "ready":
                record.pop("status_reason", None)
            else:
                record["status_reason"] = diagnostic["outcome"]
        return True
    try:
        return _session_backend().update_record(key, update)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def _mark_status(email: str, status: str, *, reason: str = "") -> bool:
    key = _normalise_email(email)
    def update(record: dict) -> bool:
        record["status"] = str(status or "invalid")
        fixed_reason = str(reason or "").strip()
        if fixed_reason:
            record["status_reason"] = fixed_reason
        else:
            record.pop("status_reason", None)
        return True
    try:
        return _session_backend().update_record(key, update)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def mark_invalid(email: str, *, reason: str = "") -> bool:
    return _mark_status(email, "invalid", reason=reason)


def mark_stale(email: str, *, reason: str = "") -> bool:
    return _mark_status(email, "stale", reason=reason)


def delete_session(email: str) -> bool:
    key = _normalise_email(email)
    try:
        return _session_backend().delete(key)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def delete_sessions(emails: Iterable[str]) -> int:
    try:
        return _session_backend().delete_many(emails)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def prune_sessions(valid_emails: Iterable[str]) -> int:
    try:
        return _session_backend().prune(valid_emails)
    except SessionDbError as exc:
        raise ChatGPTSessionStoreError(exc.error_code) from exc


def cookies_from_http_session(session) -> list[dict]:
    try:
        return normalise_cookies(list(session.cookies.jar))
    except Exception as exc:
        raise ChatGPTSessionStoreError("session_cookie_capture_failed") from exc


def clear_transient_chatgpt_cookies(session) -> int:
    """Remove route-bound edge cookies while preserving account identity.

    A stored Web Session may have Cloudflare/load-balancer cookies minted on
    the Roxy exit.  Reusing those values through a different regional proxy
    creates a contradictory request context.  Only cookie names are
    inspected; values are never returned or logged.
    """

    try:
        jar = getattr(session.cookies, "jar", None)
        raw_cookies = list(jar or [])
    except Exception as exc:
        raise ChatGPTSessionStoreError("session_cookie_read_failed") from exc
    targets = [
        cookie for cookie in raw_cookies
        if is_transient_edge_cookie_name(getattr(cookie, "name", ""))
    ]
    if not targets:
        return 0
    try:
        for cookie in targets:
            jar.clear(
                getattr(cookie, "domain", None),
                getattr(cookie, "path", None) or "/",
                getattr(cookie, "name", ""),
            )
        return len(targets)
    except (AttributeError, TypeError):
        try:
            preserved = [
                item for item in normalise_cookies(raw_cookies)
                if not is_transient_edge_cookie_name(item.get("name") or "")
            ]
            session.cookies.clear()
            for cookie in preserved:
                _set_http_cookie(session.cookies, cookie)
            return len(targets)
        except Exception as exc:
            raise ChatGPTSessionStoreError("session_cookie_clear_failed") from exc


def hydrate_browser_session(
    env,
    record: dict,
    *,
    allow_revalidation: bool = False,
    strip_transient_cookies: bool = False,
    restore_profile: bool = True,
) -> None:
    """Restore one stored identity into an existing ``BrowserSession``."""
    status = record_status(record)
    if status != "ready" and not (
        allow_revalidation and can_revalidate_session(record)
    ):
        raise ChatGPTSessionStoreError(f"session_{status}")
    cookies = normalise_cookies(record.get("cookies") or [])
    if strip_transient_cookies:
        cookies = [
            item for item in cookies
            if not is_transient_edge_cookie_name(item.get("name") or "")
        ]
    _hydrate_browser_context(env, record, cookies, restore_profile=restore_profile)


def hydrate_browser_identity_context(env, record: dict) -> None:
    """Restore a saved device/profile without trusting its authentication.

    This is deliberately narrower than :func:`hydrate_browser_session`.  It is
    intended for a flow that already knows the old NextAuth Session is stale
    and will perform a fresh login.  Only ``oai-did`` is copied from the Cookie
    jar; Session, OAuth-state, CSRF, edge and telemetry cookies are discarded.
    """

    if not isinstance(record, dict):
        raise ChatGPTSessionStoreError("session_identity_context_missing")
    cookies = normalise_cookies(record.get("cookies") or [])
    device_id = str(record.get("device_id") or "").strip()
    if not device_id:
        for item in cookies:
            if str(item.get("name") or "").strip().lower() == "oai-did":
                device_id = str(item.get("value") or "").strip()
                if device_id:
                    break
    profile = _normalise_browser_profile(
        record.get("browser_profile")
        or {
            "user_agent": record.get("user_agent"),
            "accept_language": record.get("accept_language"),
        }
    )
    if not device_id or not str(profile.get("user_agent") or "").strip():
        raise ChatGPTSessionStoreError("session_identity_context_missing")
    identity_record = {
        **record,
        "device_id": device_id,
        "browser_profile": profile,
    }
    identity_cookies = [
        item
        for item in cookies
        if str(item.get("name") or "").strip().lower() == "oai-did"
    ]
    _hydrate_browser_context(env, identity_record, identity_cookies)


def _hydrate_browser_context(env, record: dict, cookies: list[dict], *, restore_profile=True) -> None:
    """Apply an already-authorized Cookie subset plus device/profile state."""

    from .protocol_csrf_cache import clear_protocol_csrf
    clear_protocol_csrf(env, reason='restored')
    try:
        env.session.cookies.clear()
    except Exception:
        pass
    for cookie in cookies:
        kwargs = {
            "domain": cookie.get("domain") or ".chatgpt.com",
            "path": cookie.get("path") or "/",
        }
        try:
            env.session.cookies.set(cookie["name"], cookie["value"], **kwargs)
        except TypeError:
            env.session.cookies.set(cookie["name"], cookie["value"])
    device_id = str(record.get("device_id") or "")
    if not device_id:
        # Early schema-v1 snapshots sometimes stored only the oai-did Cookie.
        # Recovering it keeps the account device stable without exposing the
        # value outside the in-memory request context.
        for item in cookies:
            if (
                str(item.get("name") or "").strip().lower() == "oai-did"
                and str(item.get("domain") or ".chatgpt.com").lstrip(".").lower() == "chatgpt.com"
            ):
                device_id = str(item.get("value") or "")
                break
    if device_id:
        env.device_id = device_id
        # BrowserSession normally seeds this identity Cookie on all three
        # OpenAI front-end domains. Hydration clears the fresh random jar, so
        # restore the same fixed device identity for the complete request
        # context without persisting synthetic domain copies.
        for domain in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
            try:
                env.session.cookies.set("oai-did", device_id, domain=domain, path="/")
            except TypeError:
                try:
                    env.session.cookies.set("oai-did", device_id)
                except Exception:
                    pass
    if not restore_profile:
        return
    profile = getattr(env, "browser_profile", None)
    stored_profile = _normalise_browser_profile(
        record.get("browser_profile")
        or {
            "user_agent": record.get("user_agent"),
            "accept_language": record.get("accept_language"),
        }
    )
    if isinstance(profile, dict):
        profile.update(stored_profile)
        if stored_profile.get("accept_language") and not stored_profile.get("navigator_language"):
            profile["navigator_language"] = str(stored_profile.get("accept_language")).split(",", 1)[0]
        brands = stored_profile.get("user_agent_data_brands") or []
        if brands:
            profile["sec_ch_ua"] = ", ".join(
                f'"{item["brand"]}";v="{item["version"]}"' for item in brands
            )
        if "user_agent_data_mobile" in stored_profile:
            profile["sec_ch_ua_mobile"] = "?1" if stored_profile["user_agent_data_mobile"] else "?0"
        if stored_profile.get("user_agent_data_platform"):
            profile["sec_ch_ua_platform"] = f'"{stored_profile["user_agent_data_platform"]}"'


def _set_http_cookie(jar, cookie: dict) -> None:
    cookie_jar = getattr(jar, "jar", jar)
    if "hostOnly" in cookie and hasattr(cookie_jar, "set_cookie"):
        from http.cookiejar import Cookie
        domain = str(cookie.get("domain") or "chatgpt.com")
        host_only = bool(cookie["hostOnly"])
        if host_only:
            domain = domain.lstrip(".")
        expires = cookie.get("expires")
        expires = int(float(expires)) if expires not in (None, "", -1) else None
        rest = {}
        if cookie.get("httpOnly"):
            rest["HttpOnly"] = None
        if cookie.get("sameSite"):
            rest["SameSite"] = cookie["sameSite"]
        cookie_jar.set_cookie(Cookie(
            version=0, name=cookie["name"], value=cookie["value"], port=None,
            port_specified=False, domain=domain, domain_specified=not host_only,
            domain_initial_dot=domain.startswith("."), path=cookie.get("path") or "/",
            path_specified=True, secure=bool(cookie.get("secure", True)),
            expires=expires, discard=expires is None, comment=None, comment_url=None,
            rest=rest, rfc2109=False,
        ))
        return
    kwargs = {
        "domain": cookie.get("domain") or ".chatgpt.com",
        "path": cookie.get("path") or "/",
        "secure": bool(cookie.get("secure", True)),
    }
    try:
        jar.set(cookie["name"], cookie["value"], **kwargs)
    except TypeError:
        kwargs.pop("secure", None)
        try:
            jar.set(cookie["name"], cookie["value"], **kwargs)
        except TypeError:
            jar.set(cookie["name"], cookie["value"])


def _response_cookies(response) -> list[dict]:
    try:
        container = getattr(response, "cookies", None)
        raw = getattr(container, "jar", container)
        return normalise_cookies(list(raw or []))
    except Exception:
        return []


def apply_session_cookie_rotation(session, response, session_info: dict) -> bool:
    """Atomically replace the Session Cookie family returned by NextAuth.

    ``curl_cffi`` applies Set-Cookie to the shared jar before returning the
    response, but a shape change (unchunked to ``.0/.1`` or the reverse) can
    leave the old names behind.  Rebuilding only this cookie family prevents
    old and new Session Tokens from being sent together while preserving
    device and Cloudflare cookies.
    """
    response_cookies = _response_cookies(response)
    response_session_cookies = [
        item for item in response_cookies
        if _is_session_cookie_name(item.get("name") or "")
    ]
    rotated = _complete_session_cookie_family(response_session_cookies)
    if response_session_cookies and not rotated:
        raise ChatGPTSessionStoreError("session_cookie_rotation_failed")
    current = cookies_from_http_session(session)
    if not rotated:
        session_token = str((session_info or {}).get("sessionToken") or "").strip()
        if not session_token:
            return False
        previous_family = _complete_session_cookie_family(current)
        if not previous_family:
            return False
        template = previous_family[0]
        base = _session_cookie_base(template.get("name") or "")
        if not base:
            return False
        rotated = [{
            **template,
            "name": base,
            "value": session_token,
        }]
    if not has_complete_session_cookie(rotated):
        return False

    try:
        raw_jar = getattr(session.cookies, "jar", None)
        raw_cookies = list(raw_jar or [])
        try:
            for cookie in raw_cookies:
                if not _is_session_cookie_name(getattr(cookie, "name", "")):
                    continue
                raw_jar.clear(
                    getattr(cookie, "domain", None),
                    getattr(cookie, "path", None) or "/",
                    getattr(cookie, "name", ""),
                )
        except (AttributeError, TypeError):
            # Lightweight test/fallback jars may not expose CookieJar.clear
            # with a name argument. Rebuild them from all normalisable rows.
            preserved = []
            for cookie in raw_cookies:
                name = str(getattr(cookie, "name", "") or "")
                value = str(getattr(cookie, "value", "") or "")
                if not name or not value or _is_session_cookie_name(name):
                    continue
                preserved.append({
                    "name": name,
                    "value": value,
                    "domain": str(getattr(cookie, "domain", "") or ""),
                    "path": str(getattr(cookie, "path", "/") or "/"),
                    "secure": bool(getattr(cookie, "secure", False)),
                })
            session.cookies.clear()
            for cookie in preserved:
                _set_http_cookie(session.cookies, cookie)
        for cookie in rotated:
            _set_http_cookie(session.cookies, cookie)
    except Exception as exc:
        raise ChatGPTSessionStoreError("session_cookie_rotation_failed") from exc
    return True


def snapshot_from_http_session(
    env,
    *,
    previous: dict,
    session_info: dict,
    account_id: int,
) -> dict:
    # Route-bound Cloudflare/load-balancer cookies are valid only for the
    # proxy that minted them. They must never become part of the durable
    # account Session snapshot or leak into another regional context.
    cookies = [
        item
        for item in cookies_from_http_session(env.session)
        if not is_transient_edge_cookie_name(item.get("name") or "")
    ]
    if not has_session_cookie(cookies):
        raise ChatGPTSessionStoreError("session_cookie_missing_after_refresh")
    return {
        **dict(previous or {}),
        "account_id": int(account_id),
        "cookies": cookies,
        "device_id": str(getattr(env, "device_id", "") or previous.get("device_id") or ""),
        "browser_profile": _normalise_browser_profile(
            previous.get("browser_profile")
            or getattr(env, "browser_profile", {})
        ),
        "session_expires_at": str((session_info or {}).get("expires") or previous.get("session_expires_at") or ""),
        "status": "ready",
    }
