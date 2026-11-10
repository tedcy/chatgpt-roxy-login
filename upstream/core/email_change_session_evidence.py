"""Local-only session evidence around existing /me reads; never log credentials."""
import hashlib
import hmac
import json
import logging
import re
import secrets
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
_KEY = secrets.token_bytes(32)  # Fingerprints are comparable only in this process.


def _fingerprint(value):
    return hmac.new(_KEY, value.encode(), hashlib.sha256).hexdigest()[:20] if value else None


def _cookies(rows):
    from core.chatgpt_session_store import _is_session_cookie_name
    if not isinstance(rows, list):
        return {"state": "unavailable", "count": 0, "fingerprint": None}
    values = sorted((str(c.get("name") or ""), str(c.get("domain") or ""),
                     str(c.get("path") or "/"), str(c.get("value") or ""))
                    for c in rows if isinstance(c, dict) and _is_session_cookie_name(c.get("name")))
    return {"state": "present" if values else "missing", "count": len(values),
            "fingerprint": _fingerprint(json.dumps(values)) if values else None}


def _browser_cookies(driver):
    try:
        # Selenium reads current-page cookies, including HttpOnly, locally.
        return _cookies(driver.get_cookies())
    except Exception:
        return _cookies(None)


def _relation(left, right):
    if not left.get("fingerprint") or not right.get("fingerprint"):
        return "unknown"
    return "same" if left["fingerprint"] == right["fingerprint"] else "different"


def _page_route(driver):
    """Return a credential-free browser route for the evidence record."""

    try:
        parsed = urlsplit(str(driver.current_url or ""))
        host = str(parsed.hostname or "").strip().lower()
        path = str(parsed.path or "/")
        path = re.sub(r"/[A-Za-z0-9_-]{24,}(?=/|$)", "/<opaque>", path)
        if len(path) > 160:
            path = path[:157] + "..."
        # Query strings can contain opaque challenge/session values.  They are
        # not needed to distinguish the ChatGPT page from an auth page.
        return host or "unknown", path or "/"
    except Exception:
        return "unknown", "/"


def observed_me_reader(account, *, target, session_info, token, driver, read_once):
    """Wrap existing reads only. Diagnostic failures never affect authentication."""
    try:
        old = str(account.get("email") or "").strip().lower()
        pending = str(account.get("email_change_pending_email") or "").strip().lower()
        target = str(target or "").strip().lower()
        if not old or old == target or pending != target:
            return read_once
        from core.chatgpt_plan import token_claims, normalize_token
        from core.chatgpt_session_store import get_session
        def email_relation(value):
            value = str(value or "").strip().lower()
            return "missing" if not value else "target" if value == target else "old" if value == old else "other"
        try:
            saved = get_session(old, account_id=int(account["id"]))
            baseline = _cookies(saved.get("cookies")) if isinstance(saved, dict) else _cookies(None)
        except Exception:
            saved = None
            baseline = _cookies(None)
        fields = {
            "account_id": int(account["id"]), "evidence_id": secrets.token_hex(6),
            "session_email": email_relation((session_info.get("user") or {}).get("email")),
            "token_email": email_relation(token_claims(token).get("email")),
            "token_fingerprint": _fingerprint(token),
            "token_vs_saved": "same" if token == normalize_token(account.get("access_token") or "") else "different",
            "saved_old_session_cookie": baseline,
            "cookie_scope": "current_page_visible_to_webdriver",
            "request_credentials": "include", "request_cache": "no-store",
            "account_header_sent": bool(str(account.get("account_id") or "").strip()),
        }
    except Exception:
        return read_once
    attempt = 0

    def observed():
        nonlocal attempt
        attempt += 1
        before = _browser_cookies(driver)
        wire = None
        collector = None
        try:
            from core.email_change_wire_evidence import begin
            wire = begin(int(account['id']), token, normalize_token(account.get('access_token') or ''),
                         str(account.get('account_id') or ''), saved.get('cookies', []) if isinstance(saved, dict) else [])
            from core.email_change_me_collector import MeCollector
            collector = MeCollector(driver, int(account['id']))
            collector.start()
        except Exception:
            pass
        status, remote = None, None
        try:
            status, remote = read_once()
            return status, remote
        finally:
            wire_data = {'state': 'unavailable'}
            collector_data = {'state': 'collector_unavailable'}
            if collector is not None:
                try:
                    collector_data = collector.close()
                except Exception:
                    collector_data = {'state': 'collector_close_failed'}
            if wire is not None:
                try:
                    from core.email_change_wire_evidence import finish
                    wire_data = finish(int(account['id']), wire)
                except Exception:
                    pass
            wire_data['collector'] = collector_data
            try:
                after = _browser_cookies(driver)
                page_host, page_path = _page_route(driver)
                data = {**fields, "attempt": attempt, "http_status": status,
                        "me_email": email_relation(remote.get("email")) if isinstance(remote, dict) else "unavailable",
                        "cookie_before": before, "cookie_after": after,
                        "cookie_before_vs_saved": _relation(before, baseline),
                        "cookie_after_vs_before": _relation(after, before),
                        "page_host": page_host, "page_path": page_path,
                        "wire_evidence": wire_data}
                message = "[EmailChangeSessionEvidence] " + json.dumps(
                    data, separators=(",", ":")
                )
                # The account sink is intentionally independent of the
                # process-wide logger level and of the helper thread that
                # performed the browser read.  Console/caplog visibility is
                # retained for local diagnostics and unit tests.
                try:
                    from core import account_operation_log

                    written = account_operation_log.append_event(
                        int(account.get("id") or 0),
                        "email_change",
                        message,
                        level="INFO",
                    )
                except Exception:
                    written = False
                if written:
                    logger.info(
                        message,
                        extra={"_account_event_written": True},
                    )
                else:
                    logger.info(message)
            except Exception:
                pass
    return observed
