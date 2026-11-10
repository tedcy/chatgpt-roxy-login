"""Safe proxy-wire snapshots for the headed-Chrome registration driver."""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from datetime import datetime, timezone
from typing import Callable


MODE = "headed_chrome_proxy_wire_totals"
COLLECTOR = "headed_chrome_reference_proxy_chain"
SCOPE = "headed_chrome_registration"
SCHEMA_VERSION = 6
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]{1,253}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _counter(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain or domain in {"unknown", "(unknown)"}:
        return "(unknown)"
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return "(unknown)"
    if not _DOMAIN_RE.fullmatch(domain) or ".." in domain:
        return "(unknown)"
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    return "(unknown)"


def empty_usage(
    state: str = "measuring",
    *,
    started_at: str | None = None,
    error_code: str | None = None,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "state": state,
        "mode": MODE,
        "collector": COLLECTOR,
        "scope": SCOPE,
        "download_bytes": 0,
        "upload_bytes": 0,
        "total_bytes": 0,
        "retry_bytes": 0,
        "proxy_handshake_bytes": 0,
        "degraded_reason": None,
        "error_code": error_code,
        "started_at": started_at or _utc_now(),
        "completed_at": None,
        "requests": {"observed": 0, "failed": 0, "cache_hits": 0},
        "profile_cache": {
            "enabled": False,
            "source": "not_applicable",
            "expectation": "unknown",
        },
        "breakdown": {
            "stages": {},
            "resource_types": {},
            "top_domains": [],
            "other_domains_download_bytes": 0,
            "unattributed_download_bytes": 0,
        },
        "wire_phases": {
            "headed_chrome_registration": {
                "download_bytes": 0,
                "upload_bytes": 0,
                "total_bytes": 0,
            }
        },
        "wire_connections": {
            "opened": 0,
            "completed": 0,
            "reset": 0,
            "rejected": 0,
            "policy_blocked": 0,
            "failed": 0,
            "active": 0,
        },
        "wire_targets": [],
        "wire_other": {
            "opened": 0,
            "completed": 0,
            "reset": 0,
            "rejected": 0,
            "policy_blocked": 0,
            "failed": 0,
            "active": 0,
            "download_bytes": 0,
            "upload_bytes": 0,
            "total_bytes": 0,
        },
    }


def usage_from_breakdown(
    value: object,
    *,
    state: str,
    started_at: str,
    error_code: str | None = None,
) -> dict:
    source = value if isinstance(value, dict) else {}
    download = _counter(source.get("download_bytes"))
    upload = _counter(source.get("upload_bytes"))
    unknown = _counter(source.get("unknown_bytes"))
    if unknown and state == "complete":
        state = "partial"
        error_code = error_code or "headed_chrome_traffic_direction_unknown"
    result = empty_usage(state, started_at=started_at, error_code=error_code)
    result["download_bytes"] = download
    result["upload_bytes"] = upload
    result["total_bytes"] = download + upload
    result["retry_bytes"] = _counter(source.get("retry_bytes"))
    result["proxy_handshake_bytes"] = _counter(
        source.get("proxy_handshake_bytes")
    )
    if state in {"complete", "partial", "unavailable"}:
        result["completed_at"] = _utc_now()
    opened = _counter(source.get("connections"))
    completed = _counter(source.get("success_connections"))
    failed = _counter(source.get("failed_connections"))
    active = _counter(source.get("open_connections"))
    result["requests"] = {
        "observed": opened,
        "failed": min(opened, failed),
        "cache_hits": 0,
    }
    result["wire_phases"]["headed_chrome_registration"] = {
        "download_bytes": download,
        "upload_bytes": upload,
        "total_bytes": download + upload,
    }
    result["wire_connections"] = {
        "opened": opened,
        "completed": completed,
        "reset": 0,
        "rejected": 0,
        "policy_blocked": 0,
        "failed": failed,
        "active": active,
    }
    targets = []
    for raw in source.get("targets") or []:
        if not isinstance(raw, dict):
            continue
        target_download = _counter(raw.get("download_bytes"))
        target_upload = _counter(raw.get("upload_bytes"))
        target_opened = _counter(raw.get("connections"))
        targets.append(
            {
                "domain": _safe_domain(raw.get("target")),
                "opened": target_opened,
                "completed": _counter(raw.get("success_connections")),
                "reset": 0,
                "rejected": 0,
                "policy_blocked": 0,
                "failed": _counter(raw.get("failed_connections")),
                "active": _counter(raw.get("open_connections")),
                "download_bytes": target_download,
                "upload_bytes": target_upload,
                "total_bytes": target_download + target_upload,
            }
        )
    targets.sort(key=lambda item: (-item["total_bytes"], item["domain"]))
    result["wire_targets"] = targets[:20]
    result["breakdown"]["top_domains"] = [
        {
            "domain": item["domain"],
            "download_bytes": item["download_bytes"],
            "upload_bytes": item["upload_bytes"],
            "total_bytes": item["total_bytes"],
            "requests": item["opened"],
            "failed": item["failed"],
        }
        for item in targets[:20]
    ]
    other_download = sum(item["download_bytes"] for item in targets[20:])
    other_upload = sum(item["upload_bytes"] for item in targets[20:])
    result["wire_other"].update(
        {
            "opened": sum(item["opened"] for item in targets[20:]),
            "completed": sum(item["completed"] for item in targets[20:]),
            "failed": sum(item["failed"] for item in targets[20:]),
            "active": sum(item["active"] for item in targets[20:]),
            "download_bytes": other_download,
            "upload_bytes": other_upload,
            "total_bytes": other_download + other_upload,
        }
    )
    result["breakdown"]["other_domains_download_bytes"] = other_download
    return result


class HeadedChromeTrafficReporter:
    """Throttle safe in-progress snapshots without retaining credentials."""

    def __init__(self, callback: Callable[[dict], None] | None = None):
        self.callback = callback
        self.started_at = _utc_now()
        self.chain = None
        self._lock = threading.RLock()
        self._last_emit = 0.0

    def attach(self, chain) -> None:
        self.chain = chain

    def on_bytes(self, _delta: int) -> None:
        if self.callback is None or self.chain is None:
            return
        now = time.monotonic()
        with self._lock:
            if now - self._last_emit < 1.0:
                return
            self._last_emit = now
        try:
            self.callback(self.snapshot("measuring"))
        except Exception:
            return

    def snapshot(self, state: str, *, error_code: str | None = None) -> dict:
        try:
            breakdown = self.chain.traffic_breakdown() if self.chain else {}
            return usage_from_breakdown(
                breakdown,
                state=state,
                started_at=self.started_at,
                error_code=error_code,
            )
        except Exception:
            return empty_usage(
                "unavailable",
                started_at=self.started_at,
                error_code="headed_chrome_traffic_snapshot_failed",
            )


__all__ = [
    "COLLECTOR",
    "HeadedChromeTrafficReporter",
    "MODE",
    "SCHEMA_VERSION",
    "SCOPE",
    "empty_usage",
    "usage_from_breakdown",
]
