# -*- coding: utf-8 -*-
"""Shared value objects, locks, and compatibility helpers for RoxyBrowser."""
from __future__ import annotations

import logging
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)

class RoxyCreateBusyError(RuntimeError):
    """Roxy 云端仍在处理另一个 Profile 创建请求。"""


class RoxyRateLimitError(RuntimeError):
    """Roxy Local API 明确拒绝了一个过于频繁的请求。"""


class RoxyProfileValidationError(RuntimeError):
    """缓存 Profile 的代理或 Locale 回读结果不可信。"""

    def __init__(self, reason_code: str, *, stage: str, issues: list[str]):
        safe_reason = re.sub(
            r"[^a-z0-9_]", "_", str(reason_code or "unknown").lower()
        )
        safe_stage = re.sub(r"[^a-z0-9_]", "_", str(stage or "unknown").lower())
        safe_issues = [
            re.sub(r"[^a-z0-9_]", "_", str(issue or "unknown").lower())
            for issue in issues
        ]
        self.reason_code = safe_reason
        self.stage = safe_stage
        self.issues = tuple(safe_issues)
        super().__init__(
            "Roxy Profile 回读校验失败："
            f"reason={safe_reason} stage={safe_stage} "
            f"issues={','.join(safe_issues) or 'unknown'}"
        )


# Roxy 的公开 Local API 没有批量创建接口，且明确可能返回“正在创建中”。只保留
# create 单路串行；不同 Profile 的写代理、随机化、回读和 open 可以并行。
_PROFILE_CREATE_LOCK = threading.RLock()
_PROFILE_OPERATION_LOCKS_GUARD = threading.Lock()
_PROFILE_OPERATION_LOCKS: dict[str, tuple[threading.RLock, int]] = {}
_CREATE_BUSY_DELAYS = (2.0, 4.0)
_RATE_LIMIT_DELAYS = (2.0, 4.0, 8.0)
_PROFILE_READBACK_DELAYS = (1.0, 2.0)
_MAX_RETRY_AFTER_SECONDS = 300.0


def _merge_roxy_open_args(
    configured: list[object],
    task_args: tuple[str, ...] | list[str],
) -> list[str]:
    """Merge task-local Chrome flags without changing the disabled path.

    Chrome accepts one effective ``--disable-features`` value.  Roxy users may
    already provide one through ``ROXY_OPEN_EXTRA_PARAMS``; merge feature names
    instead of appending a second flag whose precedence varies by Chromium
    version.  Other arguments preserve configured-first order and are deduped.
    """

    combined = [*configured, *task_args]
    result: list[str] = []
    seen: set[str] = set()
    disabled_features: list[str] = []
    feature_slot: int | None = None
    for raw in combined:
        value = str(raw or "").strip()
        if not value:
            continue
        if value.startswith("--disable-features="):
            if feature_slot is None:
                feature_slot = len(result)
                result.append("")
            for feature in value.split("=", 1)[1].split(","):
                fixed = feature.strip()
                if fixed and fixed not in disabled_features:
                    disabled_features.append(fixed)
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)
    if feature_slot is not None:
        if disabled_features:
            result[feature_slot] = "--disable-features=" + ",".join(
                disabled_features
            )
        else:
            result.pop(feature_slot)
    return result


@contextmanager
def _profile_operation_slot(profile_id: object):
    """Serialize mutations of one Profile without blocking unrelated Profiles."""
    key = str(profile_id or "").strip() or "(missing)"
    with _PROFILE_OPERATION_LOCKS_GUARD:
        entry = _PROFILE_OPERATION_LOCKS.get(key)
        if entry is None:
            lock = threading.RLock()
            refs = 0
        else:
            lock, refs = entry
        _PROFILE_OPERATION_LOCKS[key] = (lock, refs + 1)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _PROFILE_OPERATION_LOCKS_GUARD:
            current = _PROFILE_OPERATION_LOCKS.get(key)
            if current is not None and current[0] is lock:
                remaining = current[1] - 1
                if remaining <= 0:
                    _PROFILE_OPERATION_LOCKS.pop(key, None)
                else:
                    _PROFILE_OPERATION_LOCKS[key] = (lock, remaining)


@dataclass
class RoxyOpenResult:
    profile_id: str
    raw: dict = field(repr=False)
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False
    pooled: bool = False
    lease_token: str | None = None
    profile_cache_source: str = "not_applicable"
    profile_cache_expectation: str = "unknown"
    profile_cache_discard: bool = False
    proxy_safe_label: str = ""
    task_proxy_url: str = field(default="", repr=False)
    task_proxy_upstream_url: str = field(default="", repr=False)
    task_proxy_geo: dict = field(default_factory=dict, repr=False)
    # False 仅用于固定 Profile：项目不知道该环境实际使用代理还是直连。
    task_proxy_resolved: bool = False
