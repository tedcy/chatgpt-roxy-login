# -*- coding: utf-8 -*-
"""Process-local Roxy Profile cache pool with exclusive task leases."""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from config import roxybrowser as _cfg
from core.roxy_profile_utils import project_id_from_row

logger = logging.getLogger(__name__)

# 注册 Profile 缓存池按实际并发按需扩容，不设置项目侧数量上限。
# 保留公开常量用于状态/API 兼容；None 明确表示 demand-driven。
PROFILE_CACHE_LIMIT: int | None = None
PROFILE_CACHE_REMARK = "turb-gpt-free-register:profile-cache:v1"
PROFILE_CACHE_NAME_PREFIX = "turb-gpt-cache-"


class RoxyProfilePoolUnavailable(RuntimeError):
    """The cache pool cannot safely provision a Profile."""


def _configured_project_id() -> str:
    return str(getattr(_cfg, "ROXY_PROJECT_ID", "") or "").strip()


def _row_project_id(row: dict) -> str:
    return project_id_from_row(row)


@dataclass(frozen=True)
class RoxyProfileLease:
    token: str
    profile_id: str
    window_name: str
    newly_created: bool
    adopted: bool
    # 两者都只在任务内使用；proxy_info 含认证信息，summary 可含已验证 Geo。
    proxy_info: dict = field(repr=False)
    proxy_summary: dict = field(repr=False)

    @property
    def source(self) -> str:
        if self.newly_created:
            return "new"
        if self.adopted:
            return "adopted"
        return "cached"


def _profile_time(row: dict) -> float:
    for key in ("closeTime", "updateTime", "createTime"):
        raw = str(row.get(key) or "").strip()
        if not raw:
            continue
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                return datetime.strptime(raw.rstrip("Z"), fmt).timestamp()
            except ValueError:
                continue
    return 0.0


def _profile_open_state(client, row: dict) -> bool | None:
    strict_resolver = getattr(client, "resolve_profile_open_state_strict", None)
    if callable(strict_resolver):
        return strict_resolver(row)
    resolver = getattr(client, "resolve_profile_open_state", None)
    if callable(resolver):
        return resolver(row)
    return client.profile_open_state(row)


class RoxyProfilePool:
    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._waiters: deque[str] = deque()
        self._leases_by_profile: dict[str, RoxyProfileLease] = {}
        self._leases_by_token: dict[str, RoxyProfileLease] = {}
        self._released_at: dict[str, float] = {}
        self._quarantined: set[str] = set()
        # Profiles owned by a manual window from a previous WebUI process
        # have no live lease after restart.  Keep a separate reservation set
        # so a stale/incorrect Roxy ``openStatus`` cannot make them eligible
        # for registration, Session refresh, or email-change work.
        self._external_reservations: set[str] = set()
        self._pending_recovery: dict[str, str] = {}
        self._recovery_in_progress: set[str] = set()
        self._pending_create_names: set[str] = set()
        self._last_snapshot: dict | None = None
        self._last_refreshed_at: str | None = None

    @staticmethod
    def enabled() -> bool:
        return bool(getattr(_cfg, "ROXY_PROFILE_CACHE_REUSE", False))

    @staticmethod
    def _owned(row: dict) -> bool:
        if str(row.get("windowRemark") or "").strip() != PROFILE_CACHE_REMARK:
            return False
        expected_project = _configured_project_id()
        actual_project = _row_project_id(row)
        return bool(
            expected_project
            and actual_project
            and actual_project == expected_project
        )

    @staticmethod
    def _slot_name(
        rows: list[dict],
        reserved_names: set[str] | None = None,
    ) -> str:
        used: set[int] = set()
        names = [str(row.get("windowName") or "") for row in rows]
        names.extend(str(name or "") for name in (reserved_names or set()))
        for name in names:
            if not name.startswith(PROFILE_CACHE_NAME_PREFIX):
                continue
            suffix = name[len(PROFILE_CACHE_NAME_PREFIX) :]
            if suffix.isdigit():
                used.add(int(suffix))
        slot = 1
        while slot in used:
            slot += 1
        return f"{PROFILE_CACHE_NAME_PREFIX}{slot:02d}"

    def _remove_waiter(self, ticket: str) -> None:
        try:
            self._waiters.remove(ticket)
        except ValueError:
            pass

    def _owned_sort_key(self, client, row: dict) -> tuple[float, float, str]:
        profile_id = client.profile_id_from_row(row)
        return (
            self._released_at.get(profile_id, 0.0),
            _profile_time(row),
            profile_id,
        )

    @staticmethod
    def _first_closed(
        client,
        rows: list[dict],
        known_states: dict[str, bool | None] | None = None,
    ) -> dict | None:
        """Resolve candidates lazily and stop after the first confirmed closed row."""
        resolved = known_states or {}
        for row in rows:
            profile_id = client.profile_id_from_row(row)
            state = (
                resolved[profile_id]
                if profile_id in resolved
                else _profile_open_state(client, row)
            )
            if state is False:
                return row
        return None

    def _reconcile_one(
        self, client, rows: list[dict]
    ) -> dict[str, bool | None]:
        """Recheck one quarantined Profile without holding the pool state lock."""
        with self._condition:
            profile_id = next(
                (
                    value
                    for value in self._pending_recovery
                    if value not in self._recovery_in_progress
                ),
                "",
            )
            if not profile_id:
                return {}
            self._recovery_in_progress.add(profile_id)
        row = next(
            (row for row in rows if client.profile_id_from_row(row) == profile_id),
            None,
        )
        try:
            state = None if row is None else _profile_open_state(client, row)
        except BaseException:
            with self._condition:
                self._recovery_in_progress.discard(profile_id)
                self._condition.notify_all()
            raise
        with self._condition:
            # Remove the marker and apply the result atomically so another
            # allocator cannot select the same recovery between both steps.
            self._recovery_in_progress.discard(profile_id)
            if profile_id not in self._pending_recovery:
                self._condition.notify_all()
                return {profile_id: state}
            if row is None:
                self._pending_recovery.pop(profile_id, None)
                self._quarantined.discard(profile_id)
                self._condition.notify_all()
                return {}
            if state is False:
                self._pending_recovery.pop(profile_id, None)
                self._quarantined.discard(profile_id)
                self._released_at[profile_id] = time.time()
                logger.info("[Roxy缓存池] 待恢复环境已确认关闭，重新加入缓存池")
            self._condition.notify_all()
            return {profile_id: state}

    def acquire(
        self,
        client,
        *,
        proxy_info: dict | None = None,
        proxy_summary: dict | None = None,
        stop_check: Callable[[], None] | None = None,
        excluded_profile_ids: set[str] | frozenset[str] | None = None,
    ) -> RoxyProfileLease:
        """Acquire one closed Profile or create another for the current concurrent task."""
        if not _configured_project_id():
            raise RoxyProfilePoolUnavailable(
                "Roxy Profile 缓存复用必须配置 ROXY_PROJECT_ID；"
                "已拒绝按 Workspace 跨项目扫描环境"
            )
        # Resolve the proxy before the first list/detail/create request. The
        # production open path normally passes an already selected candidate;
        # keeping this fallback preserves direct pool callers and tests without
        # moving validation behind a Roxy management request.
        if proxy_info is None or proxy_summary is None:
            proxy_info, proxy_summary = client.choose_task_proxy()
        proxy_info = dict(proxy_info or {})
        proxy_summary = dict(proxy_summary or {})
        excluded = {
            str(value or "").strip()
            for value in (excluded_profile_ids or set())
            if str(value or "").strip()
        }
        ticket = uuid.uuid4().hex
        window_name = ""
        with self._condition:
            self._waiters.append(ticket)
        try:
            while True:
                if stop_check is not None:
                    stop_check()
                with self._condition:
                    if self._waiters and self._waiters[0] == ticket:
                        break
                    self._condition.wait(timeout=2.0)

            # The FIFO head owns allocation, but no network call holds the
            # pool state lock. Once it reserves an existing Profile or a new
            # window name, the next waiter may begin its own snapshot.
            rows = client.list_profiles()
            reconciled_states = self._reconcile_one(client, rows)
            with self._condition:
                released_at = dict(self._released_at)
                leased_ids = set(self._leases_by_profile)
                quarantined = set(self._quarantined)
                externally_reserved = set(self._external_reservations)
                pending_names = set(self._pending_create_names)
            owned_rows = [row for row in rows if self._owned(row)]
            eligible_owned = [
                row
                for row in owned_rows
                if client.profile_id_from_row(row) not in leased_ids
                and client.profile_id_from_row(row) not in quarantined
                and client.profile_id_from_row(row) not in externally_reserved
                and client.profile_id_from_row(row) not in excluded
                and str(row.get("windowName") or "") not in pending_names
            ]
            eligible_owned.sort(
                key=lambda row: (
                    released_at.get(client.profile_id_from_row(row), 0.0),
                    _profile_time(row),
                    client.profile_id_from_row(row),
                ),
                reverse=True,
            )
            selected_owned = self._first_closed(
                client, eligible_owned, reconciled_states
            )

            with self._condition:
                if selected_owned is not None:
                    profile_id = client.profile_id_from_row(selected_owned)
                    if (
                        profile_id not in self._leases_by_profile
                        and profile_id not in self._quarantined
                        and profile_id not in self._external_reservations
                        and profile_id not in excluded
                        and str(selected_owned.get("windowName") or "")
                        not in self._pending_create_names
                    ):
                        window_name = str(
                            selected_owned.get("windowName")
                            or self._slot_name(
                                owned_rows,
                                self._pending_create_names,
                            )
                        )
                        token = uuid.uuid4().hex
                        lease = RoxyProfileLease(
                            token=token,
                            profile_id=profile_id,
                            window_name=window_name,
                            newly_created=False,
                            adopted=False,
                            proxy_info=dict(proxy_info),
                            proxy_summary=dict(proxy_summary),
                        )
                        self._leases_by_profile[profile_id] = lease
                        self._leases_by_token[token] = lease
                        self._remove_waiter(ticket)
                        self._condition.notify_all()
                        logger.info(
                            "[Roxy缓存池] 已分配环境：source=%s protocol=%s authenticated=%s",
                            lease.source,
                            proxy_summary.get("protocol") or "unknown",
                            bool(proxy_summary.get("authenticated")),
                        )
                        return lease

                window_name = self._slot_name(
                    owned_rows,
                    self._pending_create_names,
                )
                self._pending_create_names.add(window_name)
                self._remove_waiter(ticket)
                self._condition.notify_all()
        except BaseException:
            with self._condition:
                self._remove_waiter(ticket)
                if window_name:
                    self._pending_create_names.discard(window_name)
                self._condition.notify_all()
            raise

        try:
            if stop_check is not None:
                stop_check()
            profile_id = client.create_profile(payload={
                "windowName": window_name,
                "windowRemark": PROFILE_CACHE_REMARK,
                "defaultOpenUrl": ["about:blank"],
                "proxyInfo": proxy_info,
            })
            if not profile_id:
                raise RoxyProfilePoolUnavailable(
                    "Roxy 创建缓存 Profile 未返回环境标识"
                )
            token = uuid.uuid4().hex
            lease = RoxyProfileLease(
                token=token,
                profile_id=profile_id,
                window_name=window_name,
                newly_created=True,
                adopted=False,
                proxy_info=dict(proxy_info),
                proxy_summary=dict(proxy_summary),
            )
            with self._condition:
                self._leases_by_profile[profile_id] = lease
                self._leases_by_token[token] = lease
                self._pending_create_names.discard(window_name)
                self._condition.notify_all()
            logger.info(
                "[Roxy缓存池] 已分配环境：source=%s protocol=%s authenticated=%s",
                lease.source,
                proxy_summary.get("protocol") or "unknown",
                bool(proxy_summary.get("authenticated")),
            )
            return lease
        except BaseException:
            with self._condition:
                self._pending_create_names.discard(window_name)
                self._condition.notify_all()
            raise

    def release(self, lease_token: str, *, healthy: bool) -> None:
        with self._condition:
            lease = self._leases_by_token.pop(str(lease_token or ""), None)
            if lease is None:
                return
            self._leases_by_profile.pop(lease.profile_id, None)
            if healthy:
                self._released_at[lease.profile_id] = time.time()
                self._quarantined.discard(lease.profile_id)
                self._pending_recovery.pop(lease.profile_id, None)
            else:
                self._quarantined.add(lease.profile_id)
            self._condition.notify_all()

    def defer(self, lease: RoxyProfileLease, *, reason: str = "transient_api_error") -> None:
        """Quarantine a transiently unavailable Profile without deleting its cache."""
        with self._condition:
            current = self._leases_by_token.pop(lease.token, None)
            if current is None:
                return
            self._leases_by_profile.pop(current.profile_id, None)
            self._quarantined.add(current.profile_id)
            self._pending_recovery[current.profile_id] = str(reason or "transient_api_error")
            self._condition.notify_all()
        logger.warning("[Roxy缓存池] Roxy API 暂时不可用，环境已延后核验且不会删除")

    def defer_token(self, lease_token: str, *, reason: str = "transient_api_error") -> None:
        with self._condition:
            lease = self._leases_by_token.get(str(lease_token or ""))
        if lease is not None:
            self.defer(lease, reason=reason)

    def _destructive_ownership_confirmed(self, client, lease: RoxyProfileLease) -> bool:
        if lease.adopted:
            return False
        try:
            rows = client.list_profiles()
        except Exception:
            return False
        return any(
            client.profile_id_from_row(row) == lease.profile_id and self._owned(row)
            for row in rows
        )

    def discard(self, client, lease: RoxyProfileLease) -> None:
        """Best-effort removal after setup/open failure; never mask the original error."""
        if not self._destructive_ownership_confirmed(client, lease):
            self.release(lease.token, healthy=False)
            logger.error(
                "[Roxy缓存池] 已拒绝关闭或删除未确认归属的环境："
                "reason=profile_ownership_not_confirmed"
            )
            return
        try:
            client.close_profile(lease.profile_id)
        except Exception:
            pass
        deleted = False
        try:
            deleted = bool(client.delete_profile(lease.profile_id))
        except Exception:
            deleted = False
        self.release(lease.token, healthy=False)
        if deleted:
            with self._condition:
                self._quarantined.discard(lease.profile_id)
                self._pending_recovery.pop(lease.profile_id, None)
                self._condition.notify_all()
        logger.warning("[Roxy缓存池] 环境准备失败，已隔离%s", "并删除" if deleted else "")

    def discard_token(self, client, lease_token: str) -> None:
        """Best-effort removal of an unhealthy leased Profile by token."""
        with self._condition:
            lease = self._leases_by_token.get(str(lease_token or ""))
        if lease is not None:
            self.discard(client, lease)

    @staticmethod
    def _api_status() -> dict:
        try:
            from core.roxybrowser_client import get_roxy_api_runtime_status

            return get_roxy_api_runtime_status()
        except Exception:
            return {
                "state": "unknown",
                "retry_after_ms": 0,
                "configured_per_minute": 0,
                "max_in_flight": 0,
                "in_flight": 0,
                "rate_limit_events": 0,
                "retry_successes": 0,
                "last_rate_limit_at": None,
                "waiting": 0,
            }

    def _cached_status_locked(self) -> dict:
        base = dict(self._last_snapshot or {})
        api_status = self._api_status()
        base.update({
            "ok": True,
            "enabled": self.enabled(),
            "limit": PROFILE_CACHE_LIMIT,
            "limit_mode": "demand",
            "snapshot_state": "cached" if self._last_snapshot is not None else "uninitialized",
            "refreshed_at": self._last_refreshed_at,
            "leased": len(self._leases_by_profile),
            "pending_provision": len(self._pending_create_names),
            "pending_recovery": len(self._pending_recovery),
            "external_reserved": len(self._external_reservations),
            "pending_cleanup": len(
                self._quarantined.difference(self._pending_recovery)
            ),
            "waiting": len(self._waiters),
            "rate_limit_events": int(api_status.get("rate_limit_events") or 0),
            "retry_successes": int(api_status.get("retry_successes") or 0),
            "api": api_status,
        })
        for key in ("workspace_total", "total", "idle", "open_unavailable"):
            base.setdefault(key, None)
        return base

    def status(self, client=None, *, refresh: bool = False) -> dict:
        if not refresh:
            with self._condition:
                return self._cached_status_locked()
        if client is None:
            with self._condition:
                result = self._cached_status_locked()
            result.update({"ok": False, "error_code": "roxy_profile_client_missing"})
            return result
        try:
            rows = client.list_profiles()
            reconciled_states = self._reconcile_one(client, rows)
            owned = [row for row in rows if self._owned(row)]
            with self._condition:
                leased_snapshot = set(self._leases_by_profile)
                externally_reserved_snapshot = set(self._external_reservations)
                pending_recovery_snapshot = set(self._pending_recovery)
                pending_create_snapshot = set(self._pending_create_names)
            resolved_states: dict[str, bool | None] = {}
            for row in owned:
                profile_id = client.profile_id_from_row(row)
                if profile_id in leased_snapshot:
                    continue
                if profile_id in externally_reserved_snapshot:
                    continue
                if str(row.get("windowName") or "") in pending_create_snapshot:
                    continue
                if (
                    profile_id in pending_recovery_snapshot
                    and profile_id not in reconciled_states
                ):
                    continue
                resolved_states[profile_id] = (
                    reconciled_states[profile_id]
                    if profile_id in reconciled_states
                    else _profile_open_state(client, row)
                )

            with self._condition:
                idle = 0
                opened = 0
                unknown = 0
                for row in owned:
                    profile_id = client.profile_id_from_row(row)
                    if profile_id in self._leases_by_profile:
                        continue
                    if profile_id in self._external_reservations:
                        opened += 1
                        continue
                    if str(row.get("windowName") or "") in self._pending_create_names:
                        unknown += 1
                        continue
                    if (
                        profile_id in self._pending_recovery
                        and profile_id not in reconciled_states
                    ):
                        unknown += 1
                        continue
                    state = resolved_states.get(profile_id)
                    if state is False and profile_id not in self._quarantined:
                        idle += 1
                    elif state is True:
                        opened += 1
                    else:
                        unknown += 1
                self._last_refreshed_at = datetime.now().isoformat(timespec="seconds")
                self._last_snapshot = {
                    "workspace_total": len(rows),
                    "total": len(owned),
                    "idle": idle,
                    "open_unavailable": opened,
                }
                api_status = self._api_status()
                return {
                    "ok": True,
                    "enabled": self.enabled(),
                    "limit": PROFILE_CACHE_LIMIT,
                    "limit_mode": "demand",
                    "snapshot_state": "live",
                    "refreshed_at": self._last_refreshed_at,
                    "workspace_total": len(rows),
                    "total": len(owned),
                    "idle": idle,
                    "leased": len(self._leases_by_profile),
                    "pending_provision": len(self._pending_create_names),
                    "open_unavailable": opened,
                    "pending_cleanup": len(
                        self._quarantined.difference(self._pending_recovery)
                    ) + unknown,
                    "pending_recovery": len(self._pending_recovery),
                    "external_reserved": len(self._external_reservations),
                    "waiting": len(self._waiters),
                    "rate_limit_events": int(api_status.get("rate_limit_events") or 0),
                    "retry_successes": int(api_status.get("retry_successes") or 0),
                    "api": api_status,
                }
        except Exception:
            with self._condition:
                result = self._cached_status_locked()
            result.update({"ok": False, "error_code": "roxy_profile_list_unavailable"})
            return result

    def clear(self, client) -> dict:
        if not _configured_project_id():
            return {
                "ok": False,
                "error_code": "roxy_project_id_required",
                "deleted": 0,
                "skipped_busy": 0,
                "failed": 0,
            }
        deleted = 0
        skipped_busy = 0
        failed = 0
        rows = client.list_profiles()
        for row in rows:
            if not self._owned(row):
                continue
            profile_id = client.profile_id_from_row(row)
            with self._condition:
                leased = profile_id in self._leases_by_profile
                externally_reserved = profile_id in self._external_reservations
                pending_create = (
                    str(row.get("windowName") or "")
                    in self._pending_create_names
                )
            if (
                leased
                or externally_reserved
                or pending_create
                or _profile_open_state(client, row) is not False
            ):
                skipped_busy += 1
                continue
            with self._condition:
                if (
                    profile_id in self._leases_by_profile
                    or profile_id in self._external_reservations
                ):
                    skipped_busy += 1
                    continue
                was_quarantined = profile_id in self._quarantined
                self._quarantined.add(profile_id)
            if client.delete_profile(profile_id):
                deleted += 1
                with self._condition:
                    self._released_at.pop(profile_id, None)
                    self._quarantined.discard(profile_id)
                    self._pending_recovery.pop(profile_id, None)
            else:
                failed += 1
                if not was_quarantined:
                    with self._condition:
                        self._quarantined.discard(profile_id)
        with self._condition:
            self._last_snapshot = None
            self._last_refreshed_at = None
            self._condition.notify_all()
        return {
            "ok": failed == 0,
            "deleted": deleted,
            "skipped_busy": skipped_busy,
            "failed": failed,
        }

    def wake_waiters(self) -> None:
        """Wake FIFO waiters so a newly requested task stop is observed now."""
        with self._condition:
            self._condition.notify_all()

    def replace_external_reservations(self, profile_ids) -> None:
        """Replace restart-recovered manual-window Profile reservations.

        This is called during WebUI startup before task endpoints become
        available.  A conflict with a live in-process lease is rejected
        without exposing the Profile identifier.
        """

        normalized = {
            str(value or "").strip()
            for value in (profile_ids or [])
            if str(value or "").strip()
        }
        with self._condition:
            if normalized.intersection(self._leases_by_profile):
                raise RoxyProfilePoolUnavailable(
                    "Roxy 人工窗口 Profile 与活动任务冲突"
                )
            self._external_reservations = normalized
            self._last_snapshot = None
            self._last_refreshed_at = None
            self._condition.notify_all()

    def reserve_external(self, profile_id: str) -> bool:
        """Atomically reserve one Profile unless a normal task already owns it."""

        normalized = str(profile_id or "").strip()
        if not normalized:
            return False
        with self._condition:
            if normalized in self._leases_by_profile:
                return False
            self._external_reservations.add(normalized)
            self._last_snapshot = None
            self._last_refreshed_at = None
            self._condition.notify_all()
            return True

    def release_external(self, profile_id: str) -> None:
        normalized = str(profile_id or "").strip()
        if not normalized:
            return
        with self._condition:
            self._external_reservations.discard(normalized)
            self._last_snapshot = None
            self._last_refreshed_at = None
            self._condition.notify_all()

    def is_external_reserved(self, profile_id: str) -> bool:
        normalized = str(profile_id or "").strip()
        with self._condition:
            return normalized in self._external_reservations

    def reset_for_tests(self) -> None:
        with self._condition:
            self._waiters.clear()
            self._leases_by_profile.clear()
            self._leases_by_token.clear()
            self._released_at.clear()
            self._quarantined.clear()
            self._external_reservations.clear()
            self._pending_recovery.clear()
            self._recovery_in_progress.clear()
            self._pending_create_names.clear()
            self._last_snapshot = None
            self._last_refreshed_at = None
            self._condition.notify_all()


_POOL = RoxyProfilePool()


def get_roxy_profile_pool() -> RoxyProfilePool:
    return _POOL
