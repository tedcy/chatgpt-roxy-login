# -*- coding: utf-8 -*-
"""Proxy selection and complete Roxy Profile lifecycle operations."""
from __future__ import annotations

import logging
import time

from config import roxybrowser as _cfg
from core.roxybrowser_domains.profile_config import (
    _first,
    _merge_configured_fingerprint,
    _noproxy_info,
    _project_id_value,
    _random_roxy_os,
    _random_roxy_profile_name,
    _roxy_info_runtime_proxy,
    _roxy_info_to_proxy_url,
    _proxy_url_to_roxy_info,
    _workspace_id_value,
)
from core.roxybrowser_domains.shared import (
    RoxyCreateBusyError,
    RoxyOpenResult,
    _CREATE_BUSY_DELAYS,
    _PROFILE_CREATE_LOCK,
    _merge_roxy_open_args,
    _profile_operation_slot,
)


logger = logging.getLogger("core.roxybrowser_client")


class RoxyProfileLifecycleMixin:
    def choose_task_proxy(
        self,
        task_proxy: str | None = None,
        *,
        proxy_country: str | None = None,
        proxy_wire_scope=None,
    ) -> tuple[dict, dict]:
        """Choose one task proxy, validating a configured SID template first."""
        if task_proxy is not None:
            from core.proxy_sid import mask_proxy_url

            proxy_url = str(task_proxy or "").strip()
            if not proxy_url:
                if proxy_wire_scope is not None:
                    raise RuntimeError("proxy_wire_meter_route_unresolved")
                return _noproxy_info(), {
                    "protocol": "noproxy",
                    "authenticated": False,
                    "source": "explicit_direct",
                    "safe_label": "",
                    "validated": False,
                    "expected_country": "",
                    "actual_country": "",
                    "geo": {},
                }
            routed_proxy = (
                proxy_wire_scope.wrap_proxy(
                    proxy_url,
                    phase="roxy_registration",
                )
                if proxy_wire_scope is not None
                else proxy_url
            )
            info = _proxy_url_to_roxy_info(routed_proxy)
            summary = {
                "protocol": str(
                    info.get("protocol") or info.get("proxyCategory") or "unknown"
                ),
                "authenticated": bool(
                    info.get("proxyUserName") or info.get("proxyPassword")
                ),
                "source": "explicit",
                "safe_label": (
                    "metered_http_proxy"
                    if proxy_wire_scope is not None
                    else mask_proxy_url(proxy_url)
                ),
                "validated": False,
                "expected_country": "",
                "actual_country": "",
                "geo": {},
            }
            if proxy_wire_scope is not None:
                summary["_wire_upstream_proxy_url"] = proxy_url
            return info, summary
        if not bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)):
            if proxy_wire_scope is not None:
                raise RuntimeError("proxy_wire_meter_route_unresolved")
            # Keep the long-standing public summary shape for callers and
            # tests.  open_profile records the resolved direct route on the
            # in-memory RoxyOpenResult, so no extra summary fields are needed.
            return _noproxy_info(), {
                "protocol": "noproxy",
                "authenticated": False,
            }
        from core.proxy_sid import select_default_proxy

        if proxy_country:
            if proxy_wire_scope is not None:
                selection = select_default_proxy(
                    proxy_country=proxy_country,
                    check_stop=self._check_stop_requested,
                )
            else:
                selection = select_default_proxy(
                    proxy_country=proxy_country,
                    check_stop=self._check_stop_requested,
                )
        else:
            # Keep the legacy call shape for non-rotating callers and tests.
            if proxy_wire_scope is not None:
                selection = select_default_proxy(
                    check_stop=self._check_stop_requested,
                )
            else:
                selection = select_default_proxy(
                    check_stop=self._check_stop_requested
                )
        proxy_url = selection.proxy_url
        if not proxy_url:
            if proxy_wire_scope is not None:
                raise RuntimeError("proxy_wire_meter_route_unresolved")
            logger.warning("[Roxy缓存池] 默认代理源为空，本任务明确使用 noproxy")
            return _noproxy_info(), {
                "protocol": "noproxy",
                "authenticated": False,
                "source": selection.source,
                "safe_label": "",
                "validated": False,
                "expected_country": "",
                "actual_country": "",
                "geo": {},
            }
        routed_proxy = (
            proxy_wire_scope.wrap_proxy(
                proxy_url,
                phase="roxy_registration",
            )
            if proxy_wire_scope is not None
            else proxy_url
        )
        info = _proxy_url_to_roxy_info(routed_proxy)
        summary = {
            "protocol": str(info.get("protocol") or info.get("proxyCategory") or "unknown"),
            "authenticated": bool(info.get("proxyUserName") or info.get("proxyPassword")),
            "source": selection.source,
            "safe_label": (
                "metered_http_proxy"
                if proxy_wire_scope is not None
                else selection.safe_label
            ),
            "validated": bool(selection.validated),
            "expected_country": selection.expected_country,
            "actual_country": selection.actual_country,
            "geo": dict(selection.geo or {}) if selection.validated else {},
        }
        if proxy_wire_scope is not None:
            summary["_wire_upstream_proxy_url"] = proxy_url
        return info, summary

    def prepare_cached_profile(
        self,
        profile_id: str,
        *,
        proxy_info: dict,
        proxy_summary: dict | None = None,
        clear_cache_once: bool,
        window_name: str,
        window_remark: str,
    ) -> None:
        """Bind the task proxy before randomization, then verify the final Profile."""
        selected_proxy = dict(proxy_info or _noproxy_info())
        selected_summary = dict(proxy_summary or {})

        # ``random_env`` derives language/timezone from the Profile's current
        # proxy, so the task proxy must be written before randomization.
        self.modify_profile(profile_id, {"proxyInfo": selected_proxy})
        self.randomize_profile(profile_id)
        detail = self.get_validated_profile_configuration(
            profile_id,
            proxy_info=selected_proxy,
            proxy_summary=selected_summary,
            stage="randomized",
        )
        configured = detail.get("fingerInfo")
        if not isinstance(configured, dict):
            configured = dict(
                (getattr(_cfg, "ROXY_PROFILE_CREATE_PAYLOAD", {}) or {}).get(
                    "fingerInfo"
                )
                or {}
            )
        finger_info = dict(configured)
        finger_info.update({
            "syncTab": False,
            "syncCookie": False,
            "syncPassword": False,
            "syncIndexedDb": False,
            "syncLocalStorage": False,
            "clearCacheFile": bool(clear_cache_once),
            "clearCookie": True,
            "clearLocalStorage": True,
            "randomFingerprint": False,
            "forbidSavePassword": True,
        })
        values = {
            "windowName": window_name,
            "windowRemark": window_remark,
            "defaultOpenUrl": ["about:blank"],
            "cookie": [],
            "proxyInfo": selected_proxy,
            "fingerInfo": finger_info,
        }
        resolved_os = str(detail.get("os") or "").strip()
        if resolved_os:
            values["os"] = resolved_os
        else:
            # Never assume an unknown cached Profile is macOS: doing so could
            # incorrectly add the Apple M3 fingerprint to a Windows Profile.
            logger.warning(
                "[Roxy缓存池] Profile OS 回读未知，跳过 OS 专属指纹：reason=profile_os_unknown"
            )
        _merge_configured_fingerprint(values)
        self.modify_profile(profile_id, values)
        self.get_validated_profile_configuration(
            profile_id,
            proxy_info=selected_proxy,
            proxy_summary=selected_summary,
            stage="final",
        )
        logger.info(
            "[Roxy缓存池] 租用环境已完成指纹刷新和身份预清理：protocol=%s authenticated=%s cache=%s",
            selected_proxy.get("protocol")
            or selected_proxy.get("proxyCategory")
            or "unknown",
            bool(
                selected_proxy.get("proxyUserName")
                or selected_proxy.get("proxyPassword")
            ),
            "clear-once" if clear_cache_once else "preserve",
        )

    def create_profile(self, payload: dict | None = None) -> str:
        body = dict(getattr(_cfg, "ROXY_PROFILE_CREATE_PAYLOAD", {}) or {})
        random_name_enabled = bool(
            getattr(_cfg, "ROXY_RANDOM_PROFILE_NAME_ON_CREATE", True)
        )
        if random_name_enabled:
            # 只随机 Roxy 的显示 name；缓存池的 windowName 槽位名保持稳定。
            body["name"] = _random_roxy_profile_name()
        random_os_enabled = bool(
            getattr(_cfg, "ROXY_RANDOM_OS_ON_CREATE", True)
        )
        if random_os_enabled:
            # 每次真正创建环境随机 Windows/macOS；已有 Profile 不经过此路径。
            body["os"] = _random_roxy_os()
            body.pop("osVersion", None)
        else:
            default_os = str(
                getattr(_cfg, "ROXY_DEFAULT_OS", "macOS") or "macOS"
            ).strip()
            if default_os:
                # Roxy 官方枚举大小写敏感：Windows / macOS / Linux / IOS / Android。
                body.setdefault("os", default_os)
            default_os_version = str(
                getattr(_cfg, "ROXY_DEFAULT_OS_VERSION", "") or ""
            ).strip()
            if default_os_version:
                body.setdefault("osVersion", default_os_version)
        workspace_id = _workspace_id_value()
        if workspace_id:
            # Roxy 官方 /browser/create 要求 workspaceId。
            body.setdefault("workspaceId", workspace_id)
        project_id = _project_id_value()
        if payload:
            # 顶层参数仍由调用方覆盖；fingerInfo 单独做嵌套合并，避免调用方只补一个
            # 指纹字段时把基础 Profile 配置中的其它指纹项整体丢掉。
            payload_values = dict(payload)
            payload_has_os = "os" in payload_values
            has_payload_finger_info = "fingerInfo" in payload_values
            payload_finger_info = payload_values.pop("fingerInfo", None)
            body.update(payload_values)
            if has_payload_finger_info:
                base_finger_info = body.get("fingerInfo")
                if isinstance(base_finger_info, dict) and isinstance(payload_finger_info, dict):
                    merged_finger_info = dict(base_finger_info)
                    merged_finger_info.update(payload_finger_info)
                    body["fingerInfo"] = merged_finger_info
                else:
                    body["fingerInfo"] = payload_finger_info
            # An explicit runtime OS owns its version. Otherwise a random OS
            # must not inherit a version supplied by the base payload.
            if random_os_enabled and not payload_has_os:
                body.pop("osVersion", None)
        # ROXY_PROJECT_ID is the ownership boundary.  A stale projectId in the
        # base/runtime payload must never redirect a cache Profile into another
        # Project in the same Workspace.
        if project_id:
            body["projectId"] = project_id
        if bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)) and not body.get("proxyInfo"):
            proxy_info, proxy_summary = self.choose_task_proxy()
            if str(proxy_info.get("proxyCategory") or "").lower() != "noproxy":
                body["proxyInfo"] = proxy_info
                logger.info(
                    "[Roxy] 创建环境启用默认代理：proxy=%s type=%s host=%s port=%s",
                    proxy_summary.get("safe_label") or "configured",
                    proxy_info.get("protocol") or proxy_info.get("proxyCategory"),
                    proxy_info.get("host"),
                    proxy_info.get("port"),
                )
            else:
                logger.warning("[Roxy] 已启用自动代理，但默认代理源为空，本次创建环境不设置代理")
        _merge_configured_fingerprint(body)
        logger.info("[Roxy] 创建环境已启用 Roxy 原生全量禁图（0KB）")
        if bool(getattr(_cfg, "ROXY_WEBRTC_REPLACE", False)):
            logger.info("[Roxy] 创建环境已启用 WebRTC 代理出口替换")
        if (
            bool(getattr(_cfg, "ROXY_MAC_M3_WEBGL", False))
            and str(body.get("os") or "").strip() == "macOS"
        ):
            logger.info("[Roxy] 创建 macOS 环境已启用 Apple M3 WebGL 指纹")
        if not body.get("workspaceId"):
            raise RuntimeError(
                "Roxy 创建环境需要 workspaceId。请在 config/roxybrowser.py 或 WebUI 的 RoxyBrowser 配置中填写 ROXY_WORKSPACE_ID，"
                "或直接在 ROXY_PROFILE_CREATE_PAYLOAD 里加入 {'workspaceId': '你的工作区ID'}。"
            )
        logger.info(
            "[Roxy] 创建环境参数：workspaceId=%s projectId=%s "
            "random_name=%s os=%s osVersion=%s random_os=%s",
            body.get("workspaceId"),
            body.get("projectId") or "-",
            random_name_enabled,
            body.get("os") or "-",
            body.get("osVersion") or "-",
            random_os_enabled,
        )
        # body（包括随机选中的代理）只构造一次。仅对 Roxy 明确返回的 create busy
        # 做有限退避；timeout/断连等模糊结果仍由 request() 保持单次调用，避免重复创建。
        with _PROFILE_CREATE_LOCK:
            result = None
            for attempt in range(1, len(_CREATE_BUSY_DELAYS) + 2):
                try:
                    result = self.request(
                        _cfg.ROXY_CREATE_METHOD,
                        _cfg.ROXY_CREATE_PATH,
                        json_body=body,
                    )
                    break
                except RoxyCreateBusyError:
                    if attempt > len(_CREATE_BUSY_DELAYS):
                        raise
                    delay = _CREATE_BUSY_DELAYS[attempt - 1]
                    logger.warning(
                        "[Roxy] Profile 创建通道忙，将在 %.1fs 后重试（%s/%s）",
                        delay,
                        attempt,
                        len(_CREATE_BUSY_DELAYS) + 1,
                    )
                    time.sleep(delay)
            if result is None:  # pragma: no cover - 循环只会返回或抛错
                raise RuntimeError("Roxy 创建环境未返回结果")
        profile_id = _first(result, [
            ("id",), ("dirId",), ("dir_id",), ("profile_id",), ("profileId",), ("browser_id",),
            ("data", "id"), ("data", "dirId"), ("data", "dir_id"),
            ("data", "profile_id"), ("data", "profileId"), ("data", "browser_id"),
        ])
        if not profile_id:
            from core.proxy_sid import redact_proxy_metadata

            raise RuntimeError(
                "Roxy 创建环境成功但未返回 dirId/profile_id: "
                f"{redact_proxy_metadata(result)}"
            )
        return profile_id

    @staticmethod
    def _normalize_profile_id(value: str | None) -> str:
        text = str(value or "").strip()
        # WebUI/人工配置里常用 - 表示“未配置”，这里统一按空处理。
        if text in ("-", "—", "无", "空", "none", "None", "null", "NULL"):
            return ""
        return text

    def _prepare_open_profile_request(
        self,
        profile_id: str | None,
        *,
        task_proxy: str | None,
        proxy_country: str | None,
        proxy_wire_scope,
        excluded_profile_ids: set[str] | frozenset[str] | None,
    ) -> tuple[set[str], str | None, bool, bool, str]:
        excluded_profiles = {
            str(value or "").strip()
            for value in (excluded_profile_ids or set())
            if str(value or "").strip()
        }
        normalized_proxy_country = str(proxy_country or "").strip().upper()
        if normalized_proxy_country and task_proxy is None:
            from core.proxy_sid import validate_registration_proxy_country_runtime

            # Direct callers must reject fixed/unmodifiable Profile settings
            # before touching the Roxy management API.
            proxy_country = validate_registration_proxy_country_runtime(
                normalized_proxy_country
            )
        cache_reuse = bool(getattr(_cfg, "ROXY_PROFILE_CACHE_REUSE", False))
        one_profile = (
            bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
            and not cache_reuse
        )
        configured_pid = self._normalize_profile_id(
            profile_id
            if profile_id is not None
            else getattr(_cfg, "ROXY_PROFILE_ID", "")
        )
        if (
            proxy_wire_scope is not None
            and task_proxy is None
            and not bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False))
        ):
            raise RuntimeError("proxy_wire_meter_route_unresolved")
        return (
            excluded_profiles,
            proxy_country,
            cache_reuse,
            one_profile,
            configured_pid,
        )

    def open_profile(
        self,
        profile_id: str | None = None,
        *,
        headless: bool | None = None,
        browser_args: tuple[str, ...] | list[str] | None = None,
        task_proxy: str | None = None,
        proxy_country: str | None = None,
        proxy_wire_scope=None,
        stop_check=None,
        excluded_profile_ids: set[str] | frozenset[str] | None = None,
    ) -> RoxyOpenResult:
        (
            excluded_profiles,
            proxy_country,
            cache_reuse,
            one_profile,
            configured_pid,
        ) = self._prepare_open_profile_request(
            profile_id,
            task_proxy=task_proxy,
            proxy_country=proxy_country,
            proxy_wire_scope=proxy_wire_scope,
            excluded_profile_ids=excluded_profile_ids,
        )
        if cache_reuse:
            if not _project_id_value():
                raise RuntimeError(
                    "Roxy Profile 缓存复用必须配置 ROXY_PROJECT_ID；"
                    "已拒绝按 Workspace 跨项目扫描环境"
                )
            if configured_pid or bool(getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False)):
                logger.info("[Roxy缓存池] 已忽略固定 Profile 与保留窗口配置")
            from core.roxy_profile_pool import PROFILE_CACHE_REMARK, get_roxy_profile_pool

            pool = get_roxy_profile_pool()
            lease = None
            allocation_stop_check = (
                self._check_stop_requested if stop_check is None else stop_check
            )
            try:
                # Validate the task proxy before any list/create/modify/open
                # Roxy management request. The accepted SID is then reused for
                # the complete task and is never selected again.
                if proxy_country:
                    if proxy_wire_scope is not None:
                        proxy_info, proxy_summary = self.choose_task_proxy(
                            task_proxy,
                            proxy_country=proxy_country,
                            proxy_wire_scope=proxy_wire_scope,
                        )
                    else:
                        proxy_info, proxy_summary = self.choose_task_proxy(
                            task_proxy,
                            proxy_country=proxy_country,
                        )
                else:
                    if proxy_wire_scope is not None:
                        proxy_info, proxy_summary = self.choose_task_proxy(
                            task_proxy,
                            proxy_wire_scope=proxy_wire_scope,
                        )
                    else:
                        proxy_info, proxy_summary = self.choose_task_proxy(task_proxy)
                total_started = time.monotonic()
                acquire_kwargs = {
                    "proxy_info": proxy_info,
                    "proxy_summary": proxy_summary,
                    "stop_check": allocation_stop_check,
                }
                if excluded_profiles:
                    acquire_kwargs["excluded_profile_ids"] = excluded_profiles
                lease = pool.acquire(self, **acquire_kwargs)
                lease_elapsed_ms = int((time.monotonic() - total_started) * 1000)
                if lease.adopted:
                    raise RuntimeError("roxy_profile_foreign_adoption_forbidden")
                with _profile_operation_slot(lease.profile_id):
                    prepare_started = time.monotonic()
                    self.prepare_cached_profile(
                        lease.profile_id,
                        proxy_info=lease.proxy_info,
                        proxy_summary=lease.proxy_summary,
                        clear_cache_once=False,
                        window_name=lease.window_name,
                        window_remark=PROFILE_CACHE_REMARK,
                    )
                    prepare_elapsed_ms = int(
                        (time.monotonic() - prepare_started) * 1000
                    )
                    open_started = time.monotonic()
                    opened = self._open_profile_by_id(
                        lease.profile_id,
                        created_by_run=lease.newly_created,
                        headless=headless,
                        browser_args=browser_args,
                    )
                    open_elapsed_ms = int(
                        (time.monotonic() - open_started) * 1000
                    )
                logger.info(
                    "[Roxy] Profile 启动阶段完成：source=%s lease_ms=%s "
                    "prepare_ms=%s open_ms=%s total_ms=%s",
                    lease.source,
                    lease_elapsed_ms,
                    prepare_elapsed_ms,
                    open_elapsed_ms,
                    int((time.monotonic() - total_started) * 1000),
                )
                opened.pooled = True
                opened.lease_token = lease.token
                opened.profile_cache_source = lease.source
                opened.profile_cache_expectation = (
                    "cold" if lease.source == "new" else "reused"
                )
                opened.proxy_safe_label = str(
                    lease.proxy_summary.get("safe_label") or ""
                )
                opened.task_proxy_url = _roxy_info_to_proxy_url(lease.proxy_info)
                opened.task_proxy_upstream_url = str(
                    lease.proxy_summary.get("_wire_upstream_proxy_url") or ""
                )
                opened.task_proxy_geo = dict(
                    lease.proxy_summary.get("geo") or {}
                )
                opened.task_proxy_resolved = True
                return opened
            except BaseException as exc:
                if lease is not None:
                    if self.is_transient_api_error(exc):
                        pool.defer(lease, reason="roxy_api_transient")
                    else:
                        pool.discard(self, lease)
                raise
        if one_profile and configured_pid:
            raise RuntimeError(
                "已启用 ROXY_ONE_PROFILE_PER_ACCOUNT=True（一号一环境），"
                "不能配置/传入固定 ROXY_PROFILE_ID；请留空以便每个账号创建新环境。"
            )

        if configured_pid:
            if configured_pid in excluded_profiles:
                raise RuntimeError("roxy_profile_excluded")
            if proxy_wire_scope is not None:
                raise RuntimeError("proxy_wire_meter_route_unresolved")
            # 打开已有 Profile 不占用创建通道；Roxy 自身负责已有窗口的状态校验。
            with _profile_operation_slot(configured_pid):
                return self._open_profile_by_id(
                    configured_pid,
                    created_by_run=False,
                    headless=headless,
                    browser_args=browser_args,
                )

        # create 保持单路串行；创建完成后的 open 和地址校验只与同一 Profile 互斥，
        # 因此不同环境可以并行启动。
        proxy_info = None
        proxy_summary: dict = {}
        select_proxy_before_create = task_proxy is not None or bool(
            getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)
        )
        if select_proxy_before_create:
            # This happens before create/open so a rejected SID can never be
            # assigned to a new Profile.
            if proxy_country:
                if proxy_wire_scope is not None:
                    proxy_info, proxy_summary = self.choose_task_proxy(
                        task_proxy,
                        proxy_country=proxy_country,
                        proxy_wire_scope=proxy_wire_scope,
                    )
                else:
                    proxy_info, proxy_summary = self.choose_task_proxy(
                        task_proxy,
                        proxy_country=proxy_country,
                    )
            else:
                if proxy_wire_scope is not None:
                    proxy_info, proxy_summary = self.choose_task_proxy(
                        task_proxy,
                        proxy_wire_scope=proxy_wire_scope,
                    )
                else:
                    proxy_info, proxy_summary = self.choose_task_proxy(task_proxy)
        total_started = time.monotonic()
        pid = (
            self.create_profile(payload={"proxyInfo": proxy_info})
            if proxy_info is not None
            else self.create_profile()
        )
        create_elapsed_ms = int((time.monotonic() - total_started) * 1000)
        logger.info(
            "[Roxy] 已创建临时环境：%s",
            "[REDACTED]" if self.safe_logging else pid,
        )
        with _profile_operation_slot(pid):
            try:
                open_started = time.monotonic()
                opened = self._open_profile_by_id(
                    pid,
                    created_by_run=True,
                    headless=headless,
                    browser_args=browser_args,
                )
                logger.info(
                    "[Roxy] 临时 Profile 启动阶段完成：create_ms=%s open_ms=%s total_ms=%s",
                    create_elapsed_ms,
                    int((time.monotonic() - open_started) * 1000),
                    int((time.monotonic() - total_started) * 1000),
                )
                opened.proxy_safe_label = str(proxy_summary.get("safe_label") or "")
                if proxy_info is not None:
                    opened.task_proxy_url = _roxy_info_to_proxy_url(proxy_info)
                    opened.task_proxy_upstream_url = str(
                        proxy_summary.get("_wire_upstream_proxy_url") or ""
                    )
                    opened.task_proxy_geo = dict(proxy_summary.get("geo") or {})
                    opened.task_proxy_resolved = True
                else:
                    configured_payload = dict(
                        getattr(_cfg, "ROXY_PROFILE_CREATE_PAYLOAD", {}) or {}
                    )
                    configured_proxy_info = configured_payload.get("proxyInfo")
                    if not isinstance(configured_proxy_info, dict):
                        configured_proxy_info = {}
                    resolved, configured_proxy = _roxy_info_runtime_proxy(
                        configured_proxy_info
                    )
                    opened.task_proxy_url = configured_proxy
                    opened.task_proxy_resolved = resolved
                    if configured_proxy:
                        from core.proxy_sid import mask_proxy_url

                        opened.proxy_safe_label = mask_proxy_url(configured_proxy)
                return opened
            except BaseException:
                # open_profile 尚未返回，外层拿不到 RoxyOpenResult，必须在这里清理刚创建
                # 的 Profile。KeyboardInterrupt 也必须先清理；close/delete 本身是
                # best-effort，且不能覆盖原始 open 错误。
                for action in (self.close_profile, self.delete_profile):
                    try:
                        action(pid)
                    except Exception:
                        logger.warning("[Roxy] 打开临时环境失败后的清理步骤未完成")
                raise

    @staticmethod
    def _check_stop_requested() -> None:
        try:
            from core.registration_service import check_stop_requested
        except ImportError:
            return
        check_stop_requested()

    def _open_profile_by_id(
        self,
        pid: str,
        *,
        created_by_run: bool,
        headless: bool | None = None,
        browser_args: tuple[str, ...] | list[str] | None = None,
    ) -> RoxyOpenResult:
        path = str(_cfg.ROXY_OPEN_PATH).format(profile_id=pid)
        params = dict(getattr(_cfg, "ROXY_OPEN_EXTRA_PARAMS", {}) or {})
        # Roxy 官方 /browser/open body: {workspaceId, dirId, args, forceOpen, headless}
        params.setdefault("workspaceId", _workspace_id_value())
        params.setdefault("dirId", int(pid) if str(pid).isdigit() else pid)
        open_args = list(params.get("args") or [])
        if browser_args:
            open_args = _merge_roxy_open_args(open_args, browser_args)
        for required_arg in ("--disable-http2", "--disable-component-update"):
            if required_arg not in open_args:
                open_args.append(required_arg)
        params["args"] = open_args
        params.setdefault("forceOpen", True)
        # ROXY_OPEN_HEADLESS 是显式开关，优先级应高于 ROXY_OPEN_EXTRA_PARAMS，
        # 否则 extra 里残留 headless=False 会导致 WebUI 保存无头后仍弹窗口。
        params["headless"] = (
            bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False))
            if headless is None
            else bool(headless)
        )
        profile_log_value = "[REDACTED]" if self.safe_logging else pid
        logger.info(
            "[Roxy] open 参数：profile=%s headless=%s keep_open=%s args=%s",
            profile_log_value,
            params.get("headless"),
            getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False),
            params.get("args"),
        )
        result = self.request(
            _cfg.ROXY_OPEN_METHOD,
            path,
            params=params if _cfg.ROXY_OPEN_METHOD.upper() == "GET" else None,
            json_body=params if _cfg.ROXY_OPEN_METHOD.upper() != "GET" else None,
        )
        debugger_address = self._extract_debugger_address(result)
        from core.proxy_sid import redact_proxy_metadata

        safe_result = redact_proxy_metadata(result)
        webdriver_url = _first(result, [
            ("webdriver",), ("webDriver",), ("webdriver_url",), ("webdriverUrl",),
            ("selenium",), ("selenium_url",), ("seleniumUrl",),
            ("data", "webdriver"), ("data", "webDriver"), ("data", "webdriver_url"), ("data", "webdriverUrl"),
            ("data", "selenium"), ("data", "selenium_url"), ("data", "seleniumUrl"),
        ]) or None
        ws_endpoint = _first(result, [
            ("ws",), ("wsEndpoint",), ("ws_endpoint",), ("debuggerWsUrl",),
            ("data", "ws"), ("data", "wsEndpoint"), ("data", "ws_endpoint"), ("data", "debuggerWsUrl"),
        ]) or None
        logger.info(
            "[Roxy] open 返回摘要: debugger=%s webdriver=%s ws=%s",
            "[REDACTED]" if self.safe_logging else debugger_address,
            bool(webdriver_url),
            bool(ws_endpoint),
        )
        if not debugger_address and not webdriver_url:
            raise RuntimeError(
                "Roxy 已打开环境但未返回 Selenium/调试地址，请检查 "
                f"ROXY_OPEN_PATH 或接口响应: {safe_result}"
            )
        return RoxyOpenResult(
            pid,
            safe_result,
            debugger_address=debugger_address,
            webdriver_url=webdriver_url,
            ws_endpoint=ws_endpoint,
            created_by_run=created_by_run,
        )

    def _close_profile_strict(self, profile_id: str) -> None:
        path = str(_cfg.ROXY_CLOSE_PATH).format(profile_id=profile_id)
        body = {
            "workspaceId": _workspace_id_value(),
            "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
        }
        self.request(
            _cfg.ROXY_CLOSE_METHOD,
            path,
            params=body if str(_cfg.ROXY_CLOSE_METHOD).upper() == "GET" else None,
            json_body=body if str(_cfg.ROXY_CLOSE_METHOD).upper() != "GET" else None,
        )

    def close_profile(self, profile_id: str) -> bool:
        if not profile_id:
            return False
        with _profile_operation_slot(profile_id):
            try:
                self._close_profile_strict(profile_id)
                logger.info(
                    "[Roxy] 已关闭环境：%s",
                    "[REDACTED]" if self.safe_logging else profile_id,
                )
                return True
            except Exception as exc:
                logger.warning(
                    "[Roxy] 关闭环境失败：%s",
                    type(exc).__name__ if self.safe_logging else exc,
                )
                return False

    def delete_profile(self, profile_id: str) -> bool:
        if not profile_id:
            return False
        path = str(getattr(_cfg, "ROXY_DELETE_PATH", "/browser/delete")).format(profile_id=profile_id)
        method = str(getattr(_cfg, "ROXY_DELETE_METHOD", "POST") or "POST")
        with _profile_operation_slot(profile_id):
            try:
                body = {
                    "workspaceId": _workspace_id_value(),
                    "dirIds": [int(profile_id) if str(profile_id).isdigit() else profile_id],
                }
                self.request(
                    method,
                    path,
                    params=body if method.upper() == "GET" else None,
                    json_body=body if method.upper() != "GET" else None,
                )
                logger.info(
                    "[Roxy] 已删除环境：%s",
                    "[REDACTED]" if self.safe_logging else profile_id,
                )
                return True
            except Exception as exc:
                logger.warning(
                    "[Roxy] 删除环境失败：%s",
                    type(exc).__name__ if self.safe_logging else exc,
                )
                return False

    def _profile_open_state_strict(self, profile_id: str) -> bool | None:
        """Return the Profile's confirmed open state without collapsing unknown.

        ``False`` means confirmed closed, ``True`` means confirmed open, and
        ``None`` means the list/detail responses cannot currently prove either
        state.  A temporarily missing list row is deliberately treated as
        unknown so cleanup never turns an incomplete snapshot into a delete.
        """
        rows = self.list_profiles()
        for row in rows:
            if self.profile_id_from_row(row) == str(profile_id):
                state = self.profile_open_state(row)
                if state is None:
                    detail = self.get_profile_detail(profile_id)
                    detail_id = self.profile_id_from_row(detail)
                    if detail_id and detail_id != str(profile_id):
                        return None
                    state = self.profile_open_state(detail)
                return state
        return None

    def _profile_is_closed_strict(self, profile_id: str) -> bool:
        """Compatibility wrapper for callers that only need a safe boolean."""
        return self._profile_open_state_strict(profile_id) is False

    def profile_is_closed(self, profile_id: str) -> bool:
        try:
            return self._profile_is_closed_strict(profile_id)
        except Exception:
            return False

    def cleanup_profile(self, opened: RoxyOpenResult | None) -> None:
        """任务结束清理：关闭窗口；一号一环境时删除本轮创建的 Profile。"""
        if not opened or not opened.profile_id:
            return
        with _profile_operation_slot(opened.profile_id):
            self._cleanup_profile_serialized(opened)

    def _cleanup_profile_serialized(self, opened: RoxyOpenResult) -> None:
        """Clean one Profile while its per-Profile operation lock is held."""
        if opened.pooled:
            from core.roxy_profile_pool import get_roxy_profile_pool

            pool = get_roxy_profile_pool()
            if bool(getattr(opened, "profile_cache_discard", False)):
                logger.warning("[Roxy缓存池] 环境身份清理失败，按结构性故障关闭并删除")
                pool.discard_token(self, opened.lease_token or "")
                return
            try:
                self._close_profile_strict(opened.profile_id)
            except Exception as exc:
                reason = (
                    "close_transient_api_error"
                    if self.is_transient_api_error(exc)
                    else "close_api_error"
                )
                logger.warning(
                    "[Roxy缓存池] 环境关闭未确认：reason=%s，已延后核验并保留缓存",
                    reason,
                )
                pool.defer_token(opened.lease_token or "", reason=reason)
                return
            try:
                state = self._profile_open_state_strict(opened.profile_id)
            except Exception as exc:
                reason = (
                    "close_transient_api_error"
                    if self.is_transient_api_error(exc)
                    else "close_api_error"
                )
                logger.warning(
                    "[Roxy缓存池] 环境关闭未确认：reason=%s，已延后核验并保留缓存",
                    reason,
                )
                pool.defer_token(opened.lease_token or "", reason=reason)
                return
            if state is False:
                pool.release(opened.lease_token or "", healthy=True)
                return
            reason = "close_state_open" if state is True else "close_state_unknown"
            logger.warning(
                "[Roxy缓存池] 环境关闭未确认：reason=%s，已延后核验并保留缓存",
                reason,
            )
            pool.defer_token(opened.lease_token or "", reason=reason)
            return
        keep_open = bool(getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))
        if not keep_open:
            self.close_profile(opened.profile_id)

        should_delete = (
            bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
            and bool(getattr(_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True))
            and bool(opened.created_by_run)
        )
        if should_delete:
            # 删除前尽量确保已关闭；若 keep_open=True 则不删除，便于调试保留现场。
            if keep_open:
                logger.info(
                    "[Roxy] ROXY_KEEP_BROWSER_OPEN=True，跳过删除环境：%s",
                    "[REDACTED]" if self.safe_logging else opened.profile_id,
                )
                return
            self.delete_profile(opened.profile_id)

    @staticmethod
    def _extract_debugger_address(payload: dict) -> str | None:
        value = _first(payload, [
            ("debuggerAddress",), ("debugger_address",), ("debugAddress",),
            ("debuggingPortUrl",), ("debugging_port_url",),
            ("remoteDebuggingAddress",), ("remote_debugging_address",),
            ("http",), ("debugHttp",), ("debug_http",),
            ("data", "debuggerAddress"), ("data", "debugger_address"), ("data", "debugAddress"),
            ("data", "debuggingPortUrl"), ("data", "debugging_port_url"),
            ("data", "remoteDebuggingAddress"), ("data", "remote_debugging_address"),
            ("data", "http"), ("data", "debugHttp"), ("data", "debug_http"),
        ])
        if value:
            value = value.strip()
            # 兼容 http://127.0.0.1:xxxx / 127.0.0.1:xxxx / :xxxx / 9222
            value = value.replace("http://", "").replace("https://", "").strip("/")
            if value.startswith(":") and value[1:].isdigit():
                return f"127.0.0.1{value}"
            if value.isdigit():
                return f"127.0.0.1:{value}"
            if ":" in value and not value.startswith(":"):
                return value
        port = _first(payload, [
            ("debuggingPort",), ("debugging_port",), ("debug_port",), ("port",),
            ("data", "debuggingPort"), ("data", "debugging_port"), ("data", "debug_port"), ("data", "port"),
        ])
        if port:
            port = str(port).strip()
            if port.startswith(":"):
                port = port[1:]
            if port.isdigit():
                return f"127.0.0.1:{port}"
        return None
