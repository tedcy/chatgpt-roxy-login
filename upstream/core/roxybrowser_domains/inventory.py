# -*- coding: utf-8 -*-
"""Workspace and Profile inventory, readback, and validation operations."""
from __future__ import annotations

import logging
import time

from config import roxybrowser as _cfg
from core.roxybrowser_domains.profile_config import (
    _first,
    _locale_readback_issues,
    _noproxy_info,
    _project_id_value,
    _proxy_readback_issues,
    _validated_proxy_country,
    _workspace_id_value,
)
from core.roxybrowser_domains.shared import (
    RoxyProfileValidationError,
    _PROFILE_READBACK_DELAYS,
)
from core.roxy_profile_utils import project_id_from_row


logger = logging.getLogger("core.roxybrowser_client")


class RoxyProfileInventoryMixin:
    @staticmethod
    def _extract_workspace_items(payload: dict) -> list[dict]:
        """解析 /browser/workspace：团队 rows + project_details 项目列表；兼容递归兜底。"""
        out = []

        # 官方结构：data.rows[].id/workspaceName/project_details[].projectId/projectName
        rows = None
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                rows = data.get("rows") or data.get("list") or data.get("records")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                wid = row.get("id") or row.get("workspaceId") or row.get("workspace_id")
                wname = row.get("workspaceName") or row.get("workspace_name") or row.get("name") or str(wid or "")
                projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
                if isinstance(projects, list) and projects:
                    for proj in projects:
                        if not isinstance(proj, dict):
                            continue
                        pid = proj.get("projectId") or proj.get("project_id") or proj.get("id")
                        pname = proj.get("projectName") or proj.get("project_name") or proj.get("name") or str(pid or "")
                        if wid:
                            out.append({
                                "id": str(wid),
                                "name": str(wname),
                                "projectId": str(pid or ""),
                                "projectName": str(pname or ""),
                                "label": f"{wname} / {pname} ({wid}/{pid})" if pid else f"{wname} ({wid})",
                                "raw": {"workspace": row, "project": proj},
                            })
                elif wid:
                    out.append({
                        "id": str(wid),
                        "name": str(wname),
                        "projectId": "",
                        "projectName": "",
                        "label": f"{wname} ({wid})",
                        "raw": row,
                    })

        if out:
            return out

        # 兜底：递归抽 workspace/team/company 结构。
        def pick_id_name(item: dict) -> tuple[str, str]:
            wid = _first(item, [
                ("workspaceId",), ("workspace_id",), ("workspaceID",),
                ("teamId",), ("team_id",), ("teamID",),
                ("companyId",), ("company_id",), ("orgId",), ("org_id",),
                ("id",), ("value",), ("key",),
            ])
            name = _first(item, [
                ("workspaceName",), ("workspace_name",),
                ("teamName",), ("team_name",),
                ("companyName",), ("company_name",),
                ("orgName",), ("org_name",),
                ("name",), ("label",), ("title",), ("remark",),
            ])
            return wid, name

        def looks_like_workspace(item: dict) -> bool:
            keys = {str(k).lower() for k in item.keys()}
            joined = " ".join(keys)
            return any(x in joined for x in ("workspace", "team", "company", "org")) or ("id" in keys and "name" in keys)

        def walk(node):
            if isinstance(node, dict):
                wid, name = pick_id_name(node)
                if wid and looks_like_workspace(node):
                    out.append({"id": wid, "name": name or wid, "projectId": "", "projectName": "", "label": f"{name or wid} ({wid})", "raw": node})
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)
        dedup = {}
        for item in out:
            raw_keys = {str(k).lower() for k in (item.get("raw") or {}).keys()}
            if "dirid" in raw_keys and not any(k in raw_keys for k in ("workspaceid", "teamid", "companyid")):
                continue
            key = f"{item.get('id')}::{item.get('projectId','')}"
            dedup[key] = item
        return list(dedup.values())

    def list_workspaces(self) -> dict:
        """
        获取 Roxy 团队/工作区列表。
        Roxy 不同版本路径可能有差异，因此先试配置路径，再试常见路径。
        """
        configured = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_PATH", "") or "").strip()
        method = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_METHOD", "GET") or "GET").upper()
        candidates = []
        if configured:
            candidates.append((method, configured))
        candidates.extend([
            ("GET", "/browser/workspace"),
            ("POST", "/browser/workspace"),
            ("GET", "/workspace/list"),
            ("POST", "/workspace/list"),
            ("GET", "/workspace"),
            ("POST", "/workspace"),
            ("GET", "/team/list"),
            ("POST", "/team/list"),
            ("GET", "/team"),
            ("POST", "/team"),
            ("GET", "/workspaces"),
            ("GET", "/teams"),
            ("GET", "/user/workspace/list"),
            ("POST", "/user/workspace/list"),
            ("GET", "/user/team/list"),
            ("POST", "/user/team/list"),
            ("GET", "/api/workspace/list"),
            ("POST", "/api/workspace/list"),
            ("GET", "/api/team/list"),
            ("POST", "/api/team/list"),
            ("GET", "/browser/workspace/list"),
            ("POST", "/browser/workspace/list"),
            ("GET", "/browser/team/list"),
            ("POST", "/browser/team/list"),
        ])

        errors = []
        seen = set()
        for m, path in candidates:
            key = (m, path)
            if key in seen:
                continue
            seen.add(key)
            ok, payload = self.try_request(m, path)
            if not ok:
                errors.append({"method": m, "path": path, "error": payload})
                continue
            items = self._extract_workspace_items(payload if isinstance(payload, dict) else {})
            if items:
                return {"ok": True, "path": path, "method": m, "items": items, "raw": payload}
            errors.append({"method": m, "path": path, "error": "响应中未解析到团队/工作区列表", "payload": payload})

        return {"ok": False, "items": [], "errors": errors}

    @staticmethod
    def _profile_rows(payload: dict) -> list[dict]:
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, dict):
            rows = data.get("rows") or data.get("list") or data.get("records")
            if isinstance(rows, list):
                return [dict(item) for item in rows if isinstance(item, dict)]
        return []

    def list_profiles(self) -> list[dict]:
        """Return safe inventory rows from the configured Project only.

        Prefer Roxy's responsive ``/browser/list_v3`` endpoint.  Current Roxy
        versions include Project ownership in these rows; the legacy
        ``/browser/list`` endpoint can block for 15 seconds and return the
        server's timeout envelope even for a valid workspace/project.
        """
        rows: list[dict] = []
        scanned = 0
        rejected_cross_project = 0
        missing_project_metadata = 0
        project_id = _project_id_value()
        if not project_id:
            raise RuntimeError(
                "Roxy Profile 列表必须配置 ROXY_PROJECT_ID："
                "reason=roxy_project_id_required"
            )
        page = 1
        while page <= 20:
            params = {
                "workspaceId": _workspace_id_value(),
                "projectId": project_id,
                "page_index": page,
                "page_size": 100,
            }
            payload = self.request(
                "GET",
                "/browser/list_v3",
                params=params,
            )
            current = self._profile_rows(payload)
            scanned += len(current)
            for row in current:
                actual_project = self.profile_project_id_from_row(row)
                if not actual_project:
                    missing_project_metadata += 1
                    continue
                if actual_project != str(project_id):
                    rejected_cross_project += 1
                    continue
                rows.append({
                    "projectId": actual_project,
                    **{
                        key: row[key]
                        for key in (
                            "dirId",
                            "dir_id",
                            "profileId",
                            "id",
                            "windowName",
                            "windowRemark",
                            "openStatus",
                            "isOpen",
                            "opened",
                            "open",
                            "status",
                            "closeTime",
                            "updateTime",
                            "createTime",
                        )
                        if key in row
                    },
                })
            data = payload.get("data") if isinstance(payload, dict) else {}
            total = (
                int((data or {}).get("total") or scanned)
                if isinstance(data, dict)
                else scanned
            )
            if not current or scanned >= total or len(current) < 100:
                break
            page += 1
        if missing_project_metadata:
            raise RuntimeError(
                "Roxy Profile 列表 Project 归属校验失败："
                "reason=profile_project_metadata_missing "
                f"count={missing_project_metadata}"
            )
        if rejected_cross_project:
            logger.warning(
                "[Roxy缓存池] 列表响应包含非当前 Project 环境，已拒绝纳入：count=%s",
                rejected_cross_project,
            )
        return rows

    def get_profile_detail(self, profile_id: str) -> dict:
        params = {
            "workspaceId": _workspace_id_value(),
            "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
        }
        project_id = _project_id_value()
        if project_id:
            params["projectId"] = project_id
        payload = self.request(
            "GET",
            "/browser/detail",
            params=params,
        )
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, dict):
            # RoxyBrowser 3.9.2 returns the requested Profile in
            # ``data.rows[0]`` (rather than directly in ``data``).  Keep the
            # direct-object fallback for older/local API variants.
            rows = data.get("rows") or data.get("list") or data.get("records")
            if isinstance(rows, list):
                wanted = str(profile_id or "")
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    actual_project = self.profile_project_id_from_row(row)
                    if (
                        self.profile_id_from_row(row) == wanted
                        and (
                            not project_id
                            or (actual_project and actual_project == str(project_id))
                        )
                    ):
                        return dict(row)
                return {}
            actual_project = self.profile_project_id_from_row(data)
            if (
                self.profile_id_from_row(data) == str(profile_id or "")
                and (
                    not project_id
                    or (actual_project and actual_project == str(project_id))
                )
            ):
                return dict(data)
        return {}

    def get_profile_configuration(self, profile_id: str) -> dict:
        """Read the full Profile configuration, including ``fingerInfo``.

        RoxyBrowser 3.9.2 intentionally omits fingerprint fields from
        ``/browser/detail``.  The older ``/browser/list`` endpoint supports a
        ``dirId`` filter and returns the complete proxy/fingerprint row.
        """
        params = {
            "workspaceId": _workspace_id_value(),
            "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
        }
        project_id = _project_id_value()
        if project_id:
            params["projectId"] = project_id
        payload = self.request(
            "GET",
            "/browser/list",
            params=params,
        )
        wanted = str(profile_id or "")
        for row in self._profile_rows(payload):
            actual_project = self.profile_project_id_from_row(row)
            if (
                self.profile_id_from_row(row) == wanted
                and (
                    not project_id
                    or (actual_project and actual_project == str(project_id))
                )
            ):
                return dict(row)
        return {}

    @staticmethod
    def validate_profile_configuration(
        detail: object,
        *,
        proxy_info: dict,
        proxy_summary: dict,
        stage: str,
    ) -> None:
        if not isinstance(detail, dict) or not detail:
            raise RoxyProfileValidationError(
                "roxy_profile_readback_missing",
                stage=stage,
                issues=["profile_detail_missing"],
            )

        proxy_issues = _proxy_readback_issues(
            dict(proxy_info or _noproxy_info()), detail.get("proxyInfo")
        )
        expected_country = _validated_proxy_country(proxy_summary)
        country_metadata = "not_checked"
        if expected_country and isinstance(detail.get("proxyInfo"), dict):
            actual_country = str(
                detail["proxyInfo"].get("lastCountry") or ""
            ).strip().upper()
            if not actual_country:
                country_metadata = "missing"
            elif actual_country != expected_country:
                country_metadata = "stale"
            else:
                country_metadata = "matched"
        if proxy_issues:
            raise RoxyProfileValidationError(
                "roxy_profile_proxy_mismatch",
                stage=stage,
                issues=proxy_issues,
            )

        locale_issues = _locale_readback_issues(
            detail.get("fingerInfo"), proxy_summary
        )
        if locale_issues:
            reason = (
                "roxy_profile_readback_missing"
                if any(issue.endswith("_missing") for issue in locale_issues)
                else "roxy_profile_locale_mismatch"
            )
            raise RoxyProfileValidationError(
                reason,
                stage=stage,
                issues=locale_issues,
            )

        logger.info(
            "[Roxy缓存池] Profile 回读校验通过：stage=%s proxy=matched "
            "locale=matched country=%s country_metadata=%s",
            stage,
            expected_country or "unverified",
            country_metadata,
        )

    def get_validated_profile_configuration(
        self,
        profile_id: str,
        *,
        proxy_info: dict,
        proxy_summary: dict,
        stage: str,
    ) -> dict:
        """Wait briefly for Roxy's persisted proxy/Locale view to converge."""
        total_attempts = len(_PROFILE_READBACK_DELAYS) + 1
        for attempt in range(1, total_attempts + 1):
            self._check_stop_requested()
            detail = self.get_profile_configuration(profile_id)
            try:
                self.validate_profile_configuration(
                    detail,
                    proxy_info=proxy_info,
                    proxy_summary=proxy_summary,
                    stage=stage,
                )
                return detail
            except RoxyProfileValidationError as exc:
                if attempt >= total_attempts:
                    raise
                delay = _PROFILE_READBACK_DELAYS[attempt - 1]
                logger.info(
                    "[Roxy缓存池] Profile 回读尚未收敛，将重试："
                    "stage=%s reason=%s issues=%s attempt=%s/%s delay=%.1fs",
                    exc.stage,
                    exc.reason_code,
                    ",".join(exc.issues) or "unknown",
                    attempt,
                    total_attempts,
                    delay,
                )
                time.sleep(delay)
        raise RuntimeError("Roxy Profile 回读校验未返回结果")  # pragma: no cover

    def modify_profile(self, profile_id: str, values: dict) -> None:
        body = dict(values or {})
        body["workspaceId"] = _workspace_id_value()
        body["dirId"] = int(profile_id) if str(profile_id).isdigit() else profile_id
        self.request("POST", "/browser/mdf", json_body=body)

    def randomize_profile(self, profile_id: str) -> None:
        self.request(
            "POST",
            "/browser/random_env",
            json_body={
                "workspaceId": _workspace_id_value(),
                "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
            },
        )

    @staticmethod
    def profile_id_from_row(row: dict) -> str:
        return str(
            row.get("dirId")
            or row.get("dir_id")
            or row.get("profileId")
            or row.get("id")
            or ""
        ).strip()

    @staticmethod
    def profile_project_id_from_row(row: dict) -> str:
        return project_id_from_row(row)

    @staticmethod
    def profile_open_state(row: dict) -> bool | None:
        for key in ("openStatus", "isOpen", "opened", "open"):
            if key not in row:
                continue
            value = row.get(key)
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            text = str(value or "").strip().lower()
            if text in {"true", "1", "yes", "open", "opened", "running"}:
                return True
            if text in {"false", "0", "no", "close", "closed", "stopped"}:
                return False
        status = str(row.get("status") or "").strip().lower()
        if status in {"open", "opened", "running"}:
            return True
        if status in {"close", "closed", "stopped"}:
            return False
        return None

    def resolve_profile_open_state(self, row: dict) -> bool | None:
        """Resolve open state, falling back to ``/browser/detail``.

        Lightweight or older caller rows can omit ``openStatus`` while the
        detail row includes it.  Unknown state remains unavailable so the pool
        never rents an environment it cannot prove closed.
        """
        try:
            return self.resolve_profile_open_state_strict(row)
        except Exception:
            return None

    def resolve_profile_open_state_strict(self, row: dict) -> bool | None:
        """Resolve state without hiding Local API failures from pool allocation."""
        state = self.profile_open_state(row)
        if state is not None:
            return state
        profile_id = self.profile_id_from_row(row)
        if not profile_id:
            return None
        return self.profile_open_state(self.get_profile_detail(profile_id))
