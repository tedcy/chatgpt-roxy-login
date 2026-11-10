"""Workspace UI projection over the unmodified production Roxy client."""
from .kernel_bridge import bootstrap, bound
from .settings import local_url


class RoxyError(RuntimeError):
    pass


def workspace_catalog(payload):
    """Adapt the parent inventory parser's rows/project_details format; return names and IDs only."""
    data = payload.get("data", payload)
    if isinstance(data, dict):
        rows = next((data[key] for key in ("rows", "list", "records") if isinstance(data.get(key), list)), None)
    else:
        rows = data if isinstance(data, list) else None
    if rows is None:
        raise RoxyError("未识别到 Roxy 团队列表，请检查获取团队/项目的接口配置")

    def text(value):
        return str(value).strip() if type(value) in {str, int} else ""

    workspaces = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        workspace_id = text(row.get("id") or row.get("workspaceId") or row.get("workspace_id"))
        if not workspace_id:
            continue
        name = text(row.get("workspaceName") or row.get("workspace_name") or row.get("name")) or workspace_id
        workspace = workspaces.setdefault(workspace_id, {"id": workspace_id, "name": name, "projects": []})
        projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
        if not isinstance(projects, list):
            continue
        existing = {item["id"] for item in workspace["projects"]}
        for project in projects:
            if not isinstance(project, dict):
                continue
            project_id = text(project.get("projectId") or project.get("project_id") or project.get("id"))
            if not project_id or project_id in existing:
                continue
            project_name = text(project.get("projectName") or project.get("project_name") or project.get("name")) or project_id
            workspace["projects"].append({"id": project_id, "name": project_name})
            existing.add(project_id)
    return list(workspaces.values())


class Roxy:
    def __init__(self, config, store):
        local_url(config["ROXY_API_BASE"])
        self.config, self.store = config, store
        bootstrap(store)
        from core.roxybrowser_client import RoxyBrowserClient
        with bound(store, config):
            self.client = RoxyBrowserClient(safe_logging=True)
        self.http = self.client.http

    def list_workspaces(self):
        with bound(self.store, self.config):
            result = self.client.list_workspaces()
        if not result.get("ok"):
            raise RoxyError("无法读取 Roxy 团队/项目，请检查 API 地址、Key 和接口配置")
        groups = {}
        for item in result["items"]:
            wid, pid = str(item.get("id") or ""), str(item.get("projectId") or "")
            if not wid:
                continue
            group = groups.setdefault(wid, {"id": wid, "name": str(item.get("name") or wid), "projects": []})
            if pid and not any(row["id"] == pid for row in group["projects"]):
                group["projects"].append({"id": pid, "name": str(item.get("projectName") or pid)})
        return list(groups.values())
