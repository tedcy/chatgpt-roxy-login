"""Workspace discovery never persists draft keys or returns raw Roxy payloads."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from roxy_demo.app import create_app
from roxy_demo.roxy import Roxy, RoxyError, workspace_catalog
from roxy_demo.settings import defaults


PAYLOAD = {"code": 0, "data": {"rows": [
    {"id": 12, "workspaceName": "Team A", "private": "must-not-return",
     "project_details": [{"projectId": 34, "projectName": "Project A"},
                         {"projectId": 35, "projectName": "Project B"},
                         {"projectId": 35, "projectName": "Duplicate"}]},
    {"id": 56, "workspaceName": "Team B", "project_details": [{"projectId": 78, "projectName": "Project C"}]},
    {"id": 90, "workspaceName": "Empty team", "project_details": []},
]}}


class WorkspaceParsingTests(unittest.TestCase):
    def test_groups_projects_by_workspace_and_drops_raw_credentials(self):
        result = workspace_catalog(PAYLOAD)
        self.assertEqual([item["id"] for item in result], ["12", "56", "90"])
        self.assertEqual([item["id"] for item in result[0]["projects"]], ["34", "35"])
        self.assertEqual(result[1]["projects"], [{"id": "78", "name": "Project C"}])
        self.assertEqual(result[2]["projects"], [])
        self.assertNotIn("must-not-return", json.dumps(result))

    def test_aliases_and_empty_list(self):
        result = workspace_catalog({"data": {"list": [{"workspaceId": "w", "name": "Team",
                                  "projects": [{"id": "p", "name": "Project"}]}]}})
        self.assertEqual(result, [{"id": "w", "name": "Team", "projects": [{"id": "p", "name": "Project"}]}])
        self.assertEqual(workspace_catalog({"data": {"rows": []}}), [])
        with self.assertRaises(RoxyError):
            workspace_catalog({"data": {"unknown": []}})

    def test_uses_configured_local_inventory_action(self):
        from roxy_demo.storage import Store
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder)
            config = defaults()
            config["ROXY_WORKSPACE_LIST_PATH"] = "/custom/workspaces"
            client = Roxy(config, store)
            self.addCleanup(client.http.close)
            with patch.object(client.client, "try_request", return_value=(True, PAYLOAD)) as request:
                result = client.list_workspaces()
            request.assert_called_once_with("GET", "/custom/workspaces")
            self.assertEqual(len(result), 3)


class WorkspaceApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app(self.root)
        self.client = self.app.test_client()
        self.store = self.app.extensions["demo_store"]

    def test_unsaved_form_key_and_address_work_without_workspace_ids(self):
        values = {"ROXY_API_BASE": "http://127.0.0.1:50101", "ROXY_API_TOKEN": "draft-key"}
        with patch("roxy_demo.app.Roxy") as factory:
            factory.return_value.list_workspaces.return_value = workspace_catalog(PAYLOAD)
            response = self.client.post("/api/roxy/workspaces", json=values)
            self.assertEqual(response.status_code, 200)
            config = factory.call_args.args[0]
            self.assertEqual(config["ROXY_API_BASE"], values["ROXY_API_BASE"])
            self.assertEqual(config["ROXY_API_TOKEN"], "draft-key")
            self.assertEqual(config["ROXY_WORKSPACE_ID"], "")
            self.assertEqual(config["ROXY_PROJECT_ID"], "")
            factory.return_value.http.close.assert_called_once()
        self.assertNotIn("draft-key", response.get_data(as_text=True))
        self.assertFalse((self.root / "settings.json").exists())

    def test_blank_key_uses_saved_secret_and_query_does_not_overwrite_selection(self):
        values = defaults()
        values.update(ROXY_API_TOKEN="saved-key", ROXY_WORKSPACE_ID="existing-workspace", ROXY_PROJECT_ID="existing-project")
        self.store.save_settings(values)
        before = (self.root / "settings.json").read_bytes()
        with patch("roxy_demo.app.Roxy") as factory:
            factory.return_value.list_workspaces.return_value = workspace_catalog(PAYLOAD)
            response = self.client.post("/api/roxy/workspaces", json={"ROXY_API_TOKEN": ""})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(factory.call_args.args[0]["ROXY_API_TOKEN"], "saved-key")
        self.assertEqual((self.root / "settings.json").read_bytes(), before)
        self.assertNotIn("saved-key", response.get_data(as_text=True))

    def test_missing_key_and_nonlocal_address_never_contact_roxy(self):
        for values in ({}, {"ROXY_API_TOKEN": "draft", "ROXY_API_BASE": "https://external.test"}):
            with patch("roxy_demo.app.Roxy") as factory:
                response = self.client.post("/api/roxy/workspaces", json=values)
                self.assertEqual(response.status_code, 400)
                factory.assert_not_called()

    def test_query_failure_reports_error_and_closes_http_session(self):
        with patch("roxy_demo.app.Roxy") as factory:
            factory.return_value.list_workspaces.side_effect = RoxyError("Roxy 连接失败")
            response = self.client.post("/api/roxy/workspaces", json={"ROXY_API_TOKEN": "draft-key"})
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json["error"], "Roxy 连接失败")
            factory.return_value.http.close.assert_called_once()
        self.assertFalse((self.root / "settings.json").exists())

    def test_selected_ids_can_be_saved_and_survive_reload(self):
        response = self.client.put("/api/settings", json={"ROXY_API_TOKEN": "own-key",
                                   "ROXY_WORKSPACE_ID": "56", "ROXY_PROJECT_ID": "78"})
        self.assertEqual(response.status_code, 200)
        values = self.client.get("/api/settings").json["values"]
        self.assertEqual(values["ROXY_WORKSPACE_ID"], "56")
        self.assertEqual(values["ROXY_PROJECT_ID"], "78")
        self.assertNotIn("own-key", json.dumps(values))


if __name__ == "__main__":
    unittest.main()
