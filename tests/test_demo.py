"""Offline acceptance tests. No Roxy installation or business network requests."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from copy import deepcopy
import json
from pathlib import Path
from queue import Queue
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from roxy_demo.app import create_app
from roxy_demo.primitives import normalize_proxy
from roxy_demo.settings import defaults, validate
from roxy_demo.storage import Store, StoreError


SECRET = "JBSWY3DPEHPK3PXP"
LINE = "user@example.test----test-password----" + SECRET
PROXY = "gateway.example.test:3010:user-region-US-sid-abc:p@ss:word/#%"


def snapshot(email="user@example.test", token="test-token", cookie="session-value"):
    return {"info": {"accessToken": token, "user": {"email": email, "id": "user-one"},
                     "expires": "2099-01-01T00:00:00Z"},
            "cookies": [{"name": "__Secure-next-auth.session-token", "value": cookie,
                         "domain": ".chatgpt.com", "path": "/", "secure": True, "httpOnly": True}],
            "storage": {}}


def seed_session(store, account_id, value):
    data = store._accounts()
    next(row for row in data["accounts"] if row["id"] == account_id)["session"] = value
    store._write("accounts.json", data)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root)
        self.store.import_accounts(LINE)
        self.account_id = self.store.list()[0]["id"]

    def test_restart_and_duplicate_import_preserve_proxy_session(self):
        self.store.set_proxy(self.account_id, PROXY)
        seed_session(self.store, self.account_id, snapshot())
        self.store.import_accounts("USER@example.test====new-password====" + SECRET)
        restarted = Store(self.root)
        account = restarted.get(self.account_id)
        self.assertEqual(account["password"], "new-password")
        self.assertEqual(account["proxy"], normalize_proxy(PROXY))
        self.assertEqual(restarted.token(self.account_id), "test-token")
        self.assertEqual(len(restarted.list()), 1)

    def test_busy_and_malformed_imports_are_atomic(self):
        before = (self.root / "accounts.json").read_bytes()
        for text, busy in [(LINE, {self.account_id}), (LINE + "\nnot-a-record", set())]:
            with self.assertRaises(ValueError):
                self.store.import_accounts(text, busy)
            self.assertEqual((self.root / "accounts.json").read_bytes(), before)

    def test_parallel_updates_do_not_drop_other_accounts(self):
        self.store.import_accounts("\n".join(f"a{n}@example.test----password----{SECRET}" for n in range(12)))
        rows = self.store.list()
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = [pool.submit(self.store.set_proxy, row["id"], PROXY) for row in rows]
            for future in futures:
                future.result()
        self.assertTrue(all(row["has_proxy"] for row in Store(self.root).list()))
        self.assertEqual(len(rows), 13)

    def test_bad_file_is_not_replaced_and_failed_write_preserves_previous(self):
        before = (self.root / "accounts.json").read_bytes()
        with patch("roxy_demo.storage.os.replace", side_effect=PermissionError()):
            with self.assertRaises(StoreError):
                self.store.set_proxy(self.account_id, PROXY)
        self.assertEqual((self.root / "accounts.json").read_bytes(), before)
        self.assertEqual(list(self.root.glob("*.tmp")), [])
        (self.root / "accounts.json").write_text("broken-json", encoding="utf-8")
        with self.assertRaises(StoreError):
            Store(self.root)
        self.assertEqual((self.root / "accounts.json").read_text(), "broken-json")



    def test_all_proxy_protocols_keep_password_and_sid(self):
        from urllib.parse import unquote, urlsplit
        parsed = urlsplit(normalize_proxy(PROXY))
        self.assertEqual(unquote(parsed.password), "p@ss:word/#%")
        self.assertIn("sid-abc", unquote(parsed.username))
        for scheme in ("http", "https", "socks5", "socks5h"):
            value = f"{scheme}://user:p%40ss@gateway.example.test:8080"
            self.assertEqual(normalize_proxy(value), value)
        for invalid in ("gateway:0:u:p", "ftp://gateway:80", "http://gateway:80/path", "http://gate way:80"):
            with self.assertRaises(ValueError):
                normalize_proxy(invalid)


class ApiTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.app = create_app(temp.name)
        self.client = self.app.test_client()
        self.store = self.app.extensions["demo_store"]
        self.client.post("/api/accounts/import", json={"text": LINE})
        self.account_id = self.store.list()[0]["id"]

    def test_safe_list_and_on_demand_token(self):
        self.store.set_proxy(self.account_id, PROXY)
        seed_session(self.store, self.account_id, snapshot())
        response = self.client.get("/api/accounts")
        rendered = response.get_data(as_text=True)
        for secret in ("test-password", SECRET, "test-token", "session-value", "sid-abc", "p@ss"):
            self.assertNotIn(secret, rendered)
        response = self.client.get(f"/api/accounts/{self.account_id}/token")
        self.assertEqual(response.json["token"], "test-token")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_settings_restart_and_api_token_stays_masked(self):
        values = defaults()
        values.update(ROXY_API_TOKEN="api-secret", ROXY_WORKSPACE_ID="123", ROXY_PROJECT_ID="456", HUMANIZE_DELAY_FACTOR=0.5)
        self.assertEqual(self.client.put("/api/settings", json=values).status_code, 200)
        data = self.client.get("/api/settings").json
        self.assertNotIn("api-secret", json.dumps(data))
        self.assertTrue(data["api_token_set"])
        self.assertEqual(data["values"]["HUMANIZE_DELAY_FACTOR"], 0.5)
        values["ROXY_API_TOKEN"] = ""
        self.client.put("/api/settings", json=values)
        self.assertEqual(Store(self.store.root).get_settings()["ROXY_API_TOKEN"], "api-secret")

    def test_invalid_config_never_saved(self):
        for changes in ({"ROXY_API_BASE": "https://chatgpt.com"},
                        {"ROXY_OPEN_PATH": "//external.test/open"},
                        {"ROXY_BROWSER_ARGS": ["--proxy-server=http://wrong.test"]},
                        {"BROWSER_POLL_SECONDS": 0}):
            response = self.client.put("/api/settings", json={**defaults(), **changes})
            self.assertEqual(response.status_code, 400)
        self.assertFalse((self.store.root / "settings.json").exists())

    def test_empty_proxy_external_origin_and_non_json_rejected(self):
        url = f"/api/accounts/{self.account_id}"
        self.assertEqual(self.client.post(url + "/open", json={}).status_code, 400)
        self.assertEqual(self.client.put(url + "/proxy", json={"proxy": ""}).status_code, 400)
        self.assertEqual(self.client.post("/api/accounts/import", data={"text": LINE}).status_code, 415)
        self.assertEqual(self.client.post("/api/accounts/import", json={"text": LINE}, headers={"Origin":"https://external.test"}).status_code, 403)
        self.assertEqual(self.client.get("/api/accounts", headers={"Host":"external.test"}).status_code, 403)

