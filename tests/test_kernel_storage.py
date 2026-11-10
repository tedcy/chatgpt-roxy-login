"""Boundary tests: migration, original save order, conflicts and account ownership."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import logging
from pathlib import Path
import tempfile
import unittest
from queue import Queue
from types import SimpleNamespace
from unittest.mock import Mock, patch

from roxy_demo.kernel_bridge import JsonSessions, bootstrap, bound, get_account, replace_token
from roxy_demo.runtime_core import Manager
from roxy_demo.storage import Store, StoreError

LINE = "user@example.test----password----JBSWY3DPEHPK3PXP"


class KernelStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "data")
        self.store.import_accounts(LINE)
        self.web_id = self.store.list()[0]["id"]
        self.kernel_id = self.store.get(self.web_id)["kernel_account_id"]
        bootstrap(self.store)

    def commit(self, token, expected="", cookie="cookie"):
        backend = JsonSessions(None, record_status=lambda value: "ready")
        record = {"email": "user@example.test", "account_id": self.kernel_id,
                  "cookies": [{"name": "__Secure-next-auth.session-token", "value": cookie,
                               "domain": ".chatgpt.com", "path": "/"}], "status": "ready"}
        backend.save(record)
        info = {"accessToken": token, "user": {"email": record["email"], "id": "user-one"}}
        return replace_token(acc_id=self.kernel_id, email=record["email"], new_access_token=token,
                             expected_old_token=expected, session_info=info)

    def test_migration_is_lossless_backed_up_and_repeatable(self):
        row = self.store.get(self.web_id)
        row.pop("kernel_account_id")
        row.update(proxy="http://proxy.test:80", session={"info": {"accessToken": "old"}, "cookies": [],
                                                         "storage": {"localStorage": {"keep": "value"}}})
        self.store._write("accounts.json", {"version": 1, "accounts": [row]})
        path = self.store.root / "accounts.json"
        original = path.read_bytes()
        migrated = Store(self.store.root)
        self.assertEqual((path.parent / "accounts.pre-upstream.json").read_bytes(), original)
        result = migrated.get(self.web_id)
        self.assertEqual({k: v for k, v in result.items() if k != "kernel_account_id"}, row)
        after = path.read_bytes()
        Store(self.store.root)
        self.assertEqual(path.read_bytes(), after)

    def test_two_store_instances_share_lock_and_preserve_parallel_writes(self):
        other = Store(self.store.root)
        self.assertIs(other.lock, self.store.lock)
        self.store.import_accounts("\n".join(f"a{n}@example.test----password----JBSWY3DPEHPK3PXP" for n in range(12)))
        rows = self.store.list()
        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(lambda pair: (self.store if pair[0] % 2 else other).set_proxy(pair[1]["id"], "http://proxy.test:80"), enumerate(rows)))
        self.assertTrue(all(row["has_proxy"] for row in other.list()))

    def test_snapshot_is_saved_before_conditional_token_update(self):
        with bound(self.store):
            self.assertTrue(self.commit("token-one"))
            self.assertFalse(self.commit("token-loser", expected="wrong-old", cookie="loser"))
            self.assertEqual(self.store.token(self.web_id), "token-one")
            self.assertEqual(self.store.get(self.web_id)["session"]["cookies"][0]["value"], "loser")
            self.assertTrue(self.commit("token-two", expected="token-one", cookie="new-cookie"))
            self.assertEqual(self.store.get(self.web_id)["session"]["cookies"][0]["value"], "new-cookie")
            self.assertEqual(get_account(self.kernel_id)["access_token"], "token-two")

    def test_session_backend_save_is_durable_before_token_write(self):
        with bound(self.store):
            self.commit("same-token")
            data = self.store._accounts()
            data["accounts"][0]["kernel_fields"]["session_refresh_required"] = True
            self.store._write("accounts.json", data)
            self.assertTrue(self.commit("same-token", expected="same-token"))
            self.assertTrue(get_account(self.kernel_id)["session_refresh_required"])
            saved = JsonSessions(None, record_status=lambda x: "ready").save({
                "email": "user@example.test", "cookies": [{"name": "new-cookie", "value": "saved"}]}, refreshed=True)
            self.assertEqual(saved["status"], "ready")
            self.assertTrue(saved["last_refresh_at"])
            restarted = Store(self.store.root)
            self.assertEqual(restarted.get(self.web_id)["session"]["cookies"], saved["cookies"])
            self.assertEqual(restarted.token(self.web_id), "same-token")

    def test_failed_snapshot_write_preserves_previous_file(self):
        with bound(self.store):
            self.commit("valid-token")
            path = self.store.root / "accounts.json"
            before = path.read_bytes()
            with patch.object(self.store, "_write", side_effect=StoreError("disk unavailable")):
                with self.assertRaises(StoreError):
                    self.commit("new-token", expected="valid-token")
            self.assertEqual(path.read_bytes(), before)

    def test_failed_token_write_retains_saved_snapshot_and_previous_token(self):
        with bound(self.store):
            self.commit("previous-token")
            write = self.store._write
            calls = []
            def fail_second(name, data):
                calls.append(name)
                if len(calls) == 2:
                    raise StoreError("disk unavailable")
                return write(name, data)
            with patch.object(self.store, "_write", side_effect=fail_second):
                with self.assertRaises(StoreError):
                    self.commit("new-token", expected="previous-token", cookie="saved-before-cas")
            self.assertEqual(len(calls), 2)
            self.assertEqual(self.store.token(self.web_id), "previous-token")
            self.assertEqual(self.store.get(self.web_id)["session"]["cookies"][0]["value"], "saved-before-cas")

    def test_idle_window_does_not_periodically_save_or_change_log_formatter(self):
        from roxy_demo.settings import SCHEMA
        self.assertNotIn("AUTOSAVE_SECONDS", SCHEMA)
        manager = Manager(self.store)
        manager._initialize()
        manager.commands[self.kernel_id] = Queue()
        stop = Mock()
        stop.wait.side_effect = [False, False, True]
        ctx = SimpleNamespace(account_id=self.kernel_id, stop_event=stop)
        with patch.object(manager.owner, "_check_driver_alive", return_value=True), \
                patch.object(manager.owner, "_capture_before_close") as capture:
            manager.owner._wait_until_closed(ctx)
        capture.assert_not_called()
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger = logging.getLogger()
        logger.addHandler(handler)
        try:
            with bound(self.store):
                self.assertIs(handler.formatter, formatter)
        finally:
            logger.removeHandler(handler)

    def test_persisted_open_window_blocks_credentials_and_proxy_changes(self):
        with self.store.lock:
            data = self.store._accounts()
            data["accounts"][0]["kernel_fields"] = {"roxy_window_status": "ready"}
            self.store._write("accounts.json", data)
        manager = Manager(self.store)
        with self.assertRaises(ValueError):
            manager.import_accounts(LINE)
        with self.assertRaises(ValueError):
            manager.set_proxy(self.web_id, "http://proxy.test:80")

    def test_finishing_worker_cannot_remove_a_successor_refresh_command(self):
        from core.roxy_manual_window import RoxyManualWindowManager
        manager = Manager(self.store)
        manager._initialize()
        old_queue, new_queue = Queue(), Queue()
        manager.commands[self.kernel_id] = old_queue
        manager.configs[self.kernel_id] = self.store.get_settings()
        def finish_old_core(ctx):
            manager.commands[self.kernel_id] = new_queue
            manager.temporary.add(self.kernel_id)
            new_queue.put("refresh")
        with patch.object(RoxyManualWindowManager, "_run", side_effect=finish_old_core):
            manager.owner._run(SimpleNamespace(account_id=self.kernel_id))
        self.assertIs(manager.commands[self.kernel_id], new_queue)
        self.assertEqual(new_queue.get_nowait(), "refresh")
        self.assertIn(self.kernel_id, manager.temporary)
