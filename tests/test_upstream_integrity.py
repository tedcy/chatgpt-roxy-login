"""Source fingerprints and UI coverage fail when extraction silently diverges."""
import json
from pathlib import Path
import runpy
import sys
import unittest

from roxy_demo.kernel_bridge import LOADED_SLICES, JsonSessions

ROOT = Path(__file__).resolve().parent.parent


class UpstreamIntegrityTests(unittest.TestCase):
    def test_snapshot_matches_manifest_and_loaded_function_bodies(self):
        verify = runpy.run_path(str(ROOT / "tools/verify_upstream.py"))["verify"]
        self.assertGreaterEqual(verify(), 90)
        manifest = json.loads((ROOT / "UPSTREAM_MANIFEST.json").read_text(encoding="utf-8"))
        paths = {entry["copy"]: entry["source"] for entry in manifest["files"]}
        hashes = {(entry["source"], entry["symbol"], entry["sha256"]) for entry in manifest["functions"]}
        symbols = {(entry["source"], entry["symbol"]) for entry in manifest["functions"]}
        for entry in LOADED_SLICES:
            source = paths["upstream/" + entry["source"]]
            if (source, entry["symbol"]) in symbols:
                self.assertIn((source, entry["symbol"], entry["sha256"]), hashes)

    def test_all_configuration_reads_are_in_ui_inventory(self):
        audit = runpy.run_path(str(ROOT / "tools/audit_config.py"))["audit"]
        reads = audit()
        self.assertGreaterEqual(len(reads), 50)
        self.assertIn("ROXY_PROFILE_CACHE_REUSE", reads)
        self.assertIn("REGISTRATION_WORKER_TIMEOUT_SECONDS", reads)

    def test_core_modules_are_local_and_session_backend_is_json(self):
        from core.chatgpt_session_db import ChatGPTSessionSQLiteStore
        self.assertIs(ChatGPTSessionSQLiteStore, JsonSessions)
        for name, module in list(sys.modules.items()):
            if name.startswith("core.") and getattr(module, "__file__", None):
                self.assertTrue(Path(module.__file__).resolve().is_relative_to(ROOT))
