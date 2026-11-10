"""Regression coverage for Windows 10013/10048 and duplicate file writers."""
import errno
import json
import os
from pathlib import Path
from queue import Queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.request import urlopen
from unittest.mock import Mock

from roxy_demo.app import create_app
from roxy_demo.startup import BindError, InstanceLock, start_server


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="roxy-startup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def hold_port(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        return listener.getsockname()[1]

    def test_occupied_port_automatically_serves_on_an_available_port(self):
        occupied = self.hold_port()
        app = create_app(self.root / "data")
        server, changed = start_server(app, occupied)
        self.addCleanup(server.server_close)
        self.assertTrue(changed)
        self.assertNotEqual(server.server_port, occupied)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        with urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5) as reply:
            self.assertEqual(reply.status, 200)
        thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_windows_permission_denied_uses_os_assigned_port(self):
        app = create_app(self.root / "data")
        original = PermissionError(errno.EACCES, "access denied")
        original.winerror = 10013
        from roxy_demo.startup import LocalServer
        calls = []
        def factory(host, port, application):
            calls.append(port)
            if len(calls) == 1:
                raise BindError(original)
            return LocalServer(host, port, application)
        server, changed = start_server(app, 8765, factory)
        self.addCleanup(server.server_close)
        self.assertEqual(calls, [8765, 0])
        self.assertTrue(changed)
        self.assertGreater(server.server_port, 0)

    def test_unrelated_bind_failure_does_not_silently_change_port(self):
        factory = Mock(side_effect=BindError(OSError(errno.EAFNOSUPPORT, "unsupported")))
        with self.assertRaises(BindError):
            start_server(object(), 8765, factory)
        self.assertEqual(factory.call_count, 1)

    def test_file_lock_prevents_second_writer_and_can_be_reacquired(self):
        first = InstanceLock(self.root)
        second = InstanceLock(self.root)
        try:
            self.assertTrue(first.acquire())
            first.publish(18765)
            self.assertFalse(second.acquire())
            self.assertEqual(second.current_port(), 18765)
        finally:
            second.close()
            first.close()
        again = InstanceLock(self.root)
        try:
            self.assertTrue(again.acquire())
            self.assertIsNone(again.current_port())
        finally:
            again.close()

    def test_copied_cli_persists_port_and_reuses_running_instance(self):
        occupied = self.hold_port()
        source = Path(__file__).resolve().parent.parent
        copy = self.root / "demo"
        shutil.copytree(source, copy, ignore=shutil.ignore_patterns(".venv", "__pycache__", "data", "*.pyc"))
        data = copy / "data"
        data.mkdir()
        (data / "settings.json").write_text(json.dumps({"WEB_PORT": occupied}), encoding="utf-8")
        # Suppress opening the user's browser; exercise the real CLI and file lock in child processes.
        code = "import runpy,webbrowser; webbrowser.open=lambda url: print('OPEN_URL='+url,flush=True); runpy.run_path('app.py',run_name='__main__')"
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        command = [sys.executable, "-u", "-c", code]
        process = subprocess.Popen(command, cwd=copy, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        lines = Queue()
        def read_lines():
            for line in process.stdout:
                lines.put(line)
        reader = threading.Thread(target=read_lines, daemon=True)
        reader.start()
        try:
            url = None
            for _ in range(5):
                line = lines.get(timeout=15)
                match = re.search(r"OPEN_URL=(http://127\.0\.0\.1:(\d+))", line)
                if match:
                    url, port = match[1], int(match[2])
                    break
            self.assertIsNotNone(url)
            self.assertNotEqual(port, occupied)
            self.assertEqual(json.loads((data / "settings.json").read_text(encoding="utf-8"))["WEB_PORT"], port)
            with urlopen(url, timeout=5) as reply:
                self.assertEqual(reply.status, 200)
            duplicate = subprocess.run(command, cwd=copy, env=env, capture_output=True,
                                       text=True, encoding="utf-8", timeout=15)
            self.assertEqual(duplicate.returncode, 0)
            self.assertIn("OPEN_URL=" + url, duplicate.stdout)
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
            reader.join(5)
            process.stdout.close()
        recovered = InstanceLock(data)
        try:
            self.assertTrue(recovered.acquire())
        finally:
            recovered.close()


if __name__ == "__main__":
    unittest.main()
