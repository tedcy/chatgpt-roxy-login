"""Local server startup, with a single writer even when the port changes."""
import errno
import json
import os
from pathlib import Path

from werkzeug.serving import ThreadedWSGIServer


class BindError(RuntimeError):
    def __init__(self, cause):
        self.cause = cause
        super().__init__("网页端口绑定失败")


class LocalServer(ThreadedWSGIServer):
    def server_bind(self):
        try:
            super().server_bind()
        except OSError as exc:
            # Werkzeug otherwise turns this into sys.exit before the caller can recover.
            self.server_close()
            raise BindError(exc) from None


def start_server(app, preferred_port, server_factory=LocalServer):
    try:
        return server_factory("127.0.0.1", preferred_port, app), False
    except BindError as exc:
        codes = {exc.cause.errno, getattr(exc.cause, "winerror", None)}
        if not codes & {errno.EACCES, errno.EADDRINUSE, 10013, 10048}:
            raise
    # Port 0 asks Windows to allocate a port it permits us to use, without a probe/bind race.
    return server_factory("127.0.0.1", 0, app), True


class InstanceLock:
    """An OS file lock survives neither crashes nor process exit; the JSON files have one owner."""

    def __init__(self, data_dir):
        root = Path(data_dir)
        root.mkdir(parents=True, exist_ok=True)
        self.stream = (root / "service.lock").open("a+b", buffering=0)
        self.held = False

    def acquire(self):
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        self.held = True
        if self.stream.seek(0, os.SEEK_END) == 0:
            self.stream.write(b"\0")
        self.publish(None)
        return True

    def publish(self, port):
        if not self.held:
            raise RuntimeError("未持有服务文件锁")
        self.stream.seek(1)
        self.stream.truncate(1)
        self.stream.write(json.dumps({"port": port}).encode("ascii"))

    def current_port(self):
        try:
            self.stream.seek(1)  # The first byte is locked by the other process on Windows.
            value = json.loads(self.stream.read().decode("ascii")).get("port")
            return value if type(value) is int and 1024 <= value <= 65535 else None
        except (OSError, ValueError, UnicodeError):
            return None

    def close(self):
        try:
            if self.held:
                self.publish(None)
                self.stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.held = False
            self.stream.close()
