"""Browser leases and verified local recovery for visible manual windows."""
from contextvars import copy_context
import json
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time
from urllib.parse import urlsplit


def _local_address(value):
    address = str(value or "")
    if not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", address):
        raise ValueError("manual_window_local_reference_invalid")
    if not 0 < int(address.rsplit(":", 1)[1]) < 65536:
        raise ValueError("manual_window_local_reference_invalid")
    return address


def _version(address):
    import requests

    with requests.Session() as session:
        session.trust_env = False
        response = session.get(
            f"http://{_local_address(address)}/json/version", timeout=2,
            allow_redirects=False,
        )
        response.raise_for_status()
        ws = str(response.json().get("webSocketDebuggerUrl") or "")
    parsed = urlsplit(ws)
    if (parsed.scheme != "ws" or parsed.netloc != address
            or parsed.query or parsed.fragment
            or not re.fullmatch(r"/devtools/browser/[a-zA-Z0-9-]{1,128}", parsed.path)):
        raise ValueError("manual_window_local_reference_invalid")
    return parsed.path.rsplit("/", 1)[1], ws


def _connection_refused(error):
    """Recognize a refused connection through requests' exception wrappers."""
    pending, seen = [error], set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, OSError) and (
            value.errno in {61, 111, 10061} or getattr(value, "winerror", None) == 10061
        ):
            return True
        if isinstance(value, BaseException):
            pending.extend(item for item in value.args if isinstance(item, BaseException))
            pending.extend(getattr(value, key, None) for key in ("__cause__", "__context__", "reason"))
    return False


def _windows_listener_ports():
    """Read both native TCP listener tables; unavailable is never an empty set."""
    import os

    if os.name != "nt":
        return None
    import ctypes
    import socket
    import struct

    try:
        query = ctypes.WinDLL("iphlpapi.dll").GetExtendedTcpTable
        query.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                          ctypes.c_int, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        query.restype = ctypes.c_uint32
        ports = set()
        # TCP_TABLE_OWNER_PID_LISTENER rows have different IPv4/IPv6 layouts.
        # Include every bound address, including wildcard/dual-stack listeners.
        for family, row_size, port_offset in ((socket.AF_INET, 24, 8),
                                              (socket.AF_INET6, 56, 20)):
            size = ctypes.c_uint32()
            result = query(None, ctypes.byref(size), False, family, 3, 0)
            if result not in {0, 122}:  # ERROR_INSUFFICIENT_BUFFER
                return None
            for _ in range(3):
                capacity = size.value
                if not 4 <= capacity <= 16 * 1024 * 1024:
                    return None
                buffer = ctypes.create_string_buffer(capacity)
                result = query(buffer, ctypes.byref(size), False, family, 3, 0)
                if result == 122:
                    continue  # A listener appeared between the two snapshots.
                if result != 0 or not 4 <= size.value <= capacity:
                    return None
                count = struct.unpack_from("<I", buffer)[0]
                if 4 + count * row_size > size.value:
                    return None
                for index in range(count):
                    port = struct.unpack_from("<I", buffer, 4 + index * row_size + port_offset)[0]
                    ports.add(socket.ntohs(port & 0xffff))
                break
            else:
                return None
        return ports
    except Exception:
        return None


def _current(reference):
    try:
        address = _local_address(reference["address"])
        expected = reference["browser_id"]
        if not isinstance(expected, str) or not re.fullmatch(r"[a-zA-Z0-9-]{1,128}", expected):
            return None, None
        actual, ws = _version(address)
        return (True, ws) if actual == expected else (None, None)
    except Exception as exc:
        if _connection_refused(exc):
            return False, None
        # Windows can time out even after Chrome has exited. Confirm endpoint
        # absence with the OS instead of treating a timeout itself as a close.
        from requests.exceptions import ConnectTimeout

        if isinstance(exc, ConnectTimeout):
            ports = _windows_listener_ports()
            if ports is not None and int(address.rsplit(":", 1)[1]) not in ports:
                return False, None
        return None, None


def _clear_owned_directory(reference):
    try:
        path = Path(reference["temp_dir"])
        root = Path(tempfile.gettempdir()).resolve()
        # Recorded directories must be direct children created by our launcher.
        if not path.is_absolute() or path.resolve().parent != root:
            return False
        if not path.name.startswith("turb-headed-auth-") or path.is_symlink():
            return False
        if path.exists():
            shutil.rmtree(path)
        return True
    except Exception:
        return False


def capture_local_reference(lease):
    address = _local_address(lease.opened.debugger_address)
    browser_id, _ws = _version(address)
    return {"address": address, "browser_id": browser_id, "temp_dir": str(lease.temp_dir)}


def close_local_browser(reference, *, request_close=True):
    """Never close an endpoint that now belongs to another browser."""
    if not isinstance(reference, dict):
        return False
    state, ws = _current(reference)
    if state is True and request_close:
        try:
            import websocket

            connection = websocket.create_connection(
                ws, timeout=2, suppress_origin=True, http_no_proxy=["127.0.0.1"],
            )
            try:
                connection.send(json.dumps({"id": 1, "method": "Browser.close"}))
            finally:
                connection.close()
        except Exception:
            # Chrome may close the connection as soon as it receives Browser.close.
            pass
        for _ in range(10):
            state, _ws = _current(reference)
            if state is not True:
                break
            time.sleep(0.1)
    if state is not False:
        return False
    return _clear_owned_directory(reference)


def open_manual_browser(manager, ctx, account, *, use_proxy=True):
    from core.roxy_manual_window import RoxyManualWindowError

    custom_proxy = getattr(ctx, "proxy_override", None) if use_proxy else None
    country = (
        ctx.proxy_country_override or manager._country_for_account(account)
    ) if use_proxy and not custom_proxy else None
    route_options = {}
    if custom_proxy:
        # A configured fixed Profile would bypass task_proxy entirely.
        route_options = {"profile_id": "", "task_proxy": custom_proxy}
    elif not use_proxy:
        route_options = {"profile_id": "", "task_proxy": "", "browser_args": ("--no-proxy-server",)}
    if ctx.browser_driver == "headed_chrome":
        from core.headed_chrome_auth_runtime import open_headed_browser_lease

        # A restart during launch is unknown, never evidence of a closed browser.
        if not manager._set_state(
            ctx, status="opening", stage="opening", local_browser_ref={"launching": True},
        ):
            raise RoxyManualWindowError("roxy_window_state_persist_failed", "窗口状态保存失败")
        ctx.browser_lease = open_headed_browser_lease(
            headless=False, proxy_country=country, stop_event=ctx.stop_event,
            use_proxy=use_proxy,
            target_only=ctx.target_only, low_traffic=False, raw_trace_enabled=False,
            task_kind="manual_window", account_id=ctx.account_id,
            **({"proxy": custom_proxy, "allow_any_proxy_country": True} if custom_proxy else {}),
        )
        ctx.driver, ctx.opened = ctx.browser_lease.driver, ctx.browser_lease.opened
        ctx.local_browser_ref = capture_local_reference(ctx.browser_lease)
        if not manager._set_state(
            ctx, status="opening", stage="opening",
            local_browser_ref=ctx.local_browser_ref,
        ):
            raise RoxyManualWindowError("roxy_window_state_persist_failed", "窗口状态保存失败")
        return
    from core.roxybrowser_client import RoxyBrowserClient
    from core.roxy_registration import _build_driver

    ctx.client = RoxyBrowserClient(safe_logging=True)
    try:
        ctx.opened = ctx.client.open_profile(
            headless=False, proxy_country=country, stop_check=lambda: None,
            **route_options,
        )
    except Exception as exc:
        code = "roxy_window_proxy_country_unavailable" if country else "roxy_window_open_failed"
        raise RoxyManualWindowError(code, "Roxy 窗口打开失败") from exc
    if ctx.stop_event.is_set():
        from core.chatgpt_session_refresh import ChatGPTSessionRefreshError
        raise ChatGPTSessionRefreshError("session_window_close_requested", "已请求关闭窗口")
    manager._set_state(
        ctx, status="opening", stage="opening", profile_id=ctx.opened.profile_id,
        pooled=bool(getattr(ctx.opened, "pooled", False)),
        created_by_run=bool(getattr(ctx.opened, "created_by_run", False)),
    )
    ctx.driver = _build_driver(ctx.opened, safe_logging=True)


def close_manual_chrome(ctx):
    lease = ctx.browser_lease
    if lease is None:
        return True
    try:
        lease.close()
    except Exception:
        return False
    if ctx.local_browser_ref is not None:
        return close_local_browser(ctx.local_browser_ref, request_close=False)
    try:
        return not lease.browser.is_connected() and _clear_owned_directory(
            {"temp_dir": str(lease.temp_dir)}
        )
    except Exception:
        return False


def run_local_login(callback):
    """Keep the login CDP dispatcher separate from the browser owner thread."""
    result = {}

    def invoke():
        try:
            result["value"] = callback()
        except BaseException as exc:
            result["error"] = exc

    context = copy_context()
    worker = threading.Thread(target=lambda: context.run(invoke), name="manual-chrome-login", daemon=True)
    worker.start()
    worker.join()
    if "error" in result:
        raise result["error"]
    return result["value"]
