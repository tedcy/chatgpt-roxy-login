"""Bounded, read-only auth-tab inspection without switching Selenium windows."""
import json
import time
from urllib.parse import urlsplit


def _local_debugger(address):
    try:
        parsed = urlsplit("http://" + str(address or ""))
        if (parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                or not parsed.port or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            return None
        return parsed
    except Exception:
        return None


def _get(address, path):
    import requests
    with requests.Session() as session:
        session.trust_env = False
        return session.get("http://" + address + path, timeout=2).json()


def _send(url, method, params=None):
    import websocket
    socket = websocket.create_connection(
        url, timeout=2, suppress_origin=True,
        http_no_proxy=["127.0.0.1", "localhost", "::1"],
    )
    try:
        socket.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
        end = time.monotonic() + 2
        while time.monotonic() < end:
            reply = json.loads(socket.recv())
            if reply.get("id") == 1:
                if "error" in reply:
                    raise RuntimeError("headed_auth_watch_cdp_failed")
                return reply.get("result", {})
        raise TimeoutError("headed_auth_watch_timeout")
    finally:
        socket.close()


def inspect_auth_tab(address):
    tabs = _get(address, "/json/list")
    auth = [t for t in tabs if t.get("type") == "page"
            and urlsplit(t.get("url", "")).hostname == "auth.openai.com"]
    # Multiple auth transactions are ambiguous, never choose a stale password tab.
    if len(auth) != 1:
        return {"password_page": False, "filled": False, "ambiguous": len(auth) > 1}
    tab = auth[0]
    password = urlsplit(tab["url"]).path.rstrip("/") in {"/log-in/password", "/create-account/password"}
    if not password:
        return {"password_page": False, "filled": False}
    result = _send(tab["webSocketDebuggerUrl"], "Runtime.evaluate", {
        "expression": "(() => {const a=[...document.querySelectorAll('input[type=password]')].filter(e=>e.getClientRects().length);return {visible:a.length>0,filled:a.some(e=>!!e.value),ready:document.readyState};})()",
        "returnByValue": True,
    }).get("result", {}).get("value", {})
    return {"password_page": result.get("visible") is True,
            "filled": result.get("filled") is True, "ready": result.get("ready") == "complete"}


def read_chatgpt_session(address, *, preferred_target_id=None):
    """Read a ChatGPT Session through CDP without activating or switching tabs."""
    debugger = _local_debugger(address)
    if debugger is None:
        return None
    tabs = _get(address, "/json/list")
    pages = []
    for tab in tabs:
        host = (urlsplit(tab.get("url", "")).hostname or "").lower()
        if (tab.get("type") == "page"
                and (host == "chatgpt.com" or host.endswith(".chatgpt.com"))
                and tab.get("webSocketDebuggerUrl")):
            pages.append(tab)
    if not pages:
        return None

    preferred = str(preferred_target_id or "").removeprefix("CDwindow-")
    pages.sort(key=lambda tab: 0 if preferred and tab.get("id") == preferred else 1)
    # One tab is sufficient: cookies and the auth session are profile-scoped,
    # and bounding this to a single CDP round-trip keeps the one-second manual
    # session poll from accumulating work when Chrome is slow.
    tab = pages[0]
    endpoint = urlsplit(str(tab.get("webSocketDebuggerUrl") or ""))
    if (endpoint.scheme != "ws"
            or endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}
            or endpoint.port != debugger.port):
        return None
    expression = """(async () => {
      try {
        const response = await fetch('/api/auth/session', {
          credentials: 'include', cache: 'no-store'
        });
        if (!response.ok) return null;
        const data = await response.json();
        return data && typeof data === 'object' && data.accessToken ? data : null;
      } catch (_) { return null; }
    })()"""
    reply = _send(tab["webSocketDebuggerUrl"], "Runtime.evaluate", {
        "expression": expression,
        "awaitPromise": True,
        "returnByValue": True,
    })
    if reply.get("exceptionDetails"):
        return None
    value = (reply.get("result") or {}).get("result", {}).get("value")
    return value if isinstance(value, dict) and value.get("accessToken") else None


def close_owned_browser(address):
    info = _get(address, "/json/version")
    _send(info["webSocketDebuggerUrl"], "Browser.close")


def finalize_before_close(address, driver, *, error_code, interrupted=False):
    """Use independent CDP, never the busy Selenium transport, before close.

    A stuck recorder lock or filesystem must not prevent browser cleanup.
    False means diagnostic infrastructure was not confirmed, not auth success.
    """
    import threading
    from core.roxy_dom_failure_diagnostic import get_recorder

    result = []

    def capture():
        try:
            recorder = get_recorder(driver)
            if recorder is None:
                return
            tabs = [tab for tab in _get(address, "/json/list")
                    if tab.get("type") == "page"
                    and urlsplit(tab.get("url", "")).hostname == "auth.openai.com"]
            if len(tabs) != 1:
                return
            tab = tabs[0]

            class Source:
                url = tab["url"]

                def evaluate(self, expression):
                    reply = _send(tab["webSocketDebuggerUrl"], "Runtime.evaluate", {
                        "expression": expression, "returnByValue": True,
                    })
                    if reply.get("exceptionDetails"):
                        raise RuntimeError("headed_auth_watch_dom_failed")
                    return reply.get("result", {}).get("value")

            metadata = recorder.finalize(
                terminal_status="interrupted" if interrupted else "failed",
                error_code=error_code, final_source=Source(),
            )
            result.append(metadata.get("state") == "saved"
                          and not metadata.get("capture_error"))
        except Exception:
            pass

    worker = threading.Thread(target=capture, name="headed-final-dom", daemon=True)
    worker.start()
    worker.join(5)
    return bool(result and result[0])
