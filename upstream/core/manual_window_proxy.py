"""One-shot manual-window proxy parsing and credential-free exit checks."""
from __future__ import annotations

import time
from urllib.parse import quote, unquote, urlsplit, urlunsplit


PROXY_INVALID = "roxy_window_proxy_invalid"
PROXY_INVALID_MESSAGE = "代理格式无效，请填写 host:port:username:password 或代理 URL"
_SCHEMES = {"http", "https", "socks5", "socks5h"}
_GEO_FIELDS = ("ip", "country", "region", "city", "timezone", "org")


def normalize_proxy(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(PROXY_INVALID)
    raw = value.strip()
    if not raw:
        return ""
    try:
        if len(raw) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in raw):
            raise ValueError()
        if "://" not in raw:
            parts = raw.split(":", 3)
            if len(parts) != 4 or not all(parts):
                raise ValueError()
            host, port, username, password = parts
            if not port.isascii() or not port.isdigit() or any(char in host for char in "/?#@\\"):
                raise ValueError()
            raw = f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
        parsed = urlsplit(raw)
        host, port = parsed.hostname, parsed.port
        if (parsed.scheme not in _SCHEMES or not host or port is None or not 1 <= port <= 65535
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or any(char.isspace() or char in "/?#@\\%" for char in host)):
            raise ValueError()
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if parsed.username is not None:
            username = quote(unquote(parsed.username, errors="strict"), safe="")
            password = (
                ":" + quote(unquote(parsed.password, errors="strict"), safe="")
                if parsed.password is not None else ""
            )
            authority = f"{username}{password}@{authority}"
        return urlunsplit((parsed.scheme, authority, "", "", ""))
    except (ValueError, UnicodeError):
        raise ValueError(PROXY_INVALID) from None


def check_proxy(value: object) -> dict:
    from core.proxy_sid import probe_proxy_exit

    proxy = normalize_proxy(value)
    if not proxy:
        raise ValueError("roxy_window_proxy_required")
    started = time.monotonic()
    try:
        result = probe_proxy_exit(proxy)
    except Exception as exc:
        # Exception messages can include the complete authenticated URL.
        result = {"ok": False, "primary_error": type(exc).__name__}
    elapsed_ms = round((time.monotonic() - started) * 1000)
    if result.get("ok"):
        geo = result.get("geo") or {}
        return {"ok": True, "geo": {key: str(geo.get(key) or "") for key in _GEO_FIELDS},
                "elapsed_ms": elapsed_ms}
    reasons = " ".join(str(result.get(key) or "").lower()
                       for key in ("primary_error", "fallback_error"))
    if "407" in reasons:
        code, message = "roxy_window_proxy_auth_failed", "代理认证失败，请检查用户名和密码"
    elif "timeout" in reasons or "timedout" in reasons:
        code, message = "roxy_window_proxy_timeout", "代理检测超时，请稍后重试"
    else:
        code, message = "roxy_window_proxy_check_failed", "代理连接失败或未能获取出口信息"
    return {"ok": False, "error_code": code, "error": message, "elapsed_ms": elapsed_ms}
