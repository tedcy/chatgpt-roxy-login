# -*- coding: utf-8 -*-
"""Roxy Profile proxy, locale, fingerprint, and identifier normalization."""
from __future__ import annotations

import hmac
import logging
import random
import re
import time
from urllib.parse import quote, unquote, urlparse

from config import roxybrowser as _cfg


logger = logging.getLogger("core.roxybrowser_client")

def _mask_proxy(proxy_url: str) -> str:
    parsed = urlparse(str(proxy_url or "").strip())
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://***:***@{host}{port}"
    return str(proxy_url or "").strip()


def _proxy_url_to_roxy_info(proxy_url: str) -> dict:
    """
    将 config/proxy.py 里的代理 URL 转成 Roxy /browser/create 的 proxyInfo。

    支持：
      http://user:pass@host:port
      https://user:pass@host:port
      socks5://user:pass@host:port
      socks5h://user:pass@host:port  -> Roxy 侧按 SOCKS5 处理
    """
    text = str(proxy_url or "").strip()
    if not text:
        raise ValueError("代理为空")
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(f"Roxy 暂不支持该代理协议: {scheme or '-'}")
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"代理格式缺少 host/port: {_mask_proxy(text)}")

    protocol = {
        "http": "HTTP",
        "https": "HTTPS",
        "socks5": "SOCKS5",
        "socks5h": "SOCKS5",
    }[scheme]
    # Roxy /browser/create 官方字段是：
    # proxyMethod / proxyCategory / ipType / protocol / host / port / proxyUserName / proxyPassword / checkChannel
    # 之前误用了 proxyType/proxyHost/proxyPort/proxyAccount，Roxy 会忽略，导致创建窗口实际未设置代理。
    info = {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": parsed.hostname,
        "port": str(parsed.port),
    }
    if parsed.username:
        info["proxyUserName"] = unquote(parsed.username)
    if parsed.password:
        info["proxyPassword"] = unquote(parsed.password)
    check_channel = str(getattr(_cfg, "ROXY_PROXY_CHECK_CHANNEL", "") or "").strip()
    if check_channel:
        info["checkChannel"] = check_channel
    return info


def _roxy_info_to_proxy_url(proxy_info: dict | None) -> str:
    """Rebuild an in-memory task proxy URL without exposing it to diagnostics."""
    info = dict(proxy_info or {})
    category = str(info.get("proxyCategory") or info.get("protocol") or "").upper()
    if category == "NOPROXY":
        return ""
    scheme = {"HTTP": "http", "HTTPS": "https", "SOCKS5": "socks5h"}.get(category)
    host = str(info.get("host") or "").strip()
    port = str(info.get("port") or "").strip()
    if not scheme or not host or not port:
        return ""
    rendered_host = f"[{host}]" if ":" in host else host
    username = str(info.get("proxyUserName") or "")
    password = str(info.get("proxyPassword") or "")
    auth = ""
    if username or password:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"{scheme}://{auth}{rendered_host}:{port}"


def _noproxy_info() -> dict:
    return {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": "noproxy",
        "ipType": "IPV4",
    }


def _roxy_info_runtime_proxy(proxy_info: dict | None) -> tuple[bool, str]:
    """Return whether proxy routing is known and its in-memory URL.

    An absent proxyInfo in a newly created project Profile is an explicit
    direct route.  A fixed existing Profile is handled elsewhere and remains
    unresolved because its current routing must not be inspected or changed.
    """

    info = dict(proxy_info or {})
    if not info:
        return True, ""
    category = str(info.get("proxyCategory") or info.get("protocol") or "").upper()
    if category == "NOPROXY":
        return True, ""
    proxy_url = _roxy_info_to_proxy_url(info)
    return bool(proxy_url), proxy_url


def _normalized_proxy_protocol(proxy_info: dict | None) -> str:
    info = dict(proxy_info or {})
    value = str(
        info.get("proxyCategory") or info.get("protocol") or ""
    ).strip().upper()
    if value in {"SOCKS", "SOCKS5H"}:
        return "SOCKS5"
    return value


def _constant_time_text_equal(left: object, right: object) -> bool:
    return hmac.compare_digest(str(left or ""), str(right or ""))


def _proxy_readback_issues(expected: dict, actual: object) -> list[str]:
    if not isinstance(actual, dict):
        return ["proxy_info_missing"]

    issues: list[str] = []
    expected_protocol = _normalized_proxy_protocol(expected)
    actual_protocol = _normalized_proxy_protocol(actual)
    if expected_protocol != actual_protocol:
        issues.append("proxy_protocol_mismatch")
    if expected_protocol == "NOPROXY":
        return issues

    if not str(actual.get("host") or "").strip():
        issues.append("proxy_host_missing")
    elif str(expected.get("host") or "").strip().casefold() != str(
        actual.get("host") or ""
    ).strip().casefold():
        issues.append("proxy_host_mismatch")
    if str(expected.get("port") or "").strip() != str(
        actual.get("port") or ""
    ).strip():
        issues.append("proxy_port_mismatch")
    if not _constant_time_text_equal(
        expected.get("proxyUserName"), actual.get("proxyUserName")
    ):
        issues.append("proxy_username_mismatch")
    if not _constant_time_text_equal(
        expected.get("proxyPassword"), actual.get("proxyPassword")
    ):
        issues.append("proxy_password_mismatch")
    return issues


def _bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _normalized_language(value: object) -> str:
    text = str(value or "").strip().replace("_", "-").lower()
    return re.split(r"[,;\s]", text, maxsplit=1)[0]


def _language_matches(actual: object, expected: object) -> bool:
    actual_value = _normalized_language(actual)
    expected_value = _normalized_language(expected)
    if not actual_value or not expected_value:
        return False
    return actual_value == expected_value


def _timezone_matches(actual: object, expected: object) -> bool:
    actual_value = str(actual or "").strip().casefold()
    expected_value = str(expected or "").strip().casefold()
    if not actual_value or not expected_value:
        return False
    return (
        actual_value == expected_value
        or expected_value in re.split(r"\s+", actual_value)
    )


def _validated_proxy_country(proxy_summary: dict | None) -> str:
    summary = dict(proxy_summary or {})
    geo = summary.get("geo") if isinstance(summary.get("geo"), dict) else {}
    validated = summary.get("validated")
    if validated is False or (validated is not True and not geo):
        return ""
    return str(
        summary.get("actual_country")
        or geo.get("country")
        or geo.get("country_code")
        or summary.get("expected_country")
        or ""
    ).strip().upper()


def _expected_roxy_locale(proxy_summary: dict | None) -> tuple[str, str]:
    summary = dict(proxy_summary or {})
    country = _validated_proxy_country(summary)
    if not country:
        return "", ""
    geo = summary.get("geo") if isinstance(summary.get("geo"), dict) else {}
    from config import browser as browser_cfg

    profile_key = dict(
        getattr(browser_cfg, "COUNTRY_LOCALE_PROFILE_MAP", {}) or {}
    ).get(country)
    profiles = dict(getattr(browser_cfg, "BROWSER_LOCALE_PROFILES", {}) or {})
    profile = profiles.get(profile_key) if profile_key else None
    language = str((profile or {}).get("navigator_language") or "").strip()
    timezone_name = str(
        geo.get("timezone") or (profile or {}).get("timezone_iana") or ""
    ).strip()
    return language, timezone_name


def _locale_readback_issues(
    finger_info: object, proxy_summary: dict | None
) -> list[str]:
    if not isinstance(finger_info, dict):
        return ["finger_info_missing"]

    required_fields = (
        "isLanguageBaseIp",
        "language",
        "isDisplayLanguageBaseIp",
        "displayLanguage",
        "isTimeZone",
        "timeZone",
    )
    missing = [field for field in required_fields if field not in finger_info]
    if missing:
        return [
            f"{re.sub(r'(?<!^)(?=[A-Z])', '_', field).lower()}_missing"
            for field in missing
        ]

    expected_language, expected_timezone = _expected_roxy_locale(proxy_summary)
    if not expected_language and not expected_timezone:
        return []

    issues: list[str] = []
    for value_field, auto_field, issue_prefix in (
        ("language", "isLanguageBaseIp", "language"),
        ("displayLanguage", "isDisplayLanguageBaseIp", "display_language"),
    ):
        value = str(finger_info.get(value_field) or "").strip()
        if value:
            if expected_language and not _language_matches(
                value, expected_language
            ):
                issues.append(f"{issue_prefix}_mismatch")
        elif not _bool_value(finger_info.get(auto_field)):
            issues.append(f"{issue_prefix}_unresolved")

    timezone_value = str(finger_info.get("timeZone") or "").strip()
    if timezone_value:
        if expected_timezone and not _timezone_matches(
            timezone_value, expected_timezone
        ):
            issues.append("timezone_mismatch")
    elif not _bool_value(finger_info.get("isTimeZone")):
        issues.append("timezone_unresolved")
    return issues


_ROXY_M3_FINGERPRINT_VALUES = {
    "webGLInfo": 2,
    "webGLManufacturer": "Google Inc. (Apple)",
    "webGLRender": "ANGLE (Apple, ANGLE Metal Renderer: Apple M3, Unspecified Version)",
    "webGpu": "webgl",
}


def _merge_configured_fingerprint(body: dict) -> dict:
    """Apply project fingerprint policy without replacing unrelated Roxy fields."""
    configured = body.get("fingerInfo")
    finger_info = dict(configured) if isinstance(configured, dict) else {}
    # RoxyBrowser 3.9.2: forbidImage=False + threshold 0 blocks every image.
    # This is a project safety invariant, not an optional runtime switch.
    finger_info.update({"forbidImage": False, "forbiddenPictureSize": 0})
    if bool(getattr(_cfg, "ROXY_WEBRTC_REPLACE", False)):
        finger_info["webRTC"] = 0
    os_name = str(body.get("os") or "").strip()
    if bool(getattr(_cfg, "ROXY_MAC_M3_WEBGL", False)) and os_name == "macOS":
        finger_info.update(_ROXY_M3_FINGERPRINT_VALUES)
    elif (
        os_name == "Windows"
        and finger_info.get("webGLManufacturer")
        == _ROXY_M3_FINGERPRINT_VALUES["webGLManufacturer"]
        and finger_info.get("webGLRender")
        == _ROXY_M3_FINGERPRINT_VALUES["webGLRender"]
    ):
        # The exact Apple vendor+renderer pair identifies fields previously
        # written by this policy. Remove matching managed values only; a
        # custom Windows WebGL configuration is otherwise preserved.
        for key, value in _ROXY_M3_FINGERPRINT_VALUES.items():
            if finger_info.get(key) == value:
                finger_info.pop(key, None)
    if finger_info or isinstance(configured, dict):
        body["fingerInfo"] = finger_info
    return body


def _dig(payload: dict, *keys: str):
    cur = payload
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first(payload: dict, paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        value = _dig(payload, *path)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _workspace_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_WORKSPACE_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _project_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_PROJECT_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


_ROXY_RANDOM_OS_DEFAULTS = ("Windows", "macOS")
_ROXY_RANDOM_OS_ALIASES = {
    "windows": "Windows",
    "macos": "macOS",
}


def _roxy_random_os_choices() -> tuple[str, ...]:
    """Return the configured, safe OS choices for newly created Profiles."""
    raw = str(
        getattr(_cfg, "ROXY_RANDOM_OS_CHOICES", "Windows,macOS")
        or "Windows,macOS"
    )
    choices: list[str] = []
    for token in re.split(r"[,;\s]+", raw):
        normalized = _ROXY_RANDOM_OS_ALIASES.get(token.strip().lower())
        if normalized and normalized not in choices:
            choices.append(normalized)
    if not choices:
        return _ROXY_RANDOM_OS_DEFAULTS
    return tuple(choices)


def _random_roxy_os() -> str:
    return random.choice(_roxy_random_os_choices())


def _random_roxy_profile_name() -> str:
    prefix = str(getattr(_cfg, "ROXY_PROFILE_NAME_PREFIX", "rb") or "rb").strip()
    prefix = re.sub(r"[^A-Za-z0-9_-]+", "-", prefix).strip("-_")[:32] or "rb"
    return f"{prefix}-{int(time.time() * 1000)}-{random.randrange(0x10000):04x}"
