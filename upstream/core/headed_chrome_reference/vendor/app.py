from __future__ import annotations

from collections import OrderedDict
import dataclasses
import email as email_pkg
import errno
import base64
import ctypes
from contextlib import closing, contextmanager
import hashlib
import hmac
import json
import os
import queue
import random
import re
import secrets
import shutil
import select
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from html import unescape
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, BooleanVar, Button, IntVar, StringVar, Tk, Toplevel, Label, Menu, PanedWindow, filedialog, messagebox, simpledialog
from tkinter import font as tkfont
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from urllib.parse import parse_qsl, quote, urlencode, unquote, urljoin, urlparse, urlsplit, urlunsplit

import imaplib
import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


try:
    from curl_cffi.requests import Session as CurlCffiSession  # type: ignore
except ImportError:
    CurlCffiSession = None  # type: ignore

try:
    import ttkbootstrap as ttk_bootstrap  # type: ignore
except ImportError:
    ttk_bootstrap = None  # type: ignore


APP_TITLE = "OpenAI 邮箱注册管理"
APP_DIR = Path(__file__).resolve().parent
STATE_FILE = APP_DIR / "state.json"
STATE_SCHEMA_VERSION = 4
TRAFFIC_USAGE_MODE = "latest-run-v1"
STATE_DATA_DIR = APP_DIR / "state_data"
STATE_SESSION_DIR = STATE_DATA_DIR / "sessions"
NETWORK_CAPTURE_DIR = STATE_DATA_DIR / "network_captures"
STATE_SAVE_DEBOUNCE_SECONDS = 1.5
MAX_LOG_RECORDS_PER_VIEW = 2000
MAX_TOTAL_LOG_RECORDS = 10000
UI_FONT_FAMILY = "Microsoft YaHei"
UI_FONT_SIZE = 10
UI_TEXT_FONT_SIZE = 10
TOOLTIP_DELAY_MS = 450
DEFAULT_WINDOW_GEOMETRY = "1360x860"
MIN_WINDOW_WIDTH = 1180
MIN_WINDOW_HEIGHT = 760
UI_COLOR_BG = "#f6f8fb"
UI_COLOR_SURFACE = "#ffffff"
UI_COLOR_SURFACE_ALT = "#f8fafc"
UI_COLOR_BORDER = "#e5e7eb"
UI_COLOR_TEXT = "#111827"
UI_COLOR_MUTED = "#64748b"
UI_COLOR_PRIMARY = "#2563eb"
UI_COLOR_PRIMARY_DARK = "#1d4ed8"
UI_COLOR_DANGER = "#dc2626"
UI_COLOR_DANGER_DARK = "#b91c1c"
UI_COLOR_SUCCESS_SOFT = "#dcfce7"
UI_COLOR_WARNING_SOFT = "#ffedd5"
CHATGPT_BASE_URL = "https://chatgpt.com"
AUTH_BASE_URL = "https://auth.openai.com"
AUDIO_DEFAULT_DEVICE_LABEL = "系统默认"
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)
DEFAULT_AUTH_CONCURRENCY = 10
MAX_AUTH_CONCURRENCY = 30
PROXY_CHAIN_CONNECT_RETRIES = 5
PROXY_CHAIN_CONNECT_TIMEOUT = 10
PROXY_CHAIN_SOFT_FAIL_TARGETS = (
    "auth-cdn.oaistatic.com",
    "cdn.openai.com",
    "www.google.com",
    "accounts.google.com",
    "android.clients.google.com",
    "content-autofill.googleapis.com",
    "mtalk.google.com",
)
LOW_TRAFFIC_BLOCK_RESOURCE_TYPES = {"image", "media", "font", "texttrack", "manifest", "prefetch"}
LOW_TRAFFIC_EMPTY_RESOURCE_TYPES = {"stylesheet"}
LOW_TRAFFIC_CDP_RESOURCE_TYPES = ("Image", "Media", "Font", "Stylesheet")
LOW_TRAFFIC_BLOCK_HOSTS = {
    "ab.chatgpt.com",
    "accounts.google.com",
    "android.clients.google.com",
    "clients2.google.com",
    "clients4.google.com",
    "clients6.google.com",
    "content-autofill.googleapis.com",
    "mtalk.google.com",
    "optimizationguide-pa.googleapis.com",
    "pixel-config.reddit.com",
    "px.ads.linkedin.com",
    "redirector.gvt1.com",
    "safebrowsing.googleapis.com",
    "update.googleapis.com",
    "www.googleadservices.com",
    "www.google.com",
}
LOW_TRAFFIC_BLOCK_HOST_SUFFIXES = (
    ".browser-intake-datadoghq.com",
    ".doubleclick.net",
    ".google-analytics.com",
    ".googletagmanager.com",
    ".ingest.sentry.io",
)
LOW_TRAFFIC_BLOCK_PATH_SUFFIXES = (
    ".avif", ".bmp", ".gif", ".ico", ".jpg", ".jpeg", ".png", ".svg", ".webp",
    ".mp3", ".mp4", ".mpeg", ".ogg", ".webm", ".wav",
    ".otf", ".ttf", ".woff", ".woff2",
)
LOW_TRAFFIC_BLOCK_EXACT_PATHS = {
    "/awe/api/v2/rum",
    "/api/v2/rum",
    "/cdn-cgi/rum",
}
POST_ACCOUNT_TELEMETRY_RESPONSES = {
    "/ces/statsc/flush": (200, b'{"success":true}'),
    "/ces/v1/telemetry/intake": (202, b'{"ok":true,"error":null}'),
}
SECURITY_CHALLENGE_HOSTS = {"challenges.cloudflare.com"}
SECURITY_CHALLENGE_PATH_MARKERS = ("/cdn-cgi/challenge-platform/", "/turnstile/")
AUTH_STATIC_MEMORY_CACHE_MAX_BYTES = 24 * 1024 * 1024
AUTH_STATIC_MEMORY_CACHE_WAIT_SECONDS = 30.0
AUTH_STATIC_MEMORY_CACHE_URL_PATTERN = "https://auth-cdn.oaistatic.com/assets/*"
AUTH_STATIC_DISK_CACHE_MAX_BYTES = 32 * 1024 * 1024
AUTH_STATIC_DISK_CACHE_PAYLOAD_BYTES = 28 * 1024 * 1024
AUTH_STATIC_DISK_CACHE_PATH = STATE_DATA_DIR / "auth-static-cache-v3.sqlite3"
_AUTH_STATIC_MEMORY_CACHE: OrderedDict[str, tuple[int, str, list[dict[str, str]], int, int]] = OrderedDict()
_AUTH_STATIC_MEMORY_CACHE_BYTES = 0
_AUTH_STATIC_MEMORY_CACHE_INFLIGHT: dict[str, tuple[str, float]] = {}
_AUTH_STATIC_MEMORY_CACHE_CONDITION = threading.Condition(threading.RLock())
_AUTH_STATIC_DISK_CACHE_LOADED = False
_AUTH_STATIC_DISK_CACHE_RESTORED_KEYS: set[str] = set()
_AUTH_STATIC_DISK_CACHE_TOUCHED_KEYS: set[str] = set()
_AUTH_STATIC_DISK_CACHE_LOAD_COUNT = 0
_AUTH_STATIC_DISK_CACHE_LOAD_BYTES = 0
_AUTH_STATIC_DISK_CACHE_ERROR = ""


def is_auth_static_memory_cache_url(url: str) -> bool:
    try:
        parsed = urlsplit(str(url or ""))
    except Exception:
        return False
    path = str(parsed.path or "")
    filename = path.rsplit("/", 1)[-1]
    return (
        parsed.scheme.lower() == "https"
        and str(parsed.hostname or "").lower() == "auth-cdn.oaistatic.com"
        and path.startswith("/assets/")
        and bool(re.fullmatch(r"[^/]+-[A-Za-z0-9_-]{6,}\.js", filename))
    )


def is_security_challenge_url(url: str) -> bool:
    try:
        parsed = urlsplit(str(url or ""))
    except Exception:
        return False
    host = str(parsed.hostname or "").lower()
    path = str(parsed.path or "").lower()
    return (
        host in SECURITY_CHALLENGE_HOSTS
        or host.endswith(".challenges.cloudflare.com")
        or any(marker in path for marker in SECURITY_CHALLENGE_PATH_MARKERS)
    )


def _auth_static_disk_cache_connect_locked() -> sqlite3.Connection:
    cache_path = Path(AUTH_STATIC_DISK_CACHE_PATH)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists() and cache_path.stat().st_size > AUTH_STATIC_DISK_CACHE_MAX_BYTES:
        cache_path.unlink()
    connection = sqlite3.connect(str(cache_path), timeout=5.0)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    page_size = max(512, int(connection.execute("PRAGMA page_size").fetchone()[0] or 4096))
    max_pages = max(1, AUTH_STATIC_DISK_CACHE_MAX_BYTES // page_size)
    connection.execute(f"PRAGMA max_page_count={max_pages}")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_assets (
            url TEXT PRIMARY KEY,
            status INTEGER NOT NULL,
            body_b64 TEXT NOT NULL,
            headers_json TEXT NOT NULL,
            memory_size INTEGER NOT NULL,
            wire_size INTEGER NOT NULL,
            last_access REAL NOT NULL
        )
        """
    )
    return connection


def _auth_static_disk_cache_load_locked() -> None:
    global _AUTH_STATIC_MEMORY_CACHE_BYTES
    global _AUTH_STATIC_DISK_CACHE_LOADED
    global _AUTH_STATIC_DISK_CACHE_LOAD_COUNT
    global _AUTH_STATIC_DISK_CACHE_LOAD_BYTES
    global _AUTH_STATIC_DISK_CACHE_ERROR
    if _AUTH_STATIC_DISK_CACHE_LOADED:
        return
    _AUTH_STATIC_DISK_CACHE_LOADED = True
    _AUTH_STATIC_DISK_CACHE_LOAD_COUNT = 0
    _AUTH_STATIC_DISK_CACHE_LOAD_BYTES = 0
    _AUTH_STATIC_DISK_CACHE_ERROR = ""
    try:
        with closing(_auth_static_disk_cache_connect_locked()) as connection:
            rows = connection.execute(
                "SELECT url, status, body_b64, headers_json, memory_size, wire_size "
                "FROM auth_assets ORDER BY last_access ASC"
            ).fetchall()
        for url, status, body_b64, headers_json, memory_size, wire_size in rows:
            key = str(url or "")
            value_size = max(0, int(memory_size or 0))
            if not is_auth_static_memory_cache_url(key) or not body_b64 or not value_size:
                continue
            try:
                headers = json.loads(str(headers_json or "[]"))
            except Exception:
                continue
            if not isinstance(headers, list) or value_size > AUTH_STATIC_MEMORY_CACHE_MAX_BYTES:
                continue
            previous = _AUTH_STATIC_MEMORY_CACHE.pop(key, None)
            if previous is not None:
                _AUTH_STATIC_MEMORY_CACHE_BYTES -= previous[3]
            _AUTH_STATIC_MEMORY_CACHE[key] = (
                max(100, int(status or 200)),
                str(body_b64),
                headers,
                value_size,
                max(0, int(wire_size or 0)),
            )
            _AUTH_STATIC_MEMORY_CACHE_BYTES += value_size
            _AUTH_STATIC_DISK_CACHE_RESTORED_KEYS.add(key)
            _AUTH_STATIC_DISK_CACHE_LOAD_COUNT += 1
            _AUTH_STATIC_DISK_CACHE_LOAD_BYTES += value_size
        while _AUTH_STATIC_MEMORY_CACHE_BYTES > AUTH_STATIC_MEMORY_CACHE_MAX_BYTES and _AUTH_STATIC_MEMORY_CACHE:
            old_key, old_value = _AUTH_STATIC_MEMORY_CACHE.popitem(last=False)
            _AUTH_STATIC_MEMORY_CACHE_BYTES -= old_value[3]
            _AUTH_STATIC_DISK_CACHE_RESTORED_KEYS.discard(old_key)
    except Exception as exc:
        _AUTH_STATIC_DISK_CACHE_ERROR = str(exc)[:200]


def _auth_static_disk_cache_put_locked(
    key: str,
    status: int,
    body_b64: str,
    headers: list[dict[str, str]],
    memory_size: int,
    wire_size: int,
) -> bool:
    global _AUTH_STATIC_DISK_CACHE_ERROR
    headers_json = json.dumps(headers or [], ensure_ascii=False, separators=(",", ":"))
    entry_bytes = len(key.encode("utf-8")) + len(body_b64.encode("ascii")) + len(headers_json.encode("utf-8")) + 128
    if entry_bytes > AUTH_STATIC_DISK_CACHE_PAYLOAD_BYTES:
        return False
    try:
        with closing(_auth_static_disk_cache_connect_locked()) as connection:
            with connection:
                current_bytes = int(connection.execute(
                    "SELECT COALESCE(SUM(length(url) + length(body_b64) + length(headers_json) + 128), 0) "
                    "FROM auth_assets WHERE url <> ?",
                    (key,),
                ).fetchone()[0] or 0)
                while current_bytes + entry_bytes > AUTH_STATIC_DISK_CACHE_PAYLOAD_BYTES:
                    oldest = connection.execute(
                        "SELECT url, length(url) + length(body_b64) + length(headers_json) + 128 "
                        "FROM auth_assets WHERE url <> ? ORDER BY last_access ASC LIMIT 1",
                        (key,),
                    ).fetchone()
                    if not oldest:
                        break
                    connection.execute("DELETE FROM auth_assets WHERE url = ?", (oldest[0],))
                    current_bytes -= max(0, int(oldest[1] or 0))
                connection.execute(
                    "INSERT OR REPLACE INTO auth_assets "
                    "(url, status, body_b64, headers_json, memory_size, wire_size, last_access) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (key, max(100, int(status or 200)), body_b64, headers_json,
                     max(0, int(memory_size or 0)), max(0, int(wire_size or 0)), time.time()),
                )
        _AUTH_STATIC_DISK_CACHE_ERROR = ""
        return True
    except Exception as exc:
        _AUTH_STATIC_DISK_CACHE_ERROR = str(exc)[:200]
        return False


def _auth_static_disk_cache_touch_locked(key: str) -> None:
    global _AUTH_STATIC_DISK_CACHE_ERROR
    if key in _AUTH_STATIC_DISK_CACHE_TOUCHED_KEYS:
        return
    _AUTH_STATIC_DISK_CACHE_TOUCHED_KEYS.add(key)
    try:
        with closing(_auth_static_disk_cache_connect_locked()) as connection:
            with connection:
                connection.execute("UPDATE auth_assets SET last_access = ? WHERE url = ?", (time.time(), key))
    except Exception as exc:
        _AUTH_STATIC_DISK_CACHE_ERROR = str(exc)[:200]


def auth_static_disk_cache_stats() -> tuple[int, int, int, str]:
    with _AUTH_STATIC_MEMORY_CACHE_CONDITION:
        _auth_static_disk_cache_load_locked()
        try:
            disk_bytes = Path(AUTH_STATIC_DISK_CACHE_PATH).stat().st_size
        except Exception:
            disk_bytes = 0
        return (
            int(_AUTH_STATIC_DISK_CACHE_LOAD_COUNT),
            int(_AUTH_STATIC_DISK_CACHE_LOAD_BYTES),
            max(0, int(disk_bytes or 0)),
            str(_AUTH_STATIC_DISK_CACHE_ERROR or ""),
        )


def auth_static_memory_cache_claim(url: str, wait_seconds: float = AUTH_STATIC_MEMORY_CACHE_WAIT_SECONDS):
    key = str(url or "")
    deadline = time.monotonic() + max(0.0, float(wait_seconds or 0.0))
    waited = False
    with _AUTH_STATIC_MEMORY_CACHE_CONDITION:
        _auth_static_disk_cache_load_locked()
        while True:
            item = _AUTH_STATIC_MEMORY_CACHE.pop(key, None)
            if item is not None:
                _AUTH_STATIC_MEMORY_CACHE[key] = item
                if key in _AUTH_STATIC_DISK_CACHE_RESTORED_KEYS:
                    _auth_static_disk_cache_touch_locked(key)
                    return "disk_hit", item, "", waited
                return "hit", item, "", waited
            now = time.monotonic()
            inflight = _AUTH_STATIC_MEMORY_CACHE_INFLIGHT.get(key)
            if inflight is None or now - inflight[1] >= max(0.0, float(wait_seconds or 0.0)):
                token = uuid.uuid4().hex
                _AUTH_STATIC_MEMORY_CACHE_INFLIGHT[key] = (token, now)
                return "owner", None, token, waited
            remaining = min(deadline - now, max(0.0, float(wait_seconds or 0.0)) - (now - inflight[1]))
            if remaining <= 0:
                token = uuid.uuid4().hex
                _AUTH_STATIC_MEMORY_CACHE_INFLIGHT[key] = (token, now)
                return "owner", None, token, True
            waited = True
            _AUTH_STATIC_MEMORY_CACHE_CONDITION.wait(remaining)


def auth_static_memory_cache_put(
    url: str,
    status: int,
    body_b64: str,
    headers: list[dict[str, str]],
    memory_size: int,
    wire_size: int,
    owner_token: str,
) -> bool:
    global _AUTH_STATIC_MEMORY_CACHE_BYTES
    key = str(url or "")
    value_size = max(0, int(memory_size or 0))
    with _AUTH_STATIC_MEMORY_CACHE_CONDITION:
        inflight = _AUTH_STATIC_MEMORY_CACHE_INFLIGHT.get(key)
        if inflight is not None and inflight[0] == owner_token:
            _AUTH_STATIC_MEMORY_CACHE_INFLIGHT.pop(key, None)
        if not key or not body_b64 or not value_size or value_size > AUTH_STATIC_MEMORY_CACHE_MAX_BYTES:
            _AUTH_STATIC_MEMORY_CACHE_CONDITION.notify_all()
            return False
        previous = _AUTH_STATIC_MEMORY_CACHE.pop(key, None)
        if previous is not None:
            _AUTH_STATIC_MEMORY_CACHE_BYTES -= previous[3]
        _AUTH_STATIC_MEMORY_CACHE[key] = (
            max(100, int(status or 200)),
            str(body_b64),
            list(headers or []),
            value_size,
            max(0, int(wire_size or 0)),
        )
        _AUTH_STATIC_MEMORY_CACHE_BYTES += value_size
        _AUTH_STATIC_DISK_CACHE_RESTORED_KEYS.discard(key)
        _AUTH_STATIC_DISK_CACHE_TOUCHED_KEYS.discard(key)
        while _AUTH_STATIC_MEMORY_CACHE_BYTES > AUTH_STATIC_MEMORY_CACHE_MAX_BYTES and _AUTH_STATIC_MEMORY_CACHE:
            old_key, old_value = _AUTH_STATIC_MEMORY_CACHE.popitem(last=False)
            _AUTH_STATIC_MEMORY_CACHE_BYTES -= old_value[3]
            _AUTH_STATIC_DISK_CACHE_RESTORED_KEYS.discard(old_key)
        _auth_static_disk_cache_put_locked(
            key,
            status,
            str(body_b64),
            list(headers or []),
            value_size,
            max(0, int(wire_size or 0)),
        )
        _AUTH_STATIC_MEMORY_CACHE_CONDITION.notify_all()
        return key in _AUTH_STATIC_MEMORY_CACHE


def auth_static_memory_cache_release(url: str, owner_token: str) -> None:
    key = str(url or "")
    with _AUTH_STATIC_MEMORY_CACHE_CONDITION:
        inflight = _AUTH_STATIC_MEMORY_CACHE_INFLIGHT.get(key)
        if inflight is not None and inflight[0] == str(owner_token or ""):
            _AUTH_STATIC_MEMORY_CACHE_INFLIGHT.pop(key, None)
            _AUTH_STATIC_MEMORY_CACHE_CONDITION.notify_all()


def auth_static_memory_cache_stats() -> tuple[int, int, int]:
    with _AUTH_STATIC_MEMORY_CACHE_CONDITION:
        return len(_AUTH_STATIC_MEMORY_CACHE), _AUTH_STATIC_MEMORY_CACHE_BYTES, len(_AUTH_STATIC_MEMORY_CACHE_INFLIGHT)


def auth_static_memory_cache_clear(clear_disk: bool = False) -> None:
    global _AUTH_STATIC_MEMORY_CACHE_BYTES
    global _AUTH_STATIC_DISK_CACHE_LOADED
    global _AUTH_STATIC_DISK_CACHE_LOAD_COUNT
    global _AUTH_STATIC_DISK_CACHE_LOAD_BYTES
    global _AUTH_STATIC_DISK_CACHE_ERROR
    with _AUTH_STATIC_MEMORY_CACHE_CONDITION:
        _AUTH_STATIC_MEMORY_CACHE.clear()
        _AUTH_STATIC_MEMORY_CACHE_INFLIGHT.clear()
        _AUTH_STATIC_DISK_CACHE_RESTORED_KEYS.clear()
        _AUTH_STATIC_DISK_CACHE_TOUCHED_KEYS.clear()
        _AUTH_STATIC_MEMORY_CACHE_BYTES = 0
        _AUTH_STATIC_DISK_CACHE_LOADED = False
        _AUTH_STATIC_DISK_CACHE_LOAD_COUNT = 0
        _AUTH_STATIC_DISK_CACHE_LOAD_BYTES = 0
        _AUTH_STATIC_DISK_CACHE_ERROR = ""
        if clear_disk:
            cache_path = Path(AUTH_STATIC_DISK_CACHE_PATH)
            try:
                cache_path.unlink(missing_ok=True)
            except TypeError:
                if cache_path.exists():
                    cache_path.unlink()
        _AUTH_STATIC_MEMORY_CACHE_CONDITION.notify_all()
ACCOUNT_ALL_GROUP = "全部"
ACCOUNT_DEFAULT_GROUP = "未分组"
ACCOUNT_SORT_CUSTOM = "custom"
ACCOUNT_SORT_ASC = "asc"
ACCOUNT_SORT_DESC = "desc"
ACCOUNT_SORT_DIRECTIONS = {ACCOUNT_SORT_CUSTOM, ACCOUNT_SORT_ASC, ACCOUNT_SORT_DESC}
ACCOUNT_SORT_COLUMNS = ("email", "plus_status", "type", "status", "access_token", "session_token", "refresh_token", "time", "traffic")
ACCOUNT_SORT_LABELS = {
    "email": "邮箱",
    "plus_status": "Plus状态",
    "type": "类型",
    "status": "状态",
    "access_token": "AT",
    "session_token": "Session",
    "refresh_token": "RT",
    "time": "更新时间",
    "traffic": "本次流量",
}
ACCOUNT_TYPE_UNKNOWN = "unknown"
ACCOUNT_TYPES = {ACCOUNT_TYPE_UNKNOWN, "free", "plus", "team"}
PLUS_CHECK_LABELS = {
    "plus_active": "Plus生效中",
    "plus_eligible": "可领Plus试用",
    "free": "Free",
    "check_failed": "AT检测失败",
    "banned": "封号",
}
REGISTERED_ACCOUNT_STATUSES = {"已登录", "Session已获取", "成功", "AT已刷新"}
TREE_CHECKED = "☑"
TREE_UNCHECKED = "☐"
TRAFFIC_FLUSH_BYTES = 256 * 1024

GRAPH_SCOPE_DEFAULT = "https://graph.microsoft.com/.default"
GRAPH_SCOPE_MAIL_READ = "User.Read Mail.Read offline_access"
IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
MAIL_OTP_SCAN_LIMIT = 50
GRAPH_OTP_SCAN_LIMIT = 10
IMAP_OTP_SCAN_LIMIT = 20
IMAP_OTP_PARTIAL_BYTES = 4096
URL_OTP_POLL_INTERVAL_SECONDS = 5
URL_OTP_FIRST_FETCH_DELAY_SECONDS = 10
URL_OTP_RETRY_FETCH_DELAY_SECONDS = 10
URL_OTP_CONNECT_READ_TIMEOUT_SECONDS = 25
URL_OTP_POLL_READ_TIMEOUT_SECONDS = 25
URL_OTP_MAX_CONCURRENT_REQUESTS_PER_HOST = 3
URL_OTP_MAX_RESPONSE_BYTES = 512 * 1024
URL_OTP_FORCE_REFRESH_EVERY_POLLS = 5
URL_OTP_FINAL_GRACE_SECONDS = 30
URL_OTP_RESEND_AFTER_SECONDS = 12
URL_MAIL_SESSION_PREFIX = "url-mail::"
_URL_OTP_HOST_LIMITERS: dict[str, threading.BoundedSemaphore] = {}
_URL_OTP_HOST_LIMITERS_LOCK = threading.Lock()
MAIL_WEB_SCAN_LIMIT = 30
MAIL_POLL_INTERVAL_SECONDS = 5
MAIL_TIMESTAMP_SKEW_SECONDS = 30
GRAPH_MAIL_FOLDERS = ("inbox", "junkemail")
OUTLOOK_ALIAS_DOMAINS = {"outlook.com", "hotmail.com", "live.com", "msn.com"}
OUTLOOK_ALIAS_TAG = "openai"
DEFAULT_ALIAS_CAPACITY = 6
IMAP_MAIL_FOLDERS = ("INBOX", "Junk", "Junk Email")
GRAPH_TOKEN_ENDPOINTS = [
    {"name": "GRAPH-MAIL-CONSUMERS", "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "scope": GRAPH_SCOPE_MAIL_READ},
    {"name": "GRAPH-MAIL-COMMON", "url": "https://login.microsoftonline.com/common/oauth2/v2.0/token", "scope": GRAPH_SCOPE_MAIL_READ},
    {"name": "GRAPH-DEFAULT-CONSUMERS", "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "scope": GRAPH_SCOPE_DEFAULT},
    {"name": "GRAPH-DEFAULT-COMMON", "url": "https://login.microsoftonline.com/common/oauth2/v2.0/token", "scope": GRAPH_SCOPE_DEFAULT},
    {"name": "GRAPH-LIVE", "url": "https://login.live.com/oauth20_token.srf", "scope": ""},
]
TOKEN_ENDPOINTS = [
    {"name": "LIVE+scope", "url": "https://login.live.com/oauth20_token.srf", "scope": IMAP_SCOPE},
    {"name": "V1-COMMON", "url": "https://login.microsoftonline.com/common/oauth2/token", "scope": "", "resource": "https://outlook.office.com/"},
    {"name": "V1-CONSUMERS", "url": "https://login.microsoftonline.com/consumers/oauth2/token", "scope": "", "resource": "https://outlook.office.com/"},
    {"name": "CONSUMERS", "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "scope": IMAP_SCOPE},
    {"name": "COMMON", "url": "https://login.microsoftonline.com/common/oauth2/v2.0/token", "scope": IMAP_SCOPE},
    {"name": "LIVE", "url": "https://login.live.com/oauth20_token.srf", "scope": ""},
    {"name": "CONSUMERS-noscope", "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "scope": ""},
    {"name": "COMMON-noscope", "url": "https://login.microsoftonline.com/common/oauth2/v2.0/token", "scope": ""},
]
MAIL_AUTH_MODES = {"graph_mail", "graph_default", "imap", "url"}


def normalize_mail_auth_mode(value: str) -> str:
    mode = str(value or "").strip().lower()
    return mode if mode in MAIL_AUTH_MODES else ""


def format_mail_auth_mode(value: str) -> str:
    mode = normalize_mail_auth_mode(value)
    if mode.startswith("graph_"):
        return "Graph"
    if mode == "imap":
        return "IMAP"
    if mode == "url":
        return "取码URL"
    return "未检测"


FIRST_NAMES = [
    "Ethan", "Noah", "Liam", "Mason", "Lucas", "Logan", "Owen", "Ryan", "Leo", "Adam",
    "Ella", "Ava", "Mia", "Luna", "Chloe", "Grace", "Ruby", "Nora", "Ivy", "Sofia",
]
LAST_NAMES = [
    "Smith", "Brown", "Taylor", "Walker", "Wilson", "Clark", "Hall", "Young", "Allen", "King",
    "Scott", "Green", "Baker", "Adams", "Turner",
]

TEAM_EMAIL_DOMAIN = "wishtoapp.edu.kg"
OPENAI_SUPPORTED_COUNTRY_CODES = {
    "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR",
    "AM", "AW", "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BE",
    "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR",
    "IO", "BN", "BG", "BF", "BI", "CV", "KH", "CM", "CA", "KY",
    "CF", "TD", "CL", "CX", "CC", "CO", "KM", "CG", "CK", "CR",
    "CI", "HR", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC",
    "SV", "GQ", "ER", "EE", "SZ", "FK", "FO", "FJ", "FI", "FR",
    "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR",
    "GL", "GD", "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT",
    "HM", "VA", "HN", "HU", "IS", "IN", "ID", "IQ", "IE", "IM",
    "IL", "IT", "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KW",
    "KG", "LA", "LV", "LB", "LS", "LR", "LI", "LT", "LU", "MG",
    "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT",
    "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM",
    "NA", "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", "NU",
    "NF", "MK", "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG",
    "PE", "PH", "PN", "PL", "PT", "PR", "QA", "RE", "RO", "RW",
    "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS", "SM", "ST",
    "SN", "RS", "SC", "SL", "SG", "SX", "SK", "SI", "SB", "SO",
    "ZA", "GS", "KR", "SS", "ES", "LK", "SR", "SJ", "SE", "CH",
    "TW", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TR",
    "TM", "TC", "TV", "UG", "UA", "AE", "GB", "UM", "US", "UY",
    "UZ", "VU", "WF", "EH", "ZM",
}

DEVICE_PROFILES = [
    {"locale": "en-US", "languages": ["en-US", "en"], "timezone": "America/New_York"},
    {"locale": "en-US", "languages": ["en-US", "en"], "timezone": "America/Chicago"},
    {"locale": "en-US", "languages": ["en-US", "en"], "timezone": "America/Los_Angeles"},
    {"locale": "en-GB", "languages": ["en-GB", "en"], "timezone": "Europe/London"},
]
REGISTER_DEVICE_PROFILES = [
    {"locale": "ja-JP", "languages": ["ja-JP", "ja"], "timezone": "Asia/Tokyo"},
]
TEAM_DEVICE_PROFILES = [
    {"locale": "en-US", "languages": ["en-US", "en"], "timezone": "America/New_York"},
    {"locale": "en-US", "languages": ["en-US", "en"], "timezone": "America/Chicago"},
    {"locale": "en-US", "languages": ["en-US", "en"], "timezone": "America/Los_Angeles"},
]
COUNTRY_BROWSER_LOCALE = {
    "AU": "en-AU", "BR": "pt-BR", "CA": "en-CA", "DE": "de-DE", "ES": "es-ES",
    "FR": "fr-FR", "GB": "en-GB", "ID": "id-ID", "IN": "en-IN", "IT": "it-IT",
    "JP": "ja-JP", "KR": "ko-KR", "MX": "es-MX", "NL": "nl-NL", "NZ": "en-NZ",
    "PT": "pt-PT", "SG": "en-SG", "TH": "th-TH", "TW": "zh-TW", "US": "en-US",
    "VN": "vi-VN",
}


@dataclasses.dataclass
class MailboxAccount:
    mailbox_email: str
    password: str
    client_id: str
    refresh_token: str
    raw: str
    group: str = ACCOUNT_DEFAULT_GROUP
    alias_capacity: int = DEFAULT_ALIAS_CAPACITY
    status: str = ""
    mail_auth_mode: str = ""


@dataclasses.dataclass
class MailAccount:
    email: str
    password: str
    client_id: str
    refresh_token: str
    raw: str
    account_type: str = ACCOUNT_TYPE_UNKNOWN
    status: str = ""
    group: str = ACCOUNT_DEFAULT_GROUP
    mailbox_email: str = ""
    alias_slot: int = 0
    registered: bool = False
    mail_auth_mode: str = ""
    pickup_url: str = ""
    pickup_status: str = ""
    mfa_totp_secret: str = ""


@dataclasses.dataclass
class ProxyConfig:
    local_proxy: str = ""
    dynamic_proxy: str = ""
    chain_url: str = ""

    @property
    def label(self) -> str:
        return format_proxy_chain_label(self.local_proxy, self.dynamic_proxy)


@dataclasses.dataclass(frozen=True)
class ProxyHealthResult:
    success: bool
    ip: str = ""
    country: str = ""
    region: str = ""
    city: str = ""
    timezone: str = ""
    org: str = ""
    chatgpt_status: int = 0
    failed_stage: str = ""
    error: str = ""

    @property
    def location(self) -> str:
        return "/".join(part for part in (self.country, self.region, self.city) if part)

    @property
    def summary(self) -> str:
        if not self.success:
            detail = f": {self.error}" if self.error else ""
            return f"检测失败[{self.failed_stage or 'unknown'}]{detail}"
        return " ".join(
            part
            for part in (
                self.ip,
                self.location,
                self.timezone,
                self.org,
                f"ChatGPT={self.chatgpt_status}",
            )
            if part
        )


def _proxy_exit_base(payload: dict, source: str) -> dict:
    payload = payload if isinstance(payload, dict) else {}
    if source == "ipwho.is":
        timezone_value = payload.get("timezone") or {}
        connection = payload.get("connection") or {}
        timezone_name = str(timezone_value.get("id") or "").strip() if isinstance(timezone_value, dict) else str(timezone_value).strip()
        org = ""
        if isinstance(connection, dict):
            org = str(connection.get("org") or connection.get("isp") or "").strip()
        country = str(payload.get("country_code") or payload.get("country") or "").strip().upper()
    else:
        timezone_value = payload.get("timezone") or ""
        timezone_name = str(timezone_value.get("id") or "").strip() if isinstance(timezone_value, dict) else str(timezone_value).strip()
        connection = payload.get("connection") or {}
        connection_org = str(connection.get("org") or connection.get("isp") or "").strip() if isinstance(connection, dict) else ""
        org = str(payload.get("org") or connection_org or "").strip()
        country = str(payload.get("cc") or payload.get("country_code") or payload.get("country") or "").strip().upper()
    ip = str(payload.get("ip") or "").strip()
    if not ip or not re.fullmatch(r"[A-Z]{2}", country):
        raise ValueError(f"{source} 缺少 IP 或国家代码")
    return {
        "ip": ip,
        "country": country,
        "region": str(payload.get("region") or "").strip(),
        "city": str(payload.get("city") or "").strip(),
        "timezone": timezone_name,
        "org": org,
    }


def detect_proxy_health(proxy_url: str, timeout: int = 15, session=None, traffic_callback=None, check_chatgpt: bool = True) -> ProxyHealthResult:
    client = session or requests.Session()

    def record_response_traffic(response) -> None:
        if not traffic_callback:
            return
        try:
            request = getattr(response, "request", None)
            total = 0
            if request is not None:
                total += len(str(getattr(request, "method", "") or "").encode("utf-8"))
                total += len(str(getattr(request, "url", "") or "").encode("utf-8"))
                for name, value in dict(getattr(request, "headers", {}) or {}).items():
                    total += len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
                body = getattr(request, "body", b"") or b""
                total += len(body if isinstance(body, bytes) else str(body).encode("utf-8"))
            for name, value in dict(getattr(response, "headers", {}) or {}).items():
                total += len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
            content = getattr(response, "content", None)
            if content is None:
                content = str(getattr(response, "text", "") or "").encode("utf-8")
            total += len(content if isinstance(content, bytes) else str(content).encode("utf-8"))
            traffic_callback(total)
        except Exception:
            pass
    try:
        client.trust_env = False
    except Exception:
        pass
    normalized = normalize_proxy_url(proxy_url)
    if normalized:
        client.proxies.update({"http": normalized, "https": normalized})
    exit_errors = []
    base = None
    for source, url in (
        ("ipwho.is", "https://ipwho.is/"),
        ("ipinfo.io", "https://ipinfo.io/json"),
        ("api.myip.com", "https://api.myip.com/"),
    ):
        try:
            response = client.get(url, timeout=timeout)
            record_response_traffic(response)
            if response.status_code != 200:
                exit_errors.append(f"{source} HTTP {response.status_code}")
                continue
            payload = response.json() or {}
            if source == "ipwho.is" and payload.get("success") is False:
                exit_errors.append(f"{source} 返回失败")
                continue
            base = _proxy_exit_base(payload, source)
            break
        except Exception as exc:
            exit_errors.append(f"{source} {exc}")
    if base is None:
        return ProxyHealthResult(False, failed_stage="出口", error="; ".join(exit_errors) or "出口信息不可用")

    chatgpt_status = 0
    if check_chatgpt:
        try:
            response = client.get(f"{CHATGPT_BASE_URL}/api/auth/csrf", timeout=timeout)
            record_response_traffic(response)
            chatgpt_status = int(response.status_code)
            if chatgpt_status not in (200, 403):
                return ProxyHealthResult(False, **base, chatgpt_status=chatgpt_status, failed_stage="ChatGPT", error=f"HTTP {chatgpt_status}")
        except Exception as exc:
            return ProxyHealthResult(False, **base, failed_stage="ChatGPT", error=str(exc))

    return ProxyHealthResult(True, **base, chatgpt_status=chatgpt_status)














class ToolTip:
    def __init__(self, widget, text: str, delay_ms: int = TOOLTIP_DELAY_MS):
        self.widget = widget
        self.text = str(text or "").strip()
        self.delay_ms = delay_ms
        self._after_id = None
        self._window = None
        if self.text:
            widget.bind("<Enter>", self._schedule, add="+")
            widget.bind("<Leave>", self._hide, add="+")
            widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self) -> None:
        if self._after_id:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self) -> None:
        self._after_id = None
        if self._window or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 16
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        except Exception:
            return
        window = Toplevel(self.widget)
        window.wm_overrideredirect(True)
        window.wm_geometry(f"+{x}+{y}")
        label = Label(
            window,
            text=self.text,
            justify="left",
            background="#fff7d6",
            foreground="#111827",
            relief="solid",
            borderwidth=1,
            padx=8,
            pady=5,
            wraplength=420,
            font=(UI_FONT_FAMILY, UI_FONT_SIZE),
        )
        label.pack()
        self._window = window

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self._window:
            try:
                self._window.destroy()
            except Exception:
                pass
            self._window = None


@dataclasses.dataclass
class LogRecord:
    seq: int
    time_text: str
    message: str
    email: str = ""
    scope: str = "global"


@dataclasses.dataclass
class DeviceFingerprint:
    user_agent: str
    locale: str
    languages: list[str]
    timezone: str
    viewport_width: int
    viewport_height: int
    screen_width: int
    screen_height: int
    outer_width: int
    outer_height: int
    device_scale_factor: float
    hardware_concurrency: int
    device_memory: int
    platform: str
    vendor: str = "Google Inc."
    max_touch_points: int = 0

    @property
    def accept_language(self) -> str:
        if not self.languages:
            return self.locale
        return ",".join([self.languages[0], *[f"{lang};q={max(0.5, 0.9 - i * 0.1):.1f}" for i, lang in enumerate(self.languages[1:], start=0)]])

    @property
    def chrome_major(self) -> str:
        match = re.search(r"Chrome/(\d+)", self.user_agent)
        return match.group(1) if match else "146"

    @property
    def chrome_full(self) -> str:
        match = re.search(r"Chrome/([\d.]+)", self.user_agent)
        return match.group(1) if match else "146.0.0.0"


def generate_fingerprint(profiles: list[dict] | None = None) -> DeviceFingerprint:
    profile = random.choice(profiles or DEVICE_PROFILES)
    viewport = random.choice([
        (1280, 720, 1280, 720, 1),
        (1365, 768, 1366, 768, 1),
        (1440, 900, 1440, 900, 1),
        (1536, 864, 1536, 864, 1.25),
        (1600, 900, 1600, 900, 1),
        (1920, 1080, 1920, 1080, 1),
    ])
    major = random.randint(134, 146)
    build = random.randint(6000, 9999)
    patch = random.randint(50, 220)
    user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} Safari/537.36"
    return DeviceFingerprint(
        user_agent=user_agent,
        locale=profile["locale"],
        languages=list(profile["languages"]),
        timezone=profile["timezone"],
        viewport_width=viewport[0],
        viewport_height=viewport[1],
        screen_width=viewport[2],
        screen_height=viewport[3],
        outer_width=viewport[0] + random.randint(8, 16),
        outer_height=viewport[1] + random.randint(72, 96),
        device_scale_factor=viewport[4],
        hardware_concurrency=random.choice([4, 6, 8, 8, 12, 16]),
        device_memory=random.choice([4, 8, 8, 16]),
        platform="Win32",
    )


def generate_register_fingerprint() -> DeviceFingerprint:
    return generate_fingerprint(REGISTER_DEVICE_PROFILES)


def generate_team_fingerprint() -> DeviceFingerprint:
    return generate_fingerprint(TEAM_DEVICE_PROFILES)




def generate_fingerprint_for_exit(exit_info: ProxyHealthResult) -> DeviceFingerprint:
    if not exit_info.success or not exit_info.country:
        raise ValueError("代理出口信息不可用，无法生成匹配指纹")
    locale = COUNTRY_BROWSER_LOCALE.get(exit_info.country, "en-US")
    primary_language = locale.split("-", 1)[0]
    profile = {
        "locale": locale,
        "languages": [locale, primary_language] if locale != primary_language else [locale],
        "timezone": exit_info.timezone or "UTC",
    }
    return generate_fingerprint([profile])





def install_device_fingerprint(context, fp: DeviceFingerprint) -> None:
    fp_payload = json.dumps({
        "platform": fp.platform,
        "vendor": fp.vendor,
        "languages": fp.languages,
        "hardwareConcurrency": fp.hardware_concurrency,
        "deviceMemory": fp.device_memory,
        "maxTouchPoints": fp.max_touch_points,
        "screenWidth": fp.screen_width,
        "screenHeight": fp.screen_height,
        "outerWidth": fp.outer_width,
        "outerHeight": fp.outer_height,
        "deviceScaleFactor": fp.device_scale_factor,
        "chromeMajor": fp.chrome_major,
        "chromeFull": fp.chrome_full,
    }, ensure_ascii=False)
    context.set_extra_http_headers({
        "Accept-Language": fp.accept_language,
        "sec-ch-ua": f'"Google Chrome";v="{fp.chrome_major}", "Chromium";v="{fp.chrome_major}", "Not.A/Brand";v="24"',
        "sec-ch-ua-full-version-list": f'"Google Chrome";v="{fp.chrome_full}", "Chromium";v="{fp.chrome_full}", "Not.A/Brand";v="24.0.0.0"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"15.0.0"',
    })
    context.add_init_script(
        """(() => {
            const fp = __FP_PAYLOAD__;
            const defineGetter = (obj, prop, value) => {
                try { Object.defineProperty(obj, prop, { get: () => value, configurable: true }); } catch (_) {}
            };
            defineGetter(Navigator.prototype, 'webdriver', undefined);
            defineGetter(Navigator.prototype, 'platform', fp.platform);
            defineGetter(Navigator.prototype, 'vendor', fp.vendor);
            defineGetter(Navigator.prototype, 'language', fp.languages[0]);
            defineGetter(Navigator.prototype, 'languages', fp.languages);
            defineGetter(Navigator.prototype, 'hardwareConcurrency', fp.hardwareConcurrency);
            defineGetter(Navigator.prototype, 'deviceMemory', fp.deviceMemory);
            defineGetter(Navigator.prototype, 'maxTouchPoints', fp.maxTouchPoints);
            defineGetter(Screen.prototype, 'width', fp.screenWidth);
            defineGetter(Screen.prototype, 'height', fp.screenHeight);
            defineGetter(Screen.prototype, 'availWidth', fp.screenWidth);
            defineGetter(Screen.prototype, 'availHeight', fp.screenHeight - 40);
            defineGetter(window, 'outerWidth', fp.outerWidth);
            defineGetter(window, 'outerHeight', fp.outerHeight);
            defineGetter(window, 'devicePixelRatio', fp.deviceScaleFactor);
            if (!navigator.userAgentData) {
                defineGetter(Navigator.prototype, 'userAgentData', {
                    mobile: false,
                    platform: 'Windows',
                    brands: [
                        { brand: 'Google Chrome', version: fp.chromeMajor },
                        { brand: 'Chromium', version: fp.chromeMajor },
                        { brand: 'Not.A/Brand', version: '24' },
                    ],
                    getHighEntropyValues: async hints => {
                        const values = {
                            architecture: 'x86', bitness: '64', mobile: false, model: '',
                            platform: 'Windows', platformVersion: '15.0.0', uaFullVersion: fp.chromeFull,
                            fullVersionList: [
                                { brand: 'Google Chrome', version: fp.chromeFull },
                                { brand: 'Chromium', version: fp.chromeFull },
                                { brand: 'Not.A/Brand', version: '24.0.0.0' },
                            ],
                            wow64: false,
                        };
                        return Object.fromEntries(hints.filter(h => h in values).map(h => [h, values[h]]));
                    },
                });
            }
            try {
                const originalQuery = navigator.permissions && navigator.permissions.query;
                if (originalQuery) {
                    navigator.permissions.query = params => params && params.name === 'notifications'
                        ? Promise.resolve({ state: Notification.permission })
                        : originalQuery.call(navigator.permissions, params);
                }
            } catch (_) {}
            try {
                delete window.__playwright;
                delete window.__pw_manual;
                delete window.__PW_inspect;
            } catch (_) {}
        })();""".replace("__FP_PAYLOAD__", fp_payload)
    )

def generate_team_email() -> str:
    return f"{secrets.token_hex(6)}@{TEAM_EMAIL_DOMAIN}"


def split_email(email_addr: str) -> tuple[str, str]:
    value = str(email_addr or "").strip()
    if "@" not in value:
        return value, ""
    local, domain = value.rsplit("@", 1)
    return local, domain


def is_outlook_alias_domain(email_addr: str) -> bool:
    local, domain = split_email(email_addr)
    return bool(local and domain and domain.lower() in OUTLOOK_ALIAS_DOMAINS)


def parse_outlook_openai_alias(email_addr: str) -> tuple[str, int]:
    value = str(email_addr or "").strip()
    local, domain = split_email(value)
    if not local or not domain or domain.lower() not in OUTLOOK_ALIAS_DOMAINS:
        return value, 0
    match = re.match(rf"^(.+)\+{re.escape(OUTLOOK_ALIAS_TAG)}\.(\d+)$", local, flags=re.I)
    if not match:
        return value, 0
    try:
        slot = int(match.group(2))
    except Exception:
        slot = 0
    if slot <= 0:
        return value, 0
    mailbox = f"{match.group(1)}@{domain}"
    return mailbox, slot


def build_outlook_openai_alias(mailbox_email: str, slot: int) -> str:
    value = str(mailbox_email or "").strip()
    if slot <= 0:
        return value
    local, domain = split_email(value)
    if not local or not domain:
        return value
    return f"{local}+{OUTLOOK_ALIAS_TAG}.{int(slot)}@{domain}"


def mailbox_key(email_addr: str) -> str:
    value = str(email_addr or "").strip()
    if not value:
        return ""
    mailbox, _slot = parse_outlook_openai_alias(value)
    return str(mailbox or value).strip().lower()


def normalize_mailbox_and_slot(email_addr: str, mailbox_email: str = "", alias_slot: int | str = 0) -> tuple[str, int]:
    email_value = str(email_addr or "").strip()
    mailbox_value = str(mailbox_email or "").strip()
    try:
        slot_value = int(alias_slot or 0)
    except Exception:
        slot_value = 0
    parsed_mailbox, parsed_slot = parse_outlook_openai_alias(email_value)
    if not mailbox_value:
        mailbox_value = parsed_mailbox if parsed_slot else email_value
    if not slot_value:
        if mailbox_key(mailbox_value) == mailbox_key(email_value):
            slot_value = parsed_slot
        else:
            slot_value = parsed_slot
    return mailbox_value, max(0, slot_value)


def parse_account_line(line: str) -> MailAccount:
    parts = [part.strip() for part in str(line or "").strip().split("----")]
    if len(parts) < 4:
        raise ValueError("格式错误，应为 email----password----client_id----refresh_token")
    email_addr, password, client_id, refresh_token = parts[:4]
    if not email_addr or not client_id or not refresh_token:
        raise ValueError("email / client_id / refresh_token 不能为空")
    extras = extract_account_extras(parts[4:])
    return MailAccount(
        email=email_addr,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
        raw="----".join([email_addr, password, client_id, refresh_token]),
        account_type=str(extras.get("account_type") or ACCOUNT_TYPE_UNKNOWN),
        status="",
    )


def normalize_pickup_url(value: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = urlsplit(text)
    except Exception as exc:
        raise ValueError(f"取码 URL 无效: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("取码 URL 必须是完整的 HTTP/HTTPS 地址")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def format_pickup_url_for_display(value: str) -> str:
    try:
        parsed = urlsplit(normalize_pickup_url(value))
    except Exception:
        return "无效 URL"
    segments = [unquote(segment) for segment in str(parsed.path or "").split("/") if segment]
    tail = segments[-1] if segments else ""
    suffix = f"/.../{tail}" if tail else "/..."
    return f"{parsed.scheme}://{parsed.netloc}{suffix}"


def parse_url_mail_account_line(line: str) -> MailAccount:
    raw = str(line or "").strip()
    if "----" not in raw:
        raise ValueError("格式错误，应为 email----取码url----MFA认证器密钥")
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) not in {2, 3}:
        raise ValueError("格式错误，应为 email----取码url----MFA认证器密钥；密钥可留空")
    email_addr, pickup_url = parts[:2]
    mfa_totp_secret = re.sub(r"\s+", "", parts[2]).upper() if len(parts) == 3 else ""
    if mfa_totp_secret and not re.fullmatch(r"[A-Z2-7]+=*", mfa_totp_secret):
        raise ValueError("MFA 认证器密钥格式无效")
    local, domain = split_email(email_addr)
    if not local or not domain:
        raise ValueError("邮箱地址无效")
    normalized_url = normalize_pickup_url(pickup_url)
    return MailAccount(
        email=email_addr,
        password="",
        client_id="",
        refresh_token="",
        raw=f"{email_addr}----{normalized_url}",
        account_type=ACCOUNT_TYPE_UNKNOWN,
        status="",
        mailbox_email=email_addr,
        registered=False,
        mail_auth_mode="url",
        pickup_url=normalized_url,
        mfa_totp_secret=mfa_totp_secret,
    )


def parse_url_mail_account_lines(text: str) -> tuple[list[MailAccount], list[str]]:
    accounts: list[MailAccount] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(str(text or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line or "----" not in line:
            continue
        if "@" not in line.split("----", 1)[0]:
            continue
        try:
            accounts.append(parse_url_mail_account_line(line))
        except Exception as exc:
            errors.append(f"第 {line_number} 行: {exc}")
    return accounts, errors


def url_mail_account_to_dict(account: MailAccount) -> dict:
    return {
        "email": str(account.email or "").strip(),
        "pickup_url": str(account.pickup_url or "").strip(),
        "raw": str(account.raw or "").strip(),
        "group": str(account.group or ACCOUNT_DEFAULT_GROUP),
        "account_type": normalize_account_type(account.account_type),
        "status": str(account.status or ""),
        "registered": bool(account.registered),
        "pickup_status": str(account.pickup_status or ""),
    }


def url_mail_account_from_dict(value: dict) -> MailAccount:
    email_addr = str(value.get("email") or "").strip()
    pickup_url = normalize_pickup_url(value.get("pickup_url") or "")
    return MailAccount(
        email=email_addr,
        password="",
        client_id="",
        refresh_token="",
        raw=str(value.get("raw") or f"{email_addr}----{pickup_url}"),
        group=str(value.get("group") or ACCOUNT_DEFAULT_GROUP),
        account_type=normalize_account_type(value.get("account_type") or ""),
        status=str(value.get("status") or ""),
        mailbox_email=email_addr,
        registered=bool(value.get("registered")),
        mail_auth_mode="url",
        pickup_url=pickup_url,
        pickup_status=str(value.get("pickup_status") or ""),
    )


def url_mail_session_key(email_addr: str) -> str:
    return URL_MAIL_SESSION_PREFIX + str(email_addr or "").strip().lower()


def extract_account_extras(extra_parts: list[str]) -> dict:
    result = {"account_type": ""}
    for raw_part in extra_parts:
        part = str(raw_part or "").strip()
        if not part:
            continue
        lower = part.lower()
        if lower.startswith(("account_type=", "type=")):
            account_type = part.split("=", 1)[1].strip().lower()
            if account_type in ACCOUNT_TYPES:
                result["account_type"] = account_type
    return result


def normalize_account_type(value: str) -> str:
    account_type = str(value or "").strip().lower()
    return account_type if account_type in ACCOUNT_TYPES else ACCOUNT_TYPE_UNKNOWN


def _coerce_epoch(value) -> int:
    try:
        return int(float(value or 0))
    except Exception:
        return 0


def account_type_should_update(current: str, detected: str) -> bool:
    current_type = normalize_account_type(current)
    detected_type = normalize_account_type(detected)
    if detected_type == ACCOUNT_TYPE_UNKNOWN:
        return current_type == ACCOUNT_TYPE_UNKNOWN
    if detected_type in {"plus", "team"}:
        return True
    if detected_type == "free":
        return current_type in {ACCOUNT_TYPE_UNKNOWN, "free"}
    return False


def mailbox_to_dict(mailbox: MailboxAccount) -> dict:
    raw = mailbox.raw
    if not raw and mailbox.client_id and mailbox.refresh_token:
        raw = "----".join([mailbox.mailbox_email, mailbox.password, mailbox.client_id, mailbox.refresh_token])
    return {
        "mailbox_email": mailbox.mailbox_email,
        "password": mailbox.password,
        "client_id": mailbox.client_id,
        "refresh_token": mailbox.refresh_token,
        "raw": raw,
        "group": mailbox.group or ACCOUNT_DEFAULT_GROUP,
        "alias_capacity": max(1, int(mailbox.alias_capacity or DEFAULT_ALIAS_CAPACITY)),
        "status": mailbox.status,
        "mail_auth_mode": normalize_mail_auth_mode(mailbox.mail_auth_mode),
    }


def mailbox_from_dict(value: dict) -> MailboxAccount:
    raw_value = str(value.get("raw") or "")
    parsed = None
    if raw_value:
        try:
            parsed = parse_account_line(raw_value)
        except Exception:
            parsed = None
    mailbox_email = str(value.get("mailbox_email") or value.get("email") or (parsed.email if parsed else "")).strip()
    password = str(value.get("password", parsed.password if parsed else ""))
    client_id = str(value.get("client_id", parsed.client_id if parsed else "")).strip()
    refresh_token = str(value.get("refresh_token", parsed.refresh_token if parsed else "")).strip()
    raw = raw_value or ("----".join([mailbox_email, password, client_id, refresh_token]) if mailbox_email and client_id and refresh_token else "")
    try:
        capacity = int(value.get("alias_capacity", DEFAULT_ALIAS_CAPACITY) or DEFAULT_ALIAS_CAPACITY)
    except Exception:
        capacity = DEFAULT_ALIAS_CAPACITY
    return MailboxAccount(
        mailbox_email=mailbox_email,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
        raw=raw,
        group=str(value.get("group") or ACCOUNT_DEFAULT_GROUP),
        alias_capacity=max(1, min(1000, capacity)),
        status=str(value.get("status", "") or ""),
        mail_auth_mode=normalize_mail_auth_mode(value.get("mail_auth_mode", "")),
    )


def mailbox_from_account(account: MailAccount) -> MailboxAccount:
    mailbox_email, _slot = normalize_mailbox_and_slot(account.email, account.mailbox_email, account.alias_slot)
    raw = account.raw
    if not raw and account.client_id and account.refresh_token:
        raw = "----".join([mailbox_email, account.password, account.client_id, account.refresh_token])
    return MailboxAccount(
        mailbox_email=mailbox_email,
        password=account.password,
        client_id=account.client_id,
        refresh_token=account.refresh_token,
        raw=raw,
        group=account.group or ACCOUNT_DEFAULT_GROUP,
        alias_capacity=DEFAULT_ALIAS_CAPACITY,
        status="",
        mail_auth_mode=normalize_mail_auth_mode(account.mail_auth_mode),
    )


def account_to_dict(account: MailAccount) -> dict:
    mailbox_email, alias_slot = normalize_mailbox_and_slot(account.email, account.mailbox_email, account.alias_slot)
    raw = account.raw
    if not raw and account.client_id and account.refresh_token:
        raw = "----".join([mailbox_email or account.email, account.password, account.client_id, account.refresh_token])
    return {
        "email": account.email,
        "mailbox_email": mailbox_email,
        "alias_slot": alias_slot,
        "password": account.password,
        "client_id": account.client_id,
        "refresh_token": account.refresh_token,
        "raw": raw,
        "account_type": account.account_type,
        "status": account.status,
        "group": account.group or ACCOUNT_DEFAULT_GROUP,
        "registered": bool(account.registered),
        "mail_auth_mode": normalize_mail_auth_mode(account.mail_auth_mode),
    }


def account_from_dict(value: dict) -> MailAccount:
    raw_value = str(value.get("raw") or "")
    account = None
    if raw_value:
        try:
            account = parse_account_line(raw_value)
        except Exception:
            account = None
    email_addr = str(value.get("email") or (account.email if account else "")).strip()
    password = str(value.get("password", account.password if account else ""))
    client_id = str(value.get("client_id", account.client_id if account else "")).strip()
    refresh_token = str(value.get("refresh_token", account.refresh_token if account else "")).strip()
    raw = raw_value if client_id and refresh_token else ""
    mailbox_email, alias_slot = normalize_mailbox_and_slot(email_addr, str(value.get("mailbox_email") or ""), value.get("alias_slot", 0))
    if not raw and email_addr and client_id and refresh_token:
        raw = "----".join([mailbox_email or email_addr, password, client_id, refresh_token])
    return MailAccount(
        email=email_addr,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
        raw=raw,
        account_type=normalize_account_type(value.get("account_type", account.account_type if account else ACCOUNT_TYPE_UNKNOWN)),
        status=str(value.get("status", account.status if account else "") or ""),
        group=str(value.get("group") or (account.group if account else "") or ACCOUNT_DEFAULT_GROUP),
        mailbox_email=mailbox_email,
        alias_slot=alias_slot,
        registered=bool(value.get("registered", False)),
        mail_auth_mode=normalize_mail_auth_mode(value.get("mail_auth_mode", "")),
    )


def account_export_line(account: MailAccount, name_prefix: str = "") -> str:
    export_email = account.mailbox_email or mailbox_key(account.email) or account.email
    line = account.raw or "----".join([export_email, account.password, account.client_id, account.refresh_token]).rstrip("-")
    if line and export_email:
        parts = line.split("----", 1)
        if len(parts) == 2:
            parts[0] = export_email
            line = "----".join(parts)
    if not line:
        line = export_email or account.email
    return line


def openai_password_2fa_export_line(account: MailAccount, payload: dict) -> str:
    values = dict(payload or {}) if isinstance(payload, dict) else {}
    email_addr = str(account.email or "").strip()
    openai_password = str(values.get("openai_password") or "").strip()
    mfa_secret = str(values.get("mfa_totp_secret") or account.mfa_totp_secret or "").strip()
    if not email_addr or not openai_password or not mfa_secret:
        return ""
    return f"{email_addr}---{openai_password}---{mfa_secret}"


class StateStore:
    def __init__(self, state_file: Path):
        self.state_file = state_file
        self.data_dir = STATE_DATA_DIR
        self.session_dir = STATE_SESSION_DIR
        self.loaded_legacy = False
        self.missing_session_files = False
        self.warnings: list[str] = []
        self._pending_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending: tuple[int, dict, set[str] | None] | None = None
        self._save_thread: threading.Thread | None = None
        self._version = 0
        self._latest_written_version = 0
        self._legacy_backup_done = False

    def load(self) -> dict:
        self.loaded_legacy = False
        self.missing_session_files = False
        self.warnings = []
        if not self.state_file.exists():
            return {}
        try:
            data = self._read_json_dict(self.state_file)
        except Exception as primary_exc:
            backup_path = self._backup_path(self.state_file)
            try:
                data = self._read_json_dict(backup_path)
            except Exception:
                raise primary_exc
            self.warnings.append(f"主状态文件损坏，已从上一版备份恢复读取: {backup_path}")
        if not isinstance(data, dict):
            return {}
        if int(data.get("schema_version") or 1) >= STATE_SCHEMA_VERSION:
            data["session_results"] = self._load_split_sessions(data.get("session_results", {}))
            return data
        self.loaded_legacy = True
        if not isinstance(data.get("session_results"), dict):
            data["session_results"] = {}
        return data

    def save(self, snapshot: dict, dirty_session_emails: set[str] | None, flush: bool = False) -> None:
        with self._pending_lock:
            self._version += 1
            version = self._version
            if flush:
                self._pending = None
            else:
                pending_dirty = dirty_session_emails
                if self._pending:
                    _old_version, _old_snapshot, old_dirty = self._pending
                    if old_dirty is None or dirty_session_emails is None:
                        pending_dirty = None
                    else:
                        pending_dirty = set(old_dirty) | set(dirty_session_emails)
                self._pending = (version, snapshot, pending_dirty)
                if not self._save_thread or not self._save_thread.is_alive():
                    self._save_thread = threading.Thread(target=self._save_worker, daemon=True)
                    self._save_thread.start()
                return
        self._write_if_current(version, snapshot, dirty_session_emails)

    def _save_worker(self) -> None:
        while True:
            time.sleep(STATE_SAVE_DEBOUNCE_SECONDS)
            with self._pending_lock:
                pending = self._pending
                self._pending = None
            if not pending:
                with self._pending_lock:
                    if self._pending is None:
                        self._save_thread = None
                        return
                    continue
            version, snapshot, dirty_session_emails = pending
            self._write_if_current(version, snapshot, dirty_session_emails)
            with self._pending_lock:
                if self._pending is None:
                    self._save_thread = None
                    return

    def _write_if_current(self, version: int, snapshot: dict, dirty_session_emails: set[str] | None) -> None:
        with self._write_lock:
            if version < self._latest_written_version:
                return
            self._write_snapshot(snapshot, dirty_session_emails)
            self._latest_written_version = version

    def _load_split_sessions(self, raw_index) -> dict:
        if not isinstance(raw_index, dict):
            return {}
        sessions = {}
        for email_addr, item in raw_index.items():
            email_key = str(email_addr or "").strip()
            if not email_key:
                continue
            rel_path = ""
            if isinstance(item, dict):
                rel_path = str(item.get("session_file") or "").strip()
            if not rel_path:
                rel_path = self._session_rel_path(email_key)
            session_path = (self.data_dir / rel_path).resolve()
            try:
                session_path.relative_to(self.data_dir.resolve())
            except Exception:
                self.warnings.append(f"Session 文件路径越界，已跳过: {email_key}")
                continue
            if not session_path.exists():
                self.missing_session_files = True
                self.warnings.append(f"Session 文件缺失，已跳过: {email_key}")
                continue
            try:
                payload = self._read_json_dict(session_path)
                if isinstance(payload, dict) and isinstance(payload.get("payload"), dict):
                    payload = payload["payload"]
                if isinstance(payload, dict):
                    sessions[email_key] = payload
            except Exception as exc:
                backup_path = self._backup_path(session_path)
                try:
                    payload = self._read_json_dict(backup_path)
                    if isinstance(payload.get("payload"), dict):
                        payload = payload["payload"]
                    sessions[email_key] = payload
                    self.warnings.append(f"Session 文件损坏，已从上一版备份恢复读取: {email_key}")
                    continue
                except Exception:
                    pass
                self.warnings.append(f"Session 文件读取失败，已跳过 {email_key}: {exc}")
        return sessions

    @staticmethod
    def _backup_path(path: Path) -> Path:
        return path.with_suffix(path.suffix + ".bak")

    @staticmethod
    def _read_json_dict(path: Path) -> dict:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"JSON 顶层必须是对象: {path}")
        return data

    def _atomic_write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        with tmp.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        self._read_json_dict(tmp)
        if path.exists():
            try:
                self._read_json_dict(path)
            except Exception:
                pass
            else:
                shutil.copy2(path, self._backup_path(path))
        os.replace(tmp, path)

    def _write_snapshot(self, snapshot: dict, dirty_session_emails: set[str] | None) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        if self.loaded_legacy and not self._legacy_backup_done and self.state_file.exists():
            backup = self.state_file.with_name(
                f"state.backup-before-state-split-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            )
            try:
                shutil.copy2(self.state_file, backup)
                self._legacy_backup_done = True
            except Exception:
                pass

        data = dict(snapshot)
        sessions = data.pop("session_results", {})
        if not isinstance(sessions, dict):
            sessions = {}
        dirty_all = dirty_session_emails is None
        dirty_keys = {str(email or "").strip().lower() for email in (dirty_session_emails or set()) if str(email or "").strip()}
        session_index = {}
        for email_addr, payload in sessions.items():
            email_key = str(email_addr or "").strip()
            if not email_key or not isinstance(payload, dict):
                continue
            rel_path = self._session_rel_path(email_key)
            session_path = self.data_dir / rel_path
            session_index[email_key] = {
                "session_file": rel_path,
                "has_session_json": bool(str(payload.get("session_json") or "")),
                "has_storage_state_json": bool(str(payload.get("storage_state_json") or "")),
                "updated_at": data.get("updated_at", ""),
            }
            if dirty_all or email_key.lower() in dirty_keys or not session_path.exists():
                session_path.parent.mkdir(parents=True, exist_ok=True)
                session_payload = {"email": email_key, "updated_at": data.get("updated_at", ""), "payload": payload}
                self._atomic_write_json(session_path, session_payload)

        data["schema_version"] = STATE_SCHEMA_VERSION
        data["session_results"] = session_index
        self._atomic_write_json(self.state_file, data)

    def _session_rel_path(self, email_addr: str) -> str:
        digest = hashlib.sha256(str(email_addr or "").strip().lower().encode("utf-8")).hexdigest()[:24]
        return f"sessions/{digest}.json"

    def delete_session_files(self, email_keys: list[str]) -> int:
        deleted = 0
        with self._write_lock:
            data_root = self.data_dir.resolve()
            for email_key in email_keys:
                session_path = (self.data_dir / self._session_rel_path(email_key)).resolve()
                try:
                    session_path.relative_to(data_root)
                except Exception:
                    continue
                if session_path.exists():
                    session_path.unlink()
                    deleted += 1
        return deleted


def normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"{default_scheme}://{text}"
    return text


def legacy_colon_proxy_url(value: str, default_scheme: str = "socks5") -> str:
    """Convert host:port:username:password into a standard proxy URL."""
    text = str(value or "").strip()
    if not text:
        return ""
    scheme = str(default_scheme or "socks5").strip().lower()
    body = text
    if "://" in text:
        scheme, body = text.split("://", 1)
        scheme = scheme.strip().lower()
    if scheme not in {"http", "https", "socks5", "socks5h"} or "@" in body:
        return ""
    match = re.fullmatch(r"([^:\s]+):(\d{1,5}):([^:\s]+):(.+)", body)
    if not match:
        return ""
    host, port_text, username, password = match.groups()
    port = int(port_text)
    if not (1 <= port <= 65535) or not password:
        return ""
    userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}"
    return f"{scheme}://{userinfo}@{host}:{port}"


def normalize_dynamic_proxy_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    legacy = legacy_colon_proxy_url(text, default_scheme="socks5")
    return legacy or normalize_proxy_url(text)








def random_proxy_sid(length: int = 10) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def randomize_proxy_sid(proxy_url: str) -> str:
    text = str(proxy_url or "").strip()
    if not text:
        return ""
    sid = random_proxy_sid()
    parsed = urlsplit(text)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key.lower() == "sid" for key, _value in query_pairs):
        query = urlencode([(key, sid if key.lower() == "sid" else value) for key, value in query_pairs])
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        new_userinfo = re.sub(r"(?i)(sid[-_=])([^-:@;&/?]+)", lambda m: f"{m.group(1)}{sid}", userinfo, count=1)
        if new_userinfo != userinfo:
            return urlunsplit((parsed.scheme, f"{new_userinfo}@{host}", parsed.path, parsed.query, parsed.fragment))

    new_text = re.sub(r"(?i)(sid[-_=])([^-:@;&/?]+)", lambda m: f"{m.group(1)}{sid}", text, count=1)
    return new_text


def prepare_dynamic_proxy_for_use(proxy_url: str) -> str:
    proxy_url = normalize_dynamic_proxy_url(proxy_url)
    return randomize_proxy_sid(proxy_url) if proxy_url else ""


def _provider_source_ip_forbidden_text(value: str) -> bool:
    text = str(value or "").lower()
    return "forbidden ip=" in text and "not supported" in text


def mask_proxy_url(proxy_url: str) -> str:
    text = str(proxy_url or "").strip()
    if not text:
        return "直连"
    return text


def format_proxy_chain_label(local_proxy: str = "", dynamic_proxy: str = "") -> str:
    local_text = str(local_proxy or "").strip() or "直连"
    dynamic_text = str(dynamic_proxy or "").strip() or "直连"
    return f"本地={local_text:<30} -> 动态={dynamic_text}"


def display_width(value: str) -> int:
    width = 0
    for char in str(value or ""):
        width += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
    return width


def format_traffic_bytes(value: int | float | str) -> str:
    try:
        size = max(0, int(value or 0))
    except Exception:
        size = 0
    units = ("B", "KB", "MB", "GB", "TB")
    amount = float(size)
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    if unit == "B":
        return f"{int(amount)} B"
    if amount >= 100:
        return f"{amount:.0f} {unit}"
    elif amount >= 10:
        text = f"{amount:.1f}"
    else:
        text = f"{amount:.2f}"
    return f"{text.rstrip('0').rstrip('.')} {unit}"


def latest_run_traffic_usage_from_state(data: dict) -> tuple[dict[str, int], bool]:
    if str(data.get("traffic_usage_mode") or "") != TRAFFIC_USAGE_MODE:
        return {}, True
    raw_traffic_usage = data.get("traffic_usage_bytes", {})
    if not isinstance(raw_traffic_usage, dict):
        return {}, False
    return {str(k): max(0, int(v or 0)) for k, v in raw_traffic_usage.items()}, False


def pad_display(value: str, target_width: int) -> str:
    text = str(value or "")
    return text + " " * max(0, target_width - display_width(text))


def format_named_proxy_log(label: str, proxy: ProxyConfig | str, source: str = "") -> str:
    name = str(label or "").strip()
    if source:
        name = f"{name}({source})"
    proxy_text = proxy.label if hasattr(proxy, "label") else str(proxy or "")
    return f"[代理] {pad_display(name, 32)}: {proxy_text}"


def find_access_token(value) -> str:
    if isinstance(value, dict):
        for key in ("accessToken", "access_token", "token"):
            token = str(value.get(key) or "").strip()
            if token:
                return token
        for item in value.values():
            token = find_access_token(item)
            if token:
                return token
    if isinstance(value, list):
        for item in value:
            token = find_access_token(item)
            if token:
                return token
    return ""


def extract_access_token_from_session_text(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    parts = raw.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    try:
        return find_access_token(json.loads(raw))
    except Exception:
        pass
    match = re.search(r'"(?:accessToken|access_token|token)"\s*:\s*"([^"]+)"', raw)
    if match:
        return match.group(1).strip()
    return raw if raw.count(".") >= 2 and len(raw) > 80 and not re.search(r"\s", raw) else ""


def extract_access_tokens_from_session_text(text: str) -> list[str]:
    raw = str(text or "").strip()
    if not raw:
        return []
    token = extract_access_token_from_session_text(raw)
    if token and token == raw:
        return [token]
    tokens: list[str] = []
    seen: set[str] = set()
    if token:
        tokens.append(token)
        seen.add(token)
    for match in re.finditer(r"(?:Bearer\s+)?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{20,})", raw):
        candidate = match.group(1).strip()
        if candidate and candidate not in seen:
            tokens.append(candidate)
            seen.add(candidate)
    return tokens


def find_token_by_keys(value, keys: set[str]) -> str:
    normalized_keys = {str(key or "").casefold() for key in keys}
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key or "").casefold() in normalized_keys:
                token = str(item or "").strip()
                if token:
                    return token
        for item in value.values():
            token = find_token_by_keys(item, keys)
            if token:
                return token
    if isinstance(value, list):
        for item in value:
            token = find_token_by_keys(item, keys)
            if token:
                return token
    return ""


def account_name_from_access_token(token: str) -> str:
    payload = decode_jwt_payload(token)
    for key in ("email", "account_email", "username", "account_name", "sub", "account_id"):
        value = payload.get(key) if isinstance(payload, dict) else ""
        if isinstance(value, (str, int, float)):
            text_value = str(value).strip()
            if text_value:
                return re.sub(r"\s+", " ", text_value)
    return ""


def random_urlsafe_string(length: int) -> str:
    token = secrets.token_urlsafe(max(1, length))
    return token[:length]


def pkce_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def decode_jwt_payload(token: str) -> dict:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = parts[1].replace("-", "+").replace("_", "/")
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.b64decode(payload).decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def get_nested_record(payload: dict, key: str) -> dict:
    value = payload.get(key) if isinstance(payload, dict) else None
    return value if isinstance(value, dict) else {}


def first_non_empty(*values) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""
































def account_check_record_from_payload(payload: dict, access_token: str = "") -> dict:
    if not isinstance(payload, dict):
        return {}
    accounts = payload.get("accounts")
    if not isinstance(accounts, dict) or not accounts:
        return {}
    first_info = next((item for item in accounts.values() if isinstance(item, dict)), {})
    if not isinstance(first_info, dict) or not first_info:
        return {}
    account = first_info.get("account") if isinstance(first_info.get("account"), dict) else {}
    entitlement = first_info.get("entitlement") if isinstance(first_info.get("entitlement"), dict) else {}
    promo = first_info.get("eligible_promo_campaigns") if isinstance(first_info.get("eligible_promo_campaigns"), dict) else {}
    is_deactivated = bool(account.get("is_deactivated"))
    plan_text = str(
        account.get("plan_type")
        or account.get("subscription_plan")
        or entitlement.get("subscription_plan")
        or ""
    ).strip().lower()
    has_active_subscription = bool(entitlement.get("has_active_subscription"))
    plus_promo = promo.get("plus") if isinstance(promo.get("plus"), dict) else {}
    has_plus_promo = str(plus_promo.get("id") or "").strip() == "plus-1-month-free"
    if is_deactivated:
        status = "banned"
        account_type = ACCOUNT_TYPE_UNKNOWN
    elif plan_text == "plus" or "chatgptplusplan" in plan_text or has_active_subscription:
        status = "plus_active"
        account_type = "plus"
    elif has_plus_promo:
        status = "plus_eligible"
        account_type = "free"
    else:
        status = "free"
        account_type = "free"
    email_addr = str(account.get("email") or payload.get("email") or "").strip() or account_name_from_access_token(access_token)
    record = {
        "email": email_addr,
        "account_type": account_type,
        "account_type_source": "ChatGPT接口",
        "plus_check_status": status,
        "plus_check_label": PLUS_CHECK_LABELS[status],
        "plus_check_checked_at": int(time.time()),
    }
    for key in ("expires_at", "token_expires_at", "plan_expires_at"):
        epoch = _coerce_epoch(payload.get(key) or account.get(key) or entitlement.get(key))
        if epoch:
            record[key] = epoch
    for key in ("expires_at_display", "token_expires_at_display", "plan_expires_at_display", "phone"):
        value = str(payload.get(key) or account.get(key) or entitlement.get(key) or "").strip()
        if value:
            record[key] = value
    return record


def build_account_check_session(access_token: str, proxy_url: str = ""):
    token = extract_access_token_from_session_text(access_token) or str(access_token or "").strip()
    normalized_proxy = normalize_proxy_url(proxy_url)
    if CurlCffiSession is not None:
        try:
            session = CurlCffiSession(impersonate="chrome110")
            session.headers.update({
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": DEFAULT_USER_AGENT,
            })
            if normalized_proxy:
                session.proxies.update({"http": normalized_proxy, "https": normalized_proxy})
            return session
        except Exception:
            pass
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": DEFAULT_USER_AGENT,
    })
    if normalized_proxy:
        session.proxies.update({"http": normalized_proxy, "https": normalized_proxy})
    return session


def detect_chatgpt_account_type_from_access_token(access_token: str, proxy_url: str = "", session: requests.Session | None = None) -> dict:
    token = extract_access_token_from_session_text(access_token) or str(access_token or "").strip()
    if not token:
        raise RuntimeError("当前账户没有 Access Token")
    claims = decode_jwt_payload(token) or {}
    client = session or build_account_check_session(token, proxy_url)
    url = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
    path = urlsplit(url).path
    try:
        response = client.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": DEFAULT_USER_AGENT,
                "Referer": "https://chatgpt.com/",
                "x-openai-target-path": path,
                "x-openai-target-route": path,
            },
            timeout=15,
        )
    except Exception as exc:
        raise RuntimeError(f"{path}: {exc}") from exc
    if response.status_code == 401:
        return {
            "email": account_name_from_access_token(token),
            "account_type": ACCOUNT_TYPE_UNKNOWN,
            "account_type_source": "ChatGPT接口",
            "plus_check_status": "check_failed",
            "plus_check_label": PLUS_CHECK_LABELS["check_failed"],
            "plus_check_checked_at": int(time.time()),
        }
    if response.status_code >= 400:
        raise RuntimeError(f"{path}: HTTP {response.status_code}")
    try:
        payload = response.json() or {}
    except Exception as exc:
        raise RuntimeError(f"{path}: JSON解析失败 {exc}") from exc
    record = account_check_record_from_payload(payload, token)
    if record:
        return record
    account_type, source = infer_account_type_from_payload({"accessToken": token, "jwt_payload": claims, "response": payload})
    account_type = normalize_account_type(account_type)
    return {
        "email": account_name_from_access_token(token),
        "account_type": account_type,
        "account_type_source": "ChatGPT接口" if account_type != ACCOUNT_TYPE_UNKNOWN else source,
    }






















class ProxyExitCheckError(RuntimeError):
    def __init__(self, message: str, status: str = "代理检测失败"):
        self.status = status
        super().__init__(message)


class MfaRequiredError(RuntimeError):
    def __init__(self, message: str, status: str = "需要MFA"):
        self.status = status
        super().__init__(message)


class TaskStoppedError(RuntimeError):
    pass


class InvalidEmailOtpError(RuntimeError):
    pass


def generate_totp_code(secret: str, at_time: float | None = None, period: int = 30, digits: int = 6) -> str:
    normalized = re.sub(r"\s+", "", str(secret or "")).upper()
    if not normalized:
        raise ValueError("TOTP 密钥为空")
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        key = base64.b32decode(normalized + padding, casefold=True)
    except Exception as exc:
        raise ValueError("TOTP 密钥格式无效") from exc
    timestamp = time.time() if at_time is None else float(at_time)
    counter = int(timestamp // max(1, int(period)))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % (10 ** max(1, int(digits))):0{max(1, int(digits))}d}"


ABOUT_YOU_NAME_WORDS = [
    "name", "full", "fullname", "nombre", "nom", "nome", "họ và tên", "ho va ten", "全名", "姓名", "氏名", "名前",
]
ABOUT_YOU_BIRTH_YEAR_WORDS = [
    "birth year", "year of birth", "born year",
    "生まれた年", "生年", "出生年", "出生年份",
    "năm sinh", "nam sinh",
    "año de nacimiento", "ano de nacimiento",
    "année de naissance", "annee de naissance",
    "geburtsjahr",
    "ano de nascimento",
    "anno di nascita",
    "geboortejaar",
    "tahun lahir",
]
ABOUT_YOU_AGE_WORDS = [
    "age", "how old",
    "年齢", "年龄", "年纪",
    "edad",
    "âge", "age",
    "alter",
    "idade",
    "età", "eta",
    "tuổi", "tuoi",
    "나이",
    "อายุ",
    "usia", "umur",
]
ABOUT_YOU_BIRTH_DATE_WORDS = [
    "bday", "birthday", "date of birth", "birthdate", "dob",
    "生年月日", "誕生日", "生年月",
    "fecha de nacimiento",
    "date de naissance",
    "geburtstag", "geburtsdatum",
    "ngày sinh", "ngay sinh",
    "data de nascimento",
    "data di nascita",
    "geboortedatum",
    "tanggal lahir",
]

































































OPLL_APPROVE_BURST_RESULTS = {"blocked", "exception"}






















































def parse_expired_time(value: str) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return int(datetime.fromisoformat(text).timestamp())
    except Exception:
        return 0


def resolve_organization_id(id_claims: dict, access_claims: dict) -> str:
    id_auth = get_nested_record(id_claims, "https://api.openai.com/auth")
    access_auth = get_nested_record(access_claims, "https://api.openai.com/auth")
    organizations = id_auth.get("organizations") if isinstance(id_auth.get("organizations"), list) else access_auth.get("organizations")
    if not isinstance(organizations, list) or not organizations:
        return ""
    first = organizations[0]
    return first_non_empty(first.get("id") if isinstance(first, dict) else "")


def normalize_openai_auth_record(email_addr: str, payload: dict) -> dict:
    access_token = str(payload.get("access_token") or "")
    refresh_token = str(payload.get("refresh_token") or "")
    id_token = str(payload.get("id_token") or "")
    if not access_token:
        raise RuntimeError(f"token响应缺少 access_token: {payload}")
    if not refresh_token:
        raise RuntimeError(f"token响应缺少 refresh_token: {payload}")
    if not id_token:
        raise RuntimeError(f"token响应缺少 id_token: {payload}")
    access_claims = decode_jwt_payload(access_token)
    id_claims = decode_jwt_payload(id_token)
    auth_claim = get_nested_record(access_claims, "https://api.openai.com/auth")
    id_auth_claim = get_nested_record(id_claims, "https://api.openai.com/auth")
    account_id = first_non_empty(auth_claim.get("chatgpt_account_id"), id_auth_claim.get("chatgpt_account_id"))
    exp = int(access_claims.get("exp") or 0)
    if not account_id:
        raise RuntimeError(f"token中缺少 account_id: {access_claims}")
    if not exp:
        raise RuntimeError(f"access_token中缺少 exp: {access_claims}")
    return {
        "access_token": access_token,
        "account_id": account_id,
        "disabled": False,
        "email": first_non_empty(id_claims.get("email"), access_claims.get("email"), email_addr),
        "expired": datetime.fromtimestamp(exp, timezone.utc).isoformat().replace("+00:00", "Z"),
        "id_token": id_token,
        "last_refresh": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "refresh_token": refresh_token,
        "type": "codex",
        "websockets": False,
    }


def openai_record_from_refresh_payload(email_addr: str, payload: dict) -> dict:
    access_token = str(payload.get("access_token") or "")
    if not access_token:
        raise RuntimeError("刷新 RT 后缺少 access_token")
    access_claims = decode_jwt_payload(access_token)
    access_auth = get_nested_record(access_claims, "https://api.openai.com/auth")
    account_id = first_non_empty(access_auth.get("chatgpt_account_id"), access_auth.get("account_id"))
    exp = int(access_claims.get("exp") or 0)
    refresh_token = str(payload.get("refresh_token") or "")
    if not refresh_token:
        raise RuntimeError("刷新 RT 后缺少有效 refresh_token")
    if not account_id:
        raise RuntimeError(f"access_token 中缺少 account_id: {access_claims}")
    return {
        "access_token": access_token,
        "account_id": account_id,
        "email": email_addr,
        "expired": datetime.fromtimestamp(exp, timezone.utc).isoformat().replace("+00:00", "Z") if exp else "",
        "id_token": str(payload.get("id_token") or ""),
        "last_refresh": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "plan_type": first_non_empty(access_auth.get("chatgpt_plan_type")),
        "refresh_token": refresh_token,
        "type": "codex",
    }


def normalize_auth_continue_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text if text.startswith("http") else urljoin(AUTH_BASE_URL, text)


def performance_now_ms() -> int:
    return time.perf_counter_ns() // 1_000_000


def base64_json(value) -> str:
    return base64.b64encode(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii")


def sentinel_hash_hex(value: str) -> str:
    hash_value = 2166136261
    for char in value:
        hash_value ^= ord(char)
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF
    hash_value ^= hash_value >> 16
    hash_value = (hash_value * 2246822507) & 0xFFFFFFFF
    hash_value ^= hash_value >> 13
    hash_value = (hash_value * 3266489909) & 0xFFFFFFFF
    hash_value ^= hash_value >> 16
    return f"{hash_value & 0xFFFFFFFF:08x}"


def collect_sentinel_fingerprint_data(sid: str) -> list:
    return [
        1366 + 768,
        datetime.now().astimezone().strftime("%a %b %d %Y %H:%M:%S GMT%z (%Z)"),
        4294967296,
        random.random(),
        DEFAULT_USER_AGENT,
        "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        "20260219f9f6",
        "zh-CN",
        "zh-CN,zh",
        random.random(),
        random.choice([
            f"userAgent−{DEFAULT_USER_AGENT}",
            "language−zh-CN",
            "hardwareConcurrency−8",
        ]),
        "location",
        random.choice(["window", "self", "document", "navigator", "location", "screen", "history"]),
        performance_now_ms(),
        sid,
        "sv",
        8,
        int(time.time() * 1000),
        0,
        1,
        1,
        0,
        0,
        0,
        1,
    ]


def generate_sentinel_answer(seed: str, difficulty: str) -> str:
    started = performance_now_ms()
    sid = str(uuid.uuid4())
    data = collect_sentinel_fingerprint_data(sid)
    for attempt in range(500000):
        data[3] = attempt
        data[9] = round(performance_now_ms() - started)
        encoded = base64_json(data)
        digest = sentinel_hash_hex(seed + encoded)
        if digest[:len(difficulty)] <= difficulty:
            return f"{encoded}~S"
    return "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + base64_json("max attempts exceeded")


def openai_browser_headers(extra: dict | None = None) -> dict:
    headers = {
        "user-agent": DEFAULT_USER_AGENT,
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "sec-ch-ua": '"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"',
        "sec-ch-ua-full-version-list": '"Google Chrome";v="146.0.0.0", "Chromium";v="146.0.0.0", "Not.A/Brand";v="24.0.0.0"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-ch-viewport-width": '"1365"',
    }
    if extra:
        headers.update(extra)
    return headers


def infer_account_type_from_payload(payload) -> tuple[str, str]:
    found_free = ""
    found_paid = ""
    found_weak_free = ""
    stack = [payload]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            lower_keys = {str(key).lower(): value for key, value in item.items()}
            for key in ["accesstoken", "access_token", "token"]:
                value = lower_keys.get(key)
                if isinstance(value, str) and value.count(".") >= 2:
                    claims = decode_jwt_payload(value)
                    if claims:
                        stack.append(claims)
            for key in ["is_paid_subscription_active", "has_active_subscription", "is_plus_user", "is_subscribed"]:
                if key in lower_keys:
                    value = lower_keys[key]
                    if value is True:
                        found_paid = found_paid or f"{key}=true"
                    if value is False:
                        found_free = found_free or f"{key}=false"
            for key in ["account_type", "accounttype", "subscription_plan", "chatgpt_plan_type", "plan_type", "plan", "account_plan", "product_name", "sku", "name"]:
                value = lower_keys.get(key)
                if isinstance(value, str):
                    text = value.lower()
                    if any(word in text for word in ["team", "enterprise"]):
                        return "team", f"{key}={value}"
                    if any(word in text for word in ["plus", "pro", "chatgptplusplan"]):
                        return "plus", f"{key}={value}"
                    if any(word in text for word in ["free", "none", "no_plan"]):
                        if key == "chatgpt_plan_type":
                            found_weak_free = found_weak_free or f"{key}={value}"
                        else:
                            found_free = found_free or f"{key}={value}"
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    if found_paid:
        return "plus", found_paid
    # access-token JWTs can contain chatgpt_plan_type=free even for paid accounts.
    # Treat that claim as non-authoritative so existing/imported Plus accounts are not mislabeled.
    if found_weak_free and not found_free:
        return ACCOUNT_TYPE_UNKNOWN, f"{found_weak_free} (非权威JWT字段)"
    return ("free", found_free) if found_free else ("", "未发现明确套餐字段")


def token_info_record_from_payload(payload: dict, source: str = "") -> dict:
    if not isinstance(payload, dict):
        return {}
    account_type, account_type_source = infer_account_type_from_payload(payload)
    account_type = normalize_account_type(account_type)
    if account_type == ACCOUNT_TYPE_UNKNOWN:
        return {}
    email_addr = str(payload.get("email") or payload.get("account_email") or "").strip()
    token = str(payload.get("accessToken") or payload.get("access_token") or "").strip()
    if not email_addr and token:
        email_addr = account_name_from_access_token(token)
    record = {
        "email": email_addr,
        "account_type": account_type,
        "account_type_source": f"{source}: {account_type_source}" if source else account_type_source,
    }
    for key in ("expires_at", "token_expires_at", "plan_expires_at"):
        epoch = _coerce_epoch(payload.get(key))
        if epoch:
            record[key] = epoch
    for key in ("expires_at_display", "token_expires_at_display", "plan_expires_at_display", "phone"):
        value = str(payload.get(key) or "").strip()
        if value:
            record[key] = value
    return record


def compact_account_type_source(source: str) -> str:
    text = str(source or "").strip()
    if not text:
        return ""
    lower = text.lower()
    if "backend-api/accounts/check" in lower or "subscription_plan" in lower or lower == "chatgpt接口":
        return "ChatGPT接口"
    if "chatgpt_plan_type" in lower or "jwt" in lower:
        return "JWT"
    return text.split(":", 1)[0][:32]


class ProxyChainServer:
    def __init__(self, local_proxy: str, dynamic_proxy: str, log, traffic_callback=None, force_server: bool = False):
        self.local_proxy = normalize_proxy_url(local_proxy)
        self.dynamic_proxy = normalize_dynamic_proxy_url(dynamic_proxy)
        self.log = log
        self.traffic_callback = traffic_callback
        self.force_server = bool(force_server)
        self.lock = threading.Lock()
        self.traffic_lock = threading.Lock()
        self.traffic_detail_lock = threading.Lock()
        self.handler_threads_lock = threading.Lock()
        self.active_sockets: set[socket.socket] = set()
        self.handler_threads: set[threading.Thread] = set()
        self.server: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.url = ""
        self._pending_traffic_bytes = 0
        self._traffic_connection_sequence = 0
        self._traffic_connections: dict[int, dict[str, int | str]] = {}
        self._traffic_context = threading.local()

    def __enter__(self):
        if not self.local_proxy and not self.dynamic_proxy and not self.force_server:
            return self
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(64)
        port = self.server.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.close()

    def close(self) -> None:
        self.stop_event.set()
        with self.lock:
            sockets = list(self.active_sockets)
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        self.server = None
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        server_thread = self.thread
        self.thread = None
        if server_thread is not None and server_thread is not threading.current_thread():
            server_thread.join(timeout=0.5)
        deadline = time.monotonic() + 0.75
        while time.monotonic() < deadline:
            with self.handler_threads_lock:
                handlers = [thread for thread in self.handler_threads if thread.is_alive()]
            if not handlers:
                break
            remaining = max(0.0, deadline - time.monotonic())
            handlers[0].join(timeout=min(0.05, remaining))
        self._record_traffic(0, flush=True)

    def set_dynamic_proxy(self, dynamic_proxy: str) -> None:
        sockets: list[socket.socket]
        with self.lock:
            self.dynamic_proxy = normalize_dynamic_proxy_url(dynamic_proxy)
            sockets = list(self.active_sockets)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

    def _track_socket(self, sock: socket.socket) -> None:
        with self.lock:
            self.active_sockets.add(sock)

    def _untrack_socket(self, sock: socket.socket) -> None:
        with self.lock:
            self.active_sockets.discard(sock)

    def _begin_traffic_connection(self, target: str) -> int:
        try:
            parsed = urlparse(f"//{str(target or '').strip()}")
            target_name = str(parsed.hostname or target or "unknown").strip().lower()
        except Exception:
            target_name = str(target or "unknown").strip().lower()
        target_name = target_name[:200] or "unknown"
        with self.traffic_detail_lock:
            self._traffic_connection_sequence += 1
            connection_id = self._traffic_connection_sequence
            self._traffic_connections[connection_id] = {
                "target": target_name,
                "upload_bytes": 0,
                "download_bytes": 0,
                "unknown_bytes": 0,
                "proxy_handshake_bytes": 0,
                "retry_failures": 0,
                "retry_bytes": 0,
                "outcome": "open",
            }
        self._traffic_context.connection_id = connection_id
        return connection_id

    def _current_traffic_connection_bytes(self) -> int:
        connection_id = int(getattr(self._traffic_context, "connection_id", 0) or 0)
        if not connection_id:
            return 0
        with self.traffic_detail_lock:
            item = self._traffic_connections.get(connection_id, {})
            return sum(max(0, int(item.get(name, 0) or 0)) for name in (
                "upload_bytes", "download_bytes", "unknown_bytes",
            ))

    def _record_traffic_retry_failure(self, attempt_start_bytes: int) -> None:
        connection_id = int(getattr(self._traffic_context, "connection_id", 0) or 0)
        if not connection_id:
            return
        current_bytes = self._current_traffic_connection_bytes()
        with self.traffic_detail_lock:
            item = self._traffic_connections.get(connection_id)
            if item is None:
                return
            item["retry_failures"] = max(0, int(item.get("retry_failures", 0) or 0)) + 1
            item["retry_bytes"] = max(0, int(item.get("retry_bytes", 0) or 0)) + max(
                0, current_bytes - max(0, int(attempt_start_bytes or 0))
            )

    def _finish_traffic_connection(self, connection_id: int, failed: bool = False) -> None:
        if not connection_id:
            return
        with self.traffic_detail_lock:
            item = self._traffic_connections.get(connection_id)
            if item is not None:
                item["outcome"] = "failed" if failed else "success"
        if int(getattr(self._traffic_context, "connection_id", 0) or 0) == connection_id:
            self._traffic_context.connection_id = 0

    def traffic_breakdown(self) -> dict:
        with self.traffic_detail_lock:
            connections = [dict(item) for item in self._traffic_connections.values()]
        targets: dict[str, dict[str, int | str]] = {}
        for item in connections:
            target = str(item.get("target") or "unknown")
            bucket = targets.setdefault(target, {
                "target": target,
                "connections": 0,
                "success_connections": 0,
                "failed_connections": 0,
                "open_connections": 0,
                "upload_bytes": 0,
                "download_bytes": 0,
                "unknown_bytes": 0,
                "proxy_handshake_bytes": 0,
                "retry_failures": 0,
                "retry_bytes": 0,
                "failed_connection_bytes": 0,
                "total_bytes": 0,
            })
            total = sum(max(0, int(item.get(name, 0) or 0)) for name in (
                "upload_bytes", "download_bytes", "unknown_bytes",
            ))
            outcome = str(item.get("outcome") or "open")
            bucket["connections"] += 1
            outcome_key = f"{outcome}_connections" if outcome in {"success", "failed"} else "open_connections"
            bucket[outcome_key] += 1
            for name in (
                "upload_bytes", "download_bytes", "unknown_bytes", "proxy_handshake_bytes",
                "retry_failures", "retry_bytes",
            ):
                bucket[name] += max(0, int(item.get(name, 0) or 0))
            if outcome == "failed":
                bucket["failed_connection_bytes"] += total
            bucket["total_bytes"] += total
        ordered_targets = sorted(targets.values(), key=lambda item: int(item.get("total_bytes", 0)), reverse=True)
        summary = {
            "targets": ordered_targets,
            "connections": len(connections),
            "success_connections": 0,
            "failed_connections": 0,
            "open_connections": 0,
            "upload_bytes": 0,
            "download_bytes": 0,
            "unknown_bytes": 0,
            "proxy_handshake_bytes": 0,
            "retry_failures": 0,
            "retry_bytes": 0,
            "failed_connection_bytes": 0,
            "total_bytes": 0,
        }
        for bucket in ordered_targets:
            for name in (
                "success_connections", "failed_connections", "open_connections",
                "upload_bytes", "download_bytes", "unknown_bytes", "proxy_handshake_bytes",
                "retry_failures", "retry_bytes", "failed_connection_bytes", "total_bytes",
            ):
                summary[name] += max(0, int(bucket.get(name, 0) or 0))
        return summary

    def _record_traffic(
        self,
        delta_bytes: int,
        flush: bool = False,
        direction: str = "unknown",
        phase: str = "payload",
    ) -> None:
        try:
            delta = max(0, int(delta_bytes or 0))
        except Exception:
            delta = 0
        connection_id = int(getattr(self._traffic_context, "connection_id", 0) or 0)
        if delta and connection_id:
            direction_key = direction if direction in {"upload", "download"} else "unknown"
            with self.traffic_detail_lock:
                item = self._traffic_connections.get(connection_id)
                if item is not None:
                    item[f"{direction_key}_bytes"] = max(
                        0, int(item.get(f"{direction_key}_bytes", 0) or 0)
                    ) + delta
                    if phase == "proxy_handshake":
                        item["proxy_handshake_bytes"] = max(
                            0, int(item.get("proxy_handshake_bytes", 0) or 0)
                        ) + delta
        if not self.traffic_callback:
            return
        emit = 0
        with self.traffic_lock:
            self._pending_traffic_bytes += delta
            if flush or self._pending_traffic_bytes >= TRAFFIC_FLUSH_BYTES:
                emit = self._pending_traffic_bytes
                self._pending_traffic_bytes = 0
        if emit:
            try:
                self.traffic_callback(emit)
            except Exception:
                pass

    def _serve(self) -> None:
        assert self.server is not None
        while not self.stop_event.is_set():
            try:
                client, _addr = self.server.accept()
            except OSError:
                break
            thread = threading.Thread(target=self._handle_client_thread, args=(client,), daemon=True)
            with self.handler_threads_lock:
                self.handler_threads.add(thread)
            thread.start()

    def _handle_client_thread(self, client: socket.socket) -> None:
        try:
            self._handle_client(client)
        finally:
            with self.handler_threads_lock:
                self.handler_threads.discard(threading.current_thread())

    def _handle_client(self, client: socket.socket) -> None:
        upstream = None
        target = ""
        connection_id = 0
        failed = False
        self._track_socket(client)
        try:
            client.settimeout(30)
            head = self._read_http_head(client)
            if not head:
                return
            first_line = head.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
            parts = first_line.split()
            if len(parts) < 3:
                return
            method, target, version = parts[0].upper(), parts[1], parts[2]
            if method == "CONNECT":
                if self._is_low_traffic_proxy_target(target):
                    client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                connection_id = self._begin_traffic_connection(target)
                upstream = self._open_chain_to_target(target)
                self._track_socket(upstream)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self._relay(client, upstream)
                return
            rewritten = self._rewrite_plain_request(head, method, target, version)
            plain_target = self._target_from_plain_request(method, target, head)
            if self._is_low_traffic_proxy_target(plain_target, target):
                client.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                return
            connection_id = self._begin_traffic_connection(plain_target)
            upstream = self._open_chain_to_target(plain_target)
            self._track_socket(upstream)
            upstream.sendall(rewritten)
            self._record_traffic(len(rewritten), direction="upload")
            self._relay(client, upstream)
        except Exception as exc:
            failed = not self.stop_event.is_set()
            detail = re.sub(r"(?<=://)[^/@\s]+(?=@)", "***", str(exc))
            try:
                if not self.stop_event.is_set() and not self._is_soft_tunnel_failure(target, detail):
                    self.log(f"proxy chain tunnel failed[{target or 'unknown'}]: {detail[:240]}")
            except Exception:
                pass
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
        finally:
            self._finish_traffic_connection(connection_id, failed=failed)
            self._untrack_socket(client)
            if upstream:
                self._untrack_socket(upstream)
            try:
                client.close()
            except Exception:
                pass

    def _read_http_head(
        self,
        client: socket.socket,
        count_traffic: bool = False,
        traffic_direction: str = "download",
        traffic_phase: str = "proxy_handshake",
    ) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            if self.stop_event.is_set():
                raise RuntimeError("代理链已停止")
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
            if count_traffic:
                self._record_traffic(len(chunk), direction=traffic_direction, phase=traffic_phase)
        return data

    def _target_from_plain_request(self, method: str, target: str, head: bytes) -> str:
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return f"{parsed.hostname}:{port}"
        host = ""
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("latin1")
                break
        return host

    def _rewrite_plain_request(self, head: bytes, method: str, target: str, version: str) -> bytes:
        if not (target.startswith("http://") or target.startswith("https://")):
            return head
        parsed = urlparse(target)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = head.split(b"\r\n")
        lines[0] = f"{method} {path} {version}".encode("latin1")
        return b"\r\n".join(lines)

    def _is_low_traffic_proxy_target(self, target: str, request_target: str = "") -> bool:
        try:
            host = ""
            path = ""
            if request_target.startswith("http://") or request_target.startswith("https://"):
                parsed = urlparse(request_target)
                host = (parsed.hostname or "").lower()
                path = (parsed.path or "").lower()
            if not host and (target.startswith("http://") or target.startswith("https://")):
                parsed = urlparse(target)
                host = (parsed.hostname or "").lower()
                path = (parsed.path or "").lower()
            if not host:
                host, _port = self._split_host_port(str(target or ""), 443)
                host = host.lower()
            if host in LOW_TRAFFIC_BLOCK_HOSTS:
                return True
            if any(host.endswith(suffix) for suffix in LOW_TRAFFIC_BLOCK_HOST_SUFFIXES):
                return True
            if path and any(path.endswith(suffix) for suffix in LOW_TRAFFIC_BLOCK_PATH_SUFFIXES):
                return True
        except Exception:
            return False
        return False

    def _open_chain_to_target(self, target: str) -> socket.socket:
        with self.lock:
            local_proxy = self.local_proxy
            dynamic_proxy = self.dynamic_proxy
        attempts = PROXY_CHAIN_CONNECT_RETRIES if dynamic_proxy else 1
        last_error = None
        for attempt in range(attempts):
            if self.stop_event.is_set():
                raise RuntimeError("代理链已停止")
            attempt_start_bytes = self._current_traffic_connection_bytes()
            try:
                return self._open_chain_to_target_once(target, local_proxy, dynamic_proxy)
            except Exception as exc:
                last_error = exc
                if self.stop_event.is_set():
                    raise RuntimeError("代理链已停止") from exc
                if _provider_source_ip_forbidden_text(str(exc)):
                    break
                if attempt + 1 >= attempts:
                    break
                if self.stop_event.wait(0.2 * (attempt + 1)):
                    raise RuntimeError("代理链已停止") from exc
                self._record_traffic_retry_failure(attempt_start_bytes)
        raise last_error or RuntimeError(f"proxy chain connect failed: {target}")

    def _is_soft_tunnel_failure(self, target: str, detail: str) -> bool:
        if _provider_source_ip_forbidden_text(detail):
            return True
        host = str(target or "").split(":", 1)[0].lower()
        if host not in PROXY_CHAIN_SOFT_FAIL_TARGETS:
            return False
        return (
            "10053" in detail
            or "10054" in detail
            or "SOCKS5" in detail
            or "10053" in detail
        )

    def _open_chain_to_target_once(self, target: str, local_proxy: str, dynamic_proxy: str) -> socket.socket:
        if local_proxy:
            next_target = self._proxy_connect_target(dynamic_proxy) if dynamic_proxy else target
            sock = None
            try:
                if self._is_socks5_proxy(local_proxy):
                    sock = self._connect_socks5_proxy(local_proxy)
                    self._send_socks5_connect(sock, next_target, local_proxy)
                else:
                    sock = self._connect_proxy(local_proxy)
                    self._send_connect(sock, next_target)
                if dynamic_proxy:
                    if self._is_socks5_proxy(dynamic_proxy):
                        self._send_socks5_connect(sock, target, dynamic_proxy)
                    else:
                        self._send_connect(sock, target, proxy_url=dynamic_proxy)
                return sock
            except Exception:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
                raise
        if dynamic_proxy:
            sock = None
            try:
                if self._is_socks5_proxy(dynamic_proxy):
                    sock = self._connect_socks5_proxy(dynamic_proxy)
                    self._send_socks5_connect(sock, target, dynamic_proxy)
                    return sock
                sock = self._connect_proxy(dynamic_proxy)
                self._send_connect(sock, target, proxy_url=dynamic_proxy)
                return sock
            except Exception:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
                raise
        host, port = self._split_host_port(target, 80)
        return self._create_tracked_connection(host, port)

    def _create_tracked_connection(self, host: str, port: int) -> socket.socket:
        if self.stop_event.is_set():
            raise RuntimeError("代理链已停止")
        result_queue: queue.Queue = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                result_queue.put((socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM), None))
            except Exception as exc:
                result_queue.put(([], exc))

        threading.Thread(target=resolve, name="proxy-chain-resolve", daemon=True).start()
        while True:
            if self.stop_event.is_set():
                raise RuntimeError("代理链已停止")
            try:
                addresses, resolve_error = result_queue.get(timeout=0.05)
                break
            except queue.Empty:
                continue
        if resolve_error:
            raise resolve_error

        deadline = time.monotonic() + PROXY_CHAIN_CONNECT_TIMEOUT
        last_error = None
        in_progress = {
            errno.EINPROGRESS,
            errno.EWOULDBLOCK,
            errno.EALREADY,
            getattr(errno, "WSAEINPROGRESS", 10036),
            getattr(errno, "WSAEWOULDBLOCK", 10035),
            getattr(errno, "WSAEALREADY", 10037),
        }
        connected_codes = {0, errno.EISCONN, getattr(errno, "WSAEISCONN", 10056)}
        for family, socktype, protocol, _canonical_name, address in addresses:
            if self.stop_event.is_set():
                raise RuntimeError("代理链已停止")
            sock = socket.socket(family, socktype, protocol)
            self._track_socket(sock)
            connected = False
            try:
                sock.setblocking(False)
                code = sock.connect_ex(address)
                if code not in connected_codes and code not in in_progress:
                    raise OSError(code, os.strerror(code))
                while code not in connected_codes:
                    if self.stop_event.is_set():
                        raise RuntimeError("代理链已停止")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(f"连接 {host}:{port} 超时")
                    _readable, writable, exceptional = select.select([], [sock], [sock], min(0.05, remaining))
                    if sock not in writable and sock not in exceptional:
                        continue
                    code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if code not in connected_codes:
                        raise OSError(code, os.strerror(code))
                sock.setblocking(True)
                sock.settimeout(PROXY_CHAIN_CONNECT_TIMEOUT)
                connected = True
                return sock
            except Exception as exc:
                last_error = exc
                if self.stop_event.is_set():
                    raise RuntimeError("代理链已停止") from exc
            finally:
                if not connected:
                    self._untrack_socket(sock)
                    try:
                        sock.close()
                    except Exception:
                        pass
        raise last_error or OSError(f"连接 {host}:{port} 失败")

    def _connect_proxy(self, proxy_url: str) -> socket.socket:
        parsed = urlparse(proxy_url)
        if parsed.scheme not in ("http", "https"):
            raise RuntimeError(f"链式代理当前只支持 http/https 代理: {proxy_url}")
        host = parsed.hostname
        if not host:
            raise RuntimeError(f"代理地址缺少 host: {proxy_url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        raw = self._create_tracked_connection(host, port)
        if parsed.scheme == "https":
            try:
                wrapped = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            except Exception:
                self._untrack_socket(raw)
                try:
                    raw.close()
                except Exception:
                    pass
                raise
            self._untrack_socket(raw)
            self._track_socket(wrapped)
            return wrapped
        return raw

    def _is_socks5_proxy(self, proxy_url: str) -> bool:
        return urlparse(proxy_url).scheme.lower() in {"socks5", "socks5h"}

    def _connect_socks5_proxy(self, proxy_url: str) -> socket.socket:
        parsed = urlparse(proxy_url)
        if parsed.scheme.lower() not in {"socks5", "socks5h"}:
            raise RuntimeError("不是 SOCKS5 代理")
        host = parsed.hostname
        if not host:
            raise RuntimeError("SOCKS5 代理地址缺少 host")
        try:
            port = parsed.port or 1080
        except ValueError as exc:
            raise RuntimeError("SOCKS5 代理端口无效") from exc
        return self._create_tracked_connection(host, port)

    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        chunks = []
        remaining = max(0, int(size))
        while remaining:
            if self.stop_event.is_set():
                raise RuntimeError("代理链已停止")
            chunk = sock.recv(remaining)
            if not chunk:
                raise RuntimeError("SOCKS5 代理连接意外关闭")
            chunks.append(chunk)
            remaining -= len(chunk)
            self._record_traffic(len(chunk), direction="download", phase="proxy_handshake")
        return b"".join(chunks)

    def _send_socks5_connect(self, sock: socket.socket, target: str, proxy_url: str) -> None:
        parsed = urlparse(proxy_url)
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        methods = b"\x00\x02" if username else b"\x00"
        greeting = b"\x05" + bytes([len(methods)]) + methods
        sock.sendall(greeting)
        self._record_traffic(len(greeting), direction="upload", phase="proxy_handshake")
        selected = self._recv_exact(sock, 2)
        if selected[0] != 5:
            extra = b""
            previous_timeout = sock.gettimeout()
            try:
                sock.settimeout(0.4)
                extra = sock.recv(240)
                if extra:
                    self._record_traffic(len(extra), direction="download", phase="proxy_handshake")
            except (socket.timeout, BlockingIOError):
                pass
            finally:
                sock.settimeout(previous_timeout)
            preview = re.sub(r"\s+", " ", (selected + extra).decode("latin1", errors="replace")).strip()[:160]
            raise RuntimeError(f"SOCKS5 服务端响应不是 SOCKS5（版本字节={selected[0]}，响应={preview or '无可读摘要'}）")
        if selected[1] == 255:
            raise RuntimeError("SOCKS5 代理未接受认证方式")
        if selected[1] == 2:
            user_bytes = username.encode("utf-8")
            password_bytes = password.encode("utf-8")
            if not user_bytes or len(user_bytes) > 255 or len(password_bytes) > 255:
                raise RuntimeError("SOCKS5 用户名或密码长度无效")
            auth_request = b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(password_bytes)]) + password_bytes
            sock.sendall(auth_request)
            self._record_traffic(len(auth_request), direction="upload", phase="proxy_handshake")
            auth_response = self._recv_exact(sock, 2)
            if auth_response[0] != 1 or auth_response[1] != 0:
                raise RuntimeError("SOCKS5 用户名密码认证失败")
        elif selected[1] == 0:
            if username:
                self.log("SOCKS5 服务端选择无认证方式；当前 URL 中的用户名密码不会发送给该服务端")
        else:
            raise RuntimeError(f"SOCKS5 返回了不支持的认证方式: {selected[1]}")

        host, port = self._split_host_port(target, 443)
        try:
            address = socket.inet_pton(socket.AF_INET, host)
            address_type = 1
        except OSError:
            try:
                address = socket.inet_pton(socket.AF_INET6, host)
                address_type = 4
            except OSError:
                address = host.encode("idna")
                if not address or len(address) > 255:
                    raise RuntimeError(f"SOCKS5 目标主机名无效: {host}")
                address_type = 3
                address = bytes([len(address)]) + address
        request = b"\x05\x01\x00" + bytes([address_type]) + address + int(port).to_bytes(2, "big")
        sock.sendall(request)
        self._record_traffic(len(request), direction="upload", phase="proxy_handshake")
        response = self._recv_exact(sock, 4)
        if response[0] != 5:
            raise RuntimeError("SOCKS5 响应版本无效")
        if response[1] != 0:
            reasons = {1: "常规失败", 2: "规则拒绝", 3: "网络不可达", 4: "主机不可达", 5: "连接被拒绝", 6: "TTL 过期", 7: "命令不支持", 8: "地址类型不支持"}
            raise RuntimeError(f"SOCKS5 CONNECT 失败: {reasons.get(response[1], f'错误码 {response[1]}')}")
        if response[3] == 1:
            self._recv_exact(sock, 6)
        elif response[3] == 4:
            self._recv_exact(sock, 18)
        elif response[3] == 3:
            self._recv_exact(sock, self._recv_exact(sock, 1)[0] + 2)
        else:
            raise RuntimeError("SOCKS5 响应地址类型无效")

    def _proxy_connect_target(self, proxy_url: str) -> str:
        parsed = urlparse(proxy_url)
        if not parsed.hostname:
            raise RuntimeError(f"代理地址缺少 host: {proxy_url}")
        scheme = parsed.scheme.lower()
        if parsed.port:
            port = parsed.port
        elif scheme in {"socks5", "socks5h"}:
            port = 1080
        elif scheme == "https":
            port = 443
        else:
            port = 80
        return f"{parsed.hostname}:{port}"

    def _send_connect(self, sock: socket.socket, target: str, proxy_url: str = "") -> None:
        headers = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Proxy-Connection: keep-alive"]
        auth = self._proxy_auth(proxy_url)
        if auth:
            headers.append(f"Proxy-Authorization: Basic {auth}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("latin1")
        sock.sendall(request)
        self._record_traffic(len(request), direction="upload", phase="proxy_handshake")
        response = self._read_http_head(
            sock,
            count_traffic=True,
            traffic_direction="download",
            traffic_phase="proxy_handshake",
        )
        status = response.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        if " 200 " not in f" {status} ":
            raise RuntimeError(f"代理 CONNECT 失败: {status}")

    def _proxy_auth(self, proxy_url: str) -> str:
        parsed = urlparse(proxy_url)
        if not parsed.username:
            return ""
        username = unquote(parsed.username)
        password = unquote(parsed.password or "")
        return base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")

    def _split_host_port(self, target: str, default_port: int) -> tuple[str, int]:
        if target.startswith("["):
            host, rest = target[1:].split("]", 1)
            port = int(rest[1:]) if rest.startswith(":") else default_port
            return host, port
        if ":" in target:
            host, port = target.rsplit(":", 1)
            return host, int(port)
        return target, default_port

    def _relay(self, left: socket.socket, right: socket.socket) -> None:
        sockets = [left, right]
        for sock in sockets:
            sock.settimeout(None)
        try:
            while not self.stop_event.is_set():
                readable, _, _ = select.select(sockets, [], [], 1)
                if not readable:
                    continue
                for src in readable:
                    dst = right if src is left else left
                    data = src.recv(65536)
                    if not data:
                        return
                    dst.sendall(data)
                    self._record_traffic(
                        len(data),
                        direction="upload" if src is left else "download",
                    )
        finally:
            self._record_traffic(0, flush=True)
            try:
                right.close()
            except Exception:
                pass


def decode_header_text(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def html_to_text(value: str) -> str:
    text = re.sub(r"<script[\s\S]*?</script>", " ", value, flags=re.I)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return unescape(re.sub(r"\s+", " ", text))


def extract_message_text(msg) -> str:
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type not in ("text/plain", "text/html"):
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            parts.append(html_to_text(text) if content_type == "text/html" else text)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            parts.append(html_to_text(text) if msg.get_content_type() == "text/html" else text)
    return "\n".join(parts)


def extract_openai_code(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text or " ")
    patterns = [
        r"(?:OpenAI|ChatGPT|verification|verify|code|验证码|登录码)[^\d]{0,100}(\d{6})",
        r"\b(\d{6})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, normalized, flags=re.I)
        if match:
            return match.group(1)
    return ""


def extract_openai_codes(text: str) -> list[str]:
    normalized = re.sub(r"\s+", " ", text or " ")
    result: list[str] = []
    seen: set[str] = set()
    for pattern in (
        r"(?:OpenAI|ChatGPT|verification|verify|code|验证码|登录码)[^\d]{0,100}(\d{6})",
        r"\b(\d{6})\b",
    ):
        for match in re.finditer(pattern, normalized, flags=re.I):
            code = str(match.group(1) or "")
            if code and code not in seen:
                seen.add(code)
                result.append(code)
    return result


def hotmail_token_has_imap_scope(payload: dict, endpoint: dict) -> bool:
    scope_text = " ".join(
        str(payload.get(key) or "") for key in ("scope", "scp", "resource")
    ).lower()
    requested_text = f"{endpoint.get('scope', '')} {endpoint.get('resource', '')}".lower()
    has_outlook_imap = "outlook.office.com" in scope_text and "imap.accessasuser.all" in scope_text
    if has_outlook_imap:
        return True
    if scope_text:
        return False
    return "outlook.office.com" in requested_text and (
        "imap.accessasuser.all" in requested_text or endpoint.get("resource")
    )


def hotmail_token_has_graph_mail_scope(payload: dict, endpoint: dict) -> bool:
    scope_text = " ".join(
        str(payload.get(key) or "") for key in ("scope", "scp", "resource")
    ).lower()
    requested_text = f"{endpoint.get('scope', '')} {endpoint.get('resource', '')}".lower()
    if "outlook.office.com" in scope_text:
        return False
    if "graph.microsoft.com" in scope_text and ("mail.read" in scope_text or ".default" in scope_text):
        return True
    if scope_text and "mail.read" in scope_text:
        return True
    if not scope_text and "graph.microsoft.com" in requested_text:
        return True
    return False


def refresh_graph_access_token_with_mode(
    account: MailAccount,
    log,
    proxy_url: str = "",
    preferred_mode: str = "",
) -> tuple[str, str]:
    errors: list[str] = []
    mode = normalize_mail_auth_mode(preferred_mode)
    priorities = {
        "graph_mail": ("GRAPH-MAIL", "GRAPH-DEFAULT", "GRAPH-LIVE"),
        "graph_default": ("GRAPH-DEFAULT", "GRAPH-LIVE", "GRAPH-MAIL"),
    }.get(mode, ("GRAPH-DEFAULT", "GRAPH-MAIL", "GRAPH-LIVE"))
    endpoints = sorted(
        GRAPH_TOKEN_ENDPOINTS,
        key=lambda endpoint: next(
            (index for index, prefix in enumerate(priorities) if str(endpoint.get("name") or "").startswith(prefix)),
            len(priorities),
        ),
    )
    for endpoint in endpoints:
        data = {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
        }
        if endpoint.get("scope"):
            data["scope"] = endpoint["scope"]
        if endpoint.get("resource"):
            data["resource"] = endpoint["resource"]
        try:
            resp = requests.post(
                endpoint["url"],
                data=data,
                headers={"Accept": "application/json"},
                timeout=10,
                proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None,
            )
            payload = resp.json() if resp.text else {}
            if resp.ok and payload.get("access_token"):
                if not hotmail_token_has_graph_mail_scope(payload, endpoint):
                    returned_scope = str(payload.get("scope") or payload.get("scp") or payload.get("resource") or "")
                    msg = f"返回的不是 Graph Mail token，scope/resource={returned_scope or 'empty'}"
                    errors.append(f"{endpoint['name']}: {msg}")
                    log(f"邮箱 Graph Token 端点 {endpoint['name']} 已跳过: {msg}")
                    continue
                selected_mode = "graph_mail" if str(endpoint.get("name") or "").startswith("GRAPH-MAIL") else "graph_default"
                return str(payload["access_token"]), selected_mode
            msg = payload.get("error_description") or payload.get("error") or f"HTTP {resp.status_code}"
            errors.append(f"{endpoint['name']}: {msg}")
            log(f"邮箱 Graph Token 端点 {endpoint['name']} 失败: {msg}")
        except Exception as exc:
            errors.append(f"{endpoint['name']}: {exc}")
            log(f"邮箱 Graph Token 端点 {endpoint['name']} 异常: {exc}")
    raise RuntimeError("所有邮箱 Graph Token 端点均失败 -> " + " | ".join(errors))


def refresh_graph_access_token(account: MailAccount, log, proxy_url: str = "") -> str:
    token, _mode = refresh_graph_access_token_with_mode(account, log, proxy_url, account.mail_auth_mode)
    return token


def refresh_hotmail_access_token(account: MailAccount, log, proxy_url: str = "") -> str:
    errors: list[str] = []
    for endpoint in TOKEN_ENDPOINTS:
        data = {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
        }
        if endpoint.get("scope"):
            data["scope"] = endpoint["scope"]
        if endpoint.get("resource"):
            data["resource"] = endpoint["resource"]
        try:
            resp = requests.post(
                endpoint["url"],
                data=data,
                headers={"Accept": "application/json"},
                timeout=10,
                proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None,
            )
            payload = resp.json() if resp.text else {}
            if resp.ok and payload.get("access_token"):
                if not hotmail_token_has_imap_scope(payload, endpoint):
                    returned_scope = str(payload.get("scope") or payload.get("scp") or payload.get("resource") or "")
                    msg = f"返回的不是 Outlook IMAP token，scope/resource={returned_scope or 'empty'}"
                    errors.append(f"{endpoint['name']}: {msg}")
                    log(f"邮箱 Token 端点 {endpoint['name']} 已跳过: {msg}")
                    continue
                return str(payload["access_token"])
            msg = payload.get("error_description") or payload.get("error") or f"HTTP {resp.status_code}"
            errors.append(f"{endpoint['name']}: {msg}")
            log(f"邮箱 Token 端点 {endpoint['name']} 失败: {msg}")
        except Exception as exc:
            errors.append(f"{endpoint['name']}: {exc}")
            log(f"邮箱 Token 端点 {endpoint['name']} 异常: {exc}")
    raise RuntimeError("所有邮箱 Token 端点均失败 -> " + " | ".join(errors))


class ProxiedIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(self, host: str, port: int, proxied_socket: socket.socket, timeout: float | None = None):
        self._proxied_socket = proxied_socket
        super().__init__(host=host, port=port, timeout=timeout)

    def open(self, host: str = "", port: int = 0, timeout: float | None = None):
        self.host = host
        self.port = port
        self.sock = self._proxied_socket
        self.file = self.sock.makefile("rb")


def _url_otp_host_limiter(url: str) -> threading.BoundedSemaphore:
    hostname = str(urlsplit(str(url or "")).hostname or "").lower() or "unknown"
    with _URL_OTP_HOST_LIMITERS_LOCK:
        limiter = _URL_OTP_HOST_LIMITERS.get(hostname)
        if limiter is None:
            limiter = threading.BoundedSemaphore(URL_OTP_MAX_CONCURRENT_REQUESTS_PER_HOST)
            _URL_OTP_HOST_LIMITERS[hostname] = limiter
        return limiter


class UrlOtpReader:
    def __init__(
        self,
        account: MailAccount,
        log,
        proxy_url: str = "",
        session=None,
        stop_event: threading.Event | None = None,
        browser_context=None,
    ):
        self.account = account
        self.log = log
        self.proxy_url = normalize_proxy_url(proxy_url)
        self.session = session or requests.Session()
        self.stop_event = stop_event
        self.browser_context = browser_context
        self.browser_page = None
        self.baseline_codes: set[str] = set()
        self.baseline_message_ids: set[str] = set()
        self.pending_messages: dict[str, str] = {}
        self.etag = ""
        self.last_modified = ""
        self.page_url = ""
        self.detail_base = ""
        self.detail_suffix = ""

    def target_email(self) -> str:
        return str(self.account.email or "").strip()

    def pickup_url(self) -> str:
        return normalize_pickup_url(self.account.pickup_url)

    def _raise_if_stopped(self) -> None:
        if self.stop_event is not None and self.stop_event.is_set():
            raise TaskStoppedError("iCloud 取码任务已停止")

    def _wait_or_stop(self, seconds: float) -> None:
        if self.stop_event is None:
            time.sleep(seconds)
            return
        if self.stop_event.wait(max(0.0, float(seconds))):
            raise TaskStoppedError("iCloud 取码任务已停止")

    @contextmanager
    def _request_slot(self):
        limiter = _url_otp_host_limiter(self.pickup_url())
        while not limiter.acquire(timeout=0.25):
            self._raise_if_stopped()
        try:
            yield
        finally:
            limiter.release()

    def _read_response_text(self, response) -> str:
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            remaining = URL_OTP_MAX_RESPONSE_BYTES - size
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            size += min(len(chunk), remaining)
        raw = b"".join(chunks)
        encoding = str(getattr(response, "encoding", "") or "utf-8")
        try:
            return raw.decode(encoding, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")

    def _browser_page_for_request(self):
        if self.browser_context is None:
            return None
        if self.browser_page is None or self.browser_page.is_closed():
            self.browser_page = self.browser_context.new_page()
        return self.browser_page

    def _fetch_with_browser(self, url: str, read_timeout: float, accept: str) -> tuple[str | None, dict[str, str], str]:
        self._raise_if_stopped()
        page = self._browser_page_for_request()
        if page is None:
            raise requests.ConnectionError("Chromium 取码通道尚未初始化")
        try:
            page.set_extra_http_headers({
                "Accept": accept,
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            })
            response = page.goto(
                url,
                wait_until="commit",
                timeout=int((5 + max(5.0, float(read_timeout or URL_OTP_POLL_READ_TIMEOUT_SECONDS))) * 1000),
            )
            if response is None:
                raise requests.ConnectionError("Chromium 取码请求没有返回响应")
            status = int(getattr(response, "status", 0) or 0)
            headers = {str(key).lower(): str(value) for key, value in dict(getattr(response, "headers", {}) or {}).items()}
            response_url = str(getattr(response, "url", "") or url)
            if status == 304:
                return None, headers, response_url
            if status >= 400:
                failed_response = requests.Response()
                failed_response.status_code = status
                failed_response.url = response_url
                raise requests.HTTPError(f"HTTP {status}", response=failed_response)
            raw = bytes(response.body() or b"")[:URL_OTP_MAX_RESPONSE_BYTES]
            charset_match = re.search(r"charset=([^;,\s]+)", headers.get("content-type", ""), flags=re.I)
            encoding = str(charset_match.group(1) if charset_match else "utf-8").strip('"\'')
            try:
                text = raw.decode(encoding, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            return text, headers, response_url
        except (TaskStoppedError, requests.RequestException):
            raise
        except Exception as exc:
            try:
                if self.browser_page is not None:
                    self.browser_page.close()
            except Exception:
                pass
            self.browser_page = None
            raise requests.ConnectionError(f"Chromium 取码请求失败: {exc}") from exc

    def _fetch_page(self, read_timeout: float = 10, force: bool = False) -> str | None:
        self._raise_if_stopped()
        if self.browser_context is not None:
            page_text, headers, response_url = self._fetch_with_browser(
                self.pickup_url(),
                read_timeout,
                "text/html,application/json,text/plain;q=0.9,*/*;q=0.5",
            )
            self.page_url = response_url or self.page_url or self.pickup_url()
            self.etag = str(headers.get("etag") or self.etag)
            self.last_modified = str(headers.get("last-modified") or self.last_modified)
            return page_text
        headers = {
            "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.5",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/137 Safari/537.36",
            "Cache-Control": "no-cache",
        }
        if self.etag and not force:
            headers["If-None-Match"] = self.etag
        if self.last_modified and not force:
            headers["If-Modified-Since"] = self.last_modified
        with self._request_slot():
            response = self.session.get(
                self.pickup_url(),
                headers=headers,
                timeout=(5, max(5.0, float(read_timeout or URL_OTP_POLL_READ_TIMEOUT_SECONDS))),
                allow_redirects=True,
                stream=True,
                proxies={"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None,
            )
            try:
                if int(response.status_code or 0) == 304:
                    return None
                response.raise_for_status()
                self.page_url = str(getattr(response, "url", "") or self.page_url or self.pickup_url())
                self.etag = str(response.headers.get("ETag") or self.etag)
                self.last_modified = str(response.headers.get("Last-Modified") or self.last_modified)
                return self._read_response_text(response)
            finally:
                response.close()

    def _codes_from_page(self, page_text: str) -> list[str]:
        raw = str(page_text or "")
        candidates = [raw, html_to_text(raw)]
        try:
            payload = json.loads(raw)
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, dict):
                candidates.extend(str(data.get(key) or "") for key in ("address", "subject", "snippet", "sent_at"))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        return extract_openai_codes("\n".join(candidates))

    def _message_entries_from_page(self, page_text: str) -> list[tuple[str, str]]:
        raw = str(page_text or "")
        for name, attribute in (("detailBase", "detail_base"), ("detailSuffix", "detail_suffix")):
            match = re.search(rf"\bvar\s+{name}\s*=\s*(['\"])(.*?)\1", raw, flags=re.I | re.S)
            if match:
                setattr(self, attribute, unescape(str(match.group(2) or "")).replace("\\/", "/"))
        entries: list[tuple[str, str]] = []
        for match in re.finditer(
            r"<a\b(?=[^>]*\bdata-id=['\"]([^'\"]+)['\"])[^>]*>(.*?)</a>",
            raw,
            flags=re.I | re.S,
        ):
            message_id = unescape(str(match.group(1) or "")).strip()
            if message_id:
                entries.append((message_id, html_to_text(match.group(2))))
        return entries

    def _fetch_message_detail(self, message_id: str, read_timeout: float = 10) -> dict:
        self._raise_if_stopped()
        if not self.detail_base or not self.detail_suffix:
            return {}
        relative_url = f"{self.detail_base}{quote(str(message_id), safe='')}{self.detail_suffix}"
        detail_url = urljoin(self.page_url or self.pickup_url(), relative_url)
        if self.browser_context is not None:
            response_text, _headers, _response_url = self._fetch_with_browser(
                detail_url,
                read_timeout,
                "application/json",
            )
            payload = json.loads(response_text or "{}")
            return payload if isinstance(payload, dict) else {}
        with self._request_slot():
            response = self.session.get(
                detail_url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/137 Safari/537.36",
                    "Cache-Control": "no-cache",
                },
                timeout=(5, max(5.0, float(read_timeout or URL_OTP_POLL_READ_TIMEOUT_SECONDS))),
                allow_redirects=True,
                stream=True,
                proxies={"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None,
            )
            try:
                response.raise_for_status()
                payload = json.loads(self._read_response_text(response) or "{}")
                return payload if isinstance(payload, dict) else {}
            finally:
                response.close()

    def _decode_message_body(self, value: str) -> str:
        raw = str(value or "")
        if not raw.lower().startswith("data:") or "," not in raw:
            return raw
        header, encoded = raw.split(",", 1)
        if ";base64" not in header.lower():
            return unquote(encoded)
        charset_match = re.search(r"charset=([^;,]+)", header, flags=re.I)
        charset = str(charset_match.group(1) if charset_match else "utf-8").strip()
        compact = re.sub(r"\s+", "", unquote(encoded))
        compact += "=" * (-len(compact) % 4)
        try:
            decoded = base64.b64decode(compact, validate=False)
        except Exception:
            decoded = base64.urlsafe_b64decode(compact)
        try:
            return decoded.decode(charset, errors="replace")
        except LookupError:
            return decoded.decode("utf-8", errors="replace")

    def _codes_from_message(self, payload: dict, summary: str = "") -> list[str]:
        subject = str(payload.get("subject") or "")
        sender = str(payload.get("fromAddress") or payload.get("from") or "")
        metadata = f"{summary}\n{subject}\n{sender}"
        if not re.search(r"OpenAI|ChatGPT", metadata, flags=re.I):
            return []
        body = self._decode_message_body(str(payload.get("body") or ""))
        return extract_openai_codes(metadata + "\n" + html_to_text(body))

    def _message_received_timestamp(self, payload: dict, summary: str = "") -> float | None:
        candidates = [str(payload.get("receivedAt") or ""), str(summary or "")]
        for candidate in candidates:
            match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", candidate)
            if not match:
                continue
            try:
                parsed = datetime.fromisoformat(match.group(0).replace("Z", "+00:00"))
                return parsed.timestamp()
            except ValueError:
                continue
        return None

    def connect(self) -> None:
        self._raise_if_stopped()
        hostname = str(urlsplit(self.pickup_url()).hostname or "")
        if self.browser_context is not None:
            route = "，复用认证 Chromium 网络通道"
        else:
            route = f"，代理={self.proxy_url}" if self.proxy_url else "，直连"
        self.log(f"正在连接 iCloud 取码服务: {hostname}（目标收件人: {self.target_email()}{route}）")
        page_text = ""
        last_error: Exception | None = None
        for attempt in range(4):
            self._raise_if_stopped()
            try:
                page_text = self._fetch_page(read_timeout=URL_OTP_CONNECT_READ_TIMEOUT_SECONDS, force=attempt > 0) or ""
                break
            except requests.RequestException as exc:
                last_error = exc
                self.account.pickup_status = "连接重试"
                if attempt < 3:
                    delay = 0.5 * (2 ** attempt)
                    self.log(f"iCloud 取码服务暂时不可用，{delay:g} 秒后重试({attempt + 1}/4): {exc}")
                    self._wait_or_stop(delay)
        if not page_text and last_error is not None:
            self.account.pickup_status = "连接失败"
            raise RuntimeError(f"iCloud 取码服务连接失败: {hostname}: {last_error}") from last_error
        self.baseline_codes = set(self._codes_from_page(page_text))
        self.baseline_message_ids = {message_id for message_id, _summary in self._message_entries_from_page(page_text)}
        self.pending_messages.clear()
        self.account.pickup_status = "已连接"
        self.log(
            f"iCloud 取码服务已连接，已忽略历史验证码 {len(self.baseline_codes)} 个、历史邮件 {len(self.baseline_message_ids)} 封，准备轻量轮询"
        )

    def mark_current_codes_seen(self) -> int:
        self._raise_if_stopped()
        page_text = self._fetch_page(read_timeout=URL_OTP_POLL_READ_TIMEOUT_SECONDS, force=True) or ""
        codes = set(self._codes_from_page(page_text))
        before = len(self.baseline_codes)
        self.baseline_codes.update(codes)
        for message_id, _summary in self._message_entries_from_page(page_text):
            self.baseline_message_ids.add(message_id)
        self.pending_messages.clear()
        return max(0, len(self.baseline_codes) - before)

    def wait_for_code(
        self,
        min_timestamp: float,
        timeout: int = 180,
        resend_callback=None,
        initial_delay: float = 0.0,
    ) -> str:
        self._raise_if_stopped()
        started = time.time()
        normal_deadline = started + max(1, timeout)
        final_deadline = normal_deadline + URL_OTP_FINAL_GRACE_SECONDS
        last_notice = 0.0
        last_error_notice = 0.0
        grace_announced = False
        resend_attempted = False
        poll_index = 0
        delay = max(0.0, float(initial_delay or 0.0))
        if delay:
            self.log(f"首次取码前等待 {delay:g} 秒，期间不轮询以减少本地取码流量")
            self._wait_or_stop(delay)
        while time.time() < final_deadline:
            self._raise_if_stopped()
            now = time.time()
            in_grace = now >= normal_deadline
            if in_grace and not grace_announced:
                self.log(f"常规等待已到时，继续强制补查 {URL_OTP_FINAL_GRACE_SECONDS}s，避免取码服务瞬时延迟")
                grace_announced = True
            try:
                force_refresh = in_grace or (poll_index > 0 and poll_index % URL_OTP_FORCE_REFRESH_EVERY_POLLS == 0)
                page_text = self._fetch_page(read_timeout=URL_OTP_POLL_READ_TIMEOUT_SECONDS, force=force_refresh)
            except requests.RequestException as exc:
                if time.time() - last_error_notice >= 20:
                    self.log(f"iCloud 取码轮询暂时不可用，已保留任务并继续重试: {exc}")
                    last_error_notice = time.time()
                page_text = None
            if page_text is not None:
                for message_id, summary in self._message_entries_from_page(page_text):
                    if message_id not in self.baseline_message_ids:
                        self.pending_messages.setdefault(message_id, summary)
                for message_id, summary in list(self.pending_messages.items()):
                    try:
                        payload = self._fetch_message_detail(message_id, read_timeout=URL_OTP_POLL_READ_TIMEOUT_SECONDS)
                    except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
                        if time.time() - last_error_notice >= 20:
                            self.log(f"iCloud 邮件详情暂时不可用，继续重试: {exc}")
                            last_error_notice = time.time()
                        continue
                    received_at = self._message_received_timestamp(payload, summary)
                    if received_at is not None and min_timestamp and received_at < float(min_timestamp) - 300:
                        self.baseline_message_ids.add(message_id)
                        self.pending_messages.pop(message_id, None)
                        continue
                    codes = self._codes_from_message(payload, summary)
                    self.baseline_message_ids.add(message_id)
                    self.pending_messages.pop(message_id, None)
                    for code in codes:
                        if code not in self.baseline_codes:
                            self.baseline_codes.add(code)
                            self.log(f"收到 OpenAI 验证码(取码URL详情): {code}")
                            return code
                for code in self._codes_from_page(page_text):
                    if code not in self.baseline_codes:
                        self.baseline_codes.add(code)
                        self.log(f"收到 OpenAI 验证码(取码URL): {code}")
                        return code
            if (
                not resend_attempted
                and callable(resend_callback)
                and time.time() - started >= URL_OTP_RESEND_AFTER_SECONDS
            ):
                resend_attempted = True
                try:
                    if resend_callback():
                        self.log("iCloud 暂无新验证码，已在认证页自动重发一次邮件并继续轮询")
                    else:
                        self.log("iCloud 暂无新验证码，认证页未找到可用的重发按钮，继续轮询")
                except Exception as exc:
                    self.log(f"iCloud 验证码自动重发未完成，继续轮询: {str(exc)[:160]}")
            if time.time() - last_notice >= 20:
                remain = max(0, int(final_deadline - time.time()))
                self.log(f"仍在等待 iCloud 取码服务出现新验证码，剩余约 {remain}s")
                last_notice = time.time()
            poll_index += 1
            self._wait_or_stop(URL_OTP_POLL_INTERVAL_SECONDS)
        self._raise_if_stopped()
        raise TimeoutError(f"等待 OpenAI 邮箱验证码超时: {self.target_email()}")

    def close(self) -> None:
        try:
            if self.browser_page is not None and not self.browser_page.is_closed():
                self.browser_page.close()
        except Exception:
            pass
        self.browser_page = None
        try:
            self.session.close()
        except Exception:
            pass


class HotmailOtpReader:
    def __init__(self, account: MailAccount, log, proxy_url: str = "", stop_event: threading.Event | None = None):
        self.account = account
        self.log = log
        self.proxy_url = proxy_url
        self.stop_event = stop_event
        self.seen: set[str] = set()
        self.mode: str = ""
        self.graph_token: str = ""
        self.imap: imaplib.IMAP4_SSL | None = None

    def target_email(self) -> str:
        return str(self.account.email or "").strip()

    def mailbox_email(self) -> str:
        return str(self.account.mailbox_email or self.account.email or "").strip()

    def _raise_if_stopped(self) -> None:
        if self.stop_event is not None and self.stop_event.is_set():
            raise TaskStoppedError("邮箱取码任务已停止")

    def _wait_or_stop(self, seconds: float) -> None:
        if self.stop_event is None:
            time.sleep(seconds)
            return
        if self.stop_event.wait(max(0.0, float(seconds))):
            raise TaskStoppedError("邮箱取码任务已停止")

    def connect(self) -> None:
        self._raise_if_stopped()
        self.log(f"正在连接邮箱取码: {self.mailbox_email()}（目标收件人: {self.target_email()}）")
        preferred_mode = normalize_mail_auth_mode(self.account.mail_auth_mode)
        if preferred_mode == "imap":
            try:
                self.log("复用该邮箱上次成功取件模式: IMAP")
                self._connect_imap()
                return
            except Exception as exc:
                self.log(f"邮箱 IMAP 记忆模式连接失败，回退 Graph 探测: {exc}")
        try:
            self.graph_token, selected_mode = refresh_graph_access_token_with_mode(
                self.account,
                self.log,
                self.proxy_url,
                preferred_mode,
            )
            self._probe_graph_mailbox()
            self.mode = "graph"
            self.account.mail_auth_mode = selected_mode
            self.log(f"邮箱 Graph 已连接，已记忆取件模式={selected_mode}，准备自动收 OpenAI 验证码")
            return
        except Exception as exc:
            self.graph_token = ""
            self.log(f"邮箱 Graph 连接失败，切换 IMAP: {exc}")
        self._raise_if_stopped()
        self._connect_imap()

    def _connect_imap(self) -> None:
        access_token = refresh_hotmail_access_token(self.account, self.log, self.proxy_url)
        auth_string = f"user={self.mailbox_email()}\x01auth=Bearer {access_token}\x01\x01"
        if self.proxy_url:
            self.imap = self._connect_imap_via_proxy(self.proxy_url)
        else:
            self.log("正在连接 Outlook IMAP: outlook.office365.com:993")
            self.imap = imaplib.IMAP4_SSL("outlook.office365.com", 993, timeout=20)
            try:
                self.imap.sock.settimeout(20)
            except Exception:
                pass
        self.log("正在进行邮箱 XOAUTH2 认证")
        self.imap.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))
        try:
            self.imap.sock.settimeout(30)
        except Exception:
            pass
        self.mode = "imap"
        self.account.mail_auth_mode = "imap"
        self.log("邮箱 IMAP 已连接，准备自动收 OpenAI 验证码")

    def _graph_headers(self) -> dict:
        if not self.graph_token:
            raise RuntimeError("Graph token 未初始化")
        return {"Authorization": f"Bearer {self.graph_token}", "Accept": "application/json"}

    def _graph_get(self, url: str, params: dict | None = None, timeout: float = 8) -> dict:
        response = requests.get(
            url,
            params=params,
            headers=self._graph_headers(),
            timeout=max(1.0, float(timeout or 8)),
            proxies={"http": self.proxy_url, "https": self.proxy_url} if self.proxy_url else None,
        )
        if not response.ok:
            detail = response.text[:300] if response.text else f"HTTP {response.status_code}"
            raise RuntimeError(f"Graph 邮件请求失败: HTTP {response.status_code} {detail}")
        return response.json() if response.text else {}

    def _probe_graph_mailbox(self) -> None:
        self._graph_get(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages",
            {"$top": "1", "$select": "id,receivedDateTime"},
        )

    def _graph_message_text(self, item: dict) -> tuple[str, str, str, float]:
        subject = str(item.get("subject") or "")
        sender = item.get("from") or {}
        email_address = sender.get("emailAddress") if isinstance(sender, dict) else {}
        if isinstance(email_address, dict):
            from_addr = " ".join(str(email_address.get(key) or "") for key in ("name", "address")).strip()
        else:
            from_addr = ""
        body_preview = str(item.get("bodyPreview") or "")
        body = item.get("body") if isinstance(item.get("body"), dict) else {}
        body_content = str(body.get("content") or "") if isinstance(body, dict) else ""
        body_type = str(body.get("contentType") or "").lower() if isinstance(body, dict) else ""
        if body_content and body_type == "html":
            body_content = html_to_text(body_content)
        text = "\n".join(part for part in (body_preview, body_content) if part)
        received_at = str(item.get("receivedDateTime") or "")
        try:
            mail_time = datetime.fromisoformat(received_at.replace("Z", "+00:00")).timestamp() if received_at else time.time()
        except Exception:
            mail_time = time.time()
        return subject, from_addr, text, mail_time

    def _graph_recipient_addresses(self, item: dict) -> set[str]:
        addresses: set[str] = set()
        for field in ("toRecipients", "ccRecipients", "bccRecipients"):
            values = item.get(field)
            if not isinstance(values, list):
                continue
            for recipient in values:
                if not isinstance(recipient, dict):
                    continue
                email_address = recipient.get("emailAddress")
                if isinstance(email_address, dict):
                    address = str(email_address.get("address") or "").strip().lower()
                    if address:
                        addresses.add(address)
        return addresses

    def _recipient_matches_target(self, addresses: set[str]) -> bool:
        target = self.target_email().lower()
        return bool(target and target in {str(address or "").strip().lower() for address in addresses})

    def _imap_recipient_addresses(self, msg) -> set[str]:
        texts: list[str] = []
        for header in ("To", "Cc", "Delivered-To", "X-Original-To", "Envelope-To"):
            for value in msg.get_all(header, []):
                decoded = decode_header_text(value)
                if decoded:
                    texts.append(decoded)
        for value in msg.get_all("Received", []):
            decoded = decode_header_text(value)
            if decoded:
                texts.append(decoded)
        addresses: set[str] = set()
        for text in texts:
            try:
                for _name, address in getaddresses([text]):
                    address = str(address or "").strip().lower()
                    if address:
                        addresses.add(address)
            except Exception:
                pass
            for match in re.finditer(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", text, flags=re.I):
                addresses.add(match.group(0).strip().lower())
        return addresses

    def _connect_imap_via_proxy(self, proxy_url: str) -> imaplib.IMAP4_SSL:
        parsed = urlparse(proxy_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise RuntimeError(f"IMAP 代理只支持 HTTP CONNECT: {proxy_url}")
        proxy_port = parsed.port or 80
        raw = socket.create_connection((parsed.hostname, proxy_port), timeout=30)
        target = "outlook.office365.com:993"
        request = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Proxy-Connection: keep-alive"]
        if parsed.username:
            token = base64.b64encode(f"{unquote(parsed.username)}:{unquote(parsed.password or '')}".encode("utf-8")).decode("ascii")
            request.append(f"Proxy-Authorization: Basic {token}")
        raw.sendall(("\r\n".join(request) + "\r\n\r\n").encode("latin1"))
        response = b""
        while b"\r\n\r\n" not in response and len(response) < 65536:
            chunk = raw.recv(4096)
            if not chunk:
                break
            response += chunk
        status = response.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        if " 200 " not in f" {status} ":
            raw.close()
            raise RuntimeError(f"IMAP 代理 CONNECT 失败: {status}")
        tls_sock = ssl.create_default_context().wrap_socket(raw, server_hostname="outlook.office365.com")
        try:
            tls_sock.settimeout(20)
        except Exception:
            pass
        return ProxiedIMAP4SSL("outlook.office365.com", 993, tls_sock, timeout=20)

    def close(self) -> None:
        if not self.imap:
            return
        try:
            self.imap.logout()
        except Exception:
            pass
        self.imap = None

    def wait_for_code(self, min_timestamp: float, timeout: int = 180) -> str:
        self._raise_if_stopped()
        if not self.mode:
            try:
                self.connect()
            except Exception as exc:
                self.log(f"邮箱取码连接失败: {exc}")
                raise
        started = time.time()
        last_notice = 0.0
        while time.time() - started < timeout:
            self._raise_if_stopped()
            if self.mode == "graph":
                try:
                    for folder in GRAPH_MAIL_FOLDERS:
                        self._raise_if_stopped()
                        code = self._scan_graph_folder(folder, min_timestamp, GRAPH_OTP_SCAN_LIMIT)
                        if code:
                            return code
                except Exception as exc:
                    self.log(f"邮箱 Graph 扫描失败，切换 IMAP: {exc}")
                    self.graph_token = ""
                    self.mode = ""
                    self._connect_imap()
            if self.mode == "imap":
                assert self.imap is not None
                for folder in IMAP_MAIL_FOLDERS:
                    self._raise_if_stopped()
                    code = self._scan_folder(folder, min_timestamp, IMAP_OTP_SCAN_LIMIT)
                    if code:
                        return code
            if time.time() - last_notice >= 20:
                remain = max(0, int(timeout - (time.time() - started)))
                self.log(f"仍在等待 OpenAI 新验证码邮件，剩余约 {remain}s")
                last_notice = time.time()
            self._wait_or_stop(MAIL_POLL_INTERVAL_SECONDS)
        self._raise_if_stopped()
        raise TimeoutError(f"等待 OpenAI 邮箱验证码超时: {self.target_email()}")

    def _scan_graph_folder(self, folder: str, min_timestamp: float, limit: int = GRAPH_OTP_SCAN_LIMIT) -> str:
        since = datetime.fromtimestamp(
            max(0.0, float(min_timestamp or 0.0) - MAIL_TIMESTAMP_SKEW_SECONDS),
            timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = self._graph_get(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages",
            {
                "$top": str(limit),
                "$orderby": "receivedDateTime desc",
                "$filter": f"receivedDateTime ge {since}",
                "$select": "id,subject,from,receivedDateTime,bodyPreview,toRecipients,ccRecipients,bccRecipients",
            },
            timeout=5,
        )
        items = payload.get("value") if isinstance(payload, dict) else []
        if not isinstance(items, list):
            return ""
        for item in items:
            if not isinstance(item, dict):
                continue
            msg_id = str(item.get("id") or "")
            key = f"graph:{folder}:{msg_id}"
            if key in self.seen:
                continue
            self.seen.add(key)
            subject, from_addr, body, mail_time = self._graph_message_text(item)
            if mail_time + MAIL_TIMESTAMP_SKEW_SECONDS < min_timestamp:
                continue
            if not self._recipient_matches_target(self._graph_recipient_addresses(item)):
                continue
            haystack = f"{subject}\n{from_addr}\n{body}"
            if not re.search(r"openai|chatgpt", haystack, flags=re.I):
                continue
            code = extract_openai_code(haystack)
            if not code and msg_id:
                detail = self._graph_get(
                    f"https://graph.microsoft.com/v1.0/me/messages/{quote(msg_id, safe='')}",
                    {"$select": "body"},
                    timeout=5,
                )
                _subject, _from_addr, detail_body, _mail_time = self._graph_message_text(detail)
                code = extract_openai_code(f"{haystack}\n{detail_body}")
            if code:
                self.log(f"收到 OpenAI 验证码(Graph): {code}")
                return code
        return ""

    def _select_folder(self, folder: str) -> bool:
        assert self.imap is not None
        for name in (folder, f'"{folder}"'):
            try:
                status, _ = self.imap.select(name, readonly=True)
                if status == "OK":
                    return True
            except Exception:
                continue
        return False

    def _select_folder_count(self, folder: str) -> int:
        assert self.imap is not None
        for name in (folder, f'"{folder}"'):
            try:
                status, data = self.imap.select(name, readonly=True)
                if status != "OK":
                    continue
                if data and data[0]:
                    return int(data[0])
                return 0
            except Exception:
                continue
        return -1

    def _imap_raw_from_fetch(self, msg_data) -> bytes:
        chunks = [item[1] for item in (msg_data or []) if isinstance(item, tuple) and isinstance(item[1], bytes)]
        return b"\r\n".join(chunks)

    def _imap_fetch_partial(self, msg_id) -> bytes:
        assert self.imap is not None
        query = (
            "(BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC DELIVERED-TO X-ORIGINAL-TO ENVELOPE-TO SUBJECT)] "
            f"BODY.PEEK[TEXT]<0.{IMAP_OTP_PARTIAL_BYTES}>)"
        )
        status, msg_data = self.imap.fetch(msg_id, query)
        return self._imap_raw_from_fetch(msg_data) if status == "OK" else b""

    def _imap_fetch_full(self, msg_id) -> bytes:
        assert self.imap is not None
        status, msg_data = self.imap.fetch(msg_id, "(RFC822)")
        return self._imap_raw_from_fetch(msg_data) if status == "OK" else b""

    def _scan_folder(self, folder: str, min_timestamp: float, limit: int = IMAP_OTP_SCAN_LIMIT) -> str:
        assert self.imap is not None
        if not self._select_folder(folder):
            return ""
        since = datetime.fromtimestamp(
            max(0.0, float(min_timestamp or 0.0) - MAIL_TIMESTAMP_SKEW_SECONDS),
            timezone.utc,
        ).strftime("%d-%b-%Y")
        status, data = self.imap.search(None, "SINCE", since)
        if status != "OK":
            status, data = self.imap.search(None, "ALL")
        if status != "OK" or not data or not data[0]:
            return ""
        ids = data[0].split()[-limit:]
        for msg_id in reversed(ids):
            key = f"{folder}:{msg_id.decode(errors='ignore')}"
            if key in self.seen:
                continue
            raw = self._imap_fetch_partial(msg_id)
            if not raw:
                continue
            self.seen.add(key)
            msg = email_pkg.message_from_bytes(raw)
            date_header = msg.get("Date")
            try:
                mail_time = parsedate_to_datetime(date_header).timestamp() if date_header else time.time()
            except Exception:
                mail_time = time.time()
            if mail_time + MAIL_TIMESTAMP_SKEW_SECONDS < min_timestamp:
                continue
            if not self._recipient_matches_target(self._imap_recipient_addresses(msg)):
                continue
            subject = decode_header_text(msg.get("Subject"))
            from_addr = decode_header_text(msg.get("From"))
            body = extract_message_text(msg)
            haystack = f"{subject}\n{from_addr}\n{body}"
            if not re.search(r"openai|chatgpt", haystack, flags=re.I):
                continue
            code = extract_openai_code(haystack)
            if not code:
                full_raw = self._imap_fetch_full(msg_id)
                if full_raw:
                    full_msg = email_pkg.message_from_bytes(full_raw)
                    full_body = extract_message_text(full_msg)
                    code = extract_openai_code(f"{haystack}\n{full_body}")
            if code:
                self.log(f"收到 OpenAI 验证码(IMAP): {code}")
                return code
        return ""


def random_profile() -> tuple[str, str]:
    age = random.randint(25, 34)
    today = datetime.now(timezone.utc)
    year = today.year - age
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}", f"{year:04d}-{month:02d}-{day:02d}"



class OpenAIRegistrationWorker:
    def __init__(
        self,
        account: MailAccount,
        headless: bool,
        register_proxy: ProxyConfig,
        log,
        otp_reader_factory=None,
        mfa_totp_secret: str = "",
        mfa_recovery_code: str = "",
        mfa_persist_callback=None,
        enable_mfa_enrollment: bool = False,
        stop_event: threading.Event | None = None,
    ):
        self.account = account
        self.headless = headless
        self.register_proxy = register_proxy
        self.log = log
        self.otp_reader = None
        self._otp_browser = None
        self._otp_context = None
        self._playwright_runtime = None
        self._otp_proxy_chain: ProxyChainServer | None = None
        self.otp_reader_factory = otp_reader_factory or HotmailOtpReader
        self.fingerprint = generate_register_fingerprint()
        self.current_proxy_health: ProxyHealthResult | None = None
        self._password_step_log_emitted = False
        self._email_stall_started = 0.0
        self._email_recovery_count = 0
        self._email_submission_page_key: str | None = None
        self._email_submit_started_at = 0.0
        self._email_submit_retry_count = 0
        self._oauth_callback_recovery_count = 0
        self._existing_user_recovery_count = 0
        self._auth_screen_hint = "login_or_signup"
        self.hybrid_protocol_after_otp = False
        self.protocol_prefix_before_otp = False
        self._force_headed_auth = False
        self._protocol_otp_bootstrap: dict | None = None
        self._protocol_registration_result: dict | None = None
        self.browser_traffic_callback = None
        self.browser_traffic_forward_to_account = True
        self._browser_traffic_cdp_sessions = []
        self._auth_static_local_session = None
        self._auth_traffic_stage = "初始化"
        self._auth_traffic_stage_bytes: dict[str, int] = {}
        self._auth_traffic_request_meta: dict[str, tuple[str, str, str, str, int]] = {}
        self._auth_traffic_reported = False
        self._post_auth_navigation_rewritten = False
        self._confirmed_session_payload: dict | None = None
        self.mfa_totp_secret = str(mfa_totp_secret or "").strip()
        self.mfa_recovery_code = str(mfa_recovery_code or "").strip()
        self.mfa_persist_callback = mfa_persist_callback
        self.enable_mfa_enrollment = bool(enable_mfa_enrollment)
        self.stop_event = stop_event
        self._mfa_result: dict[str, str] = {}
        self.openai_password = ""
        self.openai_password_state = ""
        self.auth_route = ""
        self.is_new_account = False
        self.auth_persist_callback = None
        self._auth_result: dict[str, str] = {}
        self._auth_flow_observer_installed = False
        self._auth_flow_active = False
        self._user_register_seen = False
        self._user_register_confirmed = False
        self._account_create_confirmed = False
        self._last_authorize_page_type = ""
        self._password_mode_selection_page_key = ""
        self._fatal_auth_error = ""
        self._security_verification_active = False

    def _raise_if_stopped(self) -> None:
        stop_event = getattr(self, "stop_event", None)
        if stop_event is not None and stop_event.is_set():
            raise TaskStoppedError("注册任务已停止")

    def _wait_or_stop(self, seconds: float) -> None:
        stop_event = getattr(self, "stop_event", None)
        if stop_event is None:
            time.sleep(seconds)
            return
        if stop_event.wait(max(0.0, float(seconds))):
            raise TaskStoppedError("注册任务已停止")

    def request_stop(self) -> None:
        if self.stop_event is not None:
            self.stop_event.set()
        if self.otp_reader:
            try:
                self.otp_reader.close()
            except Exception:
                pass
        self._close_auth_static_local_session()
        self._close_otp_proxy_chain()
    def run(self) -> dict:
        self._raise_if_stopped()
        with sync_playwright() as p:
            self._playwright_runtime = p
            register_browser = None
            register_context = None
            register_page = None
            try:
                self._raise_if_stopped()
                self._set_auth_traffic_stage("出口定位预检")
                self._prepare_fingerprint_for_proxy(self.register_proxy, "认证")
                self._use_compact_auth_window()
                if getattr(self, "otp_reader_factory", None) is not UrlOtpReader:
                    self._preconnect_otp_reader()
                self._prepare_protocol_otp_bootstrap()
                self._set_auth_traffic_stage("Chromium 启动")
                register_browser, register_context = self._new_isolated_registration_browser_context(
                    p,
                    self.register_proxy,
                )
                register_context.clear_cookies()
                self._apply_protocol_otp_cookies(register_context)
                register_page = register_context.new_page()
                if getattr(self, "otp_reader_factory", None) is UrlOtpReader:
                    if self._should_preconnect_otp_reader():
                        self._ensure_otp_reader_for_email_challenge(preconnect=True)
                    else:
                        self.log("[iCloud] 已保存 OpenAI 密码与 TOTP 密钥，本次密码+2FA 登录跳过邮箱取码通道")
                self._log_browser_proxy_status(register_page, self.register_proxy, "认证浏览器代理")
                self._register(register_page, register_context)
                self._raise_if_stopped()
                if self._protocol_registration_result:
                    self.log("[认证] 浏览器 OTP + 协议注册尾链完成，使用协议 Session 结果")
                    result = self._protocol_registration_result
                else:
                    if self.enable_mfa_enrollment and self.is_new_account:
                        self._ensure_totp_mfa(register_context)
                    elif self.enable_mfa_enrollment:
                        self.log("[MFA] 已有账号登录不执行自动 enrollment")
                    self.log("[认证] 认证完成；读取 Session 后立即关闭轻量浏览器")
                    self._set_auth_traffic_stage("Session 读取")
                    result = self._extract_session_info(register_context)
                return result
            except TaskStoppedError:
                raise
            except Exception:
                if register_context and register_browser and register_page and self._has_chatgpt_session(register_page):
                    self.log("[认证] 检测到浏览器已登录成功，读取 Session 后立即关闭轻量浏览器")
                    result = self._extract_session_info(register_context)
                    return result
                raise
            finally:
                if self.otp_reader:
                    self.otp_reader.close()
                otp_context = getattr(self, "_otp_context", None)
                otp_browser = getattr(self, "_otp_browser", None)
                if otp_context or otp_browser:
                    self._close_browser(otp_context, otp_browser)
                self._otp_context = None
                self._otp_browser = None
                self._playwright_runtime = None
                self._close_otp_proxy_chain()
                self._log_auth_traffic_report()
                self._close_auth_static_local_session()
                self._close_browser(register_context, register_browser)

    def run_auth_only(self) -> None:
        self._raise_if_stopped()
        with sync_playwright() as p:
            self._playwright_runtime = p
            browser = None
            context = None
            page = None
            try:
                self._raise_if_stopped()
                self._set_auth_traffic_stage("出口定位预检")
                self._prepare_fingerprint_for_proxy(self.register_proxy, "认证")
                self._use_compact_auth_window()
                if getattr(self, "otp_reader_factory", None) is not UrlOtpReader:
                    self._preconnect_otp_reader()
                self._prepare_protocol_otp_bootstrap()
                self._set_auth_traffic_stage("Chromium 启动")
                browser, context = self._new_isolated_registration_browser_context(
                    p,
                    self.register_proxy,
                )
                context.clear_cookies()
                self._apply_protocol_otp_cookies(context)
                page = context.new_page()
                if getattr(self, "otp_reader_factory", None) is UrlOtpReader:
                    if self._should_preconnect_otp_reader():
                        self._ensure_otp_reader_for_email_challenge(preconnect=True)
                    else:
                        self.log("[iCloud] 已保存 OpenAI 密码与 TOTP 密钥，本次密码+2FA 登录跳过邮箱取码通道")
                self._log_browser_proxy_status(page, self.register_proxy, "认证浏览器代理")
                self._register(page, context)
                self._raise_if_stopped()
                if (
                    getattr(self, "enable_mfa_enrollment", False)
                    and getattr(self, "is_new_account", False)
                    and not getattr(self, "_protocol_registration_result", None)
                ):
                    self._ensure_totp_mfa(context)
                self.log("[认证] 注册或登录完成，立即关闭轻量浏览器")
            except TaskStoppedError:
                raise
            except Exception:
                if context and browser and page and self._has_chatgpt_session(page):
                    self.log("[认证] 检测到浏览器已登录成功，忽略前序页面异常并关闭轻量浏览器")
                    return
                raise
            finally:
                if self.otp_reader:
                    self.otp_reader.close()
                otp_context = getattr(self, "_otp_context", None)
                otp_browser = getattr(self, "_otp_browser", None)
                if otp_context or otp_browser:
                    self._close_browser(otp_context, otp_browser)
                self._otp_context = None
                self._otp_browser = None
                self._playwright_runtime = None
                self._close_otp_proxy_chain()
                self._log_auth_traffic_report()
                self._close_auth_static_local_session()
                self._close_browser(context, browser)

    def refresh_session_from_storage_state(self, storage_state: dict) -> dict:
        self._raise_if_stopped()
        cookies = list((storage_state or {}).get("cookies") or []) if isinstance(storage_state, dict) else []
        if not cookies:
            raise RuntimeError("当前账户没有可复用的 Cookie 登录态")
        with sync_playwright() as p:
            browser = None
            context = None
            try:
                self._use_compact_auth_window()
                self._set_auth_traffic_stage("Cookie 快速登录")
                browser, context = self._new_browser_context(p, self.register_proxy, storage_state)
                self._raise_if_stopped()
                self.log(f"[Session] 已导入保存的 Cookie 登录态: {len(cookies)} 个")
                result = self._extract_session_info(context)
                self._raise_if_stopped()
                if not str(result.get("access_token") or "").strip():
                    raise RuntimeError("保存的 Cookie 登录态已过期，需要重新执行完整登录")
                self.log("[Session] Cookie 快速登录成功，已获取新 Access Token 并更新 Cookie")
                return result
            finally:
                self._log_auth_traffic_report()
                self._close_auth_static_local_session()
                self._close_browser(context, browser)

    def _preconnect_otp_reader(self, browser_context=None) -> None:
        if self.otp_reader:
            return
        self._raise_if_stopped()
        self.log("提前连接邮箱取件通道，准备接收 OpenAI 验证码")
        reader_proxy = ""
        if self.otp_reader_factory is UrlOtpReader:
            reader_proxy = self.register_proxy.chain_url or self.register_proxy.local_proxy
        if self.otp_reader_factory is UrlOtpReader:
            self.otp_reader = self.otp_reader_factory(
                self.account,
                self.log,
                reader_proxy,
                stop_event=self.stop_event,
                browser_context=browser_context,
            )
            self.otp_reader.connect()
            return
        try:
            self.otp_reader = self.otp_reader_factory(
                self.account,
                self.log,
                reader_proxy,
                stop_event=self.stop_event,
            )
        except TypeError as exc:
            if "stop_event" not in str(exc):
                raise
            self.otp_reader = self.otp_reader_factory(self.account, self.log, reader_proxy)
        self.otp_reader.connect()

    def _has_complete_password_totp_login_credentials(self) -> bool:
        return bool(
            str(getattr(self, "openai_password", "") or "").strip()
            and str(getattr(self, "mfa_totp_secret", "") or "").strip()
        )

    def _should_preconnect_otp_reader(self) -> bool:
        if getattr(self, "otp_reader_factory", None) is not UrlOtpReader:
            return True
        if getattr(self, "_protocol_otp_bootstrap", None):
            return True
        return not self._has_complete_password_totp_login_credentials()

    def _ensure_otp_reader_for_email_challenge(self, preconnect: bool = False) -> None:
        if self.otp_reader:
            return
        if getattr(self, "otp_reader_factory", None) is not UrlOtpReader:
            self._preconnect_otp_reader()
            return
        playwright_runtime = getattr(self, "_playwright_runtime", None)
        if playwright_runtime is None:
            raise RuntimeError("服务端要求邮箱验证码，但当前认证浏览器运行时不可用")
        if not preconnect:
            self.log("[iCloud] 服务端要求邮箱验证码，正在按需启动本地代理无头取码通道")
        otp_browser, otp_context = self._new_otp_browser_context(playwright_runtime)
        self._otp_browser = otp_browser
        self._otp_context = otp_context
        try:
            self._preconnect_otp_reader(otp_context)
        except Exception:
            self._close_browser(otp_context, otp_browser)
            self._otp_context = None
            self._otp_browser = None
            raise

    def _should_rewrite_post_auth_navigation(self, request) -> bool:
        return self._should_rewrite_post_auth_url(
            str(getattr(request, "url", "") or ""),
            str(getattr(request, "resource_type", "") or ""),
            str(getattr(request, "method", "GET") or "GET"),
        )

    def _should_rewrite_post_auth_url(self, url: str, resource_type: str, method: str) -> bool:
        if bool(getattr(self, "_post_auth_navigation_rewritten", False)):
            return False
        if str(resource_type or "").lower() != "document":
            return False
        if str(method or "GET").upper() != "GET":
            return False
        try:
            parsed = urlsplit(str(url or ""))
        except Exception:
            return False
        if str(parsed.hostname or "").lower() != "chatgpt.com" or (parsed.path or "/") != "/":
            return False
        return bool(getattr(self, "_auth_flow_active", False)) or str(
            getattr(self, "_auth_traffic_stage", "") or ""
        ) in {
            "密码提交",
            "邮箱验证码提交",
            "基础资料提交",
            "Session 确认",
        }

    def _close_auth_static_local_session(self) -> None:
        session = getattr(self, "_auth_static_local_session", None)
        self._auth_static_local_session = None
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

    def _fetch_auth_static_via_local_proxy(self, url: str, request_headers: dict | None = None):
        if bool(getattr(self, "_auth_static_local_prefetch_disabled", False)):
            return None
        register_proxy = getattr(self, "register_proxy", None)
        local_proxy = normalize_proxy_url(getattr(register_proxy, "local_proxy", ""))
        dynamic_proxy = str(getattr(register_proxy, "dynamic_proxy", "") or "").strip()
        if not local_proxy or not dynamic_proxy or not is_auth_static_memory_cache_url(url):
            return None

        session = getattr(self, "_auth_static_local_session", None)
        if session is None:
            session = requests.Session()
            session.trust_env = False
            session.proxies.update({"http": local_proxy, "https": local_proxy})
            self._auth_static_local_session = session

        source_headers = {
            str(name).lower(): str(value)
            for name, value in dict(request_headers or {}).items()
        }
        headers = {
            "Accept": source_headers.get("accept", "*/*"),
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": source_headers.get("accept-language", self.fingerprint.accept_language),
            "Referer": source_headers.get("referer", f"{AUTH_BASE_URL}/"),
        }
        if source_headers.get("user-agent"):
            headers["User-Agent"] = source_headers["user-agent"]

        try:
            response = session.get(url, headers=headers, timeout=(5, 15), allow_redirects=True)
            final_url = str(getattr(response, "url", "") or url)
            content_encoding = str(response.headers.get("content-encoding") or "").strip().lower()
            body = bytes(response.content or b"")
            if (
                int(getattr(response, "status_code", 0) or 0) != 200
                or not body
                or not is_auth_static_memory_cache_url(final_url)
                or content_encoding not in {"", "gzip", "deflate"}
            ):
                raise RuntimeError(
                    f"HTTP {getattr(response, 'status_code', 0)} encoding={content_encoding or 'identity'}"
                )
            response_headers = [
                {"name": str(name), "value": str(value)}
                for name, value in response.headers.items()
                if str(name).lower() not in {
                    "connection", "content-length", "content-encoding", "transfer-encoding", "set-cookie"
                }
            ]
            body_b64 = base64.b64encode(body).decode("ascii")
            memory_size = len(body_b64.encode("ascii")) + sum(
                len(item["name"].encode("utf-8")) + len(item["value"].encode("utf-8"))
                for item in response_headers
            )
            try:
                wire_size = max(0, int(response.headers.get("content-length") or 0))
            except Exception:
                wire_size = 0
            self._auth_static_local_prefetch_consecutive_failures = 0
            return 200, body_b64, response_headers, memory_size, wire_size or len(body)
        except Exception as exc:
            self._auth_static_local_prefetch_errors = max(
                0, int(getattr(self, "_auth_static_local_prefetch_errors", 0) or 0)
            ) + 1
            consecutive = max(
                0, int(getattr(self, "_auth_static_local_prefetch_consecutive_failures", 0) or 0)
            ) + 1
            self._auth_static_local_prefetch_consecutive_failures = consecutive
            if consecutive == 1:
                self.log(f"[traffic] auth-cdn 本地预取失败，当前资源回退注册代理: {str(exc)[:120]}")
            if consecutive >= 2:
                self._auth_static_local_prefetch_disabled = True
                self.log("[traffic] auth-cdn 本地预取连续失败，当前认证剩余静态资源使用原注册代理")
            return None

    def _install_low_traffic_cdp(self, context) -> None:
        blocked_urls = sorted({
            *(f"*://{host}/*" for host in LOW_TRAFFIC_BLOCK_HOSTS),
            *(f"*://*{suffix}/*" for suffix in LOW_TRAFFIC_BLOCK_HOST_SUFFIXES),
            *(f"*://*{path}*" for path in LOW_TRAFFIC_BLOCK_EXACT_PATHS),
            "*://chatgpt.com/cdn/assets*/*.js*",
            "*://*/*.vtt*",
            "*://*/*.webmanifest*",
        })
        fetch_patterns = [
            {"urlPattern": "*", "resourceType": resource_type, "requestStage": "Request"}
            for resource_type in LOW_TRAFFIC_CDP_RESOURCE_TYPES
        ]
        fetch_patterns.append({
            "urlPattern": f"{CHATGPT_BASE_URL}/*",
            "resourceType": "Document",
            "requestStage": "Request",
        })
        fetch_patterns.extend([
            {
                "urlPattern": AUTH_STATIC_MEMORY_CACHE_URL_PATTERN,
                "resourceType": "Script",
                "requestStage": "Request",
            },
        ])
        fetch_patterns.extend({
            "urlPattern": f"{CHATGPT_BASE_URL}{path}*",
            "requestStage": "Request",
        } for path in POST_ACCOUNT_TELEMETRY_RESPONSES)
        self._low_traffic_cdp_sessions = []
        self._low_traffic_cdp_logged = False
        self._auth_static_cache_hits = 0
        self._auth_static_disk_cache_hits = 0
        self._auth_static_cache_waited_hits = 0
        self._auth_static_cache_cold_loads = 0
        self._auth_static_cache_stores = 0
        self._auth_static_cache_errors = 0
        self._auth_static_cache_saved_wire_bytes = 0
        self._auth_static_local_prefetches = 0
        self._auth_static_local_prefetch_bytes = 0
        self._auth_static_local_prefetch_errors = 0
        self._auth_static_local_prefetch_consecutive_failures = 0
        self._auth_static_local_prefetch_disabled = False
        self._post_account_telemetry_local_responses = 0
        self._post_account_telemetry_saved_request_bytes = 0
        self._auth_static_cache_network_ids: set[str] = set()
        attached_page_ids: set[int] = set()

        def attach(page) -> None:
            page_id = id(page)
            if page_id in attached_page_ids:
                return
            try:
                session = context.new_cdp_session(page)
                session.send("Network.enable")
                session.send("Network.setBlockedURLs", {"urls": blocked_urls})
                compatible_patterns = list(fetch_patterns)
                removed_resource_types = []
                while True:
                    try:
                        session.send("Fetch.enable", {"patterns": compatible_patterns})
                        break
                    except Exception as exc:
                        match = re.search(
                            r"Unknown resource type in fetch filter:\s*['\"]([^'\"]+)['\"]",
                            str(exc),
                            flags=re.I,
                        )
                        unsupported = str(match.group(1) if match else "").strip()
                        filtered = [
                            pattern for pattern in compatible_patterns
                            if str(pattern.get("resourceType") or "").lower() != unsupported.lower()
                        ] if unsupported else compatible_patterns
                        if not unsupported or len(filtered) == len(compatible_patterns):
                            raise
                        removed_resource_types.append(unsupported)
                        compatible_patterns = filtered
                if removed_resource_types:
                    self.log(
                        "[traffic] Chromium 不支持部分 CDP 过滤类型，已移除后继续启用低流量模式: "
                        + ", ".join(removed_resource_types)
                    )
                capture_tokens: dict[str, tuple[str, str]] = {}
                capture_responses: dict[str, tuple[int, list[dict[str, str]]]] = {}

                def on_paused(params) -> None:
                    payload = dict(params or {})
                    request_id = str(payload.get("requestId") or "")
                    request = dict(payload.get("request") or {})
                    resource_type = str(payload.get("resourceType") or "").lower()
                    request_url = str(request.get("url") or "")
                    network_id = str(payload.get("networkId") or "")
                    if not request_id:
                        return
                    telemetry_response = None
                    if (
                        bool(getattr(self, "_account_create_confirmed", False))
                        and str(request.get("method") or "GET").upper() == "POST"
                    ):
                        try:
                            parsed_telemetry_url = urlsplit(request_url)
                            if str(parsed_telemetry_url.hostname or "").lower() == "chatgpt.com":
                                telemetry_response = POST_ACCOUNT_TELEMETRY_RESPONSES.get(
                                    str(parsed_telemetry_url.path or "")
                                )
                        except Exception:
                            telemetry_response = None
                    if telemetry_response is not None:
                        response_code, response_body = telemetry_response
                        request_size = len(str(request.get("method") or "POST").encode("utf-8"))
                        request_size += len(request_url.encode("utf-8"))
                        request_size += len(str(request.get("postData") or "").encode("utf-8"))
                        request_size += sum(
                            len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
                            for name, value in dict(request.get("headers") or {}).items()
                        )
                        self._post_account_telemetry_local_responses += 1
                        self._post_account_telemetry_saved_request_bytes += request_size
                        if network_id:
                            self._auth_static_cache_network_ids.add(network_id)
                        session.send("Fetch.fulfillRequest", {
                            "requestId": request_id,
                            "responseCode": int(response_code),
                            "responseHeaders": [
                                {"name": "content-type", "value": "application/json"},
                                {"name": "cache-control", "value": "no-store"},
                            ],
                            "body": base64.b64encode(bytes(response_body)).decode("ascii"),
                        })
                        return
                    if is_security_challenge_url(request_url):
                        session.send("Fetch.continueRequest", {"requestId": request_id})
                        return
                    if (
                        resource_type == "script"
                        and str(request.get("method") or "GET").upper() == "GET"
                        and is_auth_static_memory_cache_url(request_url)
                    ):
                        state, cached, owner_token, waited = auth_static_memory_cache_claim(request_url)
                        if state in {"hit", "disk_hit"} and cached is not None:
                            status, body_b64, headers, _memory_size, wire_size = cached
                            self._auth_static_cache_hits += 1
                            if state == "disk_hit":
                                self._auth_static_disk_cache_hits += 1
                            if waited:
                                self._auth_static_cache_waited_hits += 1
                            self._auth_static_cache_saved_wire_bytes += max(0, int(wire_size or 0))
                            if network_id:
                                self._auth_static_cache_network_ids.add(network_id)
                            session.send("Fetch.fulfillRequest", {
                                "requestId": request_id,
                                "responseCode": status,
                                "responseHeaders": headers,
                                "body": body_b64,
                            })
                            return
                        local_asset = self._fetch_auth_static_via_local_proxy(
                            request_url,
                            dict(request.get("headers") or {}),
                        )
                        if local_asset is not None:
                            status, body_b64, headers, memory_size, wire_size = local_asset
                            stored = auth_static_memory_cache_put(
                                request_url,
                                status,
                                body_b64,
                                headers,
                                memory_size,
                                wire_size,
                                owner_token,
                            )
                            if stored:
                                self._auth_static_cache_stores += 1
                            self._auth_static_local_prefetches += 1
                            self._auth_static_local_prefetch_bytes += max(0, int(wire_size or 0))
                            if network_id:
                                self._auth_static_cache_network_ids.add(network_id)
                            session.send("Fetch.fulfillRequest", {
                                "requestId": request_id,
                                "responseCode": status,
                                "responseHeaders": headers,
                                "body": body_b64,
                            })
                            return
                        self._auth_static_cache_cold_loads += 1
                        if network_id:
                            capture_tokens[network_id] = (request_url, owner_token)
                        else:
                            auth_static_memory_cache_release(request_url, owner_token)
                    if resource_type in LOW_TRAFFIC_EMPTY_RESOURCE_TYPES:
                        css = "*{animation:none!important;transition:none!important}"
                        session.send("Fetch.fulfillRequest", {
                            "requestId": request_id,
                            "responseCode": 200,
                            "responseHeaders": [{"name": "content-type", "value": "text/css; charset=utf-8"}],
                            "body": base64.b64encode(css.encode("utf-8")).decode("ascii"),
                        })
                        return
                    if resource_type in LOW_TRAFFIC_BLOCK_RESOURCE_TYPES:
                        session.send("Fetch.failRequest", {
                            "requestId": request_id,
                            "errorReason": "BlockedByClient",
                        })
                        return
                    if self._should_rewrite_post_auth_url(
                        str(request.get("url") or ""),
                        resource_type,
                        str(request.get("method") or "GET"),
                    ):
                        self._post_auth_navigation_rewritten = True
                        session.send("Fetch.continueRequest", {
                            "requestId": request_id,
                            "url": f"{CHATGPT_BASE_URL}/api/auth/session",
                        })
                        return
                    session.send("Fetch.continueRequest", {"requestId": request_id})

                def on_cache_response(params) -> None:
                    payload = dict(params or {})
                    network_id = str(payload.get("requestId") or "")
                    if network_id not in capture_tokens:
                        return
                    response = dict(payload.get("response") or {})
                    headers = [
                        {"name": str(name), "value": str(value)}
                        for name, value in dict(response.get("headers") or {}).items()
                    ]
                    capture_responses[network_id] = (int(response.get("status") or 0), headers)

                def on_cache_finished(params) -> None:
                    payload = dict(params or {})
                    network_id = str(payload.get("requestId") or "")
                    capture = capture_tokens.pop(network_id, None)
                    if capture is None:
                        return
                    capture_url, owner_token = capture
                    status, response_headers = capture_responses.pop(network_id, (0, []))
                    if status != 200:
                        auth_static_memory_cache_release(capture_url, owner_token)
                        return
                    try:
                        result = session.send("Network.getResponseBody", {"requestId": network_id}) or {}
                        body_text = str(result.get("body") or "")
                        if bool(result.get("base64Encoded")):
                            body_b64 = body_text
                            raw_size = len(base64.b64decode(body_text))
                        else:
                            raw = body_text.encode("utf-8")
                            body_b64 = base64.b64encode(raw).decode("ascii")
                            raw_size = len(raw)
                        headers = [
                            item for item in response_headers
                            if str(item.get("name") or "").lower() not in {
                                "content-length", "content-encoding", "transfer-encoding", "set-cookie"
                            }
                        ]
                        memory_size = len(body_b64.encode("ascii")) + sum(
                            len(str(item.get("name") or "").encode("utf-8"))
                            + len(str(item.get("value") or "").encode("utf-8"))
                            for item in headers
                        )
                        stored = auth_static_memory_cache_put(
                            capture_url,
                            status,
                            body_b64,
                            headers,
                            memory_size,
                            max(0, int(payload.get("encodedDataLength") or 0)) or raw_size,
                            owner_token,
                        )
                        if stored:
                            self._auth_static_cache_stores += 1
                    except Exception:
                        self._auth_static_cache_errors += 1
                        auth_static_memory_cache_release(capture_url, owner_token)

                def on_cache_failed(params) -> None:
                    network_id = str(dict(params or {}).get("requestId") or "")
                    capture = capture_tokens.pop(network_id, None)
                    capture_responses.pop(network_id, None)
                    if capture is not None:
                        auth_static_memory_cache_release(capture[0], capture[1])

                session.on("Fetch.requestPaused", on_paused)
                session.on("Network.responseReceived", on_cache_response)
                session.on("Network.loadingFinished", on_cache_finished)
                session.on("Network.loadingFailed", on_cache_failed)
                attached_page_ids.add(page_id)
                self._low_traffic_cdp_sessions.append(session)
                if not self._low_traffic_cdp_logged:
                    self._low_traffic_cdp_logged = True
            except Exception as exc:
                self.log(f"[traffic] CDP 低流量过滤挂载失败: {str(exc)[:120]}")

        self._attach_low_traffic_cdp_page = attach
        context.on("page", attach)
        try:
            for page in context.pages:
                attach(page)
        except Exception:
            pass

    def _ensure_low_traffic_cdp_page(self, page) -> None:
        attach = getattr(self, "_attach_low_traffic_cdp_page", None)
        if callable(attach):
            attach(page)

    def _install_network_capture(self, context, stage: str = "auth") -> None:
        # 认证阶段不抓包，避免登录/Session 流量写入本地文件，也避免额外监听影响低流量模式。
        if str(stage or "").lower() == "auth":
            return
        if not str(os.environ.get("OPENAI_REGISTER_NET_CAPTURE") or "").strip():
            return
        try:
            NETWORK_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            safe_email = re.sub(r"[^a-zA-Z0-9_.@-]+", "_", self.account.email)
            capture_path = NETWORK_CAPTURE_DIR / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_email}_{stage}.jsonl"

            def on_request(request) -> None:
                try:
                    payload = {
                        "event": "request",
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    }
                    with capture_path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
                except Exception:
                    pass

            context.on("request", on_request)
            self.log(f"[capture] browser network capture enabled: {capture_path}")
        except Exception as exc:
            self.log(f"[capture] network capture setup skipped: {exc}")

    def _goto_tolerant(self, page, url: str, label: str, timeout: int = 60000, accepted_urls: tuple[str, ...] = ()) -> bool:
        accepted = tuple(str(item or "").rstrip("/") for item in (accepted_urls or ())) + (str(url or "").rstrip("/"),)

        def reached() -> bool:
            current = str(getattr(page, "url", "") or "").rstrip("/")
            return bool(current and any(current.startswith(prefix) for prefix in accepted if prefix))

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            return True
        except PlaywrightTimeoutError as exc:
            if reached():
                self.log(f"{label}: DOM timeout，页面已到达目标地址，继续执行: {str(exc)[:120]}")
                return False
            try:
                page.goto(url, wait_until="commit", timeout=timeout)
                self.log(f"{label}: DOM timeout，已使用 commit fallback committed")
                return False
            except PlaywrightTimeoutError as commit_exc:
                if reached():
                    self.log(f"{label}: commit timeout，但页面已到达目标地址，继续执行: {str(commit_exc)[:120]}")
                    return False
                raise
        except Exception as exc:
            if reached():
                self.log(f"{label}: 导航连接中断但页面已到达目标地址，继续执行: {str(exc)[:120]}")
                return False
            try:
                page.goto(url, wait_until="commit", timeout=timeout)
                self.log(f"{label}: 导航连接中断，已使用 commit fallback committed")
                return False
            except Exception as commit_exc:
                if reached():
                    self.log(f"{label}: commit 导航中断但页面已到达目标地址，继续执行: {str(commit_exc)[:120]}")
                    return False
                raise



    def _use_compact_auth_window(self) -> None:
        fp = getattr(self, "fingerprint", None)
        if fp is None:
            return
        fp.viewport_width = min(fp.viewport_width, 720)
        fp.viewport_height = min(fp.viewport_height, 520)
        fp.outer_width = min(fp.outer_width, fp.viewport_width + 16)
        fp.outer_height = min(fp.outer_height, fp.viewport_height + 80)

    def _new_isolated_registration_browser_context(self, p, proxy: ProxyConfig):
        """Create one non-persistent Chrome environment for exactly one account run."""
        return self._new_browser_context(p, proxy)

    def _new_browser_context(self, p, proxy: ProxyConfig, storage_state: dict | None = None):
        launch_headless = self.headless
        protocol_handoff = bool(getattr(self, "_protocol_otp_bootstrap", None))
        force_headed_auth = bool(getattr(self, "_force_headed_auth", False))
        if protocol_handoff or force_headed_auth:
            launch_headless = False
            if self.headless:
                reason = "OTP 接管" if protocol_handoff else "协议状态失效后的认证接管"
                self.log(f"[hybrid] {reason}强制使用有头浏览器，已忽略无头选项")
        browser = None
        context = None
        try:
            browser = p.chromium.launch(
                channel="chrome",
                headless=launch_headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    f"--lang={self.fingerprint.locale}",
                    f"--window-size={self.fingerprint.outer_width},{self.fingerprint.outer_height}",
                    "--disable-background-networking",
                    "--disable-breakpad",
                    "--disable-client-side-phishing-detection",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--disable-domain-reliability",
                    "--disable-extensions",
                    "--disable-notifications",
                    "--disable-pings",
                    "--disable-sync",
                    "--dns-prefetch-disable",
                    "--metrics-recording-only",
                    "--no-first-run",
                    "--start-minimized",
                    "--disable-features=IsolateOrigins,site-per-process,MediaRouter,OptimizationHints,OptimizationGuideModelDownloading,Translate,AutofillServerCommunication,Prerender2,SpeculationRules,SpeculationRulesPrefetchProxy,PreloadingHeuristicsMLModel,InterestFeedContentSuggestions,NetworkTimeServiceQuerying",
                ],
                proxy={"server": proxy.chain_url} if proxy.chain_url else None,
            )
        except Exception as exc:
            raise RuntimeError("本机 Google Chrome 启动失败，认证已停止；不会回退到 Playwright Chromium") from exc
        try:
            self.log(f"[认证] 使用本机 Google Chrome 原生 TLS/UA/Client Hints: Chrome/{browser.version}")
        except Exception:
            self.log("[认证] 使用本机 Google Chrome 原生 TLS/UA/Client Hints")
        context_options = {
            "locale": self.fingerprint.locale,
            "timezone_id": self.fingerprint.timezone,
            "viewport": {"width": self.fingerprint.viewport_width, "height": self.fingerprint.viewport_height},
            "screen": {"width": self.fingerprint.screen_width, "height": self.fingerprint.screen_height},
            "device_scale_factor": self.fingerprint.device_scale_factor,
            "is_mobile": False,
            "has_touch": False,
            "accept_downloads": False,
            "service_workers": "block",
        }
        if storage_state:
            context_options["storage_state"] = storage_state
        try:
            context = browser.new_context(**context_options)
            self._install_browser_traffic_meter(context)
            self._install_fingerprint(context)
            self._install_low_traffic_cdp(context)
            self._install_network_capture(context, "auth")
            return browser, context
        except Exception:
            # The caller cannot close objects that were never returned.  Close both
            # here so a failed account setup never leaves a Chrome process/profile
            # alive for the next account.
            self._close_browser(context, browser)
            raise

    def _new_otp_browser_context(self, p):
        local_proxy = normalize_proxy_url(self.register_proxy.local_proxy)
        self._close_otp_proxy_chain()
        otp_proxy_chain = ProxyChainServer(
            local_proxy,
            "",
            self.log,
            None,
            force_server=True,
        )
        otp_proxy_chain.__enter__()
        self._otp_proxy_chain = otp_proxy_chain
        browser = None
        try:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-background-networking",
                    "--disable-breakpad",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--disable-domain-reliability",
                    "--disable-sync",
                    "--metrics-recording-only",
                    "--no-first-run",
                ],
                proxy={"server": otp_proxy_chain.url},
            )
            context = browser.new_context(
                user_agent=self.fingerprint.user_agent,
                locale=self.fingerprint.locale,
                viewport={"width": 720, "height": 520},
                accept_downloads=False,
                service_workers="block",
            )

            def block_heavy_resource(route, request) -> None:
                resource_type = str(getattr(request, "resource_type", "") or "").lower()
                if resource_type in {"image", "media", "font", "stylesheet"}:
                    route.abort()
                    return
                route.continue_()

            context.route("**/*", block_heavy_resource)
        except Exception:
            if browser is not None:
                browser.close()
            self._close_otp_proxy_chain()
            raise
        route_text = f"本地代理={local_proxy}" if local_proxy else "直连"
        self.log(f"[iCloud] 取码使用独立无头 Chromium：{route_text}；不使用注册动态代理")
        return browser, context

    def _close_otp_proxy_chain(self) -> None:
        chain = getattr(self, "_otp_proxy_chain", None)
        self._otp_proxy_chain = None
        if chain is not None:
            try:
                chain.close()
            except Exception:
                pass

    def _protocol_fingerprint_payload(self) -> dict:
        fp = self.fingerprint
        major = fp.chrome_major
        return {
            "user_agent": fp.user_agent,
            "sec_ch_ua": f'"Chromium";v="{major}", "Google Chrome";v="{major}", "Not_A Brand";v="24"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
            "sec_ch_ua_full_version_list": f'"Chromium";v="{fp.chrome_full}", "Google Chrome";v="{fp.chrome_full}"',
            "sec_ch_ua_arch": '"x86"',
            "sec_ch_ua_bitness": '"64"',
            "sec_ch_ua_model": '""',
            "screen": f"{fp.screen_width}x{fp.screen_height}",
            "lang": fp.locale.split("-", 1)[0],
            "lang_full": fp.accept_language,
            "browser_type": "chrome",
            "navigator_platform": fp.platform,
            "navigator_vendor": fp.vendor,
            "hardware_concurrency": fp.hardware_concurrency,
            "device_memory": fp.device_memory,
            "max_touch_points": fp.max_touch_points,
            "device_pixel_ratio": fp.device_scale_factor,
            "timezone": fp.timezone,
        }

    def _protocol_proxy_url(self) -> str:
        return self.register_proxy.chain_url or self.register_proxy.local_proxy or self.register_proxy.dynamic_proxy

    def _prepare_protocol_otp_bootstrap(self) -> None:
        self._force_headed_auth = False
        if not bool(getattr(self, "protocol_prefix_before_otp", False)):
            self._protocol_otp_bootstrap = None
            return
        from browser_protocol_bridge import prepare_protocol_until_otp

        self.log("[hybrid] 浏览器启动前先执行协议认证前缀（已有账号优先登录）")
        try:
            self._protocol_otp_bootstrap = prepare_protocol_until_otp(
                email=self.account.email,
                proxy_url=self._protocol_proxy_url(),
                fingerprint=self._protocol_fingerprint_payload(),
                log=self.log,
            )
        except Exception as exc:
            detail = str(exc)
            lowered = detail.lower()
            if "invalid_state" in lowered:
                self._protocol_otp_bootstrap = None
                self._force_headed_auth = True
                self.log("[hybrid] 协议 OAuth 状态连续失效，自动切换有头浏览器从认证入口继续")
                return
            network_markers = (
                "10053", "10054", "tls", "connection closed", "connection reset",
                "timed out", "timeout", "curl:", "proxy connect", "err_connection",
            )
            if any(marker in lowered for marker in network_markers):
                raise ProxyExitCheckError(f"协议认证前缀网络失败: {detail[:260]}", "代理检测失败") from exc
            raise RuntimeError(f"协议认证前缀失败: {detail[:300]}") from exc

    def _apply_protocol_otp_cookies(self, context) -> None:
        bootstrap = getattr(self, "_protocol_otp_bootstrap", None) or {}
        if not bootstrap:
            return
        cookies = list(bootstrap.get("browser_cookies") or [])
        if not cookies:
            self._protocol_otp_bootstrap = None
            self._force_headed_auth = True
            self.log("[hybrid] 协议前缀未生成可移交 Cookie，当前有头浏览器从认证入口重新开始")
            return
        context.add_cookies(cookies)
        self.log(f"[hybrid] 已向有头浏览器导入协议 OTP Cookie: {len(cookies)} 个")

    def _install_browser_traffic_meter(
        self,
        context,
        fixed_stage: str = "",
        forward_to_account: bool | None = None,
    ) -> None:
        callback = getattr(self, "browser_traffic_callback", None)
        if not callback:
            return
        if not hasattr(self, "_browser_traffic_cdp_sessions"):
            self._browser_traffic_cdp_sessions = []
        fixed_stage = str(fixed_stage or "").strip()
        request_meta = self._auth_traffic_request_meta if not fixed_stage else {}

        def attach(page) -> None:
            try:
                session = context.new_cdp_session(page)
                session.send("Network.enable")

                def on_request(params) -> None:
                    request = dict((params or {}).get("request") or {})
                    request_id = str((params or {}).get("requestId") or "")
                    resource_type = str((params or {}).get("type") or "other").lower()
                    url = str(request.get("url") or "")
                    try:
                        host = str(urlsplit(url).hostname or "").lower()
                    except Exception:
                        host = ""
                    url_key = self._auth_traffic_url_key(url)
                    stage = fixed_stage or self._auth_traffic_stage
                    total = len(str(request.get("method") or "").encode("utf-8"))
                    total += len(url.encode("utf-8"))
                    for name, value in dict(request.get("headers") or {}).items():
                        total += len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
                    total += len(str(request.get("postData") or "").encode("utf-8"))
                    if request_id:
                        previous = request_meta.pop(request_id, None)
                        redirect_response = dict((params or {}).get("redirectResponse") or {})
                        if previous and redirect_response:
                            previous_stage, previous_host, previous_type, previous_url, previous_request_bytes = previous
                            self._record_auth_traffic_resource(
                                previous_request_bytes + max(0, int(redirect_response.get("encodedDataLength") or 0)),
                                previous_stage,
                                previous_host,
                                previous_type,
                                previous_url,
                                forward_to_account,
                            )
                        request_meta[request_id] = (stage, host, resource_type, url_key, total)

                def on_finished(params) -> None:
                    request_id = str((params or {}).get("requestId") or "")
                    cache_network_ids = getattr(self, "_auth_static_cache_network_ids", set()) if not fixed_stage else set()
                    if request_id and request_id in cache_network_ids:
                        cache_network_ids.discard(request_id)
                        request_meta.pop(request_id, None)
                        return
                    stage, host, resource_type, url_key, request_bytes = request_meta.pop(
                        request_id,
                        (fixed_stage or self._auth_traffic_stage, "", "other", "未知URL", 0),
                    )
                    self._record_auth_traffic_resource(
                        request_bytes + max(0, int((params or {}).get("encodedDataLength") or 0)),
                        stage,
                        host,
                        resource_type,
                        url_key,
                        forward_to_account,
                    )

                def on_failed(params) -> None:
                    payload = dict(params or {})
                    request_id = str(payload.get("requestId") or "")
                    cache_network_ids = getattr(self, "_auth_static_cache_network_ids", set()) if not fixed_stage else set()
                    if request_id and request_id in cache_network_ids:
                        cache_network_ids.discard(request_id)
                        request_meta.pop(request_id, None)
                        return
                    stage, host, resource_type, url_key, _request_bytes = request_meta.pop(
                        request_id,
                        (fixed_stage or self._auth_traffic_stage, "", "other", "未知URL", 0),
                    )
                    blocked_reason = str(payload.get("blockedReason") or "").strip()
                    error_text = str(payload.get("errorText") or "").strip()
                    if blocked_reason or "blocked" in error_text.lower() or "aborted" in error_text.lower():
                        return
                    encoded = max(0, int(payload.get("encodedDataLength") or 0))
                    if encoded:
                        self._record_auth_traffic_resource(
                            encoded,
                            stage,
                            host,
                            resource_type,
                            url_key,
                            forward_to_account,
                        )

                session.on("Network.requestWillBeSent", on_request)
                session.on("Network.loadingFinished", on_finished)
                session.on("Network.loadingFailed", on_failed)
                self._browser_traffic_cdp_sessions.append(session)
            except Exception as exc:
                self.log(f"[traffic] Chromium 流量统计挂载失败: {str(exc)[:120]}")

        context.on("page", attach)
        try:
            for page in context.pages:
                attach(page)
        except Exception:
            pass

    def _set_auth_traffic_stage(self, stage: str) -> None:
        value = str(stage or "其他").strip() or "其他"
        self._auth_traffic_stage = value
        if not hasattr(self, "_auth_traffic_stage_bytes"):
            self._auth_traffic_stage_bytes = {}
        self._auth_traffic_stage_bytes.setdefault(value, 0)

    def _record_auth_traffic(
        self,
        delta,
        stage: str = "",
        host: str = "",
        forward_to_account: bool | None = None,
    ) -> None:
        try:
            value = max(0, int(delta or 0))
        except Exception:
            value = 0
        if not value:
            return
        stage_key = str(stage or self._auth_traffic_stage or "其他")
        if not hasattr(self, "_auth_traffic_stage_bytes"):
            self._auth_traffic_stage_bytes = {}
        self._auth_traffic_stage_bytes[stage_key] = self._auth_traffic_stage_bytes.get(stage_key, 0) + value
        callback = getattr(self, "browser_traffic_callback", None)
        should_forward = (
            bool(getattr(self, "browser_traffic_forward_to_account", True))
            if forward_to_account is None
            else bool(forward_to_account)
        )
        if callback and should_forward:
            try:
                callback(value)
            except Exception:
                pass

    def _auth_traffic_url_key(self, url: str) -> str:
        try:
            parsed = urlsplit(str(url or ""))
            host = str(parsed.hostname or "未知主机").lower()
            path = str(parsed.path or "/")
            return f"{host}{path}"[:220]
        except Exception:
            return "未知URL"

    def _record_auth_traffic_resource(
        self,
        delta,
        stage: str,
        host: str,
        resource_type: str,
        url_key: str,
        forward_to_account: bool | None = None,
    ) -> None:
        try:
            value = max(0, int(delta or 0))
        except Exception:
            value = 0
        if not value:
            return
        stage_key = str(stage or self._auth_traffic_stage or "其他")
        self._record_auth_traffic(value, stage_key, host, forward_to_account)

    def _log_auth_traffic_report(self) -> None:
        if bool(getattr(self, "_auth_traffic_reported", False)):
            return
        self._auth_traffic_reported = True

    def _prepare_fingerprint_for_proxy(self, proxy: ProxyConfig, label: str) -> ProxyHealthResult:
        proxy_url = proxy.chain_url or proxy.local_proxy or proxy.dynamic_proxy
        auth_stage = label in {"认证", "登录"}
        health = detect_proxy_health(
            proxy_url,
            traffic_callback=(
                lambda delta: self._record_auth_traffic(delta, "出口定位预检", "出口定位")
            ) if getattr(self, "browser_traffic_callback", None) else None,
            check_chatgpt=not auth_stage,
        )
        if not health.success:
            if auth_stage:
                if proxy.dynamic_proxy:
                    raise ProxyExitCheckError(
                        f"{label}动态代理出口预检失败: {health.summary}",
                        "代理检测失败",
                    )
                self.current_proxy_health = None
                self.fingerprint = generate_register_fingerprint()
                self.log(
                    f"[代理] {label}出口信息预检失败，继续启动浏览器验证实际连接: {health.summary}"
                )
                return health
            raise ProxyExitCheckError(f"{label}代理健康检查失败: {health.summary}", "代理检测失败")
        self.current_proxy_health = health
        self.fingerprint = generate_fingerprint_for_exit(health)
        if proxy.dynamic_proxy:
            self.log(
                f"[代理] 已按注册代理池出口生成浏览器指纹环境: "
                f"locale={self.fingerprint.locale} timezone={self.fingerprint.timezone}"
            )
        if auth_stage:
            self.log(
                f"[代理] {label}出口定位完成: {health.ip} {health.location or health.country} "
                f"{health.timezone or 'UTC'}；ChatGPT 连通性由后续 Chromium CSRF 直接确认"
            )
        else:
            self.log(
                f"[代理] {label}出口检查通过: {health.ip} {health.location or health.country} "
                f"{health.timezone or 'UTC'} ChatGPT={health.chatgpt_status}"
            )
        return health

    def _close_browser(self, context, browser) -> None:
        try:
            if context:
                context.close()
        except Exception:
            pass
        try:
            if browser:
                browser.close()
        except Exception:
            pass

    def _cleanup_profile_dir(self, profile_dir: str) -> None:
        for attempt in range(8):
            try:
                shutil.rmtree(profile_dir, ignore_errors=False)
                return
            except FileNotFoundError:
                return
            except PermissionError:
                time.sleep(0.5 + attempt * 0.25)
            except OSError:
                time.sleep(0.5 + attempt * 0.25)
        self.log(f"临时浏览器目录清理失败，已忽略: {profile_dir}")

    def _install_fingerprint(self, context) -> None:
        fp = self.fingerprint
        fp_payload = json.dumps({
            "platform": fp.platform,
            "vendor": fp.vendor,
            "languages": fp.languages,
            "hardwareConcurrency": fp.hardware_concurrency,
            "deviceMemory": fp.device_memory,
            "maxTouchPoints": fp.max_touch_points,
            "screenWidth": fp.screen_width,
            "screenHeight": fp.screen_height,
            "outerWidth": fp.outer_width,
            "outerHeight": fp.outer_height,
            "deviceScaleFactor": fp.device_scale_factor,
            "chromeMajor": fp.chrome_major,
            "chromeFull": fp.chrome_full,
        }, ensure_ascii=False)
        context.set_extra_http_headers({"Accept-Language": fp.accept_language})
        context.add_init_script(
            """(() => {
                const fp = __FP_PAYLOAD__;
                const defineGetter = (obj, prop, value) => {
                    try { Object.defineProperty(obj, prop, { get: () => value, configurable: true }); } catch (_) {}
                };
                defineGetter(Navigator.prototype, 'webdriver', undefined);
                defineGetter(Navigator.prototype, 'platform', fp.platform);
                defineGetter(Navigator.prototype, 'vendor', fp.vendor);
                defineGetter(Navigator.prototype, 'language', fp.languages[0]);
                defineGetter(Navigator.prototype, 'languages', fp.languages);
                defineGetter(Navigator.prototype, 'hardwareConcurrency', fp.hardwareConcurrency);
                defineGetter(Navigator.prototype, 'deviceMemory', fp.deviceMemory);
                defineGetter(Navigator.prototype, 'maxTouchPoints', fp.maxTouchPoints);
                defineGetter(Screen.prototype, 'width', fp.screenWidth);
                defineGetter(Screen.prototype, 'height', fp.screenHeight);
                defineGetter(Screen.prototype, 'availWidth', fp.screenWidth);
                defineGetter(Screen.prototype, 'availHeight', fp.screenHeight - 40);
                defineGetter(window, 'outerWidth', fp.outerWidth);
                defineGetter(window, 'outerHeight', fp.outerHeight);
                defineGetter(window, 'devicePixelRatio', fp.deviceScaleFactor);
                try {
                    const originalQuery = navigator.permissions && navigator.permissions.query;
                    if (originalQuery) {
                        navigator.permissions.query = params => params && params.name === 'notifications'
                            ? Promise.resolve({ state: Notification.permission })
                            : originalQuery.call(navigator.permissions, params);
                    }
                } catch (_) {}
                try {
                    const getParameter = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = function(parameter) {
                        if (parameter === 37445) return 'Intel Inc.';
                        if (parameter === 37446) return 'Intel Iris OpenGL Engine';
                        return getParameter.call(this, parameter);
                    };
                } catch (_) {}
            }})();"""
            .replace("__FP_PAYLOAD__", fp_payload)
        )

    def _log_browser_proxy_status(self, page, proxy: ProxyConfig, label: str) -> None:
        health = self.current_proxy_health
        if health and health.success:
            self.log(f"[代理] {label}: {health.summary}")
        else:
            self.log(f"[代理] {label}: 未记录出口信息")



    def _refresh_bad_gateway_if_visible(self, page, refresh_count: int, label: str) -> tuple[bool, int]:
        try:
            title = page.title(timeout=1000)
        except Exception:
            title = ""
        try:
            body = page.locator("body").inner_text(timeout=1000)
        except Exception:
            body = ""
        text = f"{title}\n{body}"
        if not re.search(r"Bad gateway|Error code 502|Host\s+Error|HTTP\s*502", text, flags=re.I):
            return False, refresh_count
        if refresh_count >= 8:
            raise RuntimeError(f"{label}: 连续检测到 Bad gateway/502，已刷新 {refresh_count} 次仍未恢复")
        refresh_count += 1
        self.log(f"{label}: 检测到 Bad gateway/502，刷新页面重试 ({refresh_count}/8)")
        try:
            page.reload(wait_until="domcontentloaded", timeout=60000)
        except Exception as exc:
            self.log(f"{label}: 502 页面刷新失败，继续等待: {str(exc)[:120]}")
        return True, refresh_count

    def _page_has_text(self, page, texts: list[str]) -> bool:
        try:
            body = page.locator("body").inner_text(timeout=1000)
        except Exception:
            return False
        return any(text in body for text in texts)




    def _approve_sso_login_if_visible(self, page) -> bool:
        try:
            clicked = page.evaluate(
                r"""() => {
                    const visible = el => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const enabled = el => el && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                    const candidates = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"]')).filter(el => visible(el) && enabled(el));
                    const approve = candidates.find(el => {
                        const text = `${el.value || ''} ${el.textContent || ''} ${el.getAttribute('aria-label') || ''}`.replace(/\s+/g, ' ').trim();
                        return /批准登录|批准登入|Approve\s+(login|sign[- ]?in)|Approve\s+sign[- ]?in/i.test(text)
                            && !/不认识|不認識|Not.*account|deny|cancel/i.test(text);
                    });
                    if (!approve) return false;
                    approve.scrollIntoView({ block: 'center', inline: 'center' });
                    approve.click();
                    return true;
                }"""
            )
        except Exception:
            clicked = False
        if clicked:
            self.log("已点击批准登录")
            return True
        return False




    def _raise_if_page_closed(self, page, action: str = "认证流程") -> None:
        is_closed = getattr(page, "is_closed", None)
        if not callable(is_closed):
            return
        try:
            closed = is_closed()
        except Exception as exc:
            if "closed" in str(exc).lower() or "target page" in str(exc).lower():
                raise RuntimeError(f"浏览器窗口已关闭，{action}已停止") from exc
            return
        if closed:
            raise RuntimeError(f"浏览器窗口已关闭，{action}已停止")

    def _recover_auth_page_if_closed(self, page, context, action: str):
        is_closed = getattr(page, "is_closed", None)
        if not callable(is_closed):
            return page
        try:
            if not is_closed():
                return page
        except Exception:
            self._raise_if_page_closed(page, action)

        try:
            for candidate in reversed(list(context.pages)):
                if candidate is page:
                    continue
                if not candidate.is_closed():
                    self.log(f"[auth] 原认证页已关闭，已接管同一 Chromium 上下文中的存活页面: {candidate.url}")
                    return candidate
        except Exception:
            pass

        try:
            recovery_page = context.new_page()
            for attempt in range(3):
                recovery_page.goto(
                    f"{CHATGPT_BASE_URL}/api/auth/session",
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
                body = recovery_page.locator("body").inner_text(timeout=5000).strip()
                try:
                    payload = json.loads(body)
                except Exception:
                    payload = {}
                if payload.get("accessToken"):
                    self.log("[auth] 认证页关闭后已通过 Session 小接口确认登录成功")
                    return recovery_page
                if attempt < 2:
                    self._wait_or_stop(1)
        except Exception as exc:
            self._raise_if_page_closed(page, action)
            raise RuntimeError(f"认证页关闭后的 Session 确认失败: {str(exc)[:180]}") from exc

        try:
            recovery_page.close()
        except Exception:
            pass
        raise RuntimeError("认证页已关闭，Session 小接口未返回登录会话；邮箱和密码未重复提交")




    def _persist_auth_fields(self, fields: dict[str, str]) -> None:
        allowed = {
            "openai_password", "openai_password_state", "auth_route", "account_creation_state",
        }
        clean = {
            str(key): str(value)
            for key, value in dict(fields or {}).items()
            if key in allowed and value not in (None, "")
        }
        if not clean:
            return
        if not hasattr(self, "_auth_result"):
            self._auth_result = {}
        self._auth_result.update(clean)
        if "openai_password" in clean:
            self.openai_password = clean["openai_password"]
        if "openai_password_state" in clean:
            self.openai_password_state = clean["openai_password_state"]
        if "auth_route" in clean:
            self.auth_route = clean["auth_route"]
        callback = getattr(self, "auth_persist_callback", None)
        if callback:
            callback(dict(clean))

    def _set_auth_route(self, route: str) -> None:
        value = str(route or "").strip()
        if not value or value == getattr(self, "auth_route", ""):
            return
        self.auth_route = value
        self._persist_auth_fields({"auth_route": value})

    def _ensure_new_openai_password(self) -> str:
        password = str(getattr(self, "openai_password", "") or "")
        if not password:
            password = self._generate_password()
        state = str(getattr(self, "openai_password_state", "") or "")
        if state != "confirmed":
            state = "pending_registration"
        self._persist_auth_fields({
            "openai_password": password,
            "openai_password_state": state,
            "auth_route": "new_password_signup",
        })
        self.log("[密码] 新号 OpenAI 密码已生成并保存，等待服务端确认")
        return password

    def _existing_openai_password(self) -> str:
        password = str(getattr(self, "openai_password", "") or "")
        if not password:
            raise RuntimeError("已有账号缺少保存的 OpenAI 密码，不能执行邮箱-密码登录")
        return password

    def _confirm_new_openai_password(self) -> None:
        if not getattr(self, "openai_password", ""):
            return
        self._user_register_confirmed = True
        self.is_new_account = True
        self._persist_auth_fields({
            "openai_password": self.openai_password,
            "openai_password_state": "confirmed",
            "auth_route": "new_password_signup",
        })
        self.log("[密码] 新号密码注册已由服务端确认")

    def _install_auth_flow_observer(self, context) -> None:
        if bool(getattr(self, "_auth_flow_observer_installed", False)):
            return
        on = getattr(context, "on", None)
        if not callable(on):
            return
        self._auth_flow_observer_installed = True

        def on_response(response) -> None:
            try:
                request = getattr(response, "request", None)
                method = str(getattr(request, "method", "") or "").upper()
                url = str(getattr(response, "url", "") or getattr(request, "url", "") or "")
                parsed = urlsplit(url)
                host = str(parsed.hostname or "").lower()
                path = str(parsed.path or "")
                status = int(getattr(response, "status", 0) or 0)
                if host == "auth.openai.com" and path.endswith("/api/accounts/authorize/continue"):
                    try:
                        payload = response.json()
                    except Exception:
                        payload = {}
                    page_data = payload.get("page") if isinstance(payload, dict) else {}
                    page_type = str((page_data or {}).get("type") or "").strip().lower()
                    self._last_authorize_page_type = page_type
                    if page_type == "create_account_password":
                        self.is_new_account = True
                        self._set_auth_route("new_password_signup")
                    elif page_type == "login_password":
                        self.is_new_account = False
                        self._set_auth_route("existing_password_login")
                    elif page_type == "email_otp_verification" and not self._user_register_seen:
                        self.is_new_account = False
                        self._set_auth_route("existing_email_otp_login")
                    return
                if host == "auth.openai.com" and path.endswith("/api/accounts/user/register") and method == "POST":
                    self._user_register_seen = True
                    if 200 <= status < 300:
                        self._confirm_new_openai_password()
                    return
                if host == "auth.openai.com" and path.endswith("/api/accounts/email-otp/validate") and method == "POST":
                    if status >= 400:
                        try:
                            payload = response.json()
                        except Exception:
                            payload = {}
                        error = payload.get("error") if isinstance(payload, dict) else {}
                        code = str((error or {}).get("code") or "").strip().lower()
                        if code == "account_deactivated":
                            self._fatal_auth_error = "服务端确认账号已删除或停用"
                    return
                if host == "auth.openai.com" and path.endswith("/api/accounts/create_account") and method == "POST":
                    if 200 <= status < 300:
                        self._account_create_confirmed = True
                        self.is_new_account = True
                        self._persist_auth_fields({"account_creation_state": "confirmed"})
            except Exception:
                return

        context.on("response", on_response)

    def _register(self, page, context) -> None:
        self._raise_if_stopped()
        self._auth_flow_active = True
        self._auth_screen_hint = "login_or_signup"
        self._install_auth_flow_observer(context)
        self.log(f"[认证] 开始注册或登录: {self.account.email}")
        bootstrap = getattr(self, "_protocol_otp_bootstrap", None) or {}
        if bootstrap:
            otp_min_timestamp = float(bootstrap.get("otp_sent_at") or time.time()) - 10
            otp_url = str(bootstrap.get("otp_url") or "https://auth.openai.com/email-verification")
            self._goto_tolerant(page, otp_url, "协议 OTP 有头浏览器接管", timeout=90000)
            handoff_stage = str(bootstrap.get("handoff_stage") or "email_otp_verification")
            self.log(f"[认证] 协议前缀已完成；有头浏览器从 {handoff_stage} 页面开始")
        else:
            self._set_auth_traffic_stage("CSRF/OAuth 入口")
            signin_url = self._create_openai_signin_url(context, page)
            otp_min_timestamp = time.time() - 10
            if str(getattr(page, "url", "") or "").rstrip("/") != str(signin_url or "").rstrip("/"):
                page.goto(signin_url, wait_until="domcontentloaded", timeout=90000)
            self.log("[认证] 已打开 OpenAI 认证页；如出现人机验证，请在浏览器中手动完成")

        deadline = time.time() + 600
        email_code_submitted = False
        password_submitted = False
        about_you_submitted = False
        about_you_submitted_at = 0.0
        about_you_submit_retry_at = 0.0
        mfa_totp_submitted = False
        mfa_email_mode = False
        route_error_retries = 0
        while time.time() < deadline:
            self._raise_if_stopped()
            if str(getattr(self, "_fatal_auth_error", "") or ""):
                raise RuntimeError(self._fatal_auth_error)
            page = self._recover_auth_page_if_closed(page, context, "OpenAI 认证流程")
            self._raise_if_page_closed(page, "OpenAI 认证流程")
            url = page.url
            if self._is_security_verification_page(page):
                self._set_auth_traffic_stage("安全验证")
                if not bool(getattr(self, "_security_verification_active", False)):
                    self._security_verification_active = True
                    self.log(
                        "[auth] 检测到 Cloudflare/站点安全验证页；挑战资源已完整放行，"
                        "等待页面自动完成，如出现交互请在有头浏览器中手动操作"
                    )
                self._wait_or_stop(1)
                continue
            if bool(getattr(self, "_security_verification_active", False)):
                self._security_verification_active = False
                self.log("[auth] 安全验证页已结束，继续原认证状态机")
            if "/api/auth/callback/openai" in str(url or ""):
                self._set_auth_traffic_stage("OAuth回调")
            error_text = self._detect_route_error(page)
            if error_text:
                if route_error_retries < 3 and self._retry_route_error(page):
                    route_error_retries += 1
                    # Try again may return a fresh password/OTP form. The
                    # previous document's submission flags must not suppress
                    # entering the credentials on this recovered page.
                    email_code_submitted = False
                    password_submitted = False
                    mfa_totp_submitted = False
                    mfa_email_mode = False
                    self.log(f"OpenAI 页面超时，已点击重试 ({route_error_retries}/3)")
                    self._wait_or_stop(5)
                    continue
                raise RuntimeError(f"OpenAI 页面错误，通常是代理/风控导致接口超时: {error_text}")
            if self._has_chatgpt_session(page):
                self._set_auth_traffic_stage("Session 确认")
                self.log("[认证] 认证完成，已获得 ChatGPT 会话")
                return
            if self._is_oauth_callback_error(page):
                if self._recover_oauth_callback_error(page, context):
                    otp_min_timestamp = time.time()
                    email_code_submitted = False
                    password_submitted = False
                    about_you_submitted = False
                    about_you_submitted_at = 0.0
                    about_you_submit_retry_at = 0.0
                    mfa_totp_submitted = False
                    mfa_email_mode = False
                    continue
                raise RuntimeError("OAuthCallback 回调失败，自动重开登录入口后仍未恢复")
            if self._is_user_already_exists_error(page):
                if self._recover_user_already_exists(page, context):
                    otp_min_timestamp = time.time()
                    email_code_submitted = False
                    password_submitted = False
                    about_you_submitted = False
                    about_you_submitted_at = 0.0
                    about_you_submit_retry_at = 0.0
                    mfa_totp_submitted = False
                    mfa_email_mode = False
                    continue
                raise RuntimeError("账号已存在，但自动切换登录入口后仍未恢复")
            if self._is_authenticator_mfa_page(page):
                self._set_auth_traffic_stage("MFA处理")
                self._reset_email_stall()
                if not self.mfa_totp_secret:
                    raise MfaRequiredError(
                        "当前账号已启用认证器 MFA，但本地未保存该账号的 TOTP 密钥；解除旧 MFA 后重试即可自动重新绑定",
                        status="MFA密钥缺失",
                    )
                if not mfa_totp_submitted:
                    self._submit_authenticator_mfa_code(page)
                    mfa_totp_submitted = True
                self._wait_or_stop(0.5)
                continue
            if self._is_email_mfa_page(page):
                if not mfa_email_mode:
                    mfa_email_mode = True
                    mfa_totp_submitted = False
                    otp_min_timestamp = time.time() - 5
                    email_code_submitted = False
                    self.log("检测到 MFA 邮箱验证方式，继续复用当前取码通道")
            if "add-phone" in url or "phone-verification" in url:
                raise RuntimeError("当前账户触发电话验证，已停止自动处理")
            if self._select_password_auth_mode_if_visible(page):
                self._wait_or_stop(0.5)
                continue
            if self._has_visible_password(page):
                self._set_auth_traffic_stage("密码提交")
                self._reset_email_stall()
                if password_submitted:
                    self._wait_or_stop(2)
                    continue
                self._fill_password_step(page)
                password_submitted = True
                email_code_submitted = False
                about_you_submitted = False
                about_you_submitted_at = 0.0
                about_you_submit_retry_at = 0.0
                mfa_totp_submitted = False
                mfa_email_mode = False
                continue
            if "about-you" in url or self._has_about_you_form(page):
                self._set_auth_traffic_stage("基础资料提交")
                self.is_new_account = True
                self._reset_email_stall()
                email_code_submitted = False
                password_submitted = False
                if bool(getattr(self, "hybrid_protocol_after_otp", False)):
                    self._complete_about_you_via_protocol(page, context)
                    return
                if about_you_submitted:
                    # 提交只执行一次。代理较慢时回调可能超过 30 秒，重复点击会让同一
                    # OAuth state 并发提交，最终落入 OAuthCallback/user_already_exists。
                    self._wait_or_stop(1)
                    continue
                self._fill_about_you(page)
                about_you_submitted = True
                about_you_submitted_at = time.time()
                about_you_submit_retry_at = 0.0
                continue
            if "email-verification" in url or self._has_otp_input(page):
                self._set_auth_traffic_stage("邮箱验证码提交")
                self._reset_email_stall()
                password_submitted = False
                if (
                    str(getattr(self, "auth_route", "") or "") == "new_password_signup"
                    and not bool(getattr(self, "_user_register_confirmed", False))
                ):
                    raise RuntimeError("新号已进入 OTP 页面，但未观测到 user/register 成功响应，已停止避免状态分裂")
                if email_code_submitted:
                    self._wait_or_stop(2)
                    continue
                if mfa_email_mode:
                    self._submit_mfa_email_code(page, otp_min_timestamp)
                    mfa_email_mode = False
                else:
                    self._submit_email_code(page, otp_min_timestamp)
                email_code_submitted = True
                continue
            self._set_auth_traffic_stage("邮箱分流")
            if self._fill_email_if_visible(page):
                otp_min_timestamp = time.time()
                email_code_submitted = False
                password_submitted = False
                about_you_submitted = False
                about_you_submitted_at = 0.0
                about_you_submit_retry_at = 0.0
                mfa_totp_submitted = False
                mfa_email_mode = False
                continue
            if about_you_submitted:
                about_you_submitted = False
                about_you_submitted_at = 0.0
                about_you_submit_retry_at = 0.0
            self._wait_or_stop(2)

        raise TimeoutError("认证流程超时；如果浏览器停在人机验证或异常页面，请手动处理后重试")

    def _complete_about_you_via_protocol(self, page, context) -> None:
        from browser_protocol_bridge import complete_browser_otp_registration

        self.log("[hybrid] 浏览器已完成邮箱 OTP，切换现有协议注册尾链")
        browser_cookies = context.cookies()
        try:
            result = complete_browser_otp_registration(
                email=self.account.email,
                proxy_url=self._protocol_proxy_url(),
                browser_cookies=browser_cookies,
                fingerprint=self._protocol_fingerprint_payload(),
                log=self.log,
            )
        except Exception as exc:
            detail = str(exc)
            lowered = detail.lower()
            network_markers = (
                "10053",
                "10054",
                "tls",
                "connection closed",
                "connection reset",
                "timed out",
                "timeout",
                "curl:",
                "proxy connect",
                "err_connection",
            )
            if any(marker in lowered for marker in network_markers):
                raise ProxyExitCheckError(f"协议注册尾链网络失败: {detail[:260]}", "代理检测失败") from exc
            raise RuntimeError(f"协议注册尾链失败: {detail[:300]}") from exc
        protocol_cookies = list(result.pop("browser_cookies", []) or [])
        if protocol_cookies:
            try:
                context.add_cookies(protocol_cookies)
            except Exception as exc:
                self.log(f"[hybrid] 协议 Cookie 回写浏览器失败，继续使用协议结果: {str(exc)[:140]}")
        session_payload = {
            "accessToken": str(result.get("access_token") or ""),
            "sessionToken": str(result.get("session_token") or ""),
            "authFlow": "browser_otp_protocol_tail",
        }
        result["session_json"] = json.dumps(session_payload, ensure_ascii=False, indent=2)
        try:
            result["storage_state_json"] = json.dumps(context.storage_state(), ensure_ascii=False)
        except Exception:
            result["storage_state_json"] = ""
        result["auth_flow"] = "browser_otp_protocol_tail"
        self._protocol_registration_result = result
        self.log("[hybrid] 基础资料、回调与 Session 已由协议尾链完成")


    def _is_security_verification_page(self, page) -> bool:
        try:
            title = str(page.title(timeout=700) or "").lower()
        except Exception:
            title = ""
        try:
            body = str(page.locator("body").inner_text(timeout=700) or "").lower()
        except Exception:
            body = ""
        text = f"{title}\n{body}"
        markers = (
            "just a moment",
            "performing security verification",
            "verifies you are not a bot",
            "checking your browser",
            "verify you are human",
            "security service to protect against malicious bots",
        )
        return any(marker in text for marker in markers)

    def _detect_route_error(self, page) -> str:
        try:
            text = page.locator("body").inner_text(timeout=700)
        except Exception:
            return ""
        normalized = re.sub(r"\s+", " ", text).strip()
        if "糟糕，出错了" in normalized or "Operation timed out" in normalized or "Route Error" in normalized:
            return normalized[:400]
        return ""

    def _is_oauth_callback_error(self, page) -> bool:
        try:
            url = str(getattr(page, "url", "") or "")
        except Exception:
            url = ""
        lowered = url.lower()
        if "/auth/error" in lowered and "oauthcallback" in lowered:
            return True
        try:
            text = page.locator("body").inner_text(timeout=700)
        except Exception:
            return False
        normalized = re.sub(r"\s+", " ", str(text or "")).lower()
        return "oauthcallback" in normalized or (
            "signing in" in normalized and "problem" in normalized
        )

    def _recover_oauth_callback_error(self, page, context) -> bool:
        recovery_count = max(0, int(getattr(self, "_oauth_callback_recovery_count", 0) or 0))
        if recovery_count >= 2:
            return False
        attempt = recovery_count + 1
        self._oauth_callback_recovery_count = attempt
        try:
            self._auth_screen_hint = "login"
            login_url = self._create_login_url(context, page)
            if str(getattr(page, "url", "") or "").rstrip("/") != str(login_url or "").rstrip("/"):
                self._goto_tolerant(
                    page,
                    login_url,
                    "OAuthCallback 登录恢复",
                    timeout=90000,
                    accepted_urls=(CHATGPT_BASE_URL,),
                )
            self._oauth_callback_recovery_count = 2
            self._reset_email_stall()
            self.log("[auth] 检测到 OAuthCallback 错误，已重开一次登录入口继续获取 Session")
            return True
        except Exception as exc:
            if attempt < 2:
                self.log(f"[auth] OAuthCallback 恢复跳转连接中断，2 秒后再试一次: {str(exc)[:160]}")
                self._wait_or_stop(2)
                return True
            self.log(f"[auth] OAuthCallback 自动恢复失败: {str(exc)[:160]}")
            return False

    def _is_user_already_exists_error(self, page) -> bool:
        try:
            url = str(getattr(page, "url", "") or "").lower()
        except Exception:
            url = ""
        if "user_already_exists" in url:
            return True
        try:
            text = page.locator("body").inner_text(timeout=700)
        except Exception:
            return False
        normalized = re.sub(r"\s+", " ", str(text or "")).lower()
        return "user_already_exists" in normalized or (
            "already has an account" in normalized
            or "already exists" in normalized
            or "すでにアカウントがあります" in normalized
            or "すでにアカウントが存在" in normalized
            or "账号已存在" in normalized
            or "帳戶已存在" in normalized
        )

    def _recover_user_already_exists(self, page, context) -> bool:
        recovery_count = max(0, int(getattr(self, "_existing_user_recovery_count", 0) or 0))
        if recovery_count >= 1:
            return False
        self._existing_user_recovery_count = recovery_count + 1
        self._auth_screen_hint = "login"
        retry_texts = [
            "Try again", "Retry", "もう一度試す", "再試行", "ログイン", "Log in", "Sign in", "重试", "重新登录",
        ]
        try:
            if self._click_button_by_text(page, retry_texts):
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=15000)
                except Exception:
                    pass
                self._reset_email_stall()
                self.log("[auth] 检测到 user_already_exists，已切换到登录入口继续获取 Session")
                return True
        except Exception:
            pass
        try:
            login_url = self._create_login_url(context, page)
            if str(getattr(page, "url", "") or "").rstrip("/") != str(login_url or "").rstrip("/"):
                self._goto_tolerant(
                    page,
                    login_url,
                    "user_already_exists 登录恢复",
                    timeout=90000,
                    accepted_urls=(CHATGPT_BASE_URL,),
                )
            self._reset_email_stall()
            self.log("[auth] 检测到 user_already_exists，已重开登录入口继续获取 Session")
            return True
        except Exception as exc:
            self.log(f"[auth] user_already_exists 自动切换登录失败: {str(exc)[:160]}")
            return False

    def _retry_route_error(self, page) -> bool:
        selectors = [
            'button:has-text("Try again")',
            'button:has-text("重试")',
            'a:has-text("Try again")',
            'a:has-text("重试")',
            '[role="button"]:has-text("Try again")',
            '[role="button"]:has-text("重试")',
        ]
        for selector in selectors:
            target = page.locator(selector).first
            try:
                if target.is_visible(timeout=800):
                    target.click(timeout=5000)
                    page.wait_for_load_state("domcontentloaded", timeout=15000)
                    return True
            except Exception:
                continue
        try:
            page.reload(wait_until="domcontentloaded", timeout=30000)
            return True
        except Exception:
            return False

    def _create_auth_entry_url(
        self,
        context,
        screen_hint: str,
        label: str,
        page=None,
        force_browser_channel: bool = False,
    ) -> str:
        csrf_value, device_id = self._get_chatgpt_csrf_and_device(context, page)
        if not csrf_value:
            raise RuntimeError(f"未找到 ChatGPT CSRF cookie，无法打开{label}")
        if not device_id:
            device_id = str(uuid.uuid4())

        query = urlencode({
            "prompt": "login",
            "ext-oai-did": device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "ext-passkey-client-capabilities": "0111",
            "screen_hint": screen_hint,
            "login_hint": self.account.email,
            "locale": self.fingerprint.locale,
        })
        request_url = f"{CHATGPT_BASE_URL}/api/auth/signin/openai?{query}"
        form = {"callbackUrl": f"{CHATGPT_BASE_URL}/", "csrfToken": csrf_value, "json": "true"}
        if page is not None and (
            force_browser_channel or bool(getattr(self, "_auth_csrf_via_browser", False))
        ):
            return self._browser_auth_entry_url(page, request_url, form, label)
        response = None
        last_error = ""
        for attempt in range(1, 3):
            try:
                response = context.request.post(
                    request_url,
                    form=form,
                    headers={"Accept": "application/json", "Accept-Language": self.fingerprint.accept_language},
                    timeout=30000,
                )
            except Exception as exc:
                last_error = str(exc)
                if attempt < 2:
                    self.log(f"[auth] {label}入口 POST 连接中断，1 秒后重试 2/2: {last_error[:160]}")
                    self._wait_or_stop(1)
                    continue
                if page is not None:
                    self.log(f"[auth] {label}入口 APIRequest 两次失败，切换浏览器同源 POST")
                    try:
                        return self._browser_auth_entry_url(page, request_url, form, label)
                    except Exception as browser_exc:
                        raise RuntimeError(
                            f"{label}入口 APIRequest 与浏览器通道均失败: "
                            f"APIRequest={last_error[:160]}; 浏览器={str(browser_exc)[:160]}"
                        ) from browser_exc
                raise RuntimeError(f"{label}入口 POST 两次连接失败: {last_error[:240]}") from exc
            if response.ok:
                break
            status = int(getattr(response, "status", 0) or 0)
            detail = response.text()[:300]
            if attempt < 2 and (status == 429 or status >= 500):
                self.log(f"[auth] {label}入口返回 HTTP {status}，1 秒后重试 2/2")
                self._wait_or_stop(1)
                continue
            raise RuntimeError(f"打开{label}失败: HTTP {status} {detail}")
        if response is None or not response.ok:
            raise RuntimeError(f"打开{label}失败: {last_error or '未收到响应'}")
        payload = response.json()
        signin_url = payload.get("url")
        if not signin_url:
            raise RuntimeError(f"打开{label}缺少跳转 URL: {payload}")
        return signin_url

    def _browser_auth_entry_url(self, page, request_url: str, form: dict, label: str) -> str:
        if not str(getattr(page, "url", "") or "").startswith(CHATGPT_BASE_URL):
            self._goto_tolerant(
                page,
                f"{CHATGPT_BASE_URL}/api/auth/csrf",
                "浏览器 CSRF 小接口",
                timeout=30000,
            )
        try:
            result = page.evaluate(
                """async ({url, form}) => {
                    const body = new URLSearchParams();
                    for (const [name, value] of Object.entries(form)) body.set(name, value);
                    const response = await fetch(url, {
                        method: 'POST',
                        credentials: 'include',
                        headers: {
                            accept: 'application/json',
                            'content-type': 'application/x-www-form-urlencoded',
                        },
                        body: body.toString(),
                    });
                    const text = await response.text();
                    let payload = null;
                    try { payload = JSON.parse(text); } catch (_) {}
                    return {
                        ok: response.ok,
                        status: response.status,
                        url: String(payload?.url || ''),
                        detail: text.slice(0, 240),
                    };
                }""",
                {"url": request_url, "form": form},
            )
            signin_url = str((result or {}).get("url") or "").strip()
            if bool((result or {}).get("ok")) and signin_url:
                return signin_url
            self.log(
                f"[auth] Chromium 同源 fetch 未返回{label}跳转 URL，回退浏览器原生表单 POST: "
                f"HTTP {(result or {}).get('status', 0)} {str((result or {}).get('detail') or '')[:120]}"
            )
        except Exception as exc:
            self.log(f"[auth] Chromium 同源 fetch 创建{label}失败，回退浏览器原生表单 POST: {str(exc)[:160]}")
        before_url = str(getattr(page, "url", "") or "")
        try:
            page.evaluate(
                """({url, form}) => {
                    const node = document.createElement('form');
                    node.method = 'POST';
                    node.action = url;
                    for (const [name, value] of Object.entries(form)) {
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = name;
                        input.value = value;
                        node.appendChild(input);
                    }
                    document.body.appendChild(node);
                    node.submit();
                }""",
                {"url": request_url, "form": form},
            )
        except Exception:
            if str(getattr(page, "url", "") or "") == before_url:
                raise
        try:
            page.wait_for_load_state("domcontentloaded", timeout=30000)
        except Exception:
            pass
        current_url = str(getattr(page, "url", "") or "")
        if current_url.startswith(AUTH_BASE_URL):
            return current_url
        body = page.locator("body").inner_text(timeout=5000).strip()
        try:
            payload = json.loads(body)
        except Exception as exc:
            raise RuntimeError(f"浏览器打开{label}返回的不是 JSON: url={current_url} body={body[:240]}") from exc
        signin_url = str(payload.get("url") or "").strip()
        if not signin_url:
            raise RuntimeError(f"浏览器打开{label}缺少跳转 URL: {payload}")
        return signin_url

    @staticmethod
    def _is_nextauth_bootstrap_url(url: str) -> bool:
        try:
            parsed = urlsplit(str(url or ""))
        except Exception:
            return False
        return (
            str(parsed.hostname or "").lower() == "chatgpt.com"
            and str(parsed.path or "").startswith("/api/auth/signin")
        )

    def _create_provider_auth_url(self, context, screen_hint: str, label: str, page=None) -> str:
        first_url = self._create_auth_entry_url(
            context,
            screen_hint,
            label,
            page,
        )
        if not self._is_nextauth_bootstrap_url(first_url):
            return first_url
        second_url = self._create_auth_entry_url(
            context,
            screen_hint,
            label,
            page,
            force_browser_channel=True,
        )
        if self._is_nextauth_bootstrap_url(second_url):
            self.log(f"[auth] {label}第二阶段仍返回通用登录壳，保留页面兼容路径")
            return second_url
        return second_url

    def _create_openai_signin_url(self, context, page=None) -> str:
        return self._create_provider_auth_url(context, "login_or_signup", "认证页", page)

    def _create_login_url(self, context, page=None) -> str:
        return self._create_provider_auth_url(context, "login", "登录页", page)

    def _get_chatgpt_csrf_and_device(self, context, page=None) -> tuple[str, str]:
        self._auth_csrf_via_browser = False
        cookie_urls = [CHATGPT_BASE_URL, "https://openai.com"]
        navigation_status = 0

        def cookie_values() -> tuple[str, str]:
            cookie_csrf = ""
            cookie_device = ""
            for cookie in context.cookies(cookie_urls):
                if cookie.get("name") == "__Host-next-auth.csrf-token":
                    cookie_csrf = unquote(cookie.get("value", "")).split("|")[0]
                if cookie.get("name") == "oai-did":
                    cookie_device = str(cookie.get("value") or "")
            return cookie_csrf, cookie_device

        cookies = context.cookies(cookie_urls)
        csrf_value = ""
        device_id = ""
        for cookie in cookies:
            if cookie.get("name") == "__Host-next-auth.csrf-token":
                csrf_value = unquote(cookie.get("value", "")).split("|")[0]
            if cookie.get("name") == "oai-did":
                device_id = cookie.get("value", "")
        if not csrf_value and page is not None:
            diagnostics = []
            try:
                csrf_url = f"{CHATGPT_BASE_URL}/api/auth/csrf"
                response = None
                try:
                    response = page.goto(csrf_url, wait_until="commit", timeout=30000)
                except Exception as exc:
                    diagnostics.append(f"navigation={str(exc)[:100]}")
                    if not str(getattr(page, "url", "") or "").startswith(CHATGPT_BASE_URL):
                        raise

                source = ""
                if response is not None:
                    try:
                        status = int(getattr(response, "status", 0) or 0)
                    except Exception:
                        status = 0
                    navigation_status = status
                    diagnostics.append(f"response_status={status}")
                    try:
                        payload = response.json()
                    except Exception as exc:
                        diagnostics.append(f"response_json={type(exc).__name__}")
                        payload = {}
                    csrf_value = str(payload.get("csrfToken") or "").strip() if isinstance(payload, dict) else ""
                    if csrf_value:
                        source = "response"

                if not csrf_value:
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                    body = ""
                    try:
                        body = str(page.locator("body").inner_text(timeout=3000) or "").strip()
                    except Exception as exc:
                        diagnostics.append(f"dom={type(exc).__name__}")
                    if body:
                        try:
                            payload = json.loads(body)
                        except Exception as exc:
                            diagnostics.append(f"dom_json={type(exc).__name__}")
                            payload = {}
                        csrf_value = str(payload.get("csrfToken") or "").strip() if isinstance(payload, dict) else ""
                        if csrf_value:
                            source = "dom"
                    else:
                        diagnostics.append("dom=empty")

                if not csrf_value:
                    cookie_csrf, cookie_device = cookie_values()
                    csrf_value = cookie_csrf
                    device_id = device_id or cookie_device
                    if csrf_value:
                        source = "cookie"

                if (
                    not csrf_value
                    and str(getattr(page, "url", "") or "").startswith(CHATGPT_BASE_URL)
                    and navigation_status < 400
                ):
                    try:
                        result = page.evaluate(
                            """async () => {
                                const response = await fetch('/api/auth/csrf', {
                                    method: 'GET',
                                    credentials: 'include',
                                    cache: 'no-store',
                                    headers: { accept: 'application/json' },
                                });
                                const text = await response.text();
                                let payload = null;
                                try { payload = text ? JSON.parse(text) : null; } catch (_) {}
                                return {
                                    ok: response.ok,
                                    status: response.status,
                                    csrfToken: String((payload && payload.csrfToken) || ''),
                                    contentType: String(response.headers.get('content-type') || ''),
                                    bodyLength: text.length,
                                };
                            }"""
                        )
                    except Exception as exc:
                        diagnostics.append(f"fetch={type(exc).__name__}")
                        result = {}
                    csrf_value = str((result or {}).get("csrfToken") or "").strip()
                    diagnostics.append(
                        f"fetch_status={(result or {}).get('status', 0)} "
                        f"fetch_length={(result or {}).get('bodyLength', 0)}"
                    )
                    if csrf_value:
                        source = "fetch"
                elif not csrf_value and navigation_status >= 400:
                    diagnostics.append(f"fetch=skipped-after-http-{navigation_status}")

                if not csrf_value:
                    cookie_csrf, cookie_device = cookie_values()
                    csrf_value = cookie_csrf
                    device_id = device_id or cookie_device
                    if csrf_value:
                        source = "cookie-after-fetch"

                if csrf_value:
                    self._auth_csrf_via_browser = True
                    self.log(f"[auth] 已通过 Google Chrome 获取 CSRF: source={source}")
                else:
                    final_url = str(getattr(page, "url", "") or "")[:160]
                    self.log(f"[auth] Google Chrome CSRF 未返回 token: url={final_url}; {'; '.join(diagnostics)[:360]}")
            except Exception as exc:
                self.log(f"[auth] 浏览器 CSRF 小接口失败: {str(exc)[:160]}")
        current_csrf_url = str(getattr(page, "url", "") or "") if page is not None else ""
        if (
            not csrf_value
            and navigation_status == 403
            and "__cf_chl_rt_tk=" in current_csrf_url.lower()
            and bool(getattr(self.register_proxy, "dynamic_proxy", ""))
        ):
            self.log(
                "[auth] CSRF 入口返回 Cloudflare 403；保持当前 Google Chrome context、Cookie "
                "和注册代理继续同一会话回退"
            )
        if not csrf_value and page is not None:
            self.log("[auth] Google Chrome CSRF 未成功，复用当前 context、Cookie 和注册代理切换小接口回退")
        if not csrf_value:
            for attempt in range(1, 3):
                try:
                    response = context.request.get(
                        f"{CHATGPT_BASE_URL}/api/auth/csrf",
                        headers={"Accept": "application/json", "Accept-Language": self.fingerprint.accept_language, "Referer": f"{CHATGPT_BASE_URL}/"},
                        timeout=30000,
                    )
                    if response.ok:
                        payload = response.json()
                        csrf_value = str(payload.get("csrfToken") or "").strip()
                        if csrf_value:
                            break
                    status = int(getattr(response, "status", 0) or 0)
                    if attempt < 2 and (status == 429 or status >= 500):
                        self.log(f"[auth] CSRF 小接口返回 HTTP {status}，1 秒后重试 2/2")
                        self._wait_or_stop(1)
                        continue
                    break
                except Exception as exc:
                    if attempt < 2:
                        self.log(f"[auth] CSRF 小接口连接中断，1 秒后重试 2/2: {str(exc)[:160]}")
                        self._wait_or_stop(1)
                        continue
                    self.log(f"获取 ChatGPT CSRF 接口两次失败: {str(exc)[:160]}")
            if not csrf_value:
                cookies = context.cookies([CHATGPT_BASE_URL, "https://openai.com"])
                for cookie in cookies:
                    if cookie.get("name") == "__Host-next-auth.csrf-token":
                        csrf_value = unquote(cookie.get("value", "")).split("|")[0]
                        break
        if not device_id:
            cookies = context.cookies([CHATGPT_BASE_URL, "https://openai.com"])
            for cookie in cookies:
                if cookie.get("name") == "oai-did":
                    device_id = cookie.get("value", "")
                    break
        return csrf_value, device_id

    def _has_chatgpt_session(self, page) -> bool:
        cached_payload = getattr(self, "_confirmed_session_payload", None)
        if isinstance(cached_payload, dict) and cached_payload.get("accessToken"):
            return True
        pages = [page]
        try:
            for candidate in page.context.pages:
                if candidate not in pages:
                    pages.append(candidate)
        except Exception:
            pass
        for candidate in pages:
            try:
                candidate_url = str(candidate.url or "")
                if not candidate_url.startswith(CHATGPT_BASE_URL):
                    continue
                if bool(getattr(self, "_post_auth_navigation_rewritten", False)) or candidate_url.startswith(
                    f"{CHATGPT_BASE_URL}/api/auth/session"
                ):
                    try:
                        body = candidate.locator("body").inner_text(timeout=1000).strip()
                        payload = json.loads(body)
                        if isinstance(payload, dict) and payload.get("accessToken"):
                            self._confirmed_session_payload = dict(payload)
                            return True
                    except Exception:
                        pass
                payload = candidate.evaluate(
                    """async () => {
                        const resp = await fetch('/api/auth/session', { credentials: 'include' });
                        if (!resp.ok) return null;
                        return await resp.json();
                    }"""
                )
                if payload and payload.get("accessToken"):
                    self._confirmed_session_payload = dict(payload)
                    return True
            except Exception:
                continue
        return False

    def _context_has_chatgpt_page(self, page) -> bool:
        try:
            pages = list(page.context.pages)
        except Exception:
            pages = [page]
        for candidate in pages:
            try:
                if str(candidate.url or "").startswith(CHATGPT_BASE_URL):
                    return True
            except Exception:
                pass
        return False

    def _visible_inputs(self, page, selectors: list[str]):
        visible = []
        for selector in selectors:
            locator = page.locator(selector)
            try:
                count = min(locator.count(), 12)
            except Exception:
                continue
            for index in range(count):
                item = locator.nth(index)
                try:
                    if item.is_visible():
                        visible.append(item)
                except Exception:
                    pass
        return visible

    def _click_continue(self, page) -> bool:
        selectors = [
            'button:has-text("Finish creating account")',
            'button:has-text("Finalizar la creación de la cuenta")',
            'button:has-text("Finalizar la creacion de la cuenta")',
            'button[data-dd-action-name="Continue"][type="submit"]',
            'button:has-text("Continue")',
            'button:has-text("アカウントの作成を完了する")',
            'button:has-text("作成を完了")',
            'button:has-text("继续")',
            'button:has-text("完成帐户创建")',
            'button:has-text("完成账户创建")',
            'button:has-text("Next")',
            'button:has-text("下一步")',
            'button:has-text("Create")',
            'button:has-text("完成")',
            'button[type="submit"]',
            '[role="button"]:has-text("Finish creating account")',
            '[role="button"]:has-text("Finalizar la creación de la cuenta")',
            '[role="button"]:has-text("Finalizar la creacion de la cuenta")',
            '[role="button"]:has-text("Continue")',
            '[role="button"]:has-text("アカウントの作成を完了する")',
            '[role="button"]:has-text("作成を完了")',
        ]
        for selector in selectors:
            button = page.locator(selector).first
            try:
                if button.is_visible(timeout=700):
                    button.click(timeout=5000)
                    page.wait_for_load_state("domcontentloaded", timeout=10000)
                    return True
            except Exception:
                continue
        if self._click_submit_button_by_dom(page):
            page.wait_for_load_state("domcontentloaded", timeout=10000)
            return True
        return False

    def _click_submit_button_by_dom(self, page) -> bool:
        return bool(page.evaluate(
            """() => {
                const visible = (el) => {
                    const r = el.getBoundingClientRect();
                    const s = getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                };
                const buttons = Array.from(document.querySelectorAll('button, [role="button"]')).filter(visible);
                const button = buttons.find(el =>
                    (el.textContent || '').includes('Finish creating account')
                    || (el.textContent || '').includes('アカウントの作成を完了する')
                    || (el.textContent || '').includes('作成を完了')
                    || (el.textContent || '').includes('Continue')
                    || (el.textContent || '').includes('继续')
                    || (el.textContent || '').includes('完成帐户创建')
                    || (el.textContent || '').includes('完成账户创建')
                    || (el.textContent || '').includes('続行')
                    || (el.getAttribute('data-dd-action-name') || '') === 'Continue'
                    || (el.type || '').toLowerCase() === 'submit'
                );
                if (!button || button.getAttribute('aria-disabled') === 'true' || button.disabled) return false;
                button.scrollIntoView({ block: 'center', inline: 'center' });
                button.focus();
                const form = button.closest('form');
                if (form && typeof form.requestSubmit === 'function') {
                    const isSubmitButton = button instanceof HTMLButtonElement
                        && (button.type || '').toLowerCase() === 'submit';
                    if (isSubmitButton) form.requestSubmit(button);
                    else form.requestSubmit();
                    return true;
                }
                button.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, pointerType: 'mouse', isPrimary: true }));
                button.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }));
                button.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, pointerType: 'mouse', isPrimary: true }));
                button.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, button: 0 }));
                button.click();
                return true;
            }"""
        ))

    def _email_continue_state(self, page) -> dict:
        try:
            result = page.evaluate(
                """() => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"]')).filter(visible);
                    const button = buttons.find(el => {
                        const text = `${el.value || ''} ${el.textContent || ''} ${el.getAttribute('aria-label') || ''}`.trim();
                        return /continue|next|続行|次へ|继续|下一步|ログイン|log in|sign in/i.test(text)
                            || (el.type || '').toLowerCase() === 'submit';
                    });
                    if (!button) {
                        return { ready: false, found: false, disabled: false, ariaDisabled: null };
                    }
                    const ariaDisabled = button.getAttribute('aria-disabled');
                    return {
                        ready: !button.disabled && ariaDisabled !== 'true',
                        found: true,
                        disabled: Boolean(button.disabled),
                        ariaDisabled,
                    };
                }"""
            )
            if isinstance(result, dict):
                return {
                    "ready": bool(result.get("ready", False)),
                    "found": bool(result.get("found", False)),
                    "disabled": bool(result.get("disabled", False)),
                    "aria_disabled": result.get("ariaDisabled"),
                }
            return {"ready": bool(result), "found": True, "disabled": not bool(result), "aria_disabled": None}
        except Exception:
            return {"ready": True, "found": False, "disabled": False, "aria_disabled": None}

    def _email_continue_is_ready(self, page) -> bool:
        return bool(self._email_continue_state(page).get("ready", False))

    def _wait_email_continue_ready(self, page, timeout_seconds: float = 2.5) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout_seconds or 0.0))
        while True:
            if self._email_continue_is_ready(page):
                return True
            if time.monotonic() >= deadline:
                return False
            self._wait_or_stop(0.1)

    def _email_input_hydration_state(self, input_box) -> dict:
        try:
            result = input_box.evaluate(
                """el => {
                    const form = el ? (el.form || el.closest('form')) : null;
                    const submit = form
                        ? form.querySelector('button[type="submit"], input[type="submit"], button')
                        : null;
                    let node = el;
                    let marker = '';
                    while (node && !marker) {
                        marker = Object.getOwnPropertyNames(node).find(name =>
                            name === '_valueTracker'
                            || name.startsWith('__reactProps$')
                            || name.startsWith('__reactFiber$')
                            || name.startsWith('__reactContainer$')
                        ) || '';
                        node = node.parentElement;
                    }
                    return {
                        ready: Boolean(el && el.isConnected && !el.disabled && !el.readOnly && form),
                        connected: Boolean(el && el.isConnected),
                        marker,
                        value: String((el && el.value) || ''),
                        formFound: Boolean(form),
                        submitFound: Boolean(submit),
                        submitDisabled: Boolean(submit && (submit.disabled || submit.getAttribute('aria-disabled') === 'true')),
                    };
                }"""
            )
            if isinstance(result, dict):
                return {
                    "ready": bool(result.get("ready", False)),
                    "connected": bool(result.get("connected", False)),
                    "marker": str(result.get("marker") or "none"),
                    "value": str(result.get("value") or ""),
                    "form_found": bool(result.get("formFound", False)),
                    "submit_found": bool(result.get("submitFound", False)),
                    "submit_disabled": bool(result.get("submitDisabled", False)),
                }
        except Exception:
            pass
        # Test doubles and non-React controls may not expose DOM internals. Proceed
        # immediately so diagnostics never become a new blocker.
        return {
            "ready": True,
            "connected": True,
            "marker": "evaluation-unavailable",
            "value": self._input_value_safe(input_box),
            "form_found": True,
            "submit_found": True,
            "submit_disabled": False,
        }

    def _wait_email_input_hydrated(self, input_box, timeout_seconds: float = 1.0) -> dict:
        deadline = time.monotonic() + max(0.0, float(timeout_seconds or 0.0))
        state = self._email_input_hydration_state(input_box)
        while not state.get("ready", False) and time.monotonic() < deadline:
            self._wait_or_stop(0.05)
            state = self._email_input_hydration_state(input_box)
        state["timed_out"] = not bool(state.get("ready", False))
        return state

    def _input_value_safe(self, locator) -> str:
        try:
            return str(locator.input_value(timeout=500) or "")
        except TypeError:
            try:
                return str(locator.input_value() or "")
            except Exception:
                return ""
        except Exception:
            return ""

    def _input_disabled_safe(self, locator) -> bool:
        try:
            if bool(locator.is_disabled(timeout=500)):
                return True
        except TypeError:
            try:
                if bool(locator.is_disabled()):
                    return True
            except Exception:
                pass
        except Exception:
            pass
        for attr in ("disabled", "aria-disabled", "readonly"):
            try:
                value = locator.get_attribute(attr)
            except TypeError:
                try:
                    value = locator.get_attribute(attr, timeout=500)
                except Exception:
                    continue
            except Exception:
                continue
            if value == "" and attr == "disabled":
                return True
            if value is not None and str(value).lower() not in {"", "false", "0"}:
                return True
        return False

    def _reactivate_prefilled_email(self, input_box, target_email: str) -> bool:
        if self._input_disabled_safe(input_box):
            return False
        # React tracks the previous DOM value. Re-applying the same prefilled value does not
        # reliably update framework state, so perform one real clear-and-type sequence first.
        typed = False
        try:
            input_box.click(timeout=2000)
            input_box.press("Control+A", timeout=2000)
            input_box.press("Backspace", timeout=2000)
            input_box.type(target_email, delay=5, timeout=5000)
            typed = True
            return True
        except Exception:
            if typed:
                return True
        # Locator fallback is used by unusual controls that reject key events.
        try:
            input_box.fill(target_email)
            return True
        except Exception:
            return False

    def _retry_email_form_submit(self, page) -> bool:
        selector = (
            'form:has(input:is([type="email"], [name="email"], [name="username"], [autocomplete="email"])) '
            ':is(button[type="submit"], input[type="submit"]), '
            'button[data-dd-action-name="Continue"][type="submit"]'
        )
        try:
            submit = page.locator(selector).first
            if submit.is_visible(timeout=800) and submit.is_enabled(timeout=800):
                submit.click(timeout=3000)
                return True
        except Exception:
            pass
        try:
            result = page.evaluate(
                """() => {
                    const visible = (el) => {
                        if (!el) return false;
                        const rect = el.getBoundingClientRect();
                        const style = getComputedStyle(el);
                        return rect.width > 0 && rect.height > 0
                            && style.visibility !== 'hidden' && style.display !== 'none';
                    };
                    const input = Array.from(document.querySelectorAll(
                        'input[type="email"], input[name="email"], input[name="username"], input[autocomplete="email"]'
                    )).find(visible);
                    const form = input ? (input.form || input.closest('form')) : null;
                    const submit = form
                        ? Array.from(form.querySelectorAll('button[type="submit"], input[type="submit"], button')).find(visible)
                        : null;
                    if (submit && !submit.disabled && submit.getAttribute('aria-disabled') !== 'true') {
                        submit.click();
                        return { submitted: true, method: 'button-click' };
                    }
                    if (form && form.checkValidity() && typeof form.requestSubmit === 'function') {
                        form.requestSubmit();
                        return { submitted: true, method: 'request-submit' };
                    }
                    return {
                        submitted: false,
                        method: 'not-ready',
                        formFound: Boolean(form),
                        submitFound: Boolean(submit),
                        submitDisabled: Boolean(submit && (submit.disabled || submit.getAttribute('aria-disabled') === 'true')),
                    };
                }"""
            )
        except Exception as exc:
            self.log(f"[auth] 邮箱表单直接提交检查失败: {str(exc)[:120]}")
            return False
        if isinstance(result, dict) and result.get("submitted"):
            return True
        return False

    def _start_email_submission_wait(self, page_key: str) -> None:
        self._email_submission_page_key = page_key
        now = time.monotonic()
        self._email_submit_started_at = now
        self._email_submit_retry_count = 0
        self._email_stall_started = now

    def _reset_email_stall(self) -> None:
        self._email_stall_started = 0.0
        self._email_submit_started_at = 0.0
        self._email_submit_retry_count = 0

    def _restart_stalled_email_entry(self, page) -> bool:
        recovery_count = max(0, int(getattr(self, "_email_recovery_count", 0) or 0))
        if recovery_count >= 1:
            return False
        self._email_recovery_count = recovery_count + 1
        try:
            screen_hint = str(getattr(self, "_auth_screen_hint", "signup") or "signup").lower()
            if screen_hint == "login":
                entry_url = self._create_login_url(page.context, page)
                entry_label = "登录"
            else:
                entry_url = self._create_openai_signin_url(page.context, page)
                entry_label = "注册"
            if str(getattr(page, "url", "") or "").rstrip("/") != str(entry_url or "").rstrip("/"):
                page.goto(entry_url, wait_until="domcontentloaded", timeout=90000)
            else:
                page.reload(wait_until="domcontentloaded", timeout=90000)
            self._email_submission_page_key = None
            self._reset_email_stall()
            self.log(f"[auth] 邮箱真实提交后仍未跳转，已保持 {screen_hint} 模式重开一次{entry_label}入口")
            return True
        except Exception as exc:
            self.log(f"[auth] 重开认证入口失败，继续保留浏览器供手动处理: {str(exc)[:160]}")
            return False

    def _recover_stalled_email_if_due(
        self,
        page,
        timeout_seconds: float = 8.0,
    ) -> bool:
        now = time.monotonic()
        started = float(getattr(self, "_email_stall_started", 0.0) or 0.0)
        if started <= 0:
            self._email_stall_started = now
            return False
        if now - started < max(0.0, float(timeout_seconds or 0.0)):
            return False
        return self._restart_stalled_email_entry(page)

    def _email_page_key(self, page) -> str:
        url = str(getattr(page, "url", "") or "").strip()
        if not url:
            return f"page:{id(page)}"
        try:
            parsed = urlsplit(url)
            return f"{parsed.scheme.lower()}://{str(parsed.hostname or '').lower()}{parsed.path or '/'}"
        except Exception:
            return url.split("?", 1)[0].split("#", 1)[0]

    def _fill_email_if_visible(self, page) -> bool:
        page_key = self._email_page_key(page)
        if self._email_submission_page_key == page_key:
            try:
                pending_inputs = self._visible_inputs(page, [
                    'input[type="email"]',
                    'input[name="email"]',
                    'input[name="username"]',
                    'input[autocomplete="email"]',
                ])
            except Exception:
                pending_inputs = []
            if not pending_inputs:
                return self._recover_stalled_email_if_due(
                    page,
                    timeout_seconds=20.0,
                )
            started = float(getattr(self, "_email_submit_started_at", 0.0) or 0.0)
            elapsed = time.monotonic() - started if started > 0 else 0.0
            retry_count = max(0, int(getattr(self, "_email_submit_retry_count", 0) or 0))
            if started > 0 and elapsed >= 0.8 and retry_count < 1:
                self._email_submit_retry_count = retry_count + 1
                self._retry_email_form_submit(page)
                return False
            return self._recover_stalled_email_if_due(page, timeout_seconds=5.0)
        inputs = self._visible_inputs(page, [
            'input[type="email"]',
            'input[name="email"]',
            'input[name="username"]',
            'input[autocomplete="email"]',
        ])
        if not inputs:
            return self._recover_stalled_email_if_due(page) if getattr(self, "_email_stall_started", 0.0) else False
        target_email = str(self.account.email or "").strip()
        first_enabled_empty = None
        for input_box in inputs:
            value = self._input_value_safe(input_box).strip()
            disabled = self._input_disabled_safe(input_box)
            if value:
                if value.casefold() == target_email.casefold() or "@" in value:
                    self._wait_email_input_hydrated(input_box)
                    self._start_email_submission_wait(page_key)
                    self._reactivate_prefilled_email(input_box, target_email)
                    self._retry_email_form_submit(page)
                    return True
                if disabled:
                    continue
            if not disabled and first_enabled_empty is None:
                first_enabled_empty = input_box
        if first_enabled_empty is None:
            return False
        self._wait_email_input_hydrated(first_enabled_empty)
        self._start_email_submission_wait(page_key)
        self._reactivate_prefilled_email(first_enabled_empty, target_email)
        self._retry_email_form_submit(page)
        return True












    def _has_visible_password(self, page) -> bool:
        return bool(self._visible_inputs(page, ['input[type="password"]', 'input[name="password"]']))

    def _has_register_phone_number_form(self, page) -> bool:
        """Detect OpenAI registration phone-verification screens.

        手机号自动取码已删除，但注册流程仍要能识别手机号验证页；
        否则基础资料提交后的等待逻辑会调用缺失方法导致 Worker 崩掉。
        """
        try:
            url = str(getattr(page, "url", "") or "").lower()
            if "add-phone" in url or "phone-verification" in url:
                return True
            text = page.locator("body").inner_text(timeout=1000).lower()
            has_phone_text = (
                "phone number" in text
                or "verify your phone" in text
                or "phone verification" in text
                or "sms" in text
                or "手机号" in text
                or "手机号码" in text
                or "电话验证" in text
                or "電話番号" in text
            )
            if not has_phone_text:
                return False
            return bool(self._visible_inputs(page, [
                'input[type="tel"]',
                'input[name*="phone" i]',
                'input[id*="phone" i]',
                'input[autocomplete="tel"]',
                'input[inputmode="tel"]',
            ]))
        except Exception:
            return False

    def _looks_like_register_phone_code_page(self, page) -> bool:
        """Return True for phone/SMS code pages so they are not handled as email OTP."""
        try:
            url = str(getattr(page, "url", "") or "").lower()
            text = page.locator("body").inner_text(timeout=1000).lower()
            has_phone_context = (
                "phone-verification" in url
                or "add-phone" in url
                or "phone" in text
                or "sms" in text
                or "手机号" in text
                or "手机号码" in text
                or "電話番号" in text
            )
            if not has_phone_context:
                return False
            has_code_context = (
                "code" in text
                or "verification" in text
                or "验证码" in text
                or "認証コード" in text
                or "確認コード" in text
            )
            if not has_code_context:
                return False
            return bool(self._visible_inputs(page, [
                'input[autocomplete="one-time-code"]',
                'input[inputmode="numeric"]',
                'input[type="tel"]',
                'input[name="code"]',
                'input[aria-label*="code" i]',
                'input[placeholder*="code" i]',
                'input[aria-label*="验证码" i]',
                'input[placeholder*="验证码" i]',
            ]))
        except Exception:
            return False

    def _password_page_route(self, page) -> str:
        url = str(getattr(page, "url", "") or "").lower()
        page_type = str(getattr(self, "_last_authorize_page_type", "") or "").lower()
        if "create-account/password" in url or page_type == "create_account_password":
            return "new_password_signup"
        if "log-in/password" in url or "/login/password" in url or page_type == "login_password":
            return "existing_password_login"
        try:
            text = page.locator("body").inner_text(timeout=700).lower()
        except Exception:
            text = ""
        if any(marker in text for marker in ("create your account", "create account", "アカウントを作成", "创建账户")):
            return "new_password_signup"
        if any(marker in text for marker in ("log in", "sign in", "ログイン", "登录")):
            return "existing_password_login"
        route = str(getattr(self, "auth_route", "") or "")
        if route in {"new_password_signup", "existing_password_login"}:
            return route
        raise RuntimeError("无法确认当前密码页属于新号注册还是已有账号登录，已停止避免走错分支")

    def _select_password_auth_mode_if_visible(self, page) -> bool:
        if self._has_visible_password(page):
            return False
        page_key = self._email_page_key(page)
        if page_key == str(getattr(self, "_password_mode_selection_page_key", "") or ""):
            return False
        try:
            box = page.evaluate(
                r"""() => {
                    const visible = el => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0
                            && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const include = /continue with password|use password|sign up with password|create password|password instead|パスワードを使用|パスワードで続行|密码登录|使用密码|使用密碼|continuar con contraseña|continuer avec un mot de passe/i;
                    const exclude = /forgot|reset|忘れ|重置|找回|olvid|oubli/i;
                    const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
                        .filter(visible)
                        .filter(el => {
                            const text = `${el.textContent || ''} ${el.getAttribute('aria-label') || ''}`.replace(/\s+/g, ' ').trim();
                            return include.test(text) && !exclude.test(text);
                        });
                    const el = candidates[0];
                    if (!el || el.disabled || el.getAttribute('aria-disabled') === 'true') return null;
                    el.scrollIntoView({ block: 'center', inline: 'center' });
                    const r = el.getBoundingClientRect();
                    return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
                }"""
            )
        except Exception:
            box = None
        if not box:
            return False
        self._password_mode_selection_page_key = page_key
        page.mouse.click(float(box["x"]), float(box["y"]))
        self._set_auth_traffic_stage("密码方式选择")
        self.log("[认证] 已通过真实鼠标选择密码注册/登录方式")
        return True

    def _type_password_trusted(self, input_box, value: str) -> bool:
        try:
            input_box.click(timeout=3000)
            input_box.press("Control+A", timeout=2000)
            input_box.press("Backspace", timeout=2000)
            input_box.type(str(value), delay=8, timeout=10000)
            return True
        except Exception:
            return self._force_fill_locator(input_box, value)

    def _fill_password_step(self, page) -> None:
        route = self._password_page_route(page)
        if route == "new_password_signup":
            self._set_auth_traffic_stage("新号密码注册")
            self.is_new_account = True
            self._set_auth_route(route)
            openai_password = self._ensure_new_openai_password()
            self._log_password_step_once("新号密码注册步骤：使用独立保存的 OpenAI 密码")
        else:
            self._set_auth_traffic_stage("已有账号密码登录")
            self.is_new_account = False
            self._set_auth_route(route)
            openai_password = self._existing_openai_password()
            self._log_password_step_once("已有账号密码登录步骤：使用已保存的 OpenAI 密码")

        inputs = self._visible_inputs(page, ['input[type="password"]', 'input[name="password"]'])
        if not inputs:
            raise RuntimeError("进入密码步骤但未找到密码输入框")
        for input_box in inputs:
            if not self._type_password_trusted(input_box, openai_password):
                raise RuntimeError("OpenAI 密码未能通过真实键盘事件填写")
        if not self._click_continue(page):
            raise RuntimeError("密码已填写，但未找到继续按钮")

    def _log_password_step_once(self, message: str) -> None:
        if self._password_step_log_emitted:
            return
        self._password_step_log_emitted = True
        self.log(message)

    def _generate_password(self) -> str:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        suffix = "!A7"
        return "".join(random.choice(alphabet) for _ in range(13)) + suffix

    def _chatgpt_page_for_mfa(self, context):
        for candidate in list(getattr(context, "pages", []) or []):
            try:
                if str(candidate.url or "").startswith(CHATGPT_BASE_URL):
                    return candidate
            except Exception:
                continue
        page = context.new_page()
        page.goto(f"{CHATGPT_BASE_URL}/api/auth/session", wait_until="domcontentloaded", timeout=60000)
        return page

    def _browser_chatgpt_json(
        self,
        page,
        path: str,
        method: str = "GET",
        payload: dict | None = None,
        access_token: str = "",
        action: str = "ChatGPT 接口",
    ) -> dict:
        if not str(getattr(page, "url", "") or "").startswith(CHATGPT_BASE_URL):
            page.goto(f"{CHATGPT_BASE_URL}/api/auth/session", wait_until="domcontentloaded", timeout=60000)
        result = page.evaluate(
            """async ({path, method, payload, accessToken}) => {
                const headers = { accept: 'application/json' };
                if (payload !== null) headers['content-type'] = 'application/json';
                if (accessToken) headers.authorization = `Bearer ${accessToken}`;
                const response = await fetch(path, {
                    method,
                    credentials: 'include',
                    headers,
                    body: payload === null ? undefined : JSON.stringify(payload),
                });
                const text = await response.text();
                let data = null;
                try { data = text ? JSON.parse(text) : {}; } catch (_) {}
                return { ok: response.ok, status: response.status, data, detail: text.slice(0, 240) };
            }""",
            {
                "path": str(path or ""),
                "method": str(method or "GET").upper(),
                "payload": payload,
                "accessToken": str(access_token or ""),
            },
        )
        if not isinstance(result, dict) or not result.get("ok"):
            status = int((result or {}).get("status", 0) or 0) if isinstance(result, dict) else 0
            detail = str((result or {}).get("detail") or "")[:160] if isinstance(result, dict) else ""
            raise RuntimeError(f"{action}失败: HTTP {status} {detail}".strip())
        data = result.get("data")
        return data if isinstance(data, dict) else {}

    def _confirmed_session_for_mfa(self, context) -> dict:
        page = self._chatgpt_page_for_mfa(context)
        self._mfa_browser_page = page
        payload = getattr(self, "_confirmed_session_payload", None)
        if not isinstance(payload, dict) or not payload.get("accessToken"):
            payload = self._browser_chatgpt_json(
                page,
                "/api/auth/session",
                action="MFA 初始化读取 Session",
            )
        if not isinstance(payload, dict) or not payload.get("accessToken"):
            raise RuntimeError("MFA 初始化缺少有效登录 Session")
        self._confirmed_session_payload = dict(payload)
        return dict(payload)

    def _persist_mfa_fields(self, fields: dict[str, str]) -> None:
        clean = {
            str(key): str(value)
            for key, value in dict(fields or {}).items()
            if key in {"mfa_totp_secret", "mfa_recovery_code", "mfa_enrollment_state", "mfa_enrolled_at"}
            and value not in (None, "")
        }
        if not clean:
            return
        self._mfa_result.update(clean)
        if "mfa_totp_secret" in clean:
            self.mfa_totp_secret = clean["mfa_totp_secret"]
        if "mfa_recovery_code" in clean:
            self.mfa_recovery_code = clean["mfa_recovery_code"]
        if self.mfa_persist_callback:
            self.mfa_persist_callback(dict(clean))

    def _ensure_totp_mfa(self, context) -> None:
        self._set_auth_traffic_stage("MFA状态")
        session = self._confirmed_session_for_mfa(context)
        page = getattr(self, "_mfa_browser_page", None)
        if page is None:
            raise RuntimeError("MFA 初始化缺少 ChatGPT 浏览器页面")
        access_token = str(session.get("accessToken") or "")
        info = self._browser_chatgpt_json(
            page,
            "/backend-api/accounts/mfa_info",
            access_token=access_token,
            action="读取 MFA 状态",
        )
        factors = info.get("factors") if isinstance(info.get("factors"), dict) else {}
        totp_factors = factors.get("totp") if isinstance(factors.get("totp"), list) else []
        server_mfa_enabled = bool(info.get("mfa_enabled")) and bool(totp_factors)
        if server_mfa_enabled:
            if not self.mfa_totp_secret:
                raise MfaRequiredError(
                    "服务器已启用 MFA，但本地没有该账号的 TOTP 密钥；解除旧 MFA 后重新登录即可自动绑定",
                    status="MFA密钥缺失",
                )
            self._persist_mfa_fields({"mfa_enrollment_state": "enabled"})
            self.log("[MFA] 已复用该账号本地保存的认证器密钥")
            return
        self._complete_totp_mfa_enrollment(page, access_token)

    def _complete_totp_mfa_enrollment(self, page, access_token: str) -> None:
        self._set_auth_traffic_stage("MFA绑定")
        enrollment = self._browser_chatgpt_json(
            page,
            "/backend-api/accounts/mfa/enroll",
            method="POST",
            payload={"factor_type": "totp"},
            access_token=access_token,
            action="TOTP enrollment",
        )
        secret = str(enrollment.get("secret") or "").strip()
        session_id = str(enrollment.get("session_id") or "").strip()
        if not secret or not session_id:
            raise RuntimeError("TOTP enrollment 响应缺少密钥或 session_id")
        generate_totp_code(secret)

        self._persist_mfa_fields({
            "mfa_totp_secret": secret,
            "mfa_enrollment_state": "pending_totp_activation",
        })
        remaining = 30.0 - (time.time() % 30.0)
        if remaining < 3.0:
            self._wait_or_stop(remaining + 0.25)
        self._set_auth_traffic_stage("MFA激活")
        activated = self._browser_chatgpt_json(
            page,
            "/backend-api/accounts/mfa/user/activate_enrollment",
            method="POST",
            payload={
                "code": generate_totp_code(secret),
                "factor_type": "totp",
                "session_id": session_id,
            },
            access_token=access_token,
            action="TOTP 激活",
        )
        if activated.get("success") is not True:
            raise RuntimeError("TOTP 激活接口未确认 success=true")

        self._set_auth_traffic_stage("MFA复核")
        confirmed_info = self._browser_chatgpt_json(
            page,
            "/backend-api/accounts/mfa_info",
            access_token=access_token,
            action="MFA 启用状态复核",
        )
        confirmed_factors = confirmed_info.get("factors") if isinstance(confirmed_info.get("factors"), dict) else {}
        confirmed_totp = confirmed_factors.get("totp") if isinstance(confirmed_factors.get("totp"), list) else []
        if not bool(confirmed_info.get("mfa_enabled")) or not confirmed_totp:
            raise RuntimeError("TOTP 激活后 mfa_info 未确认 MFA 已启用")
        self._persist_mfa_fields({
            "mfa_enrollment_state": "enabled",
            "mfa_enrolled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
        confirmed = getattr(self, "_confirmed_session_payload", None)
        if isinstance(confirmed, dict) and isinstance(confirmed.get("user"), dict):
            confirmed["user"] = {**confirmed["user"], "mfa": True}
        self.log("[MFA] 已按 enroll → activate → mfa_info 完成认证器绑定并保存独立密钥")

    def _submit_authenticator_mfa_code(self, page) -> None:
        secret = str(self.mfa_totp_secret or "").strip()
        if not secret:
            raise MfaRequiredError("当前账号缺少本地 TOTP 密钥", status="MFA密钥缺失")
        remaining = 30.0 - (time.time() % 30.0)
        if remaining < 2.0:
            self._wait_or_stop(remaining + 0.25)
        code = generate_totp_code(secret)
        inputs = self._visible_inputs(page, [
            'input[autocomplete="one-time-code"]',
            'input[inputmode="numeric"]',
            'input[type="number"]',
            'input[type="tel"]',
            'input[name="code"]',
        ])
        if not inputs:
            raise MfaRequiredError("认证器 MFA 页面未找到动态码输入框")
        if len(inputs) >= 6:
            for index, char in enumerate(code):
                inputs[index].fill(char)
        elif not self._force_fill_locator(inputs[0], code):
            raise MfaRequiredError("认证器 MFA 动态码输入失败")
        if not self._click_continue(page):
            try:
                inputs[0].press("Enter")
            except Exception as exc:
                raise MfaRequiredError("认证器 MFA 动态码已填写，但未找到提交按钮") from exc
        self.log("[MFA] 已自动生成并提交认证器动态码")

        started = time.time()
        while time.time() - started < 20.0:
            if self._has_chatgpt_session(page) or self._context_has_chatgpt_page(page):
                return
            url = str(getattr(page, "url", "") or "").lower()
            if "mfa-challenge" not in url and "/mfa/" not in url:
                return
            try:
                body = page.locator("body").inner_text(timeout=500).lower()
            except Exception:
                body = ""
            if any(marker in body for marker in (
                "incorrect code", "invalid code", "コードが正しく", "验证码不正确", "驗證碼不正確",
            )):
                raise MfaRequiredError("认证器动态码被服务器判定为无效")
            self._wait_or_stop(0.5)
        raise MfaRequiredError("认证器动态码提交后页面未在 20 秒内完成跳转")

    def _is_authenticator_mfa_page(self, page) -> bool:
        url = str(getattr(page, "url", "") or "").lower()
        if "mfa-challenge" not in url and "/mfa/" not in url:
            return False
        try:
            text = page.locator("body").inner_text(timeout=1000).lower()
        except Exception:
            return False
        markers = (
            "authenticator app",
            "authentication app",
            "認証アプリ",
            "身份验证器",
            "身份驗證器",
            "驗證器應用程式",
            "ワンタイム認証コード",
        )
        return any(marker in text for marker in markers)

    def _is_email_mfa_page(self, page) -> bool:
        url = str(getattr(page, "url", "") or "").lower()
        if "mfa-challenge" not in url and "/mfa/" not in url:
            return False
        if self._is_authenticator_mfa_page(page):
            return False
        try:
            text = page.locator("body").inner_text(timeout=1000).lower()
        except Exception:
            return False
        markers = (
            "check your email", "email code", "code sent to your email",
            "メールを確認", "メールに送信", "メールで受け取ったコード",
            "检查你的邮箱", "邮箱验证码", "发送到邮箱",
            "檢查你的電子郵件", "電子郵件驗證碼", "傳送到電子郵件",
        )
        if not any(marker in text for marker in markers):
            return False
        return bool(self._visible_inputs(page, [
            'input[autocomplete="one-time-code"]',
            'input[inputmode="numeric"]',
            'input[name="code"]',
        ]))

    def _submit_mfa_email_code(self, page, min_timestamp: float) -> None:
        self.log("等待 MFA 邮箱验证码")
        self._ensure_otp_reader_for_email_challenge()
        code = self.otp_reader.wait_for_code(min_timestamp)
        inputs = self._visible_inputs(page, [
            'input[autocomplete="one-time-code"]',
            'input[inputmode="numeric"]',
            'input[type="tel"]',
            'input[name="code"]',
        ])
        if not inputs:
            raise MfaRequiredError("MFA 邮箱验证页未找到验证码输入框")
        if len(inputs) >= 6:
            for index, char in enumerate(code[:6]):
                inputs[index].fill(char)
        else:
            inputs[0].fill(code)
        if not self._click_continue(page):
            try:
                inputs[0].press("Enter")
            except Exception as exc:
                raise MfaRequiredError("MFA 邮箱验证码已填写，但未找到提交按钮") from exc
        self.log("已通过浏览器提交 MFA 邮箱验证码")
        self._wait_after_mfa_submit(page)

    def _wait_after_mfa_submit(self, page, timeout: float = 20.0) -> None:
        started = time.time()
        while time.time() - started < max(0.0, float(timeout or 0.0)):
            if self._has_chatgpt_session(page) or self._context_has_chatgpt_page(page):
                return
            url = str(getattr(page, "url", "") or "").lower()
            if "mfa-challenge" not in url and "/mfa/" not in url:
                return
            if self._is_authenticator_mfa_page(page):
                return
            self._wait_or_stop(0.5)
        summary = self._page_text_summary(page)
        raise MfaRequiredError(f"MFA 邮箱验证码提交后仍未完成验证: {summary}")

    def _has_otp_input(self, page) -> bool:
        if "about-you" in page.url or self._has_about_you_form(page):
            return False
        if self._is_authenticator_mfa_page(page):
            return False
        if self._looks_like_register_phone_code_page(page):
            return False
        return bool(self._visible_inputs(page, [
            'input[autocomplete="one-time-code"]',
            'input[name="code"]',
            'input[aria-label*="code" i]',
            'input[placeholder*="code" i]',
            'input[aria-label*="验证码" i]',
            'input[placeholder*="验证码" i]',
        ]))

    def _resend_email_otp(self, page) -> bool:
        selectors = [
            'button:has-text("メールを再送信する")',
            'button:has-text("Resend email")',
            'button:has-text("Resend")',
            'button:has-text("重新发送邮件")',
            'button:has-text("重新发送")',
            'button:has-text("再送信")',
            '[role="button"]:has-text("メールを再送信する")',
            '[role="button"]:has-text("Resend")',
            '[role="button"]:has-text("重新发送")',
        ]
        for selector in selectors:
            button = page.locator(selector).first
            try:
                if button.is_visible(timeout=700) and button.is_enabled(timeout=700):
                    button.click(timeout=5000)
                    return True
            except Exception:
                continue
        return False

    def _submit_email_code(self, page, min_timestamp: float) -> None:
        self.log("等待 OpenAI 邮箱验证码")
        self._ensure_otp_reader_for_email_challenge()
        submitted_codes: set[str] = set()
        retry_attempted = False
        while True:
            if isinstance(self.otp_reader, UrlOtpReader):
                code = self.otp_reader.wait_for_code(
                    min_timestamp,
                    resend_callback=None,
                    initial_delay=(
                        URL_OTP_RETRY_FETCH_DELAY_SECONDS
                        if retry_attempted
                        else URL_OTP_FIRST_FETCH_DELAY_SECONDS
                    ),
                )
            else:
                code = self.otp_reader.wait_for_code(min_timestamp)
            if code in submitted_codes:
                raise RuntimeError("邮箱取码服务重复返回已提交验证码")
            submitted_codes.add(code)
            try:
                self._submit_email_code_once(page, code)
                return
            except InvalidEmailOtpError:
                if retry_attempted or not isinstance(self.otp_reader, UrlOtpReader):
                    raise
                retry_attempted = True
                self.otp_reader.mark_current_codes_seen()
                if not self._resend_email_otp(page):
                    raise RuntimeError("邮箱验证码无效，且页面未找到可用的重发按钮")
                min_timestamp = time.time()
                self.log("邮箱验证码无效，已重发并丢弃全部旧码；等待不同的新码后重试一次")

    def _submit_email_code_once(self, page, code: str) -> None:
        inputs = self._visible_inputs(page, [
            'input[autocomplete="one-time-code"]',
            'input[inputmode="numeric"]',
            'input[type="tel"]',
            'input[name="code"]',
        ])
        if not inputs:
            raise RuntimeError("页面未找到验证码输入框")
        if len(inputs) >= 6:
            for index, char in enumerate(code[:6]):
                inputs[index].fill(char)
        else:
            inputs[0].fill(code)
        failed_submit_requests: list[str] = []

        def record_failed_submit(request) -> None:
            request_url = str(getattr(request, "url", "") or "")
            if "/api/accounts/email-otp/validate" not in request_url:
                return
            failure = getattr(request, "failure", "")
            if callable(failure):
                failure = failure()
            failed_submit_requests.append(f"{request_url} => {str(failure or 'request failed')[:180]}")

        listener_installed = False
        try:
            page.on("requestfailed", record_failed_submit)
            listener_installed = True
        except Exception:
            pass
        try:
            submitted_by_browser = self._click_continue(page)
            if submitted_by_browser:
                self.log("已通过有头浏览器点击提交邮箱验证码")
            else:
                try:
                    inputs[-1].press("Enter")
                    submitted_by_browser = True
                    self.log("已通过有头浏览器按 Enter 提交邮箱验证码")
                except Exception as exc:
                    raise RuntimeError("邮箱验证码已填写，但未找到可用的真实浏览器提交控件") from exc
            self._wait_after_otp_submit(page)
        except ProxyExitCheckError:
            raise
        except Exception as exc:
            detail = str(exc or "")
            network_markers = (
                "failed to fetch", "err_connection", "err_tunnel", "10053", "10054",
                "connection closed", "connection reset", "proxy connect",
            )
            if failed_submit_requests or any(marker in detail.lower() for marker in network_markers):
                failed_detail = failed_submit_requests[-1] if failed_submit_requests else detail
                raise ProxyExitCheckError(
                    f"邮箱验证码浏览器提交被代理连接中断: {failed_detail[:300]}",
                    "代理检测失败",
                ) from exc
            raise
        finally:
            if listener_installed:
                try:
                    page.remove_listener("requestfailed", record_failed_submit)
                except Exception:
                    try:
                        page.off("requestfailed", record_failed_submit)
                    except Exception:
                        pass

    def _wait_after_otp_submit(self, page, timeout: int = 20) -> None:
        started = time.time()
        while time.time() - started < timeout:
            if str(getattr(self, "_fatal_auth_error", "") or ""):
                raise RuntimeError(self._fatal_auth_error)
            if self._has_chatgpt_session(page):
                return
            if self._context_has_chatgpt_page(page):
                self._wait_or_stop(1)
                continue
            if "about-you" in page.url or self._has_about_you_form(page):
                return
            if not ("email-verification" in page.url or self._has_otp_input(page)):
                return
            page_text = self._page_text_summary(page).lower()
            if any(marker in page_text for marker in (
                "incorrect code", "invalid code", "code is incorrect",
                "验证码不正确", "验证码无效", "驗證碼不正確", "驗證碼無效",
                "コードが正しく", "無効なコード",
            )):
                raise InvalidEmailOtpError("邮箱验证码被服务器判定为无效")
            self._wait_or_stop(1)
        if self._context_has_chatgpt_page(page):
            self.log("邮箱验证码提交后已打开 ChatGPT 页面，继续等待 session 生效")
            return
        page_text = self._page_text_summary(page)
        raise RuntimeError(f"验证码提交后页面仍停留在邮箱验证页，可能验证码已过期/已使用或页面校验失败。页面内容: {page_text}")

    def _page_text_summary(self, page, max_length: int = 300) -> str:
        try:
            text = page.locator("body").inner_text(timeout=1500)
        except Exception:
            return page.url
        text = re.sub(r"\s+", " ", text).strip()
        return text[:max_length] or page.url

    def _has_about_you_form(self, page) -> bool:
        try:
            text = page.locator("body").inner_text(timeout=1000).lower()
            has_about_text = (
                "tell us about you" in text
                or "about you" in text
                or "birth" in text
                or "how old are you" in text
                or "full name" in text
                or "finish creating account" in text
                or "confirmemos tu edad" in text
                or "fecha de nacimiento" in text
                or "nombre y apellidos" in text
                or "finalizar la creación de la cuenta" in text
                or "finalizar la creacion de la cuenta" in text
                or "date de naissance" in text
                or "nom complet" in text
                or "terminer la création du compte" in text
                or "terminer la creation du compte" in text
                or "生まれた年" in text
                or "生年" in text
                or "年齢" in text
                or "アカウントの作成を完了する" in text
                or "出生年" in text
                or "年龄" in text
            )
            if not has_about_text:
                return False
            try:
                return len(self._visible_inputs(page, ['input', 'textarea', 'select', '[contenteditable="true"]'])) >= 2
            except Exception:
                return True
        except Exception:
            return False

    def _fill_about_you(self, page) -> None:
        name, birthdate = random_profile()
        birth_year = str(birthdate.split("-")[0])
        age = str(max(18, datetime.now(timezone.utc).year - int(birth_year)))
        self.log(f"填写基础资料: {name} / birthdate={birthdate}")
        self._wait_for_about_you_inputs(page)
        self._fill_about_you_inputs(page, name, birthdate, birth_year, age)
        self._wait_or_stop(1.5)
        if not self._submit_about_you(page):
            raise RuntimeError("基础资料已填写，但未找到“完成帐户创建”按钮")
        self.log("基础资料已提交")

    def _about_you_submit_done(self, page, before_url: str) -> bool:
        if page.is_closed():
            raise RuntimeError("浏览器页面已关闭，无法等待基础资料提交结果")
        current_url = page.url
        if self._has_chatgpt_session(page):
            return True
        if current_url != before_url:
            return True
        if "add-phone" in current_url or "phone-verification" in current_url:
            return True
        if self._has_register_phone_number_form(page):
            return True
        if self._has_visible_password(page):
            return True
        return not self._has_about_you_form(page)

    def _about_you_form_state(self, page) -> dict:
        try:
            return dict(page.evaluate(
                """() => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"]')).filter(visible);
                    const button = buttons.find(el => {
                        const text = `${el.value || ''} ${el.textContent || ''} ${el.getAttribute('aria-label') || ''}`.trim();
                        return /finish creating account|finalizar|アカウントの作成を完了|作成を完了|完成账户创建|完成帐户创建|create account|continue/i.test(text)
                            || (el.type || '').toLowerCase() === 'submit';
                    });
                    const requiredUnchecked = Array.from(document.querySelectorAll('input[type="checkbox"]'))
                        .filter(el => visible(el) && !el.checked && (el.required || el.getAttribute('aria-required') === 'true'))
                        .map(el => el.name || el.id || 'checkbox');
                    const invalidFields = Array.from(document.querySelectorAll('input, textarea, select'))
                        .filter(el => visible(el) && !el.checkValidity())
                        .map(el => el.name || el.id || el.getAttribute('aria-label') || el.type || 'field');
                    const alerts = Array.from(document.querySelectorAll('[role="alert"], .error, [data-testid*="error"]'))
                        .filter(visible)
                        .map(el => (el.textContent || '').trim())
                        .filter(Boolean);
                    return {
                        button_found: !!button,
                        button_text: button ? `${button.value || ''} ${button.textContent || ''}`.trim() : '',
                        button_disabled: !!(button && button.disabled),
                        button_aria_disabled: !!(button && button.getAttribute('aria-disabled') === 'true'),
                        form_valid: invalidFields.length === 0 && requiredUnchecked.length === 0,
                        required_unchecked: requiredUnchecked,
                        invalid_fields: invalidFields,
                        alerts,
                        date_segments: []
                    };
                }"""
            ) or {})
        except Exception:
            return {
                "button_found": False,
                "button_text": "",
                "button_disabled": False,
                "button_aria_disabled": False,
                "form_valid": True,
                "required_unchecked": [],
                "invalid_fields": [],
                "alerts": [],
                "date_segments": [],
            }

    def _ensure_about_you_required_consents(self, page) -> int:
        try:
            boxes = page.evaluate(
                """() => { /* about-you-consent-checkboxes */
                    return Array.from(document.querySelectorAll('input[type="checkbox"]')).map((el, index) => {
                    const label = el.closest('label')?.textContent || (el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`)?.textContent || '' : '');
                    return {
                        index,
                        name: el.name || '',
                        id: el.id || '',
                        label,
                        required: !!el.required || el.getAttribute('aria-required') === 'true',
                        checked: !!el.checked,
                        disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true'
                    };
                    });
                }"""
            ) or []
        except Exception:
            return 0
        checked = 0
        locator = page.locator('input[type="checkbox"]')
        for item in boxes:
            label = str(item.get("label") or "")
            name = str(item.get("name") or "")
            ident = str(item.get("id") or "")
            haystack = f"{name} {ident} {label}".lower()
            optional = any(word in haystack for word in ("optional", "marketing", "newsletter", "product news", "营销", "行銷"))
            requiredish = bool(item.get("required")) or any(
                word in haystack
                for word in ("required", "mandatory", "personal", "privacy", "terms", "必須", "同意", "개인")
            )
            if optional or not requiredish or item.get("checked") or item.get("disabled"):
                continue
            try:
                locator.nth(int(item.get("index"))).check(timeout=3000)
                checked += 1
            except Exception as exc:
                if hasattr(self, "log"):
                    self.log(f"基础资料必选同意勾选失败: {str(exc)[:120]}")
        return checked

    def _confirm_about_you_age_fallback_if_visible(self, page) -> bool:
        try:
            return bool(page.evaluate(
                """() => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const buttons = Array.from(document.querySelectorAll('button, [role="button"]')).filter(visible);
                    const button = buttons.find(el => /confirm|continue|ok|はい|確認|同意|继续|确定/i.test(el.textContent || el.getAttribute('aria-label') || ''));
                    if (!button || button.disabled || button.getAttribute('aria-disabled') === 'true') return false;
                    button.click();
                    return true;
                }"""
            ))
        except Exception:
            return False

    def _reactivate_about_you_inputs(self, page) -> int:
        """Emit trusted keyboard events without changing the visible values."""
        try:
            controls = self._visible_inputs(page, ['input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"])'])
        except Exception:
            return 0
        touched = 0
        for control in controls[:4]:
            try:
                value = str(control.input_value(timeout=1000) or "")
                if not value:
                    continue
                input_type = str(control.get_attribute("type") or "text").lower()
                control.click(timeout=2000)
                if input_type == "number":
                    control.press("ArrowUp", timeout=2000)
                    control.press("ArrowDown", timeout=2000)
                else:
                    control.press("End", timeout=2000)
                    control.press("Backspace", timeout=2000)
                    control.type(value[-1], delay=40, timeout=2000)
                control.press("Tab", timeout=2000)
                touched += 1
            except Exception as exc:
                self.log(f"基础资料输入状态重激活失败: {str(exc)[:120]}")
        return touched

    def _submit_about_you(self, page, timeout: float = 90) -> bool:
        self._ensure_about_you_required_consents(page)
        self._reactivate_about_you_inputs(page)
        state = self._about_you_form_state(page)
        if state.get("button_found") and (state.get("button_disabled") or state.get("button_aria_disabled")):
            raise RuntimeError("基础资料提交按钮不可用")
        if state.get("required_unchecked"):
            raise RuntimeError(f"基础资料仍有必选项未勾选: {state.get('required_unchecked')}")
        before_url = page.url
        submission_requests: list[str] = []
        failed_submission_requests: list[str] = []
        submission_responses: list[str] = []
        submission_response_errors: list[str] = []
        submission_continue_urls: list[str] = []
        auxiliary_submission_requests: list[str] = []
        auxiliary_submission_responses: list[str] = []
        sentinel_response_errors: list[str] = []
        browser_submit_diagnostics: list[str] = []
        sentinel_inflight = 0
        sentinel_wait_logged = False

        def submission_request_info(request) -> tuple[str, str]:
            method = str(getattr(request, "method", "") or "").upper()
            url = str(getattr(request, "url", "") or "")
            lowered = url.lower()
            telemetry_markers = (
                "/awe/api/v2/rum",
                "datadoghq.",
                "/telemetry",
                "/rum?",
                "sentry.io/",
            )
            if method in {"", "GET", "HEAD", "OPTIONS"} or any(marker in lowered for marker in telemetry_markers):
                return "", ""
            auxiliary_markers = (
                "sentinel.openai.com/backend-api/sentinel/req",
                "/ces/v1/",
            )
            label = f"{method} {url[:180]}"
            if any(marker in lowered for marker in auxiliary_markers):
                return "auxiliary", label
            try:
                parsed = urlsplit(url)
                host = str(parsed.hostname or "").lower()
                path = str(parsed.path or "").lower()
            except Exception:
                host = ""
                path = lowered
            business_markers = (
                "/api/accounts/",
                "/authorize/continue",
                "/api/authorize",
                "/create-account",
            )
            if host == "auth.openai.com" or any(marker in path for marker in business_markers):
                return "business", label
            return "auxiliary", label

        def record_submission_request(request) -> None:
            nonlocal sentinel_inflight
            try:
                kind, label = submission_request_info(request)
                if kind == "business" and label:
                    submission_requests.append(label)
                elif kind == "auxiliary" and label:
                    auxiliary_submission_requests.append(label)
                    if "sentinel.openai.com/backend-api/sentinel/req" in label.lower():
                        sentinel_inflight += 1
            except Exception:
                pass

        def record_failed_submission_request(request) -> None:
            nonlocal sentinel_inflight
            try:
                kind, label = submission_request_info(request)
                if not label:
                    return
                failure = str(getattr(request, "failure", "") or "network request failed")
                if kind == "business":
                    try:
                        submission_requests.remove(label)
                    except ValueError:
                        pass
                    failed_submission_requests.append(f"{label} => {failure[:160]}")
                elif "sentinel.openai.com/backend-api/sentinel/req" in label.lower():
                    sentinel_inflight = max(0, sentinel_inflight - 1)
                    sentinel_response_errors.append(f"{label} => {failure[:160]}")
            except Exception:
                pass

        def record_submission_response(response) -> None:
            nonlocal sentinel_inflight
            try:
                request = getattr(response, "request", None)
                kind, label = submission_request_info(request)
                if not label:
                    return
                status = int(getattr(response, "status", 0) or 0)
                if kind == "auxiliary":
                    auxiliary_submission_responses.append(f"{status} {label}")
                    if "sentinel.openai.com/backend-api/sentinel/req" in label.lower():
                        sentinel_inflight = max(0, sentinel_inflight - 1)
                        if status >= 400:
                            error_text = ""
                            try:
                                error_text = str(response.text() or "")[:400]
                            except Exception:
                                pass
                            sentinel_response_errors.append(f"{status} {label} body={error_text}")
                    return
                payload = {}
                try:
                    payload = response.json() or {}
                except Exception:
                    payload = {}
                continue_url = ""
                if isinstance(payload, dict):
                    page_payload = payload.get("page") or {}
                    nested_payload = page_payload.get("payload") or {} if isinstance(page_payload, dict) else {}
                    continue_url = str(
                        payload.get("continue_url")
                        or payload.get("url")
                        or nested_payload.get("url")
                        or ""
                    ).strip()
                if not continue_url:
                    try:
                        continue_url = str(response.header_value("location") or "").strip()
                    except Exception:
                        continue_url = ""
                detail = f"{status} {label}"
                submission_responses.append(detail)
                if continue_url:
                    submission_continue_urls.append(continue_url)
                if status >= 400:
                    error_text = ""
                    try:
                        error_text = str(response.text() or "")[:400]
                    except Exception:
                        pass
                    submission_response_errors.append(f"{detail} body={error_text}")
            except Exception:
                pass

        def record_browser_console(message) -> None:
            try:
                level = str(getattr(message, "type", "") or "").lower()
                text = str(getattr(message, "text", "") or "").strip()
                if level in {"error", "warning"} and text:
                    browser_submit_diagnostics.append(f"console.{level}: {text[:240]}")
            except Exception:
                pass

        def record_page_error(error) -> None:
            text = str(error or "").strip()
            if text:
                browser_submit_diagnostics.append(f"pageerror: {text[:240]}")

        request_observer_installed = False
        try:
            page.on("request", record_submission_request)
            page.on("requestfailed", record_failed_submission_request)
            page.on("response", record_submission_response)
            page.on("console", record_browser_console)
            page.on("pageerror", record_page_error)
            request_observer_installed = True
        except Exception:
            pass
        if not self._click_finish_creating_account(page) and not self._click_continue(page):
            if not self._click_button_by_text(page, ["Finish creating account", "Finalizar la creación de la cuenta", "Finalizar la creacion de la cuenta", "アカウントの作成を完了する", "作成を完了", "完成帐户创建", "完成账户创建", "Create account", "Continue", "完成"]):
                return False

        started = time.time()
        submit_stage = 0
        pointer_after = min(4.0, max(0.01, float(timeout) * 0.25))
        keyboard_after = min(8.0, max(pointer_after + 0.01, float(timeout) * 0.50))
        native_after = min(12.0, max(keyboard_after + 0.01, float(timeout) * 0.75))
        sentinel_wait_until = min(20.0, max(pointer_after + 0.01, float(timeout) * 0.35))
        final_wait_until = min(float(timeout), native_after + min(20.0, max(0.01, float(timeout) * 0.20)))
        try:
            while time.time() - started < float(timeout):
                if self._about_you_submit_done(page, before_url):
                    return True
                if submission_response_errors:
                    raise RuntimeError(f"基础资料提交接口返回错误: {submission_response_errors[-1]}")
                if sentinel_response_errors:
                    raise RuntimeError(f"基础资料 Sentinel 验证失败: {sentinel_response_errors[-1]}")
                if submission_continue_urls:
                    continue_url = submission_continue_urls.pop(0)
                    self._goto_tolerant(
                        page,
                        continue_url,
                        "基础资料提交响应跳转",
                        timeout=90000,
                        accepted_urls=(CHATGPT_BASE_URL, AUTH_BASE_URL),
                    )
                    return True
                self._confirm_about_you_age_fallback_if_visible(page)
                elapsed = time.time() - started
                if (
                    request_observer_installed
                    and not submission_requests
                    and self._has_about_you_form(page)
                ):
                    waiting_for_sentinel = sentinel_inflight > 0 and elapsed < sentinel_wait_until
                    if waiting_for_sentinel:
                        if not sentinel_wait_logged:
                            sentinel_wait_logged = True
                            self.log("基础资料提交已触发 Sentinel，等待验证完成后继续后备提交")
                        self._wait_or_stop(0.25)
                        continue
                    if submit_stage == 0 and elapsed >= pointer_after:
                        submit_stage = 1
                        self.log("基础资料首次点击未产生提交请求，自动改用真实鼠标坐标提交")
                        self._reactivate_about_you_inputs(page)
                        self._pointer_click_finish_creating_account(page)
                    elif submit_stage == 1 and elapsed >= keyboard_after:
                        submit_stage = 2
                        self.log("基础资料鼠标提交仍未产生请求，自动改用键盘 Enter 提交")
                        self._reactivate_about_you_inputs(page)
                        self._keyboard_submit_about_you(page)
                    elif submit_stage == 2 and elapsed >= native_after:
                        submit_stage = 3
                        self.log("基础资料键盘提交仍未产生请求，自动执行原生 requestSubmit")
                        self._reactivate_about_you_inputs(page)
                        self._click_submit_button_by_dom(page)
                    elif submit_stage >= 3 and elapsed >= final_wait_until:
                        if failed_submission_requests:
                            raise ProxyExitCheckError(
                                f"基础资料业务提交请求被代理连接中断: {failed_submission_requests[-1]}",
                                "代理检测失败",
                            )
                        state = self._about_you_form_state(page)
                        raise RuntimeError(
                            "基础资料已自动尝试点击、鼠标、Enter 和 requestSubmit，但页面未产生业务提交请求: "
                            f"form_valid={state.get('form_valid')}; invalid={state.get('invalid_fields')}; "
                            f"alerts={state.get('alerts')}; auxiliary_requests={auxiliary_submission_requests[-3:]}; "
                            f"browser_diagnostics={browser_submit_diagnostics[-5:]}"
                        )
                self._wait_or_stop(0.25)
        finally:
            if request_observer_installed:
                try:
                    page.remove_listener("request", record_submission_request)
                    page.remove_listener("requestfailed", record_failed_submission_request)
                    page.remove_listener("response", record_submission_response)
                    page.remove_listener("console", record_browser_console)
                    page.remove_listener("pageerror", record_page_error)
                except Exception:
                    try:
                        page.off("request", record_submission_request)
                        page.off("requestfailed", record_failed_submission_request)
                        page.off("response", record_submission_response)
                        page.off("console", record_browser_console)
                        page.off("pageerror", record_page_error)
                    except Exception:
                        pass
        state = self._about_you_form_state(page)
        invalid_fields = list(state.get("invalid_fields") or [])
        alerts = list(state.get("alerts") or [])
        raise RuntimeError(
            "基础资料提交后页面未离开 about-you: "
            f"button={state.get('button_text')}; disabled={state.get('button_disabled')}; "
            f"aria_disabled={state.get('button_aria_disabled')}; form_valid={state.get('form_valid')}; "
            f"invalid={invalid_fields}; alerts={alerts}; submit_requests={submission_requests[:3]}; "
            f"submit_responses={submission_responses[-3:]}; failed_submit_requests={failed_submission_requests[-3:]}; "
            f"auxiliary_requests={auxiliary_submission_requests[-3:]}; auxiliary_responses={auxiliary_submission_responses[-3:]}; "
            f"browser_diagnostics={browser_submit_diagnostics[-3:]}"
        )

    def _pointer_click_finish_creating_account(self, page) -> bool:
        selectors = [
            'button:has-text("Finish creating account")',
            'button:has-text("Finalizar la creación de la cuenta")',
            'button:has-text("アカウントの作成を完了する")',
            'button:has-text("作成を完了")',
            'button[type="submit"]',
        ]
        for selector in selectors:
            button = page.locator(selector).first
            try:
                if not button.is_visible(timeout=700):
                    continue
                button.scroll_into_view_if_needed(timeout=3000)
                box = button.bounding_box(timeout=3000)
                if not box:
                    continue
                page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                page.mouse.down()
                time.sleep(0.12)
                page.mouse.up()
                return True
            except Exception as exc:
                self.log(f"真实鼠标坐标点击失败 {selector}: {str(exc)[:120]}")
        return False

    def _keyboard_submit_about_you(self, page) -> bool:
        selectors = [
            'button:has-text("Finish creating account")',
            'button:has-text("Finalizar la creación de la cuenta")',
            'button:has-text("アカウントの作成を完了する")',
            'button:has-text("作成を完了")',
            'button[type="submit"]',
        ]
        for selector in selectors:
            button = page.locator(selector).first
            try:
                if not button.is_visible(timeout=700):
                    continue
                button.scroll_into_view_if_needed(timeout=3000)
                button.focus(timeout=3000)
                page.keyboard.press("Enter")
                return True
            except Exception as exc:
                self.log(f"键盘 Enter 提交失败 {selector}: {str(exc)[:120]}")
        return False

    def _click_finish_creating_account(self, page) -> bool:
        selectors = [
            'button:has-text("Finish creating account")',
            'button:has-text("Finalizar la creación de la cuenta")',
            'button:has-text("Finalizar la creacion de la cuenta")',
            'button:has-text("アカウントの作成を完了する")',
            'button:has-text("作成を完了")',
            'button[type="submit"]:has-text("Finish")',
            'button[type="submit"]:has-text("作成")',
            'button[data-dd-action-name="Continue"][type="submit"]:has-text("Finish")',
        ]
        for selector in selectors:
            button = page.locator(selector).first
            try:
                if not button.is_visible(timeout=700):
                    continue
                button.scroll_into_view_if_needed(timeout=3000)
                button.click(timeout=5000)
                return True
            except Exception as exc:
                self.log(f"基础资料按钮普通点击失败 {selector}: {str(exc)[:120]}")
            try:
                button.click(timeout=5000, force=True)
                return True
            except Exception as exc:
                self.log(f"force click 失败 {selector}: {str(exc)[:120]}")
            try:
                box = button.bounding_box(timeout=3000)
                if box:
                    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                    page.mouse.down()
                    time.sleep(0.1)
                    page.mouse.up()
                    return True
            except Exception as exc:
                self.log(f"坐标点击失败 {selector}: {str(exc)[:120]}")
            try:
                button.focus(timeout=3000)
                page.keyboard.press("Enter")
                return True
            except Exception as exc:
                self.log(f"按钮回车失败 {selector}: {str(exc)[:120]}")

        clicked = page.evaluate(
            """() => {
                const visible = (el) => {
                    const r = el.getBoundingClientRect();
                    const s = getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                };
                const enabled = (el) => el && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                const buttons = Array.from(document.querySelectorAll('button')).filter(el => visible(el) && enabled(el));
                const finish = buttons.find(el => {
                    const text = (el.textContent || '').trim();
                    return text.includes('Finish creating account')
                        || text.includes('Finalizar la creación de la cuenta')
                        || text.includes('Finalizar la creacion de la cuenta')
                        || text.includes('アカウントの作成を完了する')
                        || text.includes('作成を完了')
                        || text.includes('完成帐户创建')
                        || text.includes('完成账户创建');
                });
                const submit = finish || buttons.find(el =>
                    (el.type || '').toLowerCase() === 'submit'
                    && (el.getAttribute('data-dd-action-name') || '') === 'Continue'
                    && /Finish|作成|完成/.test((el.textContent || '').trim())
                );
                if (!submit) return false;
                submit.scrollIntoView({ block: 'center', inline: 'center' });
                submit.focus();
                const form = submit.closest('form');
                if (form && typeof form.requestSubmit === 'function') {
                    const isSubmitButton = submit instanceof HTMLButtonElement
                        && (submit.type || '').toLowerCase() === 'submit';
                    if (isSubmitButton) form.requestSubmit(submit);
                    else form.requestSubmit();
                    return true;
                }
                submit.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, pointerType: 'mouse', isPrimary: true }));
                submit.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }));
                submit.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, pointerType: 'mouse', isPrimary: true }));
                submit.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, button: 0 }));
                submit.click();
                return true;
            }"""
        )
        if clicked:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=10000)
            except Exception:
                pass
            return True
        return False

    def _click_button_by_text(self, page, texts: list[str]) -> bool:
        box = page.evaluate(
            """({texts}) => {
                const visible = (el) => {
                    const r = el.getBoundingClientRect();
                    const s = getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                };
                const candidates = Array.from(document.querySelectorAll('button, [role="button"]'))
                    .filter(visible)
                    .filter(el => texts.some(text => (el.textContent || '').includes(text)));
                const el = candidates[0];
                if (!el) return null;
                el.scrollIntoView({ block: 'center', inline: 'center' });
                const r = el.getBoundingClientRect();
                return { x: r.left + r.width / 2, y: r.top + r.height / 2, text: el.textContent || '' };
            }""",
            {"texts": texts},
        )
        if not box:
            return False
        page.mouse.click(float(box["x"]), float(box["y"]))
        return True

    def _wait_for_about_you_inputs(self, page, timeout: int = 30) -> None:
        started = time.time()
        while time.time() - started < timeout:
            count = page.evaluate("""() => Array.from(document.querySelectorAll('input, textarea, select, [contenteditable="true"]')).filter(el => {
                const r = el.getBoundingClientRect();
                const s = getComputedStyle(el);
                return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
            }).length""")
            if int(count or 0) >= 2:
                return
            self._wait_or_stop(0.5)
        raise RuntimeError("about-you 页面 30 秒内未出现姓名/年龄输入框")

    def _fill_about_you_inputs(self, page, name: str, birthdate: str, birth_year: str, age: str) -> None:
        second_context = self._about_you_second_field_context(page)
        second_kind = self._about_you_second_field_kind_from_context(second_context)
        second_value = self._about_you_second_field_value(second_kind, birth_year, age, birthdate, second_context)
        if second_kind == "birth_date":
            try:
                self._fill_visible_input_by_keyboard(page, 0, name)
            except Exception as exc:
                self.log(f"姓名键盘输入失败，继续尝试 DOM 填写: {str(exc)[:120]}")
            if self._fill_about_you_birth_date_inputs(page, birthdate, second_context):
                values = self._visible_input_values(page)
                if self._about_you_values_ok(values, second_kind):
                    self._focus_about_you_submit_or_body(page)
                    return

        try:
            self._fill_visible_input_by_keyboard(page, 0, name)
            self._fill_visible_input_by_keyboard(page, 1, second_value)
            self._focus_about_you_submit_or_body(page)
            values = self._visible_input_values(page)
            if self._about_you_values_ok(values, second_kind):
                return
        except Exception as exc:
            self.log(f"基础资料键盘输入失败，改用 DOM 填写: {str(exc)[:120]}")

        values = self._fill_about_you_inputs_by_dom(page, name, second_value, second_kind)
        if self._about_you_values_ok(values, second_kind):
            return

        filled_name = self._fill_first_visible(page, [
            'input[name="name"]',
            'input[autocomplete="name"]',
            'input[placeholder*="name" i]',
            'input[placeholder*="全名" i]',
            'input[aria-label*="name" i]',
            'input[aria-label*="全名" i]',
        ], name)
        second_selectors = self._about_you_second_field_selectors(second_kind)
        filled_second = self._fill_first_visible(page, second_selectors, second_value)

        if not filled_name or not filled_second:
            visible_inputs = self._visible_inputs(page, ['input'])
            if not filled_name and len(visible_inputs) >= 1:
                self._force_fill_locator(visible_inputs[0], name)
                filled_name = True
            if not filled_second and len(visible_inputs) >= 2:
                self._force_fill_locator(visible_inputs[1], second_value)
                filled_second = True

        values = page.evaluate("""() => Array.from(document.querySelectorAll('input')).filter(el => {
            const r = el.getBoundingClientRect();
            const s = getComputedStyle(el);
            return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
        }).map(el => el.value || '')""")
        if self._about_you_values_ok(values, second_kind):
            return

        self.log("基础资料 DOM 填写未生效，改用鼠标点击 + 键盘输入")
        self._fill_visible_input_by_keyboard(page, 0, name)
        self._fill_visible_input_by_keyboard(page, 1, second_value)
        self._focus_about_you_submit_or_body(page)
        values = self._visible_input_values(page)
        if not self._about_you_values_ok(values, second_kind):
            self.log(f"基础资料自动填写未确认成功，当前可见输入值={values}。请在浏览器中手动填写/提交；程序将继续等待登录完成")

    def _fill_about_you_birth_date_inputs(self, page, birthdate: str, context: str) -> bool:
        values = self._about_you_birth_date_value_map(birthdate, context)
        if self._fill_about_you_birth_date_segments_by_keyboard(page, values):
            current = self._visible_input_values(page)
            if self._about_you_values_ok(current, "birth_date"):
                return True
        structured = self._fill_about_you_birth_date_structured(page, values)
        if structured.get("filled"):
            mode = str(structured.get("mode") or "structured")
            current = self._visible_input_values(page)
            if self._about_you_values_ok(current, "birth_date"):
                return True

        target_index = self._about_you_birth_date_input_index(page)
        if target_index is not None:
            for label, value in self._about_you_birth_date_keyboard_candidates(context, values):
                try:
                    self._fill_visible_input_by_keyboard(page, int(target_index), value)
                    current = self._visible_input_values(page)
                    if self._about_you_values_ok(current, "birth_date"):
                        return True
                except Exception as exc:
                    self.log(f"生日 {label} 键盘输入失败: {str(exc)[:120]}")

        fallback = self._fill_about_you_birth_date_single_by_dom(page, values)
        if fallback.get("filled"):
            current = self._visible_input_values(page)
            if self._about_you_values_ok(current, "birth_date"):
                return True
        return False

    def _about_you_birth_date_keyboard_candidates(self, context: str, values: dict[str, str]) -> list[tuple[str, str]]:
        fmt = self._about_you_birth_date_format_kind(context)
        if fmt == "de":
            return [("TTMMJJJJ 掩码", values["compact_eu"]), ("TT.MM.JJJJ", values["de"])]
        if fmt == "eu":
            return [("DDMMYYYY 掩码", values["compact_eu"]), ("DD/MM/YYYY", values["eu"])]
        if fmt == "iso":
            return [("YYYY-MM-DD", values["iso"])]
        return [("MMDDYYYY 掩码", values["compact_us"]), ("MM/DD/YYYY", values["us"])]

    def _fill_about_you_birth_date_segments_by_keyboard(self, page, values: dict[str, str]) -> bool:
        try:
            segments = page.evaluate(
                """() => { /* about-you-date-segments */
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const controls = Array.from(document.querySelectorAll('[role="spinbutton"], [contenteditable="true"]')).filter(visible);
                    const roleOf = (el, index) => {
                        const text = [
                            el.getAttribute('aria-label'),
                            el.getAttribute('autocomplete'),
                            el.getAttribute('data-testid'),
                            el.id,
                            el.textContent,
                            el.parentElement?.textContent
                        ].filter(Boolean).join(' ').toLowerCase();
                        if (/year|yyyy|生年|年/.test(text)) return 'year';
                        if (/month|mm|月/.test(text)) return 'month';
                        if (/day|dd|日/.test(text)) return 'day';
                        return ['year', 'month', 'day'][index] || '';
                    };
                    return controls.map((el, index) => ({ role: roleOf(el, index), index }));
                }"""
            ) or []
        except Exception as exc:
            if hasattr(self, "log"):
                self.log(f"生日分段识别失败: {str(exc)[:120]}")
            return False
        by_role = {
            str(item.get("role") or ""): int(item.get("index"))
            for item in segments
            if str(item.get("role") or "") in {"year", "month", "day"}
        }
        if not all(role in by_role for role in ("year", "month", "day")):
            return False
        controls = page.locator('[role="spinbutton"], [contenteditable="true"]')
        for role in ("year", "month", "day"):
            try:
                controls.nth(by_role[role]).click(timeout=3000)
                page.keyboard.press("Control+A")
                page.keyboard.press("Backspace")
                page.keyboard.type(str(values[role]), delay=30)
            except Exception as exc:
                if hasattr(self, "log"):
                    self.log(f"生日分段 {role} 键盘输入失败: {str(exc)[:120]}")
                return False
        return True

    def _fill_about_you_birth_date_structured(self, page, values: dict[str, str]) -> dict:
        try:
            return dict(page.evaluate(
                """({values}) => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const controls = Array.from(document.querySelectorAll('input, textarea, select, [contenteditable="true"]')).filter(visible);
                    const textOf = (el) => {
                        const parts = [
                            el.getAttribute('name'), el.getAttribute('autocomplete'), el.getAttribute('placeholder'),
                            el.getAttribute('aria-label'), el.id, el.getAttribute('data-testid'),
                            el.getAttribute('inputmode'), el.getAttribute('type') || el.type
                        ];
                        const labelledBy = el.getAttribute('aria-labelledby');
                        if (labelledBy) {
                            for (const id of labelledBy.split(/\\s+/)) {
                                const labelEl = document.getElementById(id);
                                if (labelEl) parts.push(labelEl.textContent || '');
                            }
                        }
                        for (const label of Array.from(document.querySelectorAll('label'))) {
                            if (label.htmlFor && label.htmlFor === el.id) parts.push(label.textContent || '');
                            if (label.contains(el)) parts.push(label.textContent || '');
                        }
                        let node = el.parentElement;
                        for (let i = 0; node && i < 2; i += 1, node = node.parentElement) parts.push(node.textContent || '');
                        return parts.filter(Boolean).join(' ').toLowerCase();
                    };
                    const isName = (el) => /\\b(full\\s*)?name\\b|nombre|全名/.test(textOf(el));
                    const setControl = (el, value) => {
                        if (!el) return false;
                        el.scrollIntoView({ block: 'center', inline: 'center' });
                        el.focus();
                        if (el.tagName === 'SELECT') {
                            const want = String(value || '').toLowerCase().replace(/^0+/, '') || String(value || '').toLowerCase();
                            const option = Array.from(el.options).find(opt => {
                                const ov = String(opt.value || '').toLowerCase();
                                const ot = String(opt.textContent || '').trim().toLowerCase();
                                const ovNum = ov.replace(/^0+/, '');
                                const otNum = ot.replace(/^0+/, '');
                                return ov === String(value).toLowerCase() || ot === String(value).toLowerCase()
                                    || ovNum === want || otNum === want
                                    || (String(value).length <= 2 && ot.startsWith(want + ' '))
                                    || (String(value).length <= 2 && ot.includes(' ' + want));
                            });
                            if (option) el.value = option.value;
                        } else if (el.isContentEditable) {
                            el.textContent = value;
                        } else {
                            const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                            const desc = Object.getOwnPropertyDescriptor(proto, 'value');
                            if (desc && desc.set) desc.set.call(el, value); else el.value = value;
                        }
                        el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: String(value) }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        el.dispatchEvent(new Event('blur', { bubbles: true }));
                        return true;
                    };
                    const roleOf = (el) => {
                        const t = textOf(el);
                        const ac = String(el.getAttribute('autocomplete') || '').toLowerCase();
                        if (ac.split(/\\s+/).includes('bday-month')) return 'month';
                        if (ac.split(/\\s+/).includes('bday-day')) return 'day';
                        if (ac.split(/\\s+/).includes('bday-year')) return 'year';
                        if (/\\b(mm|month|mes|monat|月)\\b/.test(t) && !/yyyy|year|jjjj|aaaa|年/.test(t)) return 'month';
                        if (/\\b(dd|day|dia|día|tag|日)\\b/.test(t) && !/yyyy|year|jjjj|aaaa|年/.test(t)) return 'day';
                        if (/\\b(yyyy|year|aaaa|jjjj|jahr|año|ano|年)\\b/.test(t)) return 'year';
                        return '';
                    };
                    const birthdayish = controls.filter(el => !isName(el) && /bday|birth|birthday|date of birth|dob|fecha de nacimiento|date de naissance|naissance|nacimiento|geburtstag|geburtsdatum|mm\\s*[/.-]\\s*dd|dd\\s*[/.-]\\s*mm|jj\\s*[/.-]\\s*mm|tt\\s*\\.\\s*mm|yyyy|aaaa|jjjj/.test(textOf(el)));
                    const parts = { month: null, day: null, year: null };
                    for (const el of controls.filter(el => !isName(el))) {
                        const role = roleOf(el);
                        if (role && !parts[role]) parts[role] = el;
                    }
                    let partCount = Object.values(parts).filter(Boolean).length;
                    if (partCount >= 2) {
                        setControl(parts.month, values.month);
                        setControl(parts.day, values.day);
                        setControl(parts.year, values.year);
                        return { filled: true, mode: 'bday-month/day/year' };
                    }
                    const full = birthdayish.find(el => {
                        const ac = String(el.getAttribute('autocomplete') || '').toLowerCase().split(/\\s+/);
                        return ac.includes('bday') || (el.tagName === 'INPUT' && String(el.type || '').toLowerCase() === 'date');
                    });
                    if (full) {
                        setControl(full, values.iso);
                        return { filled: true, mode: 'bday/type=date YYYY-MM-DD' };
                    }
                    return { filled: false, mode: '' };
                }""",
                {"values": values},
            ) or {})
        except Exception as exc:
            self.log(f"生日结构化 DOM 填写失败: {str(exc)[:120]}")
            return {"filled": False}

    def _fill_about_you_birth_date_single_by_dom(self, page, values: dict[str, str]) -> dict:
        try:
            return dict(page.evaluate(
                """({values}) => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const controls = Array.from(document.querySelectorAll('input, textarea, select, [contenteditable="true"]')).filter(visible);
                    const textOf = (el) => [
                        el.getAttribute('name'), el.getAttribute('autocomplete'), el.getAttribute('placeholder'),
                        el.getAttribute('aria-label'), el.id, el.getAttribute('data-testid'),
                        el.getAttribute('type') || el.type,
                        el.closest('label')?.textContent || '',
                        el.parentElement?.textContent || ''
                    ].filter(Boolean).join(' ').toLowerCase();
                    const isName = (el) => /\\b(full\\s*)?name\\b|nombre|全名/.test(textOf(el));
                    const setValue = (el, value) => {
                        if (!el) return false;
                        el.scrollIntoView({ block: 'center', inline: 'center' });
                        el.focus();
                        if (el.tagName === 'SELECT') {
                            const option = Array.from(el.options).find(opt => String(opt.value) === String(value) || String(opt.textContent || '').trim() === String(value));
                            if (option) el.value = option.value;
                        } else if (el.isContentEditable) {
                            el.textContent = value;
                        } else {
                            const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                            const desc = Object.getOwnPropertyDescriptor(proto, 'value');
                            if (desc && desc.set) desc.set.call(el, value); else el.value = value;
                        }
                        el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: String(value) }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        el.dispatchEvent(new Event('blur', { bubbles: true }));
                        return true;
                    };
                    const el = controls.find(el => !isName(el) && /bday|birthday|date of birth|birthdate|dob|fecha de nacimiento|date de naissance|naissance|nacimiento|geburtstag|geburtsdatum|mm\\s*[/.-]\\s*dd|dd\\s*[/.-]\\s*mm|jj\\s*[/.-]\\s*mm|tt\\s*\\.\\s*mm|yyyy|aaaa|jjjj/.test(textOf(el))) || controls.find(el => !isName(el));
                    if (!el) return { filled: false };
                    const t = textOf(el);
                    const value = /tt\\s*\\.\\s*mm|geburt/.test(t) ? values.de
                        : /dd\\s*[/.-]\\s*mm|jj\\s*[/.-]\\s*mm|fecha|nacimiento|naissance/.test(t) ? values.eu
                        : /yyyy\\s*[-/.]\\s*mm\\s*[-/.]\\s*dd|type=date|autocomplete=.*bday/.test(t) ? values.iso
                        : values.us;
                    setValue(el, value);
                    return { filled: true, mode: 'single-date DOM' };
                }""",
                {"values": values},
            ) or {})
        except Exception as exc:
            self.log(f"生日单字段 DOM 填写失败: {str(exc)[:120]}")
            return {"filled": False}

    def _about_you_birth_date_input_index(self, page) -> int | None:
        try:
            result = page.evaluate(
                """() => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const controls = Array.from(document.querySelectorAll('input, textarea, [contenteditable="true"]')).filter(visible);
                    const textOf = (el) => [
                        el.getAttribute('name'), el.getAttribute('autocomplete'), el.getAttribute('placeholder'),
                        el.getAttribute('aria-label'), el.id, el.getAttribute('data-testid'),
                        el.getAttribute('type') || el.type,
                        el.closest('label')?.textContent || '',
                        el.parentElement?.textContent || ''
                    ].filter(Boolean).join(' ').toLowerCase();
                    const isName = (el) => /\\b(full\\s*)?name\\b|nombre|全名/.test(textOf(el));
                    const idx = controls.findIndex(el => !isName(el) && /bday|birthday|date of birth|birthdate|dob|fecha de nacimiento|date de naissance|naissance|nacimiento|geburtstag|geburtsdatum|mm\\s*[/.-]\\s*dd|dd\\s*[/.-]\\s*mm|jj\\s*[/.-]\\s*mm|tt\\s*\\.\\s*mm|yyyy|aaaa|jjjj/.test(textOf(el)));
                    if (idx >= 0) return idx;
                    const fallback = controls.findIndex(el => !isName(el));
                    return fallback >= 0 ? fallback : null;
                }"""
            )
            if result is None:
                return None
            return int(result)
        except Exception:
            return None

    def _about_you_keyword_payload(self) -> dict[str, list[str]]:
        return {
            "name": ABOUT_YOU_NAME_WORDS,
            "birth_year": ABOUT_YOU_BIRTH_YEAR_WORDS,
            "age": ABOUT_YOU_AGE_WORDS,
            "birth_date": ABOUT_YOU_BIRTH_DATE_WORDS,
        }

    def _fill_about_you_inputs_by_dom(self, page, name: str, second_value: str, second_kind: str) -> list[str]:
        return page.evaluate(
            """({name, secondValue, secondKind, keywords}) => {
                const normalizeText = (value) => String(value || '').toLowerCase().normalize('NFD').replace(/[\\u0300-\\u036f]/g, '');
                const visible = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const s = getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                };
                const controls = Array.from(document.querySelectorAll('input, textarea, select, [contenteditable="true"]')).filter(visible);
                const setValue = (el, value) => {
                    if (!el) return false;
                    el.scrollIntoView({ block: 'center', inline: 'center' });
                    el.focus();
                    if (el.tagName === 'SELECT') {
                        const option = Array.from(el.options).find(opt => String(opt.value) === String(value) || String(opt.textContent || '').trim() === String(value));
                        if (option) el.value = option.value;
                    } else if (el.isContentEditable) {
                        el.textContent = value;
                    } else {
                        const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                        const desc = Object.getOwnPropertyDescriptor(proto, 'value');
                        if (desc && desc.set) desc.set.call(el, value); else el.value = value;
                    }
                    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: value }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    el.dispatchEvent(new Event('blur', { bubbles: true }));
                    return true;
                };
                const includesWord = (text, word) => normalizeText(text).includes(normalizeText(word));
                const attrMatch = (el, words) => words.some(word => [
                    el.getAttribute('name'), el.getAttribute('autocomplete'), el.getAttribute('placeholder'),
                    el.getAttribute('aria-label'), el.id, el.getAttribute('data-testid')
                ].some(value => includesWord(value, word)));
                const byLabel = (words) => {
                    for (const label of Array.from(document.querySelectorAll('label'))) {
                        const text = (label.textContent || '').trim();
                        if (!words.some(word => includesWord(text, word))) continue;
                        if (label.htmlFor) {
                            const linked = document.getElementById(label.htmlFor);
                            if (visible(linked)) return linked;
                        }
                        const nested = label.querySelector('input, textarea, select, [contenteditable="true"]');
                        if (visible(nested)) return nested;
                        const sibling = label.parentElement?.querySelector('input, textarea, select, [contenteditable="true"]');
                        if (visible(sibling)) return sibling;
                    }
                    return null;
                };
                const nameWords = keywords.name || [];
                const nameEl = controls.find(el => attrMatch(el, nameWords)) || byLabel(nameWords) || controls[0];
                const birthDateWords = [...(keywords.birth_date || []), 'dd/mm', 'jj/mm', 'mm/dd', 'tt.mm', 'aaaa', 'yyyy', 'jjjj'];
                const birthWords = secondKind === 'birth_date'
                    ? birthDateWords
                    : [...(keywords.birth_year || []), 'birth', 'born', 'year', '生年', '生まれた年', '出生年'];
                const ageWords = keywords.age || [];
                const preferredWords = secondKind === 'age' ? ageWords : birthWords;
                const fallbackWords = secondKind === 'age' ? birthWords : ageWords;
                const secondEl = controls.find(el => el !== nameEl && attrMatch(el, preferredWords))
                    || byLabel(preferredWords)
                    || controls.find(el => el !== nameEl && attrMatch(el, fallbackWords))
                    || byLabel(fallbackWords)
                    || controls.find(el => el !== nameEl && (el.type === 'number' || el.inputMode === 'numeric'))
                    || controls.find(el => el !== nameEl)
                    || controls[1];
                setValue(nameEl, name);
                setValue(secondEl, secondValue);
                return controls.map(el => el.isContentEditable ? (el.textContent || '') : (el.value || ''));
            }""",
            {
                "name": name,
                "secondValue": second_value,
                "secondKind": second_kind,
                "keywords": self._about_you_keyword_payload(),
            },
        )

    def _visible_input_values(self, page) -> list[str]:
        return page.evaluate("""() => Array.from(document.querySelectorAll('input, textarea, select, [contenteditable="true"]')).filter(el => {
            const r = el.getBoundingClientRect();
            const s = getComputedStyle(el);
            return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
        }).map(el => el.isContentEditable ? (el.textContent || '') : (el.value || ''))""")

    def _about_you_values_ok(self, values: list[str], second_kind: str = "birth_year") -> bool:
        normalized = [str(value).strip() for value in values]
        nonempty = [value for value in normalized if value]
        if len(nonempty) < 2:
            return False
        second = nonempty[1]
        if second_kind == "age":
            if not re.fullmatch(r"\d{1,3}", second):
                return False
            age = int(second)
            return 13 <= age <= 120
        if second_kind == "birth_date":
            parsed = self._about_you_birth_date_from_values(nonempty)
            if not parsed:
                return False
            year, month, day = parsed
            try:
                birth = datetime(year, month, day, tzinfo=timezone.utc)
            except ValueError:
                return False
            today = datetime.now(timezone.utc)
            age = today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
            return 13 <= age <= 120
        if not re.fullmatch(r"\d{4}", second):
            return False
        year = int(second)
        current_year = datetime.now(timezone.utc).year
        return 1900 <= year <= current_year - 13

    def _about_you_birth_date_from_values(self, values: list[str]) -> tuple[int, int, int] | None:
        for value in values[1:]:
            parsed = self._parse_about_you_birth_date(value)
            if parsed:
                return parsed
        numeric = [value for value in values if re.fullmatch(r"\d{1,4}", value)]
        if len(numeric) >= 3:
            for index in range(0, len(numeric) - 2):
                first, second, third = numeric[index:index + 3]
                if len(first) == 4:
                    return int(first), int(second), int(third)
                if len(third) == 4:
                    first_int, second_int = int(first), int(second)
                    if first_int > 12:
                        return int(third), second_int, first_int
                    return int(third), first_int, second_int
        return None

    def _parse_about_you_birth_date(self, value: str) -> tuple[int, int, int] | None:
        text = re.sub(r"\s+", "", str(value or "").strip())
        match = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", text)
        if match:
            year = int(match.group(1))
            if year >= 1900:
                return year, int(match.group(2)), int(match.group(3))
        match = re.fullmatch(r"(\d{2})(\d{2})(\d{4})", text)
        if match:
            first, second, year = int(match.group(1)), int(match.group(2)), int(match.group(3))
            if first > 12:
                return year, second, first
            return year, first, second
        match = re.fullmatch(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", text)
        if match:
            return int(match.group(1)), int(match.group(2)), int(match.group(3))
        match = re.fullmatch(r"(\d{1,2})([-/.])(\d{1,2})[-/.](\d{4})", text)
        if match:
            first, separator, second, year = int(match.group(1)), match.group(2), int(match.group(3)), int(match.group(4))
            if separator == "." or first > 12:
                return year, second, first
            return year, first, second
        return None

    def _about_you_current_values_ok(self, page) -> bool:
        try:
            values = self._visible_input_values(page)
            return self._about_you_values_ok(values, self._about_you_second_field_kind(page))
        except Exception:
            return False

    def _about_you_second_field_selectors(self, second_kind: str) -> list[str]:
        if second_kind == "age":
            return [
                'input[name*="age" i]',
                'input[placeholder*="age" i]',
                'input[aria-label*="age" i]',
                'input[placeholder*="年齢" i]',
                'input[aria-label*="年齢" i]',
                'input[placeholder*="年龄" i]',
                'input[aria-label*="年龄" i]',
                'input[placeholder*="edad" i]',
                'input[aria-label*="edad" i]',
                'input[placeholder*="idade" i]',
                'input[aria-label*="idade" i]',
                'input[placeholder*="tuổi" i]',
                'input[aria-label*="tuổi" i]',
                'input[placeholder*="tuoi" i]',
                'input[aria-label*="tuoi" i]',
                'input[placeholder*="usia" i]',
                'input[aria-label*="usia" i]',
                'input[placeholder*="umur" i]',
                'input[aria-label*="umur" i]',
            ]
        if second_kind == "birth_date":
            return [
                'input[type="date"]',
                'input[autocomplete~="bday" i]',
                'select[autocomplete~="bday" i]',
                'input[name*="dateOfBirth" i]',
                'input[name*="birthday" i]',
                'input[name*="birth" i]',
                'input[name*="dob" i]',
                'input[placeholder*="Birthday" i]',
                'input[placeholder*="DD/MM" i]',
                'input[placeholder*="MM/DD" i]',
                'input[placeholder*="DD / MM" i]',
                'input[placeholder*="MM / DD" i]',
                'input[placeholder*="JJ/MM" i]',
                'input[placeholder*="JJ / MM" i]',
                'input[placeholder*="AAAA" i]',
                'input[placeholder*="YYYY" i]',
                'input[placeholder*="TT.MM" i]',
                'input[placeholder*="JJJJ" i]',
                'input[placeholder*="fecha" i]',
                'input[aria-label*="fecha" i]',
                'input[placeholder*="naissance" i]',
                'input[aria-label*="naissance" i]',
                'input[placeholder*="geburt" i]',
                'input[aria-label*="geburt" i]',
                'input[placeholder*="ngày sinh" i]',
                'input[aria-label*="ngày sinh" i]',
                'input[placeholder*="ngay sinh" i]',
                'input[aria-label*="ngay sinh" i]',
                'input[placeholder*="data de nascimento" i]',
                'input[aria-label*="data de nascimento" i]',
                'input[placeholder*="birth" i]',
                'input[aria-label*="birth" i]',
            ]
        return [
            'input[name*="birth" i]',
            'input[name*="year" i]',
            'input[placeholder*="birth" i]',
            'input[placeholder*="year" i]',
            'input[aria-label*="birth" i]',
            'input[aria-label*="year" i]',
            'input[placeholder*="生年" i]',
            'input[aria-label*="生年" i]',
            'input[placeholder*="出生年" i]',
            'input[aria-label*="出生年" i]',
            'input[placeholder*="Năm sinh" i]',
            'input[aria-label*="Năm sinh" i]',
            'input[placeholder*="Nam sinh" i]',
            'input[aria-label*="Nam sinh" i]',
            'input[placeholder*="año de nacimiento" i]',
            'input[aria-label*="año de nacimiento" i]',
            'input[placeholder*="ano de nacimiento" i]',
            'input[aria-label*="ano de nacimiento" i]',
            'input[placeholder*="geburtsjahr" i]',
            'input[aria-label*="geburtsjahr" i]',
            'input[placeholder*="tahun lahir" i]',
            'input[aria-label*="tahun lahir" i]',
        ]

    def _about_you_second_field_value(self, second_kind: str, birth_year: str, age: str, birthdate: str = "", context: str = "") -> str:
        if second_kind == "age":
            return str(age)
        if second_kind == "birth_date":
            return self._format_about_you_birth_date(birthdate or f"{birth_year}-01-01", context)
        return str(birth_year)

    def _about_you_birth_date_value_map(self, birthdate: str, context: str = "") -> dict[str, str]:
        year, month, day = self._about_you_birth_date_parts(birthdate)
        return {
            "year": f"{year:04d}",
            "month": f"{month:02d}",
            "day": f"{day:02d}",
            "month_int": str(month),
            "day_int": str(day),
            "iso": f"{year:04d}-{month:02d}-{day:02d}",
            "us": f"{month:02d}/{day:02d}/{year:04d}",
            "eu": f"{day:02d}/{month:02d}/{year:04d}",
            "de": f"{day:02d}.{month:02d}.{year:04d}",
            "compact_us": f"{month:02d}{day:02d}{year:04d}",
            "compact_eu": f"{day:02d}{month:02d}{year:04d}",
            "display": self._format_about_you_birth_date(birthdate, context),
        }

    def _about_you_birth_date_parts(self, birthdate: str) -> tuple[int, int, int]:
        parsed = self._parse_about_you_birth_date(birthdate)
        if parsed:
            return parsed
        text = str(birthdate or "").strip()
        year = int(text[:4]) if re.match(r"\d{4}", text) else datetime.now(timezone.utc).year - 30
        return year, 1, 1

    def _format_about_you_birth_date(self, birthdate: str, context: str = "") -> str:
        year, month, day = self._about_you_birth_date_parts(birthdate)
        fmt = self._about_you_birth_date_format_kind(context)
        if fmt == "de":
            return f"{day:02d}.{month:02d}.{year:04d}"
        if fmt == "eu":
            return f"{day:02d}/{month:02d}/{year:04d}"
        if fmt == "us":
            return f"{month:02d}/{day:02d}/{year:04d}"
        return f"{year:04d}-{month:02d}-{day:02d}"

    def _about_you_birth_date_format_kind(self, context: str = "") -> str:
        text = re.sub(r"\s+", " ", str(context or "")).strip().lower()
        if re.search(r"\btt\s*\.\s*mm\s*\.\s*jjjj\b", text) or "geburtstag" in text or "geburtsdatum" in text:
            return "de"
        if (
            re.search(r"\b(dd|jj)\s*[/.-]\s*mm\s*[/.-]\s*(yyyy|aaaa)\b", text)
            or "fecha de nacimiento" in text
            or "date de naissance" in text
            or "naissance" in text
        ):
            return "eu"
        if re.search(r"\bmm\s*[/.-]\s*dd\s*[/.-]\s*yyyy\b", text):
            return "us"
        if re.search(r"\byyyy\s*[/.-]\s*mm\s*[/.-]\s*dd\b", text) or "type=date" in text or re.search(r"autocomplete=.*\bbday\b", text):
            return "iso"
        return "iso"

    def _normalize_about_you_text(self, value: str) -> str:
        text = unicodedata.normalize("NFD", str(value or "").lower())
        text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
        return re.sub(r"\s+", " ", text).strip()

    def _about_you_text_has_word(self, text: str, word: str) -> bool:
        text = self._normalize_about_you_text(text)
        word = self._normalize_about_you_text(word)
        if not word:
            return False
        if re.fullmatch(r"[a-z0-9]+", word):
            return bool(re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", text))
        return word in text

    def _about_you_text_has_any_word(self, text: str, words: list[str]) -> bool:
        return any(self._about_you_text_has_word(text, word) for word in words)

    def _about_you_second_field_kind_from_context(self, context: str) -> str:
        raw_text = str(context or "")
        text = self._normalize_about_you_text(raw_text)
        # 字段自身的 name/id/data-testid 比页面说明文字更可靠。年龄页的正文可能同时
        # 出现生日/隐私说明，不能让这些正文关键词把 name=age 误判成 birth_date。
        if re.search(
            r"(?:^|\s)(?:name|id|data-testid)\s*=\s*[^\s]*(?:^|[-_])age(?:[-_]|$)[^\s]*(?=\s|$)",
            text,
            flags=re.I,
        ) or re.search(r"(?:^|\s)(?:name|id|data-testid)\s*=\s*age(?=\s|$)", text, flags=re.I):
            return "age"
        birth_date_patterns = [
            r"\bbday\b",
            r"\bbirthday\b",
            r"date\s*of\s*birth",
            r"birthdate",
            r"\bdob\b",
            r"fecha\s+de\s+nacimiento",
            r"date\s+de\s+naissance",
            r"\bgeburtstag\b",
            r"\bgeburtsdatum\b",
            r"ngay\s+sinh",
            r"data\s+de\s+nascimento",
            r"data\s+di\s+nascita",
            r"geboortedatum",
            r"tanggal\s+lahir",
            r"\b(dd|jj)\s*[/.-]\s*mm\s*[/.-]\s*(yyyy|aaaa)\b",
            r"\btt\s*\.\s*mm\s*\.\s*jjjj\b",
            r"\bmm\s*[/.-]\s*dd\s*[/.-]\s*yyyy\b",
            r"\byyyy\s*[/.-]\s*mm\s*[/.-]\s*dd\b",
            r"type=date",
            r"autocomplete=.*\bbday\b",
            r"生年月日",
            r"誕生日",
        ]
        if any(re.search(pattern, text, flags=re.I) for pattern in birth_date_patterns):
            return "birth_date"
        if self._about_you_text_has_any_word(raw_text, ABOUT_YOU_BIRTH_DATE_WORDS):
            return "birth_date"
        if self._about_you_text_has_any_word(raw_text, ABOUT_YOU_BIRTH_YEAR_WORDS):
            return "birth_year"
        if self._about_you_text_has_any_word(raw_text, ABOUT_YOU_AGE_WORDS):
            return "age"
        return "birth_year"

    def _about_you_second_field_context(self, page) -> str:
        try:
            return str(page.evaluate(
                """() => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const controls = Array.from(document.querySelectorAll('input, textarea, [contenteditable="true"]')).filter(visible);
                    const el = controls[1];
                    if (!el) return document.body?.innerText || document.title || '';
                    const parts = [
                        `name=${el.getAttribute('name') || ''}`, `id=${el.id || ''}`,
                        `placeholder=${el.getAttribute('placeholder') || ''}`,
                        `aria-label=${el.getAttribute('aria-label') || ''}`,
                        `autocomplete=${el.getAttribute('autocomplete') || ''}`,
                        `inputmode=${el.getAttribute('inputmode') || ''}`,
                        `type=${el.getAttribute('type') || el.type || ''}`,
                        `data-testid=${el.getAttribute('data-testid') || ''}`
                    ];
                    const labelledBy = el.getAttribute('aria-labelledby');
                    if (labelledBy) {
                        for (const id of labelledBy.split(/\\s+/)) {
                            const labelEl = document.getElementById(id);
                            if (labelEl) parts.push(labelEl.textContent || '');
                        }
                    }
                    for (const label of Array.from(document.querySelectorAll('label'))) {
                        if (label.htmlFor && label.htmlFor === el.id) parts.push(label.textContent || '');
                        if (label.contains(el)) parts.push(label.textContent || '');
                    }
                    let node = el.parentElement;
                    for (let i = 0; node && i < 3; i += 1, node = node.parentElement) {
                        parts.push(node.textContent || '');
                    }
                    parts.push(document.querySelector('h1,h2')?.textContent || '');
                    parts.push(document.body?.innerText || '');
                    parts.push(document.title || '');
                    return parts.filter(Boolean).join(' ');
                }"""
            ) or "")
        except Exception:
            return ""

    def _about_you_second_field_kind(self, page) -> str:
        try:
            return self._about_you_second_field_kind_from_context(self._about_you_second_field_context(page))
        except Exception:
            return "birth_year"

    def _focus_about_you_submit_or_body(self, page) -> None:
        try:
            page.evaluate(
                """() => {
                    const visible = (el) => {
                        if (!el) return false;
                        const r = el.getBoundingClientRect();
                        const s = getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                    };
                    const enabled = (el) => el && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                    const buttons = Array.from(document.querySelectorAll('button, [role="button"]')).filter(el => visible(el) && enabled(el));
                    const button = buttons.find(el => {
                        const text = (el.textContent || '').trim();
                        return text.includes('Finish creating account')
                            || text.includes('Finalizar la creación de la cuenta')
                            || text.includes('Finalizar la creacion de la cuenta')
                            || text.includes('アカウントの作成を完了する')
                            || text.includes('作成を完了')
                            || text.includes('完成帐户创建')
                            || text.includes('完成账户创建')
                            || (el.type || '').toLowerCase() === 'submit';
                    });
                    if (button) {
                        button.focus();
                        return true;
                    }
                    if (!document.body.hasAttribute('tabindex')) document.body.setAttribute('tabindex', '-1');
                    document.body.focus();
                    return false;
                }"""
            )
        except Exception:
            pass

    def _fill_visible_input_by_keyboard(self, page, index: int, value: str) -> None:
        box = page.evaluate(
            """({index}) => {
                const controls = Array.from(document.querySelectorAll('input, textarea, [contenteditable="true"]')).filter(el => {
                    const r = el.getBoundingClientRect();
                    const s = getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                });
                const el = controls[index];
                if (!el) return null;
                el.scrollIntoView({ block: 'center', inline: 'center' });
                const r = el.getBoundingClientRect();
                return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
            }""",
            {"index": index},
        )
        if not box:
            raise RuntimeError(f"未找到第 {index + 1} 个可见输入框")
        page.mouse.click(float(box["x"]), float(box["y"]))
        page.keyboard.press("Control+A")
        page.keyboard.press("Backspace")
        page.keyboard.type(str(value), delay=30)
        page.evaluate(
            """({index}) => {
                const controls = Array.from(document.querySelectorAll('input, textarea, [contenteditable="true"]')).filter(el => {
                    const r = el.getBoundingClientRect();
                    const s = getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
                });
                const el = controls[index];
                if (!el) return false;
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                el.dispatchEvent(new Event('blur', { bubbles: true }));
                return true;
            }""",
            {"index": index},
        )
        time.sleep(0.5)

    def _fill_first_visible(self, page, selectors: list[str], value: str) -> bool:
        for locator in self._visible_inputs(page, selectors):
            if self._force_fill_locator(locator, value):
                return True
        return False

    def _force_fill_locator(self, locator, value: str) -> bool:
        try:
            locator.click(timeout=3000)
            locator.fill(str(value), timeout=5000)
            locator.evaluate("""(el, value) => {
                const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                const desc = Object.getOwnPropertyDescriptor(proto, 'value');
                if (desc && desc.set) desc.set.call(el, value); else el.value = value;
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                el.dispatchEvent(new Event('blur', { bubbles: true }));
            }""", str(value))
            return True
        except Exception:
            return False









    def _extract_session_info(self, context) -> dict:
        page = None
        try:
            cached_payload = getattr(self, "_confirmed_session_payload", None)
            if isinstance(cached_payload, dict) and cached_payload.get("accessToken"):
                session = dict(cached_payload)
            else:
                page = context.new_page()
                page.goto("https://chatgpt.com/api/auth/session", wait_until="domcontentloaded", timeout=60000)
                body = page.locator("body").inner_text(timeout=15000).strip()
                try:
                    session = json.loads(body)
                except Exception as exc:
                    raise RuntimeError(f"Session 接口返回不是有效 JSON: {body[:300]}") from exc
                if isinstance(session, dict) and session.get("accessToken"):
                    self._confirmed_session_payload = dict(session)
            access_token = str(session.get("accessToken") or "")
            if not access_token:
                self.log("[Session] Session JSON 已获取，但未发现 accessToken")
            else:
                self.log("[Session] Session JSON 和 Access Token 已获取")
            storage_state = context.storage_state()
            session_token = ""
            for cookie in list(storage_state.get("cookies") or []):
                if str(cookie.get("name") or "") in {
                    "__Secure-next-auth.session-token",
                    "next-auth.session-token",
                }:
                    session_token = str(cookie.get("value") or "")
                    break
            result = {
                "url": "",
                "access_token": access_token,
                "session_token": session_token,
                "session_json": json.dumps(session, ensure_ascii=False, indent=2),
                "storage_state_json": json.dumps(storage_state, ensure_ascii=False),
            }
            result.update(dict(getattr(self, "_auth_result", {}) or {}))
            result.update(dict(getattr(self, "_mfa_result", {}) or {}))
            return result
        finally:
            if page is not None:
                try:
                    page.bring_to_front()
                except Exception:
                    pass
