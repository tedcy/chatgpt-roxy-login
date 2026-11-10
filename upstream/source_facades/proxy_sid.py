# -*- coding: utf-8 -*-
"""Sticky-SID proxy generation and country validation.

The country probes in this module are deliberately constrained to two fixed
HTTP endpoints and are always sent through the generated proxy candidate.
No direct fallback, environment proxy discovery, socket probing, or TLS
certificate inspection is performed here.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import secrets
import string
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote, unquote, urlsplit, urlunsplit


logger = logging.getLogger(__name__)

PROXY_SID_CANDIDATE_LIMIT = 6
PROXY_COUNTRY_PRIMARY_URL = "http://ipinfo.io/json"
PROXY_COUNTRY_FALLBACK_URL = (
    "http://ip-api.com/json/"
    "?fields=status,message,countryCode,regionName,city,timezone,isp,org,query"
)
PROXY_COUNTRY_CONNECT_TIMEOUT = 3
PROXY_COUNTRY_READ_TIMEOUT = 5
_GEO_LOG_VALUE_MAX_LENGTH = 160

# Candidate validation is allowed to use the relay pool's own shard and
# upstream-connection capacity.  Do not add a second process-wide preflight
# gate here: it would serialize otherwise independent registration lanes.
_METERED_PROXY_SELECTION_RETRY_DELAYS = (1.0, 3.0)

_REGION_PATTERN = re.compile(
    r"(?i)(?:^|-)region-(?P<region>[A-Za-z]{2})(?=-|$)"
)
_RANDOM_REGION_PATTERN = re.compile(
    r"(?i)(?:^|-)region-(?P<region>[A-Za-z]{2}|rand)(?=-|$)"
)
_STATE_PATTERN = re.compile(
    r"(?i)(?:^|-)st-(?P<state>[A-Za-z0-9._]+)(?=-|$)"
)
_SID_PATTERN = re.compile(
    r"(?i)(?:^|-)sid-(?P<sid>[A-Za-z0-9]+)-t-(?P<ttl>[0-9]+)(?=-|$)"
)
_SUPPORTED_PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}

StopCheck = Callable[[], None]


class ProxySidTemplateError(ValueError):
    code = "proxy_sid_template_invalid"

    def __init__(self, message: str) -> None:
        super().__init__(f"{self.code}: {message}")


class ProxySidGenerationError(RuntimeError):
    code = "proxy_sid_generation_failed"

    def __init__(self) -> None:
        super().__init__(f"{self.code}: 无法生成未使用的代理 SID")


class ProxySidCandidatesExhausted(RuntimeError):
    code = "proxy_sid_candidates_exhausted"

    def __init__(
        self,
        *,
        candidate_limit: int,
        last_result: dict[str, Any] | None = None,
    ) -> None:
        self.candidate_limit = int(candidate_limit)
        # Only normalized probe metadata is retained. Candidate URLs, proxy
        # credentials, SID values, and response bodies never enter the error.
        self.last_result = dict(last_result or {})
        super().__init__(
            f"{self.code}: {self.candidate_limit} 个 SID 候选均未通过目标国家校验"
        )


class RegistrationProxyCountryError(ValueError):
    code = "registration_proxy_country_invalid"

    def __init__(self, reason: str = "") -> None:
        self.reason = str(reason or "").strip()
        message = self.code if not self.reason else f"{self.code}: {self.reason}"
        super().__init__(message)


def normalize_registration_proxy_countries(value: Any) -> list[str]:
    """Normalize the ordered registration-country configuration.

    Configuration can arrive from source defaults, ``.env`` or the WebUI, so
    strings and iterable values are both accepted. All registration drivers
    use the supported country codes in the browser profile map.
    """

    if value is None:
        raw_values: list[Any] = []
    elif isinstance(value, str):
        raw_values = re.split(r"[,;\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        raw_values = []
        for item in value:
            raw_values.extend(re.split(r"[,;\s]+", str(item or "")))
    else:
        raise RegistrationProxyCountryError("配置必须是国家码列表")

    from config import browser as browser_config

    supported = {
        str(country or "").strip().upper()
        for country in (
            getattr(browser_config, "COUNTRY_LOCALE_PROFILE_MAP", {}) or {}
        )
        if str(country or "").strip()
    }
    countries: list[str] = []
    for raw in raw_values:
        country = str(raw or "").strip().upper()
        if not country:
            continue
        if not re.fullmatch(r"[A-Z]{2}", country) or country not in supported:
            raise RegistrationProxyCountryError("存在未支持的国家码")
        if country not in countries:
            countries.append(country)
    return countries


def configured_registration_proxy_countries() -> list[str]:
    from config import proxy as proxy_config

    return normalize_registration_proxy_countries(
        getattr(proxy_config, "REGISTRATION_PROXY_COUNTRIES", [])
    )


def registration_proxy_country_snapshot(*, driver: str | None = None) -> list[str]:
    """Read and validate the country list once for a new registration batch.

    All three registration drivers consume the same ordered country list.
    Only Roxy adds Profile requirements; this validation performs no network I/O.
    """

    if driver is None:
        from core.registration_driver_context import registration_driver
        driver = registration_driver()
    driver_name = str(driver or "protocol").strip().lower()
    if driver_name not in {"roxy", "headed_chrome", "protocol", "go_protocol"}:
        return []

    countries = configured_registration_proxy_countries()
    if not countries:
        return []

    # Validate all configured codes before creating the first job. Drivers
    # also check their selected target/template immediately before selection.
    for country in countries:
        if driver_name in {"protocol", "go_protocol"}:
            validate_registration_proxy_template_country(country)
        elif driver_name == "headed_chrome":
            validate_headed_chrome_proxy_country_runtime(country)
        else:
            validate_registration_proxy_country_runtime(country)
    return countries


def validate_headed_chrome_proxy_country_runtime(country: str) -> str:
    """Validate a persisted headed-Chrome country without Roxy coupling."""

    return validate_registration_proxy_template_country(country)


def validate_registration_proxy_template_country(country: str) -> str:
    """Validate the target and SID template, without driver or Geo requirements."""

    normalized = normalize_registration_proxy_countries([country])
    if not normalized:
        raise RegistrationProxyCountryError("任务国家为空")
    from config import proxy as proxy_config

    template_text = str(
        getattr(proxy_config, "PROXY_SID_TEMPLATE", "") or ""
    ).strip()
    if not template_text:
        raise RegistrationProxyCountryError("未配置 PROXY_SID_TEMPLATE")
    try:
        parse_proxy_template(template_text).for_country(normalized[0])
    except Exception as exc:
        raise RegistrationProxyCountryError("PROXY_SID_TEMPLATE 无效") from exc
    return normalized[0]


def validate_registration_proxy_country_runtime(country: str) -> str:
    """Validate one persisted target without re-reading the country list.

    A queued task must survive later edits to the ordered rotation list, while
    unsafe Roxy/template/Profile changes still fail closed before management
    requests are sent.
    """

    normalized = normalize_registration_proxy_countries([country])
    if not normalized:
        raise RegistrationProxyCountryError("任务国家为空")

    from config import roxybrowser as roxy_config

    if not bool(getattr(roxy_config, "ROXY_CREATE_USE_PROXY_POOL", False)):
        raise RegistrationProxyCountryError("Roxy 注册未启用代理池")
    from config import proxy as proxy_config

    template_text = str(getattr(proxy_config, "PROXY_SID_TEMPLATE", "") or "").strip()
    if not template_text:
        raise RegistrationProxyCountryError("未配置 PROXY_SID_TEMPLATE")
    try:
        parse_proxy_template(template_text)
    except Exception as exc:
        raise RegistrationProxyCountryError("PROXY_SID_TEMPLATE 无效") from exc
    profile_id = str(getattr(roxy_config, "ROXY_PROFILE_ID", "") or "").strip()
    if profile_id and profile_id.lower() not in {
        "-", "—", "无", "空", "none", "null",
    } and not bool(getattr(roxy_config, "ROXY_PROFILE_CACHE_REUSE", False)):
        raise RegistrationProxyCountryError("固定 Profile 不支持国家轮换")
    if bool(getattr(roxy_config, "ROXY_PROFILE_CACHE_REUSE", False)) and not str(
        getattr(roxy_config, "ROXY_PROJECT_ID", "") or ""
    ).strip():
        raise RegistrationProxyCountryError("缓存 Profile 未配置 ROXY_PROJECT_ID")
    return normalized[0]


def registration_proxy_country_for_index(
    countries: list[str] | tuple[str, ...] | None,
    index: int,
) -> str | None:
    values = list(countries or [])
    if not values:
        return None
    return values[int(index) % len(values)]


@dataclass(frozen=True, slots=True)
class SidProxyTemplate:
    scheme: str
    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)
    region_span: tuple[int, int]
    sid_span: tuple[int, int]
    country: str
    original_sid: str = field(repr=False)
    sid_length: int
    sid_alphabet: str
    ttl: int

    @property
    def registry_key(self) -> tuple[Any, ...]:
        sid_start, sid_end = self.sid_span
        username_shape = self.username[:sid_start] + "<SID>" + self.username[sid_end:]
        return (
            self.scheme,
            self.host,
            self.port,
            username_shape,
            self.password,
            self.sid_length,
            self.sid_alphabet,
            self.ttl,
        )

    def render(self, sid: str) -> str:
        sid_start, sid_end = self.sid_span
        username = self.username[:sid_start] + sid + self.username[sid_end:]
        host = f"[{self.host}]" if ":" in self.host else self.host
        netloc = (
            f"{quote(username, safe='')}:{quote(self.password, safe='')}@"
            f"{host}:{self.port}"
        )
        return urlunsplit((self.scheme, netloc, "", "", ""))

    def for_country(self, country: str) -> "SidProxyTemplate":
        """Return a parsed template targeted at one ISO country code.

        A state selector belongs to the template's original country.  Keeping
        ``st-California`` while changing ``region-US`` to ``region-JP`` would
        create a contradictory provider username, so cross-country variants
        deliberately remove state selectors.  Credentials and the original
        SID shape/TTL remain unchanged and are never logged.
        """

        target = str(country or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", target):
            raise ProxySidTemplateError("目标地区必须是二位 ASCII 国家码")
        region_start, region_end = self.region_span
        username = self.username[:region_start] + target + self.username[region_end:]
        if target != self.country:
            username = _STATE_PATTERN.sub("", username)
        host = f"[{self.host}]" if ":" in self.host else self.host
        netloc = (
            f"{quote(username, safe='')}:{quote(self.password, safe='')}@"
            f"{host}:{self.port}"
        )
        return parse_proxy_template(urlunsplit((self.scheme, netloc, "", "", "")))


@dataclass(frozen=True, slots=True)
class ProxySelection:
    proxy_url: str = field(repr=False)
    source: str
    safe_label: str
    validated: bool = False
    expected_country: str = ""
    actual_country: str = ""
    validation_source: str = ""
    candidate_index: int = 0
    candidate_limit: int = 0
    ttl: int = 0
    # 出口 Geo 不进入 repr/异常；需要诊断时只通过专用安全日志函数输出。
    geo: dict[str, Any] = field(default_factory=dict, repr=False)


def mask_proxy_url(proxy_url: Any) -> str:
    """Return a stable proxy label without username, password, or SID."""

    value = str(proxy_url or "").strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if not host:
            return "***"
        rendered_host = f"[{host}]" if ":" in host else host
        port = f":{parsed.port}" if parsed.port else ""
        auth = "***:***@" if parsed.username or parsed.password else ""
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        return f"{scheme}{auth}{rendered_host}{port}"
    except Exception:
        return "***"


_PROXY_URL_IN_TEXT_PATTERN = re.compile(
    r"(?i)\b(?:https?|socks5h?)://[^\s\"'<>]+"
)
_PROXY_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(proxy(?:username|user|account|password|pass)[\"']?\s*[:=]\s*)"
    r"([\"']?)([^\"',\s;}\]]+)([\"']?)"
)
_GENERIC_PROXY_CONTEXT_SECRET_PATTERN = re.compile(
    r"(?i)((?:username|user|account|password|pass)[\"']?\s*[:=]\s*)"
    r"([\"']?)([^\"',\s;}\]]+)([\"']?)"
)


def _redact_proxy_text(value: str) -> str:
    """Remove proxy credentials and complete SID values from arbitrary text."""

    def replace_url(match: re.Match[str]) -> str:
        raw = match.group(0)
        # Do not consume punctuation commonly attached to a serialized value.
        suffix = ""
        while raw and raw[-1] in ",;)]}":
            suffix = raw[-1] + suffix
            raw = raw[:-1]
        return mask_proxy_url(raw) + suffix

    redacted = _PROXY_URL_IN_TEXT_PATTERN.sub(replace_url, str(value or ""))

    def replace_assignment(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}***{match.group(4)}"

    redacted = _PROXY_SECRET_ASSIGNMENT_PATTERN.sub(
        replace_assignment,
        redacted,
    )
    if re.search(r"(?i)proxy.?info", redacted):
        redacted = _GENERIC_PROXY_CONTEXT_SECRET_PATTERN.sub(
            replace_assignment,
            redacted,
        )
    return _SID_PATTERN.sub(
        lambda match: match.group(0).replace(match.group("sid"), "***"),
        redacted,
    )


def redact_proxy_metadata(value: Any, *, _proxy_context: bool = False) -> Any:
    """Return a diagnostic/persistence-safe copy of nested proxy metadata.

    Roxy responses may echo ``proxyInfo``.  The browser connection fields are
    still useful, but proxy usernames, passwords, and complete sticky SIDs
    must never enter logs, account JSON, or exports.
    """

    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, child in value.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            child_proxy_context = _proxy_context or "proxy" in normalized_key
            is_proxy_secret = (
                normalized_key in {
                    "proxyusername",
                    "proxyuser",
                    "proxyaccount",
                    "proxypassword",
                    "proxypass",
                }
                or (
                    _proxy_context
                    and normalized_key
                    in {"username", "user", "account", "password", "pass", "pwd"}
                )
            )
            redacted[key] = (
                "***"
                if is_proxy_secret and child is not None and child != ""
                else redact_proxy_metadata(
                    child,
                    _proxy_context=child_proxy_context,
                )
            )
        return redacted
    if isinstance(value, list):
        return [
            redact_proxy_metadata(item, _proxy_context=_proxy_context)
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            redact_proxy_metadata(item, _proxy_context=_proxy_context)
            for item in value
        )
    if isinstance(value, str):
        return _redact_proxy_text(value)
    return value


def parse_proxy_template(value: Any, *, allow_random_region: bool = False) -> SidProxyTemplate:
    """Random regions require an opt-in from consumers without country validation."""
    raw = str(value or "").strip()
    if not raw:
        raise ProxySidTemplateError("代理 SID 模板为空")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (TypeError, ValueError):
        raise ProxySidTemplateError("代理 SID 模板 URL 无效") from None
    scheme = str(parsed.scheme or "").strip().lower()
    if scheme not in _SUPPORTED_PROXY_SCHEMES:
        raise ProxySidTemplateError("只支持 HTTP、HTTPS、SOCKS5 或 SOCKS5H 代理 URL")
    if not parsed.hostname or not port:
        raise ProxySidTemplateError("代理 SID 模板必须包含 host 和 port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ProxySidTemplateError("代理 SID 模板不能包含 path、query 或 fragment")

    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if not username or not password:
        raise ProxySidTemplateError("代理 SID 模板必须包含用户名和密码")

    region_pattern = _RANDOM_REGION_PATTERN if allow_random_region else _REGION_PATTERN
    region_matches = list(region_pattern.finditer(username))
    sid_matches = list(_SID_PATTERN.finditer(username))
    if len(region_matches) != 1 or len(sid_matches) != 1:
        raise ProxySidTemplateError(
            "用户名必须且只能包含一个 "
            + ("region-XX 或 region-Rand" if allow_random_region else "region-XX")
            + " 和一个 sid-字母数字-t-正数 段"
        )

    region_match = region_matches[0]
    sid_match = sid_matches[0]
    sid = sid_match.group("sid")
    try:
        ttl = int(sid_match.group("ttl"))
    except (TypeError, ValueError):
        ttl = 0
    if not 1 <= len(sid) <= 128 or ttl <= 0:
        raise ProxySidTemplateError("SID 长度或 Sticky 时间无效")
    if not sid.isascii() or not sid.isalnum():
        raise ProxySidTemplateError("SID 只能使用 ASCII 字母和数字")

    alphabet = ""
    if any(character.islower() for character in sid):
        alphabet += string.ascii_lowercase
    if any(character.isupper() for character in sid):
        alphabet += string.ascii_uppercase
    if any(character.isdigit() for character in sid):
        alphabet += string.digits
    if not alphabet:
        raise ProxySidTemplateError("SID 字符集无效")

    country = region_match.group("region").upper()
    return SidProxyTemplate(
        scheme=scheme,
        host=str(parsed.hostname),
        port=int(port),
        username=username,
        password=password,
        region_span=region_match.span("region"),
        sid_span=sid_match.span("sid"),
        country='' if country == 'RAND' else country,
        original_sid=sid,
        sid_length=len(sid),
        sid_alphabet=alphabet,
        ttl=ttl,
    )


class ProxySidGenerator:
    """Thread-safe generator shared by all tasks using one logical template."""

    def __init__(self, template: SidProxyTemplate) -> None:
        self.template = template
        self._lock = threading.RLock()
        self._used_sids: set[str] = {template.original_sid}

    def generate(self) -> str:
        with self._lock:
            for _ in range(256):
                sid = "".join(
                    secrets.choice(self.template.sid_alphabet)
                    for _ in range(self.template.sid_length)
                )
                if sid in self._used_sids:
                    continue
                self._used_sids.add(sid)
                return self.template.render(sid)
        raise ProxySidGenerationError()


_GENERATOR_REGISTRY_LOCK = threading.RLock()
_GENERATOR_REGISTRY: dict[tuple[Any, ...], ProxySidGenerator] = {}


def _generator_for(template: SidProxyTemplate) -> ProxySidGenerator:
    with _GENERATOR_REGISTRY_LOCK:
        generator = _GENERATOR_REGISTRY.get(template.registry_key)
        if generator is None:
            generator = ProxySidGenerator(template)
            _GENERATOR_REGISTRY[template.registry_key] = generator
        return generator


def reset_proxy_sid_state_for_tests() -> None:
    with _GENERATOR_REGISTRY_LOCK:
        _GENERATOR_REGISTRY.clear()


def new_proxy_probe_session(proxy: str) -> Any:
    """Create a session that can only use the supplied candidate proxy."""

    try:
        import curl_cffi.requests as curl_requests
    except Exception as exc:  # pragma: no cover - deployment dependency check
        raise RuntimeError(f"curl_cffi unavailable: {type(exc).__name__}") from exc
    try:
        session = curl_requests.Session(trust_env=False)
    except TypeError:
        session = curl_requests.Session()
    from core.protocol_task_observability import bind_session
    bind_session(session)
    try:
        session.trust_env = False
    except Exception:
        pass
    headers = getattr(session, "headers", None)
    if headers is not None:
        headers.clear()
        headers.update(
            {
                "Accept": "application/json",
                "Connection": "close",
                "User-Agent": "turb-gpt-proxy-country-check/1",
            }
        )
    session.proxies = {"http": proxy, "https": proxy}
    return session


def _response_text(response: Any) -> str:
    value = getattr(response, "text", "")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _geo_debug_log_enabled() -> bool:
    try:
        from config import proxy as proxy_config

        return bool(getattr(proxy_config, "PROXY_SID_LOG_EXIT_GEO", True))
    except Exception:
        return True


def _safe_geo_log_value(value: Any, *, fallback: str = "-") -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    if not text:
        return fallback
    return text[:_GEO_LOG_VALUE_MAX_LENGTH]


def _safe_geo_log_ip(value: Any) -> str:
    try:
        return ipaddress.ip_address(str(value or "").strip()).compressed
    except ValueError:
        return "unavailable"


def _log_proxy_geo_debug(
    result: dict[str, Any],
    *,
    candidate_index: int,
    candidate_limit: int,
) -> None:
    if not _geo_debug_log_enabled():
        return
    geo = result.get("geo") if isinstance(result.get("geo"), dict) else {}
    logger.info(
        "[ProxySID][GeoDebug] candidate=%s/%s exit_ip=%s country=%s "
        "region=%s city=%s timezone=%s org=%s source=%s result=%s",
        candidate_index,
        candidate_limit,
        _safe_geo_log_ip(geo.get("ip")),
        _safe_geo_log_value(
            geo.get("country") or result.get("actual_country"),
            fallback="unknown",
        ),
        _safe_geo_log_value(geo.get("region")),
        _safe_geo_log_value(geo.get("city")),
        _safe_geo_log_value(geo.get("timezone")),
        _safe_geo_log_value(geo.get("org")),
        _safe_geo_log_value(result.get("source"), fallback="none"),
        "matched" if result.get("ok") else _safe_geo_log_value(
            result.get("reason"),
            fallback="rejected",
        ),
    )


def parse_proxy_location_response(response: Any, source: str) -> dict[str, Any]:
    """Strictly parse one non-redirected HTTP 200 country response."""

    if int(getattr(response, "status_code", 0) or 0) != 200:
        return {}
    if getattr(response, "history", None):
        return {}
    try:
        payload = json.loads(_response_text(response))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}

    normalized_source = str(source or "").strip().lower()
    if normalized_source == "ipinfo":
        country_value = payload.get("country")
        ip_value = payload.get("ip")
        region = payload.get("region")
        city = payload.get("city")
        timezone = payload.get("timezone")
        org = payload.get("org")
    elif normalized_source == "ip-api":
        if str(payload.get("status") or "").strip().lower() != "success":
            return {}
        country_value = payload.get("countryCode")
        ip_value = payload.get("query")
        region = payload.get("regionName")
        city = payload.get("city")
        timezone = payload.get("timezone")
        org = payload.get("org") or payload.get("isp")
    else:
        return {}

    country = str(country_value or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        return {}
    try:
        actual_ip = ipaddress.ip_address(str(ip_value or "").strip()).compressed
    except ValueError:
        return {}
    return {
        "ip": actual_ip,
        "country": country,
        "region": str(region or ""),
        "city": str(city or ""),
        "timezone": str(timezone or ""),
        "org": str(org or ""),
    }


def _check_stop(check_stop: StopCheck | None) -> None:
    if check_stop is not None:
        check_stop()


def _probe_request(
    session: Any,
    url: str,
    source: str,
    *,
    check_stop: StopCheck | None = None,
) -> tuple[dict[str, Any], str]:
    try:
        response = session.get(
            url,
            timeout=(PROXY_COUNTRY_CONNECT_TIMEOUT, PROXY_COUNTRY_READ_TIMEOUT),
            allow_redirects=False,
        )
    except Exception as exc:
        _check_stop(check_stop)
        return {}, type(exc).__name__
    _check_stop(check_stop)
    location = parse_proxy_location_response(response, source)
    if location:
        return location, ""
    status_code = int(getattr(response, "status_code", 0) or 0)
    if getattr(response, "history", None):
        return {}, "redirect_rejected"
    return {}, f"http_{status_code}_invalid"


def probe_proxy_exit(
    proxy: str,
    expected_country: str = "",
    *,
    session_factory: Callable[[str], Any] | None = None,
    check_stop: StopCheck | None = None,
) -> dict[str, Any]:
    """Read a valid exit, optionally enforcing a country, via the fixed probes."""

    expected = str(expected_country or "").strip().upper()
    if expected and not re.fullmatch(r"[A-Z]{2}", expected):
        raise ProxySidTemplateError("模板 region 必须是二位 ASCII 国家码")
    _check_stop(check_stop)
    factory = session_factory or new_proxy_probe_session
    result: dict[str, Any] = {}
    started = time.monotonic()
    session = factory(proxy)
    try:
        primary, primary_error = _probe_request(
            session,
            PROXY_COUNTRY_PRIMARY_URL,
            "ipinfo",
            check_stop=check_stop,
        )
        if primary and (not expected or primary["country"] == expected):
            result = {
                "ok": True,
                "expected_country": expected,
                "actual_country": primary["country"],
                "source": "ipinfo",
                "reason": "",
                "geo": primary,
                "primary_error": "",
                "fallback_error": "",
            }
            return result

        fallback, fallback_error = _probe_request(
            session,
            PROXY_COUNTRY_FALLBACK_URL,
            "ip-api",
            check_stop=check_stop,
        )
        if not primary and fallback and (not expected or fallback["country"] == expected):
            result = {
                "ok": True,
                "expected_country": expected,
                "actual_country": fallback["country"],
                "source": "ip-api",
                "reason": "",
                "geo": fallback,
                "primary_error": primary_error,
                "fallback_error": "",
            }
            return result

        observed = primary or fallback
        if primary and fallback and primary.get("country") != fallback.get("country"):
            reason = "country_conflict"
        elif observed:
            reason = "country_mismatch"
        else:
            reason = "connectivity_failed"
        result = {
            "ok": False,
            "expected_country": expected,
            "actual_country": str(observed.get("country") or ""),
            "source": "ipinfo" if primary else ("ip-api" if fallback else ""),
            "reason": reason,
            "geo": dict(observed or {}),
            "primary_error": primary_error,
            "fallback_error": fallback_error,
        }
        return result
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
        if result:
            logger.info(
                "[ProxyPreflight] stage=exit expected_country=%s actual_country=%s "
                "source=%s result=%s reason=%s elapsed_ms=%d",
                expected or "unknown", result.get("actual_country") or "unknown",
                result.get("source") or "none", "pass" if result.get("ok") else "failed",
                result.get("reason") or "none", round((time.monotonic() - started) * 1000),
            )


def verify_proxy_country(
    proxy: str,
    expected_country: str,
    *,
    session_factory: Callable[[str], Any] | None = None,
    check_stop: StopCheck | None = None,
) -> dict[str, Any]:
    """Keep country-required callers on the existing strict matching policy."""

    expected = str(expected_country or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", expected):
        raise ProxySidTemplateError("模板 region 必须是二位 ASCII 国家码")
    return probe_proxy_exit(proxy, expected, session_factory=session_factory, check_stop=check_stop)


def _select_sid_proxy_unlocked(
    template: Any,
    *,
    candidate_limit: int = PROXY_SID_CANDIDATE_LIMIT,
    verifier: Callable[..., dict[str, Any]] = verify_proxy_country,
    candidate_probe: Callable[[str, str, dict[str, Any]], dict[str, Any]] | None = None,
    proxy_adapter: Callable[[str], str] | None = None,
    check_stop: StopCheck | None = None,
) -> ProxySelection:
    parsed = template if isinstance(template, SidProxyTemplate) else parse_proxy_template(template)
    limit = max(1, min(int(candidate_limit), PROXY_SID_CANDIDATE_LIMIT))
    generator = _generator_for(parsed)
    last_result: dict[str, Any] = {}

    for candidate_index in range(1, limit + 1):
        _check_stop(check_stop)
        candidate = generator.generate()
        probe_proxy = proxy_adapter(candidate) if proxy_adapter is not None else candidate
        result = dict(
            verifier(
                probe_proxy,
                parsed.country,
                check_stop=check_stop,
            )
            or {}
        )
        if result.get("ok") and candidate_probe is not None:
            try:
                edge_result = dict(
                    candidate_probe(
                        probe_proxy,
                        parsed.country,
                        result,
                    )
                    or {}
                )
            except Exception as exc:
                edge_result = {
                    "ok": False,
                    "state": "network_error",
                    "reason": type(exc).__name__,
                }
            result["preflight_state"] = str(edge_result.get("state") or "")
            result["preflight_reason"] = str(edge_result.get("reason") or "")
            if not bool(edge_result.get("ok")):
                result["ok"] = False
                result["reason"] = str(
                    edge_result.get("reason")
                    or edge_result.get("state")
                    or "proxy_preflight_failed"
                )
        _check_stop(check_stop)
        last_result = {
            "ok": bool(result.get("ok")),
            "expected_country": parsed.country,
            "actual_country": str(result.get("actual_country") or ""),
            "source": str(result.get("source") or ""),
            "reason": str(result.get("reason") or ""),
            "primary_error": str(result.get("primary_error") or ""),
            "fallback_error": str(result.get("fallback_error") or ""),
            "preflight_state": str(result.get("preflight_state") or ""),
        }
        logger.info(
            "[ProxySID] candidate=%s/%s expected_country=%s actual_country=%s "
            "source=%s result=%s",
            candidate_index,
            limit,
            parsed.country,
            last_result["actual_country"] or "unknown",
            last_result["source"] or "none",
            "matched"
            if result.get("ok")
            else (last_result["reason"] or last_result["preflight_state"] or "rejected"),
        )
        # A metered registration task must never emit the upstream exit IP or
        # detailed Geo.  The safe candidate/country line above remains enough
        # to diagnose country matching.
        if proxy_adapter is None:
            _log_proxy_geo_debug(
                result,
                candidate_index=candidate_index,
                candidate_limit=limit,
            )
        if result.get("ok"):
            return ProxySelection(
                proxy_url=candidate,
                source="sid_template",
                safe_label=mask_proxy_url(candidate),
                validated=True,
                expected_country=parsed.country,
                actual_country=str(result.get("actual_country") or parsed.country),
                validation_source=str(result.get("source") or ""),
                candidate_index=candidate_index,
                candidate_limit=limit,
                ttl=parsed.ttl,
                geo=dict(result.get("geo") or {}),
            )

    raise ProxySidCandidatesExhausted(
        candidate_limit=limit,
        last_result=last_result,
    )


def select_sid_proxy(
    template: Any,
    *,
    candidate_limit: int = PROXY_SID_CANDIDATE_LIMIT,
    verifier: Callable[..., dict[str, Any]] = verify_proxy_country,
    candidate_probe: Callable[[str, str, dict[str, Any]], dict[str, Any]] | None = None,
    proxy_adapter: Callable[[str], str] | None = None,
    check_stop: StopCheck | None = None,
) -> ProxySelection:
    """Generate and validate one SID without a second preflight concurrency gate."""

    retry_count = len(_METERED_PROXY_SELECTION_RETRY_DELAYS) if proxy_adapter is not None else 0
    for attempt in range(retry_count + 1):
        try:
            return _select_sid_proxy_unlocked(
                template,
                candidate_limit=candidate_limit,
                verifier=verifier,
                candidate_probe=candidate_probe,
                proxy_adapter=proxy_adapter,
                check_stop=check_stop,
            )
        except ProxySidCandidatesExhausted as exc:
            last_result = dict(getattr(exc, "last_result", {}) or {})
            transient = (
                str(last_result.get("reason") or "").strip().lower()
                == "connectivity_failed"
                and any(
                    str(last_result.get(key) or "").strip().lower()
                    in {"http_502_invalid", "connectivity_failed"}
                    for key in ("primary_error", "fallback_error")
                )
            )
            if attempt >= retry_count or not transient:
                raise
            delay = _METERED_PROXY_SELECTION_RETRY_DELAYS[attempt]
            logger.warning(
                "[ProxySID] 计量中继候选探测暂时不可达，退避后重试："
                "attempt=%s/%s delay=%.1fs",
                attempt + 1,
                retry_count,
                delay,
            )
            _check_stop(check_stop)
            time.sleep(delay)
    raise AssertionError("unreachable")


def select_sid_proxy_for_country(
    template: Any,
    country: str,
    *,
    candidate_limit: int = PROXY_SID_CANDIDATE_LIMIT,
    verifier: Callable[..., dict[str, Any]] = verify_proxy_country,
    candidate_probe: Callable[[str, str, dict[str, Any]], dict[str, Any]] | None = None,
    proxy_adapter: Callable[[str], str] | None = None,
    check_stop: StopCheck | None = None,
) -> ProxySelection:
    """Generate and validate one Sticky SID for a requested country."""

    parsed = template if isinstance(template, SidProxyTemplate) else parse_proxy_template(template)
    return select_sid_proxy(
        parsed.for_country(country),
        candidate_limit=candidate_limit,
        verifier=verifier,
        candidate_probe=candidate_probe,
        proxy_adapter=proxy_adapter,
        check_stop=check_stop,
    )


def select_default_proxy(
    *,
    country: str | None = None,
    proxy_country: str | None = None,
    proxy_adapter: Callable[[str], str] | None = None,
    probe_session_factory: Callable[[str], Any] | None = None,
    candidate_probe: Callable[[str, str, dict[str, Any]], dict[str, Any]] | None = None,
    check_stop: StopCheck | None = None,
) -> ProxySelection:
    """Resolve the process' default proxy source without any unsafe fallback."""

    from config import proxy as proxy_config

    template = str(getattr(proxy_config, "PROXY_SID_TEMPLATE", "") or "").strip()
    verifier = verify_proxy_country
    if probe_session_factory is not None:
        def verifier(
            candidate_proxy: str,
            expected_country: str,
            *,
            check_stop: StopCheck | None = None,
        ) -> dict[str, Any]:
            return verify_proxy_country(
                candidate_proxy,
                expected_country,
                session_factory=probe_session_factory,
                check_stop=check_stop,
            )

    if country and proxy_country and str(country).strip().upper() != str(proxy_country).strip().upper():
        raise RegistrationProxyCountryError("目标国家参数冲突")
    requested_country = str(country or proxy_country or "").strip()
    if requested_country:
        normalized = normalize_registration_proxy_countries([requested_country])
        if not template:
            raise RegistrationProxyCountryError("未配置 PROXY_SID_TEMPLATE")
        return select_sid_proxy_for_country(
            template,
            normalized[0],
            verifier=verifier,
            candidate_probe=candidate_probe,
            proxy_adapter=proxy_adapter,
            check_stop=check_stop,
        )
    if template:
        return select_sid_proxy(
            template,
            verifier=verifier,
            candidate_probe=candidate_probe,
            proxy_adapter=proxy_adapter,
            check_stop=check_stop,
        )

    legacy_proxy = str(proxy_config.pick_proxy() or "").strip()
    if legacy_proxy:
        if candidate_probe is not None:
            result = dict(candidate_probe(legacy_proxy, requested_country, {}) or {})
            if not bool(result.get("ok")):
                raise ProxySidCandidatesExhausted(
                    candidate_limit=1,
                    last_result={
                        "ok": False,
                        "actual_country": "",
                        "source": "proxy_pool",
                        "reason": str(
                            result.get("reason")
                            or result.get("state")
                            or "proxy_preflight_failed"
                        ),
                        "preflight_state": str(result.get("state") or ""),
                    },
                )
        return ProxySelection(
            proxy_url=legacy_proxy,
            source="proxy_pool",
            safe_label=mask_proxy_url(legacy_proxy),
        )
    return ProxySelection(proxy_url="", source="direct", safe_label="")


__all__ = [
    "PROXY_COUNTRY_CONNECT_TIMEOUT",
    "PROXY_COUNTRY_FALLBACK_URL",
    "PROXY_COUNTRY_PRIMARY_URL",
    "PROXY_COUNTRY_READ_TIMEOUT",
    "PROXY_SID_CANDIDATE_LIMIT",
    "ProxySelection",
    "RegistrationProxyCountryError",
    "ProxySidCandidatesExhausted",
    "ProxySidGenerationError",
    "ProxySidGenerator",
    "ProxySidTemplateError",
    "SidProxyTemplate",
    "mask_proxy_url",
    "configured_registration_proxy_countries",
    "normalize_registration_proxy_countries",
    "registration_proxy_country_for_index",
    "registration_proxy_country_snapshot",
    "validate_registration_proxy_country_runtime",
    "validate_headed_chrome_proxy_country_runtime",
    "validate_registration_proxy_template_country",
    "new_proxy_probe_session",
    "parse_proxy_location_response",
    "parse_proxy_template",
    "probe_proxy_exit",
    "redact_proxy_metadata",
    "reset_proxy_sid_state_for_tests",
    "select_default_proxy",
    "select_sid_proxy",
    "select_sid_proxy_for_country",
    "verify_proxy_country",
]
