# -*- coding: utf-8 -*-
"""ChatGPT 账号套餐/试用资格查询。"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import quote, urlparse

from core.plan_promo import (
    first_plus_free_trial_campaign,
    normalize_plan_promo_campaigns,
)
from core.session import BrowserSession
from core.account_grace_period import parse_entitlement as parse_grace_period

logger = logging.getLogger(__name__)

ACCOUNTS_CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"
MAX_PLAN_CHECK_REGIONS = 8
PLAN_CHECK_CONTEXT_MODES = frozenset({"saved_session", "at_only"})


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_token(token: str) -> str:
    token = (token or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _mask_proxy(proxy: str) -> str:
    """返回可用于日志/API 结果的代理摘要，不泄露用户名和密码。"""
    value = str(proxy or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        auth = "***:***@" if parsed.username or parsed.password else ""
        return f"{scheme}{auth}{host}{port}" or "***"
    except Exception:
        return "***"


def _local_proxy_status(proxy: str) -> tuple[bool, bool, str | None]:
    """检查回环代理端口；非本地代理不做预探测，避免额外网络请求。"""
    value = str(proxy or "").strip()
    if not value:
        return False, False, None
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        is_loopback = host.lower() == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            return False, True, None
        if not parsed.port:
            return True, False, "本地代理未配置端口"
        try:
            with socket.create_connection((host, parsed.port), timeout=0.5):
                return True, True, None
        except OSError as exc:
            return True, False, f"本地代理 {host}:{parsed.port} 未监听（{type(exc).__name__}）"
    except Exception as exc:
        return False, False, f"代理地址解析失败（{type(exc).__name__}）"


def resolve_plan_check_route(
    explicit_proxy: Optional[str] = None,
    *,
    proxy_adapter: Callable[[str], str] | None = None,
    route_adapter: Callable[[str], str] | None = None,
) -> dict:
    """解析套餐查询的实际网络路径。

    explicit_proxy 不是 None 时表示 API 调用方明确覆盖配置；空字符串代表直连。
    """
    if explicit_proxy is not None:
        selected = str(explicit_proxy or "").strip()
        routed = route_adapter(selected) if selected and route_adapter else selected
        return {
            "proxy": routed,
            "proxy_mode": "request",
            "network_route": "proxy" if selected else "direct",
            "proxy_used": (
                "metered_plan_proxy"
                if selected and route_adapter is not None
                else (_mask_proxy(selected) or None)
            ),
            "proxy_fallback_reason": None,
        }

    from config import proxy as proxy_cfg

    mode = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError(f"PLAN_CHECK_PROXY_MODE={mode!r} 无效，可选 auto / proxy / direct")
    if mode == "direct":
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": None,
        }

    selected = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY", "") or "").strip()
    selected_label = _mask_proxy(selected)
    if not selected:
        from core.proxy_sid import select_default_proxy

        if proxy_adapter is not None:
            selection = select_default_proxy(proxy_adapter=proxy_adapter)
        else:
            selection = select_default_proxy()
        selected = selection.proxy_url
        selected_label = selection.safe_label
    if not selected:
        if mode == "proxy":
            raise ValueError(
                "套餐查询网络模式为 proxy，但未配置 PLAN_CHECK_PROXY、"
                "PROXY_SID_TEMPLATE 或 PROXY_POOL"
            )
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": "未配置套餐查询代理或代理池",
        }

    is_local, available, reason = _local_proxy_status(selected)
    if mode == "auto" and is_local and not available:
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct_fallback",
            "proxy_used": selected_label,
            "proxy_fallback_reason": reason,
        }
    routed = route_adapter(selected) if route_adapter is not None else selected
    return {
        "proxy": routed,
        "proxy_mode": mode,
        "network_route": "proxy",
        "proxy_used": (
            "metered_plan_proxy"
            if route_adapter is not None
            else selected_label
        ),
        "proxy_fallback_reason": None,
    }


def decode_jwt_payload_unverified(token: str) -> dict:
    """仅本地解析 JWT payload，不校验签名。"""
    token = normalize_token(token)
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def token_claims(token: str) -> dict:
    payload = decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    exp = payload.get("exp")
    exp_iso = None
    expired = None
    if isinstance(exp, (int, float)):
        exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        expired = datetime.now(tz=timezone.utc).timestamp() >= float(exp)
    return {
        "payload": payload,
        "email": profile.get("email"),
        "user_name": profile.get("name"),
        "user_id": auth.get("chatgpt_user_id") or auth.get("user_id"),
        "account_id": auth.get("chatgpt_account_id"),
        "claim_plan_type": auth.get("chatgpt_plan_type"),
        "exp": exp,
        "token_expires_at": exp_iso,
        "token_expired": expired,
    }


def _common_headers(env: BrowserSession, token: str) -> dict[str, str]:
    # Keep the same frontend context as the browser/FreePP request path:
    # client build, device/session IDs, Datadog context and client hints all
    # need to agree with the restored Cookie jar.
    get_headers = getattr(env, "get_chatgpt_headers", None)
    if callable(get_headers):
        headers = dict(get_headers(referer="https://chatgpt.com/") or {})
    else:
        # Keep compatibility with small embedders/test doubles created before
        # BrowserSession exposed the complete frontend header factory.
        headers = dict(env._get_common_headers())
    device_id = str(getattr(env, "device_id", "") or "")
    navigator_language = getattr(env, "navigator_language", None)
    language = str(navigator_language() if callable(navigator_language) else "zh-CN")
    try:
        from config import OAI_CLIENT_BUILD_NUMBER, OAI_CLIENT_VERSION
    except Exception:
        OAI_CLIENT_BUILD_NUMBER = ""
        OAI_CLIENT_VERSION = ""
    headers.update({
        "accept": "application/json",
        "authorization": f"Bearer {normalize_token(token)}",
        "oai-device-id": device_id,
        "oai-session-id": str(getattr(env, "oai_session_id", "") or ""),
        "oai-client-build-number": str(
            headers.get("oai-client-build-number") or OAI_CLIENT_BUILD_NUMBER or ""
        ),
        "oai-client-version": str(
            headers.get("oai-client-version") or OAI_CLIENT_VERSION or ""
        ),
        "oai-language": language,
        "origin": "https://chatgpt.com",
        "referer": "https://chatgpt.com/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-openai-target-path": ACCOUNTS_CHECK_PATH,
        "x-openai-target-route": ACCOUNTS_CHECK_PATH,
    })
    return headers


def warmup_chatgpt_page(env: BrowserSession, *, timeout: float = 30.0) -> dict:
    """Warm one proxy-bound browser context before the JSON API request.

    The response body is intentionally discarded.  Only a fixed status and
    whether the request completed are returned to callers.
    """

    try:
        headers = env.get_chatgpt_navigate_headers(
            referer="https://chatgpt.com/",
            user_initiated=False,
        )
        headers["cache-control"] = "no-cache"
        response = env.session.get(
            "https://chatgpt.com/",
            headers=headers,
            allow_redirects=True,
            timeout=max(3.0, min(60.0, float(timeout or 30.0))),
        )
        status = int(getattr(response, "status_code", 0) or 0)
        return {
            "ok": 200 <= status < 400,
            "http_status": status or None,
        }
    except Exception as exc:
        logger.debug(
            "套餐查询 warmup 失败: error_type=%s",
            type(exc).__name__,
        )
        return {
            "ok": False,
            "http_status": None,
            "error_code": "plan_check_warmup_failed",
        }


def _select_accounts_check_item(
    data: dict,
    *,
    token: str = "",
) -> tuple[dict, object, dict]:
    """Select the token-bound account entry from an accounts/check payload."""

    claims = token_claims(token) if token else {}
    claim_account_id = claims.get("account_id")
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        raise ValueError("响应缺少 accounts 对象")

    item = None
    account_key = None
    if claim_account_id and isinstance(accounts.get(claim_account_id), dict):
        item = accounts.get(claim_account_id)
        account_key = claim_account_id
    elif isinstance(accounts.get("default"), dict):
        item = accounts.get("default")
        account = item.get("account") or {}
        account_key = account.get("account_id") or "default"
    else:
        for key, value in accounts.items():
            if key != "default" and isinstance(value, dict):
                item = value
                account_key = key
                break
    if not isinstance(item, dict):
        raise ValueError("未找到可解析的账号条目")
    return item, account_key, claims


def parse_accounts_promos(data: dict, *, token: str = "") -> dict:
    """Extract only safe Plus/Go/Pro campaigns and the current Free predicate."""

    item, _, claims = _select_accounts_check_item(data, token=token)
    account = item.get("account") or {}
    entitlement = item.get("entitlement") or {}
    eligible_promo_campaigns = item.get("eligible_promo_campaigns") or {}
    promo_campaigns = normalize_plan_promo_campaigns(eligible_promo_campaigns)
    plus_trial_campaign = first_plus_free_trial_campaign(promo_campaigns)
    plan_type = account.get("plan_type") or claims.get("claim_plan_type") or ""
    subscription_plan = entitlement.get("subscription_plan") or ""
    account_is_free = (
        str(plan_type).strip().lower() == "free"
        or str(subscription_plan).strip().lower() == "chatgptfreeplan"
    )
    return {
        "ok": True,
        "checked_at": now_iso(),
        "account_is_free": account_is_free,
        "plus_trial_eligible": bool(account_is_free and plus_trial_campaign),
        "plan_promo_campaigns": promo_campaigns,
    }


def parse_accounts_check(data: dict, *, token: str = "") -> dict:
    """从 accounts/check 响应提取套餐、Plus 资格和安全 Plus/Go/Pro 活动 ID。"""
    item, account_key, claims = _select_accounts_check_item(data, token=token)
    claim_account_id = claims.get("account_id")

    account = item.get("account") or {}
    raw_entitlement = item.get("entitlement")
    entitlement = raw_entitlement if isinstance(raw_entitlement, dict) else {}
    last_sub = item.get("last_active_subscription") or {}
    eligible_promo_campaigns = item.get("eligible_promo_campaigns") or {}
    promo_campaigns = normalize_plan_promo_campaigns(eligible_promo_campaigns)
    plus_trial_campaign = first_plus_free_trial_campaign(promo_campaigns)
    plan_type = account.get("plan_type") or claims.get("claim_plan_type") or ""
    subscription_plan = entitlement.get("subscription_plan") or ""
    has_active_subscription = bool(entitlement.get("has_active_subscription"))
    is_free = str(plan_type).lower() == "free" or str(subscription_plan).lower() == "chatgptfreeplan"
    # The Plus promotion bucket also contains paid discounts.  Only an
    # explicitly free campaign grants trial eligibility; malformed or unknown
    # campaign IDs fail closed for extraction, HME priority and trial guards.
    plus_trial_eligible = bool(is_free and plus_trial_campaign)

    offers = ((item.get("eligible_offers") or {}).get("offers") or [])
    eligible_offer_ids = [o.get("id") for o in offers if isinstance(o, dict) and o.get("id")]

    result = {
        "ok": True,
        "checked_at": now_iso(),
        "account_id": account.get("account_id") or account_key or claim_account_id,
        "account_user_role": account.get("account_user_role"),
        "current_plan_type": plan_type,
        "subscription_plan": subscription_plan,
        "has_active_subscription": has_active_subscription,
        "is_active_subscription_gratis": bool(entitlement.get("is_active_subscription_gratis")),
        "expires_at": entitlement.get("expires_at"),
        "renews_at": entitlement.get("renews_at"),
        "cancels_at": entitlement.get("cancels_at"),
        "billing_period": entitlement.get("billing_period"),
        "billing_currency": entitlement.get("billing_currency"),
        "is_delinquent": bool(entitlement.get("is_delinquent")),
        "discount_type": (entitlement.get("discount") or {}).get("discount_type"),
        "discount_amount": (entitlement.get("discount") or {}).get("amount"),
        "discount_duration_num_periods": (entitlement.get("discount") or {}).get("duration_num_periods"),
        "discount_expires_at": (entitlement.get("discount") or {}).get("discount_expires_at"),
        "discount_cancellation_policy": (entitlement.get("discount") or {}).get("cancellation_policy"),
        "discount_promo_campaign_id": (entitlement.get("discount") or {}).get("promo_campaign_id"),
        "last_purchase_origin_platform": last_sub.get("purchase_origin_platform"),
        "last_will_renew": bool(last_sub.get("will_renew")),
        "plus_trial_eligible": plus_trial_eligible,
        "plus_trial_campaign_id": (plus_trial_campaign or {}).get("campaign_id"),
        "plan_promo_campaigns": promo_campaigns,
        "eligible_offer_ids": eligible_offer_ids,
        "features_count": len(item.get("features") or []),
        "can_access_with_session": bool(item.get("can_access_with_session")),
        "raw_account_plan_type": account.get("plan_type"),
    }
    result.update(parse_grace_period(raw_entitlement))
    result.update({k: v for k, v in claims.items() if k != "payload" and v is not None})
    return result


def _driver_plan_result_base(token: str, timeout_seconds: float) -> dict:
    claims = token_claims(token)
    return {
        "checked_at": now_iso(),
        "attempt_count": 1,
        "max_attempts": 1,
        "request_timeout": timeout_seconds,
        "retryable": False,
        "proxy_mode": "roxy_browser",
        "network_route": "roxy_browser",
        "proxy_used": None,
        "proxy_fallback_reason": None,
        **{k: v for k, v in claims.items() if k != "payload" and v is not None},
    }


def configured_plan_check_regions() -> list[str]:
    """Return validated, ordered region codes for Plus-offer discovery."""

    from config import browser as browser_cfg
    from config import proxy as proxy_cfg

    raw = getattr(proxy_cfg, "PLAN_CHECK_REGIONS", []) or []
    if isinstance(raw, str):
        values = re.split(r"[\s,;]+", raw)
    else:
        values = list(raw)
    supported = {
        str(code or "").strip().upper()
        for code in (getattr(browser_cfg, "COUNTRY_LOCALE_PROFILE_MAP", {}) or {})
    }
    regions: list[str] = []
    for value in values:
        region = str(value or "").strip().upper()
        if not region:
            continue
        if not re.fullmatch(r"[A-Z]{2}", region) or region not in supported:
            raise ValueError(f"不支持的套餐查询地区: {region or value!s}")
        if region not in regions:
            regions.append(region)
    if len(regions) > MAX_PLAN_CHECK_REGIONS:
        raise ValueError(f"套餐查询地区最多 {MAX_PLAN_CHECK_REGIONS} 个")
    return regions


def plan_check_region_settings(explicit_proxy: Optional[str] = None) -> dict:
    """Resolve whether regional SID scanning is active for this request.

    Explicit request proxies, a dedicated plan proxy and direct mode retain
    the legacy single-route behavior because their actual country cannot be
    safely inferred or rewritten.
    """

    from config import proxy as proxy_cfg

    regions = configured_plan_check_regions()
    mode = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError(f"PLAN_CHECK_PROXY_MODE={mode!r} 无效，可选 auto / proxy / direct")
    dedicated_proxy = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY", "") or "").strip()
    template = str(getattr(proxy_cfg, "PROXY_SID_TEMPLATE", "") or "").strip()
    enabled = bool(
        regions
        and explicit_proxy is None
        and mode != "direct"
        and not dedicated_proxy
        and template
    )
    return {
        "enabled": enabled,
        "regions": regions,
        "stop_on_eligible": bool(
            getattr(proxy_cfg, "PLAN_CHECK_STOP_ON_ELIGIBLE", True)
        ),
        "fallback_reason": (
            None
            if enabled
            else (
                "explicit_proxy" if explicit_proxy is not None else
                "direct_mode" if mode == "direct" else
                "dedicated_proxy" if dedicated_proxy else
                "template_missing" if not template else
                "regions_empty"
            )
        ),
    }


def resolve_plan_check_region_route(
    region: str,
    *,
    proxy_adapter: Callable[[str], str] | None = None,
    route_adapter: Callable[[str], str] | None = None,
) -> dict:
    """Create one verified Sticky SID route for a configured region."""

    from config import proxy as proxy_cfg
    from core.proxy_sid import select_sid_proxy_for_country

    template = str(getattr(proxy_cfg, "PROXY_SID_TEMPLATE", "") or "").strip()
    if not template:
        raise ValueError("PROXY_SID_TEMPLATE 为空，无法执行地区套餐查询")
    if proxy_adapter is not None:
        selection = select_sid_proxy_for_country(
            template,
            region,
            proxy_adapter=proxy_adapter,
        )
    else:
        # Preserve the legacy call shape for existing callers and mocks.
        selection = select_sid_proxy_for_country(template, region)
    selected_proxy = selection.proxy_url
    routed_proxy = (
        route_adapter(selected_proxy)
        if route_adapter is not None
        else selected_proxy
    )
    return {
        "proxy": routed_proxy,
        "proxy_mode": "regional_sid",
        "network_route": "regional_proxy",
        "proxy_used": (
            "metered_regional_proxy"
            if route_adapter is not None
            else selection.safe_label
        ),
        "proxy_fallback_reason": None,
        "plan_region": str(region or "").strip().upper(),
        "_validated_geo": dict(selection.geo or {}),
    }


def check_account_plan_in_driver(
    driver,
    token: str,
    *,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
) -> dict:
    """Query accounts/check inside the current authenticated ChatGPT tab.

    Only parsed JSON crosses the WebDriver boundary.  HTML challenge bodies,
    cookies and request headers are never returned, logged or persisted.
    """
    token = normalize_token(token)
    try:
        timeout_seconds, _, _ = _plan_check_settings(timeout, 1, 0)
    except Exception:
        timeout_seconds = 15.0
    base = _driver_plan_result_base(token, timeout_seconds)
    if not token:
        return {
            "ok": False,
            "http_status": None,
            "error": "token 为空",
            "error_code": "plan_check_token_missing",
            **base,
        }
    if base.get("token_expired") is True:
        return {
            "ok": False,
            "http_status": None,
            "error": "token 已过期",
            "error_code": "token_expired",
            "auth_error_code": "token_expired",
            **base,
        }

    try:
        current = str(getattr(driver, "current_url", "") or "")
        host = str(urlparse(current).hostname or "").lower()
    except Exception:
        host = ""
    if host != "chatgpt.com" and not host.endswith(".chatgpt.com"):
        return {
            "ok": False,
            "http_status": None,
            "error": "当前浏览器不在 ChatGPT 页面",
            "error_code": "plan_check_browser_context_invalid",
            **base,
        }

    try:
        driver.set_script_timeout(timeout_seconds + 3.0)
        transport = driver.execute_async_script(
            r"""
            const accessToken = arguments[0];
            const timezoneOffset = arguments[1];
            const timeoutMs = arguments[2];
            const done = arguments[arguments.length - 1];
            const path = '/backend-api/accounts/check/v4-2023-04-27';
            const controller = new AbortController();
            let finished = false;
            let timer = null;
            const finish = value => {
              if (finished) return;
              finished = true;
              if (timer !== null) clearTimeout(timer);
              done(value);
            };
            timer = setTimeout(() => {
              controller.abort();
              finish({transport_ok:false, error_code:'timeout'});
            }, timeoutMs);
            fetch(`${path}?timezone_offset_min=${encodeURIComponent(timezoneOffset)}`, {
              method: 'GET',
              credentials: 'include',
              cache: 'no-store',
              headers: {
                'accept': 'application/json',
                'authorization': `Bearer ${accessToken}`,
                'oai-language': navigator.language || 'en-US',
                'x-openai-target-path': path,
                'x-openai-target-route': path,
              },
              signal: controller.signal,
            }).then(async response => {
              const text = await response.text();
              let data = null;
              let jsonObject = false;
              try {
                data = JSON.parse(text);
                jsonObject = !!data && typeof data === 'object' && !Array.isArray(data);
              } catch (_) {}
              finish({
                transport_ok: true,
                status: response.status,
                content_type: response.headers.get('content-type') || '',
                json_object: jsonObject,
                data: jsonObject ? data : null,
                body_length: text.length,
              });
            }).catch(error => {
              finish({
                transport_ok: false,
                error_code: error && error.name === 'AbortError' ? 'timeout' : 'fetch_failed',
              });
            });
            """,
            token,
            str(timezone_offset_min or "-"),
            int(timeout_seconds * 1000),
        )
    except Exception as exc:
        logger.warning(
            "[Plan][Roxy] 浏览器内套餐查询异常：reason=plan_check_browser_driver_error error_type=%s",
            type(exc).__name__,
        )
        return {
            "ok": False,
            "http_status": None,
            "error": "浏览器内套餐查询执行失败",
            "error_code": "plan_check_browser_driver_error",
            **base,
        }

    if not isinstance(transport, dict) or not transport.get("transport_ok"):
        timed_out = isinstance(transport, dict) and transport.get("error_code") == "timeout"
        return {
            "ok": False,
            "http_status": None,
            "error": "浏览器内套餐查询超时" if timed_out else "浏览器内套餐查询网络失败",
            "error_code": "plan_check_browser_timeout" if timed_out else "plan_check_browser_fetch_failed",
            **base,
        }

    try:
        http_status = int(transport.get("status"))
    except (TypeError, ValueError):
        http_status = None
    data = transport.get("data") if transport.get("json_object") else None
    content_type = str(transport.get("content_type") or "").lower()
    if http_status == 403 and not isinstance(data, dict):
        logger.warning(
            "[Plan][Roxy] 浏览器内套餐查询被边缘防护拦截：reason=plan_check_edge_blocked http_status=403 content_type=%s",
            "html" if "html" in content_type else "non_json",
        )
        return {
            "ok": False,
            "http_status": 403,
            "error": "浏览器内套餐查询被边缘防护拦截（HTTP 403）",
            "error_code": "plan_check_edge_blocked",
            **base,
        }
    if http_status is None or not (200 <= http_status < 300):
        auth_error = _auth_error_code(json.dumps(data, ensure_ascii=False)) if isinstance(data, dict) else None
        return {
            "ok": False,
            "http_status": http_status,
            "error": f"HTTP {http_status}" if http_status is not None else "浏览器未返回 HTTP 状态",
            "error_code": auth_error or "plan_check_http_error",
            "auth_error_code": auth_error,
            **base,
        }
    if not isinstance(data, dict):
        return {
            "ok": False,
            "http_status": http_status,
            "error": "套餐查询响应不是 JSON 对象",
            "error_code": "plan_check_non_json_response",
            **base,
        }
    try:
        parsed = parse_accounts_check(data, token=token)
    except Exception as exc:
        logger.warning(
            "[Plan][Roxy] 浏览器内套餐响应解析失败：reason=plan_check_response_invalid error_type=%s",
            type(exc).__name__,
        )
        return {
            "ok": False,
            "http_status": http_status,
            "error": "套餐查询响应结构无效",
            "error_code": "plan_check_response_invalid",
            **base,
        }
    parsed.update(base)
    parsed["http_status"] = http_status
    parsed["error_code"] = None
    return parsed


def _plan_check_settings(
    timeout: float | None,
    max_attempts: int | None,
    retry_delay: float | None,
) -> tuple[float, int, float]:
    from config import proxy as proxy_cfg

    timeout_value = timeout if timeout is not None else getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0)
    attempts_value = max_attempts if max_attempts is not None else getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 2)
    delay_value = retry_delay if retry_delay is not None else getattr(proxy_cfg, "PLAN_CHECK_RETRY_DELAY", 1.5)
    return (
        max(1.0, min(60.0, float(timeout_value or 15.0))),
        max(1, min(4, int(attempts_value or 1))),
        max(0.0, min(30.0, float(delay_value or 0.0))),
    )


def _retryable_plan_error(http_status: int | None) -> bool:
    if http_status is None:
        return True
    return http_status in {408, 409, 425, 429} or http_status >= 500


def _auth_error_code(response_text: str) -> str | None:
    """Return only the two server errors that are safe to session-refresh."""
    text = str(response_text or "")
    values: list[str] = []
    try:
        payload = json.loads(text)

        def collect(value: Any) -> None:
            if isinstance(value, str):
                values.append(value)
            elif isinstance(value, dict):
                for key, item in value.items():
                    if str(key).lower() in {"code", "type", "error", "message"}:
                        if isinstance(item, str):
                            values.append(item)
                        else:
                            collect(item)
                    elif isinstance(item, (dict, list)):
                        collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(payload)
    except Exception:
        values.append(text)
    lowered = "\n".join(values).lower()
    for code in ("token_invalidated", "token_expired"):
        if code in lowered:
            return code
    return None


def _retry_wait_seconds(resp: Any, base_delay: float, attempt: int) -> float:
    try:
        retry_after = (getattr(resp, "headers", {}) or {}).get("retry-after")
        if retry_after is not None:
            return max(0.0, min(30.0, float(retry_after)))
    except (TypeError, ValueError):
        pass
    return max(0.0, min(30.0, base_delay * attempt))


def normalize_promo_check_region(value: object) -> str:
    from config.browser import COUNTRY_LOCALE_PROFILE_MAP

    region = str(value or "").strip().upper()
    if region not in COUNTRY_LOCALE_PROFILE_MAP:
        raise ValueError("promo_region_invalid")
    return region


def check_account_promos(
    token: str,
    *,
    region: str,
    timeout: float | None = None,
    retry_delay: float | None = None,
    env: BrowserSession | None = None,
    resolved_route: dict | None = None,
    request_via_env: bool = False,
    on_eligible_promo_campaigns: Callable[[dict[str, Any]], None] | None = None,
) -> dict:
    """Perform one AT-only regional promotion query.

    This deliberately does not hydrate a saved Session, warm ChatGPT, rotate
    tokens, clear edge cookies, or perform a delayed second scan.  A transient
    network failure, HTTP 429, or 5xx response may repeat once through the
    exact same route and BrowserSession.
    """

    try:
        normalized_region = normalize_promo_check_region(region)
    except ValueError:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "error_code": "promo_region_invalid",
            "http_status": None,
            "attempt_count": 0,
        }

    token = normalize_token(token)
    if not token:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "error_code": "promo_check_token_missing",
            "http_status": None,
            "attempt_count": 0,
        }
    claims = token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "error_code": "token_expired",
            "http_status": None,
            "attempt_count": 0,
        }

    try:
        route = (
            dict(resolved_route)
            if isinstance(resolved_route, dict)
            else resolve_plan_check_region_route(normalized_region)
        )
        timeout_seconds, _, base_delay = _plan_check_settings(
            timeout,
            2,
            retry_delay,
        )
    except Exception:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "error_code": "promo_check_network_config_error",
            "http_status": None,
            "attempt_count": 0,
        }

    request_env = env
    owns_env = request_env is None
    if request_env is None:
        geo = dict(route.get("_validated_geo") or {})
        request_env = BrowserSession(
            proxy=str(route.get("proxy") or ""),
            detect_exit_geo=bool(geo),
            validated_geo=geo,
            force_locale_from_geo=bool(geo),
        )
    try:
        try:
            timezone_offset_min = str(request_env.js_timezone_offset_min())
        except Exception:
            timezone_offset_min = "-"
        url = (
            f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}"
            f"?timezone_offset_min={quote(timezone_offset_min)}"
        )
        last_result: dict | None = None
        for attempt in (1, 2):
            response = None
            retryable = False
            campaign_logged = False

            def notify_campaign_snapshot(present: bool, value: object) -> None:
                nonlocal campaign_logged
                if campaign_logged:
                    return
                campaign_logged = True
                if on_eligible_promo_campaigns is None:
                    return
                try:
                    on_eligible_promo_campaigns({
                        "attempt": attempt,
                        "region": normalized_region,
                        "http_status": status,
                        "present": bool(present),
                        "value": value,
                    })
                except Exception:
                    # Diagnostics must never turn a successful query into a
                    # failed account operation.
                    pass

            try:
                request_client = (
                    request_env
                    if request_via_env and callable(getattr(request_env, "get", None))
                    else request_env.session
                )
                response = request_client.get(
                    url,
                    headers=_common_headers(request_env, token),
                    allow_redirects=False,
                    timeout=timeout_seconds,
                )
                status = int(getattr(response, "status_code", 0) or 0)
                response_text = str(getattr(response, "text", "") or "")
                if 200 <= status < 300:
                    try:
                        data: Any = response.json()
                    except Exception:
                        data = (
                            json.loads(response_text)
                            if response_text.strip().startswith(("{", "["))
                            else None
                        )
                    if not isinstance(data, dict):
                        notify_campaign_snapshot(False, None)
                        return {
                            "ok": False,
                            "checked_at": now_iso(),
                            "error_code": "promo_check_non_json_response",
                            "http_status": status,
                            "attempt_count": attempt,
                        }
                    try:
                        campaign_item, _, _ = _select_accounts_check_item(
                            data,
                            token=token,
                        )
                        notify_campaign_snapshot(
                            "eligible_promo_campaigns" in campaign_item,
                            campaign_item.get("eligible_promo_campaigns"),
                        )
                    except Exception:
                        notify_campaign_snapshot(False, None)
                    try:
                        parsed = parse_accounts_promos(data, token=token)
                    except Exception:
                        notify_campaign_snapshot(False, None)
                        return {
                            "ok": False,
                            "checked_at": now_iso(),
                            "error_code": "promo_check_response_invalid",
                            "http_status": status,
                            "attempt_count": attempt,
                        }
                    parsed.update({
                        "http_status": status,
                        "attempt_count": attempt,
                        "region": normalized_region,
                    })
                    return parsed

                auth_error = _auth_error_code(response_text)
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "error_code": auth_error or "promo_check_http_error",
                    "http_status": status or None,
                    "attempt_count": attempt,
                    "region": normalized_region,
                }
                retryable = status == 429 or status >= 500
            except Exception:
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "error_code": "promo_check_network_error",
                    "http_status": None,
                    "attempt_count": attempt,
                    "region": normalized_region,
                }
                retryable = True

            if attempt == 1 and retryable:
                wait_seconds = _retry_wait_seconds(response, base_delay, attempt)
                if wait_seconds > 0:
                    time.sleep(wait_seconds)
                continue
            return last_result or {
                "ok": False,
                "checked_at": now_iso(),
                "error_code": "promo_check_unexpected",
                "http_status": None,
                "attempt_count": attempt,
                "region": normalized_region,
            }
    finally:
        if owns_env:
            try:
                request_env.session.close()
            except Exception:
                pass


def check_account_plan(
    token: str,
    *,
    proxy: Optional[str] = None,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
    max_attempts: int | None = None,
    retry_delay: float | None = None,
    env: BrowserSession | None = None,
    resolved_route: dict | None = None,
    context_mode: str = "at_only",
    edge_retry: bool = True,
) -> dict:
    token = normalize_token(token)
    context_mode = str(context_mode or "at_only").strip().lower()
    if context_mode not in PLAN_CHECK_CONTEXT_MODES:
        context_mode = "at_only"
    if not token:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "error": "token 为空",
            "error_code": "plan_check_token_missing",
            "plan_check_context_mode": context_mode,
            "edge_retry_count": 0,
        }
    claims = token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": "token 已过期",
            "error_code": "token_expired",
            "auth_error_code": "token_expired",
            "plan_check_context_mode": context_mode,
            "edge_retry_count": 0,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    try:
        route = dict(resolved_route) if isinstance(resolved_route, dict) else resolve_plan_check_route(proxy)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询网络配置错误: {exc}",
            "error_code": "plan_check_network_config_error",
            "plan_check_context_mode": context_mode,
            "edge_retry_count": 0,
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    route_meta = {
        k: v for k, v in route.items()
        if k != "proxy" and not str(k).startswith("_")
    }
    url = f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}?timezone_offset_min={quote(str(timezone_offset_min))}"
    try:
        timeout_seconds, attempts, base_delay = _plan_check_settings(timeout, max_attempts, retry_delay)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询重试配置错误: {exc}",
            "error_code": "plan_check_retry_config_error",
            "retryable": False,
            "plan_check_context_mode": context_mode,
            "edge_retry_count": 0,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    last_result: dict | None = None
    request_env = env
    owns_env = request_env is None
    edge_retry_count = 0
    request_count = 0
    regular_attempt = 0
    try:
        if request_env is None:
            request_env = BrowserSession(proxy=route["proxy"], detect_exit_geo=False)
        while regular_attempt < attempts:
            regular_attempt += 1
            request_count += 1
            attempt = request_count
            resp = None
            response_text = ""
            http_status: int | None = None
            request_error: str | None = None
            auth_error: str | None = None
            try:
                resp = request_env.session.get(
                    url,
                    headers=_common_headers(request_env, token),
                    allow_redirects=False,
                    timeout=timeout_seconds,
                )
                response_text = resp.text or ""
                http_status = int(resp.status_code)
                auth_error = _auth_error_code(response_text)
                if not (200 <= http_status < 300):
                    error_code = auth_error
                    if http_status == 403 and not auth_error:
                        error_code = "plan_check_edge_blocked"
                    if not error_code:
                        error_code = "plan_check_http_error"
                    last_result = {
                        "ok": False,
                        "checked_at": now_iso(),
                        "http_status": http_status,
                        "error": f"HTTP {http_status}",
                        "error_code": error_code,
                        "auth_error_code": auth_error,
                        "retryable": _retryable_plan_error(http_status),
                    }
                else:
                    try:
                        data: Any = resp.json()
                    except Exception:
                        data = json.loads(response_text) if response_text.strip().startswith(("{", "[")) else None
                    if not isinstance(data, dict):
                        last_result = {
                            "ok": False,
                            "checked_at": now_iso(),
                            "http_status": http_status,
                            "error": "响应不是 JSON 对象",
                            "error_code": "plan_check_non_json_response",
                            "retryable": True,
                        }
                    else:
                        parsed = parse_accounts_check(data, token=token)
                        parsed["http_status"] = http_status
                        parsed["attempt_count"] = attempt
                        parsed["max_attempts"] = attempts
                        parsed["request_timeout"] = timeout_seconds
                        parsed["retryable"] = False
                        parsed["error_code"] = None
                        parsed["plan_check_context_mode"] = context_mode
                        parsed["edge_retry_count"] = edge_retry_count
                        parsed.update(route_meta)
                        return parsed
            except Exception as exc:
                request_error = type(exc).__name__
                logger.debug(
                    "套餐查询失败: error_type=%s",
                    request_error,
                )
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "http_status": http_status,
                    "error": "套餐查询网络失败",
                    "error_code": "plan_check_network_error",
                    "retryable": True,
                }

            # A plain 403 is retried once only after the route-bound edge
            # cookies are cleared and ChatGPT is warmed up again.  It never
            # triggers Session exchange or Roxy login.
            if (
                http_status == 403
                and not auth_error
                and edge_retry
                and edge_retry_count == 0
            ):
                edge_retry_count = 1
                try:
                    from core.chatgpt_session_store import clear_transient_chatgpt_cookies

                    clear_transient_chatgpt_cookies(request_env.session)
                except Exception:
                    logger.debug(
                        "套餐查询边缘 Cookie 清理失败: error_type=plan_check_edge_cookie_clear_failed",
                    )
                warmup_chatgpt_page(request_env, timeout=timeout_seconds)
                regular_attempt -= 1
                continue

            last_result = last_result or {
                "ok": False,
                "checked_at": now_iso(),
                "error": "未知错误",
                "error_code": "plan_check_unknown_error",
                "retryable": True,
            }
            if http_status == 403 and not auth_error:
                last_result["error"] = "地区套餐接口被边缘防护拦截（HTTP 403）"
                last_result["error_code"] = "plan_check_edge_blocked"
                last_result["retryable"] = False
                last_result["session_refresh_required"] = False
            last_result.update({
                "attempt_count": attempt,
                "max_attempts": attempts,
                "request_timeout": timeout_seconds,
                "plan_check_context_mode": context_mode,
                "edge_retry_count": edge_retry_count,
                **route_meta,
                **{k: v for k, v in claims.items() if k != "payload"},
            })
            if not last_result.get("retryable") or regular_attempt >= attempts:
                return last_result

            wait_seconds = _retry_wait_seconds(resp, base_delay, regular_attempt)
            logger.warning(
                "套餐查询临时失败，第 %s/%s 次，%.1fs 后重试: error_code=%s",
                regular_attempt,
                attempts,
                wait_seconds,
                last_result.get("error_code") or "plan_check_retryable",
            )
            if wait_seconds > 0:
                time.sleep(wait_seconds)
    finally:
        if owns_env and request_env is not None:
            try:
                request_env.session.close()
            except Exception:
                pass

    return last_result or {
        "ok": False,
        "checked_at": now_iso(),
        "http_status": None,
        "error": "套餐查询未执行",
        "error_code": "plan_check_not_executed",
        "retryable": False,
        "plan_check_context_mode": context_mode,
        "edge_retry_count": edge_retry_count,
        **route_meta,
        **{k: v for k, v in claims.items() if k != "payload"},
    }
