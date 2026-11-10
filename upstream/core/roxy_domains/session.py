"""Roxy Session implementation domain.

Loaded into :mod:`core.roxy_registration` so its public compatibility module
retains one shared namespace, locks, and test seams.
"""
from __future__ import annotations
from textwrap import dedent
_SOURCE = dedent(r'''
def _click_if_enabled_submit(driver) -> bool:
    """提交资料页：优先 form.requestSubmit/button[type=submit]，不依赖按钮文字。"""
    try:
        target = driver.execute_script(r"""
        const visible = (el) => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const forms = [...document.querySelectorAll('form')].filter(visible);
        for (const form of forms) {
          const submit = form.querySelector('button[type="submit"], input[type="submit"]');
          if (submit && visible(submit) && !submit.disabled) {
            submit.scrollIntoView({block:'center'});
            return submit;
          }
          if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
            return 'submitted_by_requestSubmit';
          }
        }
        const submitters = [...document.querySelectorAll('button[type="submit"], input[type="submit"]')]
          .filter(el => visible(el) && !el.disabled);
        if (submitters.length) {
          submitters[0].scrollIntoView({block:'center'});
          return submitters[0];
        }
        // 兜底：页面只有一个可点击 button 时点击它，但仍不读文字。
        const buttons = [...document.querySelectorAll('button:not([disabled])')].filter(visible);
        if (buttons.length === 1) {
          buttons[0].scrollIntoView({block:'center'});
          return buttons[0];
        }
        return null;
        """)
        if not target:
            return False
        if isinstance(target, str):
            return True
        _human_click(driver, target, label="profile_submit")
        return True
    except Exception:
        return False

def _read_chatgpt_session_once(driver) -> dict | None:
    """当前页面必须在 chatgpt.com；读取 /api/auth/session，拿不到 token 返回 None。"""
    try:
        current = urlparse(str(driver.current_url or ""))
        if (
            str(current.hostname or "").lower() == "chatgpt.com"
            and str(current.path or "") == "/api/auth/session"
        ):
            raw_body = driver.execute_script(
                "return document.body ? document.body.innerText : '';"
            )
            payload = json.loads(str(raw_body or ""))
            if isinstance(payload, dict) and payload.get("accessToken"):
                logger.info(
                    "%s /api/auth/session 文档已返回 accessToken",
                    _log_prefix(driver),
                )
                return payload
    except Exception:
        # Chromium may render JSON differently across versions.  The normal
        # same-origin fetch below remains authoritative.
        pass
    script = r"""
    const done = arguments[0];
    fetch('/api/auth/session', {credentials: 'include'})
      .then(r => r.json())
      .then(j => done({ok: true, data: j}))
      .catch(e => done({ok: false, error: String(e)}));
    """
    result = driver.execute_async_script(script)
    if result and result.get("ok"):
        data = result.get("data") or {}
        if data.get("accessToken"):
            logger.info("%s /api/auth/session 已返回 accessToken", _log_prefix(driver))
            return data
        logger.info("%s 等待 ChatGPT session 写入 accessToken，当前响应 keys=%s", _log_prefix(driver), list(data.keys()))
    return None

def _switch_to_chatgpt_window_if_any(driver) -> bool:
    """有些浏览器/适配层会在新窗口完成 callback；尝试切到已有 chatgpt.com 句柄。"""
    try:
        handles = list(getattr(driver, "window_handles", []) or [])
        current_handle = None
        try:
            current_handle = getattr(driver, "current_window_handle", None)
        except Exception:
            current_handle = None
        for handle in handles:
            try:
                driver.switch_to.window(handle)
                if "chatgpt.com" in str(getattr(driver, "current_url", "") or ""):
                    return True
            except Exception:
                continue
        if current_handle is not None:
            try:
                driver.switch_to.window(current_handle)
            except Exception:
                pass
    except Exception:
        pass
    return False

def _fetch_chatgpt_session(driver, timeout: int = 90, auto_jump_wait: int = 15) -> dict:
    """等待页面完成跳转并从 ChatGPT 页面内读取登录 session/accessToken。

    旧逻辑会在 auth.openai.com 上一直等到总超时，部分 Chromium 场景下
    实际账号已创建成功但当前句柄 URL 没及时更新，导致白等 120 秒。现在只给
    自动跳转 `auto_jump_wait` 秒；超过后立即主动打开 chatgpt.com 读 session。
    """
    end = time.time() + timeout
    auto_jump_end = time.time() + max(3, int(auto_jump_wait or 15))
    last_data = None
    forced_chatgpt_open = False

    while time.time() < end:
        try:
            current = str(driver.current_url or '')
        except Exception:
            current = ''

        if 'chatgpt.com' not in current:
            if _switch_to_chatgpt_window_if_any(driver):
                current = str(getattr(driver, "current_url", "") or "")
            elif time.time() >= auto_jump_end and not forced_chatgpt_open:
                try:
                    logger.info("%s 未在 %ss 内观察到当前窗口跳转 chatgpt.com，主动打开 ChatGPT 内读取 session", _log_prefix(driver), int(auto_jump_wait or 15))
                    _safe_get(
                        driver,
                        "https://chatgpt.com/",
                        timeout=35,
                        attempts=2,
                        accept_hosts=("chatgpt.com",),
                    )
                    forced_chatgpt_open = True
                    time.sleep(3)
                    current = str(getattr(driver, "current_url", "") or "")
                except Exception as exc:
                    last_data = f"{type(exc).__name__}: {exc}"
            else:
                time.sleep(1)
                continue

        if 'chatgpt.com' in current:
            try:
                data = _read_chatgpt_session_once(driver)
                if data:
                    return data
                last_data = "session 暂无 accessToken"
            except Exception as exc:
                last_data = f"{type(exc).__name__}: {exc}"
        time.sleep(2)

    raise RuntimeError(f"等待 /api/auth/session accessToken 超时，最后响应: {str(last_data)[:800]}")

def _check_manual_stop() -> None:
    callback = getattr(_STOP_CHECK_CONTEXT, "callback", None)
    if callback is not None:
        from core.otp_stop import check_stop

        check_stop(callback)
        return
    try:
        from core.registration_service import check_stop_requested
        check_stop_requested()
    except ImportError:
        return

def _quit_driver_for_shutdown(driver) -> None:
    """Quit Selenium without replaying requests to an already-dead driver.

    Selenium's urllib3 connection pool defaults to several connection
    retries.  During a manual stop the browser may already have exited; those
    retries used to add 10–20 seconds to every task shutdown.  Disable retries
    only for this final best-effort quit call.  The registration traffic and
    normal browser command behavior are unchanged.
    """

    if driver is None:
        return
    connection = None
    old_manager_retries = None
    old_pool_retries: list[tuple[object, object]] = []
    old_pool_kw_retries = None
    changed_retries = False
    try:
        executor = getattr(driver, "command_executor", None)
        candidate = getattr(executor, "_conn", None)
        if candidate is not None and str(type(candidate).__module__).startswith("urllib3"):
            connection = candidate
            from urllib3.util.retry import Retry

            no_retry = Retry(
                total=0,
                connect=0,
                read=0,
                redirect=0,
                status=0,
            )
            # PoolManager keeps retry policy on each HTTPConnectionPool.  Set
            # the manager default for pools created during quit and update any
            # already-created localhost pool as well.
            pool_kw = getattr(connection, "connection_pool_kw", None)
            if isinstance(pool_kw, dict):
                old_pool_kw_retries = pool_kw.get("retries")
                pool_kw["retries"] = no_retry
            pools = getattr(connection, "pools", None)
            container = getattr(pools, "_container", None)
            if isinstance(container, dict):
                for pool in list(container.values()):
                    if hasattr(pool, "retries"):
                        old_pool_retries.append((pool, pool.retries))
                        pool.retries = no_retry
            # A few Selenium/urllib3 versions expose a manager-level retries
            # attribute; support it without depending on that implementation.
            if hasattr(connection, "retries"):
                old_manager_retries = connection.retries
                connection.retries = no_retry
            changed_retries = True
        driver.quit()
    except Exception:
        logger.warning(
            "[Roxy] Selenium 清理未确认：reason=webdriver_shutdown_failed"
        )
    finally:
        if changed_retries and connection is not None:
            try:
                if old_manager_retries is not None:
                    connection.retries = old_manager_retries
                pool_kw = getattr(connection, "connection_pool_kw", None)
                if isinstance(pool_kw, dict):
                    if old_pool_kw_retries is None:
                        pool_kw.pop("retries", None)
                    else:
                        pool_kw["retries"] = old_pool_kw_retries
                for pool, retries in old_pool_retries:
                    pool.retries = retries
            except Exception:
                pass

def _set_traffic_stage(
    meter: RoxyTrafficMeter | None,
    stage: str,
    raw_trace=None,
) -> None:
    """Stage markers are best-effort and must never affect registration."""
    if meter is None:
        pass
    else:
        try:
            meter.set_stage(stage)
        except Exception:
            pass
    if raw_trace is not None:
        try:
            raw_trace.set_stage(stage)
        except Exception:
            # Raw diagnostics are strictly non-functional.
            pass

def _stop_traffic_meter(
    meter: RoxyTrafficMeter | None,
    current_usage: dict,
) -> dict:
    """Stop metering at the last browser action without affecting registration."""
    if meter is None:
        return current_usage
    try:
        usage = meter.stop(drain_timeout=0.5)
        logger.info(
            "[Roxy流量] HTTP 流量计量完成：state=%s mode=%s download=%s upload=%s total=%s",
            usage.get("state"),
            usage.get("mode"),
            usage.get("download_bytes"),
            usage.get("upload_bytes"),
            usage.get("total_bytes"),
        )
        return usage
    except Exception:
        usage = empty_network_usage("unavailable")
        usage["error_code"] = "meter_stop_failed"
        logger.warning("[Roxy流量] HTTP 流量计量收尾失败，注册结果不受影响")
        return usage

def _attach_profile_cache_context(usage: dict, opened: RoxyOpenResult | None) -> dict:
    """Attach a non-sensitive cold/reuse hint to one traffic aggregate."""
    result = dict(usage or empty_network_usage("unavailable"))
    if opened is None or not bool(getattr(opened, "pooled", False)):
        result["profile_cache"] = {
            "enabled": False,
            "source": "not_applicable",
            "expectation": "unknown",
        }
        return result
    source = str(getattr(opened, "profile_cache_source", "unknown") or "unknown")
    if source not in {"new", "adopted", "cached"}:
        source = "unknown"
    expectation = str(
        getattr(opened, "profile_cache_expectation", "unknown") or "unknown"
    )
    if expectation not in {"cold", "reused"}:
        expectation = "unknown"
    result["profile_cache"] = {
        "enabled": True,
        "source": source,
        "expectation": expectation,
    }
    return result
''')
def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
