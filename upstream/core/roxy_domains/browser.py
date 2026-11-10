"""Roxy Browser implementation domain.

Loaded into :mod:`core.roxy_registration` so its public compatibility module
retains one shared namespace, locks, and test seams.
"""
from __future__ import annotations
from textwrap import dedent
_SOURCE = dedent(r'''
def _build_driver(
    opened: RoxyOpenResult,
    *,
    safe_logging: bool = False,
):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

    if opened.debugger_address:
        logger.info(
            "[Roxy] Selenium 连接 debuggerAddress=%s",
            "[REDACTED]" if safe_logging else opened.debugger_address,
        )
        options = Options()
        # The login page can keep background requests alive after the DOM is
        # usable.  Waiting for DOMContentLoaded avoids turning those requests
        # into a Selenium page-load failure.
        options.page_load_strategy = "eager"
        options.add_experimental_option("debuggerAddress", opened.debugger_address)
        driver_path = ""
        try:
            raw_data = opened.raw.get("data") if isinstance(opened.raw, dict) else {}
            if isinstance(raw_data, dict):
                driver_path = str(raw_data.get("driver") or raw_data.get("driverPath") or raw_data.get("driver_path") or "").strip()
        except Exception:
            driver_path = ""
        if driver_path:
            logger.info(
                "[Roxy] 使用 Roxy chromedriver=%s",
                "[REDACTED]" if safe_logging else driver_path,
            )
            driver = webdriver.Chrome(service=Service(executable_path=driver_path), options=options)
        else:
            driver = webdriver.Chrome(options=options)
        _apply_browser_automation_mask(driver)
        from core.registration_verification_traffic import metered_browser_driver
        return metered_browser_driver(driver)

    if opened.webdriver_url:
        logger.info(
            "[Roxy] Selenium 连接 webdriver_url=%s",
            "[REDACTED]" if safe_logging else opened.webdriver_url,
        )
        options = Options()
        options.page_load_strategy = "eager"
        driver = RemoteWebDriver(command_executor=opened.webdriver_url, options=options)
        _apply_browser_automation_mask(driver)
        from core.registration_verification_traffic import metered_browser_driver
        return metered_browser_driver(driver)

    raise RuntimeError("Roxy 未返回可连接的 Selenium 地址")

def _center_browser_window(driver, *, headless: bool | None = None) -> None:
    """把可见的 Roxy 窗口移动到 Windows 主屏工作区中央。"""
    effective_headless = (
        bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False))
        if headless is None
        else bool(headless)
    )
    if effective_headless:
        return
    try:
        import ctypes

        class _Rect(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        work_area = _Rect()
        if not ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work_area), 0):
            raise OSError("无法读取 Windows 工作区")
        size = driver.get_window_size()
        width = max(1, int(size.get("width") or 1))
        height = max(1, int(size.get("height") or 1))
        x = int(work_area.left + max(0, (work_area.right - work_area.left - width) // 2))
        y = int(work_area.top + max(0, (work_area.bottom - work_area.top - height) // 2))
        driver.set_window_position(x, y)
        logger.info("[Roxy] 浏览器窗口已居中：x=%s y=%s width=%s height=%s", x, y, width, height)
    except Exception as exc:
        logger.warning("[Roxy] 浏览器窗口居中失败，继续执行：%s", exc)

def _effective_keep_browser_open() -> bool:
    if bool(getattr(_cfg, "ROXY_PROFILE_CACHE_REUSE", False)):
        return False
    return bool(getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))

def _reset_pooled_profile_identity(driver) -> None:
    """Clear account identity stores without touching Chromium's HTTP cache."""
    def _delete_cookie_records(records: object) -> None:
        """Delete cookies that survived the browser-wide clear operation.

        Roxy can acknowledge ``Network.clearBrowserCookies`` before its
        profile worker has finished applying the deletion.  Explicitly
        deleting the observed records makes the follow-up verification
        deterministic while keeping the operation fail-closed.
        """
        if not isinstance(records, list):
            return
        for record in records:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "").strip()
            domain = str(record.get("domain") or "").strip()
            if not name or not domain:
                continue
            params = {
                "name": name,
                "domain": domain,
                "path": str(record.get("path") or "/"),
            }
            partition_key = record.get("partitionKey")
            if partition_key:
                params["partitionKey"] = partition_key
            try:
                driver.execute_cdp_cmd("Network.deleteCookies", params)
            except Exception:
                # The next verification remains authoritative; a CDP method
                # unavailable on an older Roxy driver must not weaken the
                # identity-reset guarantee.
                continue

    def _cookies_after_clear() -> list[dict]:
        payload = driver.execute_cdp_cmd("Network.getAllCookies", {}) or {}
        cookies = payload.get("cookies") if isinstance(payload, dict) else []
        return cookies if isinstance(cookies, list) else []

    try:
        handles = list(driver.window_handles or [])
        if handles:
            try:
                primary = driver.current_window_handle
            except Exception:
                primary = handles[0]
            if primary not in handles:
                primary = handles[0]
            driver.switch_to.window(primary)
            driver.get("about:blank")
            for handle in handles:
                if handle == primary:
                    continue
                try:
                    driver.switch_to.window(handle)
                    driver.close()
                except Exception:
                    continue
            driver.switch_to.window(primary)

        driver.execute_cdp_cmd("Network.enable", {})
        # The first pass is deliberately followed by a short bounded retry:
        # pooled Profiles occasionally report the old cookie set for one CDP
        # round-trip after a previous task has just released the lease.
        last_cookies: list[dict] = []
        for _attempt in range(3):
            driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
            try:
                driver.delete_all_cookies()
            except Exception:
                pass
            for origin in _OPENAI_IDENTITY_ORIGINS:
                driver.execute_cdp_cmd(
                    "Storage.clearDataForOrigin",
                    {"origin": origin, "storageTypes": "all"},
                )
                # Storage.clearDataForOrigin normally covers DOM storage; explicitly clear
                # both namespaces as a compatibility fallback. Missing namespaces are safe.
                for is_local in (True, False):
                    try:
                        driver.execute_cdp_cmd(
                            "DOMStorage.clear",
                            {"storageId": {"securityOrigin": origin, "isLocalStorage": is_local}},
                        )
                    except Exception:
                        pass
            last_cookies = _cookies_after_clear()
            if not last_cookies:
                break
            _delete_cookie_records(last_cookies)
            try:
                import time as _time

                _time.sleep(0.15 * (_attempt + 1))
            except Exception:
                pass
        if last_cookies:
            raise RoxyIdentityResetError("pooled_profile_cookie_reset_incomplete")
        logger.info("[Roxy缓存池] 账号身份数据已清理，HTTP 磁盘缓存保留")
    except RoxyIdentityResetError:
        raise
    except Exception as exc:
        logger.warning("[Roxy缓存池] 账号身份清理失败：%s", type(exc).__name__)
        raise RoxyIdentityResetError("pooled_profile_identity_reset_failed") from None

def _wait(driver, timeout: int | None = None):
    from selenium.webdriver.support.ui import WebDriverWait
    return WebDriverWait(driver, timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))

def _hostname_matches(current_url: str, accepted_hosts: tuple[str, ...]) -> bool:
    """Return whether *current_url* belongs to an explicitly accepted host.

    Matching on parsed hostnames prevents lookalike domains such as
    ``evil-chatgpt.com`` from passing a substring check.  Subdomains of an
    accepted host remain valid.
    """
    try:
        current_host = str(urlparse(str(current_url or "")).hostname or "").rstrip(".").lower()
    except Exception:
        return False
    if not current_host:
        return False
    for raw_host in accepted_hosts:
        host = str(raw_host or "").strip().rstrip(".").lower()
        if host and (current_host == host or current_host.endswith(f".{host}")):
            return True
    return False

_RETRYABLE_CHROME_NAVIGATION_ERRORS = frozenset(
    {
        "ERR_CONNECTION_ABORTED",
        "ERR_CONNECTION_CLOSED",
        "ERR_CONNECTION_RESET",
        "ERR_NETWORK_CHANGED",
        "ERR_TIMED_OUT",
    }
)

_CHROME_NAVIGATION_ERROR_PATTERN = re.compile(
    r"(?<![A-Z0-9_])net::(?P<code>ERR_[A-Z0-9_]+)(?![A-Z0-9_])",
    re.IGNORECASE,
)

def _retryable_navigation_error_code(exc: BaseException) -> str:
    """Return a safe Chrome transport error code when navigation may be retried."""

    matched = _CHROME_NAVIGATION_ERROR_PATTERN.search(str(exc or ""))
    if not matched:
        return ""
    code = str(matched.group("code") or "").upper()
    return code if code in _RETRYABLE_CHROME_NAVIGATION_ERRORS else ""

def _prepare_navigation_retry(driver, attempt: int) -> None:
    # Leaving Chromium's internal network error document before retrying avoids
    # retaining a failed navigation in the renderer.  about:blank is local and
    # does not create another proxy or target-site request.
    try:
        driver.get("about:blank")
    except Exception:
        pass
    time.sleep(1.5 * max(1, int(attempt or 1)))

def _safe_get(
    driver,
    url: str,
    *,
    timeout: int = 45,
    attempts: int = 2,
    accept_hosts: tuple[str, ...] = (),
) -> None:
    """Navigate with bounded recovery for safe, explicitly known failures.

    A Roxy Chromium page may have a usable DOM while background requests keep
    Selenium waiting until ``TimeoutException``.  In that precise case we stop
    loading and continue only when both the parsed hostname and ``document.body``
    are valid.  A small allow-list of transient Chrome transport failures is
    retried because navigation is an idempotent GET.  Session, certificate and
    unknown WebDriver failures are deliberately not retried.
    """
    from selenium.common.exceptions import TimeoutException, WebDriverException

    target_host = str(urlparse(str(url)).hostname or "").rstrip(".").lower()
    hosts = tuple(accept_hosts or ((target_host,) if target_host else ()))
    max_attempts = max(1, int(attempts or 1))
    old_timeout = max(1, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90))
    last_exc: TimeoutException | None = None
    try:
        for attempt in range(1, max_attempts + 1):
            driver.set_page_load_timeout(max(10, int(timeout or 45)))
            try:
                driver.get(url)
                return
            except TimeoutException as exc:
                last_exc = exc
                logger.warning(
                    "%s 页面加载超时，停止加载并检查当前 DOM：host=%s attempt=%s/%s",
                    _log_prefix(driver),
                    target_host or "-",
                    attempt,
                    max_attempts,
                )
                try:
                    driver.execute_script("window.stop();")
                except Exception:
                    pass

                try:
                    current_url = str(driver.current_url or "")
                except Exception:
                    current_url = ""
                try:
                    dom_state = driver.execute_script(
                        "return {readyState: document.readyState || '', hasBody: !!document.body};"
                    ) or {}
                except Exception:
                    dom_state = {}

                if (
                    _hostname_matches(current_url, hosts)
                    and bool(dom_state.get("hasBody"))
                ):
                    logger.info(
                        "%s 页面加载虽超时但目标 DOM 已可用，继续流程：readyState=%s",
                        _log_prefix(driver),
                        str(dom_state.get("readyState") or "-"),
                    )
                    return

                if attempt < max_attempts:
                    _prepare_navigation_retry(driver, attempt)
            except WebDriverException as exc:
                error_code = _retryable_navigation_error_code(exc)
                if not error_code:
                    raise
                if attempt >= max_attempts:
                    logger.warning(
                        "%s 页面导航临时网络错误重试耗尽：host=%s code=%s "
                        "attempt=%s/%s",
                        _log_prefix(driver),
                        target_host or "-",
                        error_code,
                        attempt,
                        max_attempts,
                    )
                    raise
                logger.warning(
                    "%s 页面导航遇到临时网络错误，准备重试：host=%s code=%s "
                    "attempt=%s/%s",
                    _log_prefix(driver),
                    target_host or "-",
                    error_code,
                    attempt,
                    max_attempts,
                )
                _prepare_navigation_retry(driver, attempt)
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("页面跳转失败")
    finally:
        try:
            driver.set_page_load_timeout(old_timeout)
        except Exception:
            pass

def _visible(el) -> bool:
    try:
        return el.is_displayed() and el.is_enabled()
    except Exception:
        return False

def _browser_actions_enabled() -> bool:
    try:
        from config import humanize as _humanize_cfg

        return bool(
            getattr(_humanize_cfg, "ENABLE_HUMANIZE_BROWSER_ACTIONS", True)
        )
    except Exception:
        return True

_ROXY_AUTOMATION_MASK_SCRIPT = r"""
(() => {
  try {
    // Roxy owns the complete browser fingerprint. Only remove Selenium's
    // explicit automation marker when it remains observable; do not synthesize
    // unrelated browser APIs with detectable shims.
    if (navigator.webdriver !== undefined) {
      Object.defineProperty(Navigator.prototype, 'webdriver', {
        configurable: true,
        get: () => undefined
      });
    }
  } catch (_) {}
})();
"""

def _apply_browser_automation_mask(driver) -> None:
    """Install the narrow Roxy automation mask without changing its fingerprint."""
    if not _browser_actions_enabled():
        return

    installed_for_navigation = False
    try:
        if hasattr(driver, "execute_cdp_cmd"):
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": _ROXY_AUTOMATION_MASK_SCRIPT},
            )
            installed_for_navigation = True
    except Exception as exc:
        logger.debug(
            "%s 自动化标志预注入失败，继续尝试当前页面：%s",
            _log_prefix(driver),
            type(exc).__name__,
        )

    applied_to_current_page = False
    try:
        driver.execute_script(_ROXY_AUTOMATION_MASK_SCRIPT)
        applied_to_current_page = True
    except Exception as exc:
        logger.debug(
            "%s 当前页面自动化标志处理失败：%s",
            _log_prefix(driver),
            type(exc).__name__,
        )

    if installed_for_navigation or applied_to_current_page:
        logger.info(
            "%s 已启用 Roxy 自动化标志弱化：new_document=%s current_page=%s",
            _log_prefix(driver),
            installed_for_navigation,
            applied_to_current_page,
        )

def _human_scroll_to(driver, el) -> None:
    """Bring an element into view with a small bounded scroll variation."""
    try:
        block = random.choice(["center", "nearest", "center"])
        driver.execute_script(
            "arguments[0].scrollIntoView({block: arguments[1], inline:'nearest'});",
            el,
            block,
        )
        if _browser_actions_enabled():
            time.sleep(random.uniform(0.08, 0.35))
            driver.execute_script(
                "window.scrollBy(0, arguments[0]);", random.randint(-90, 90)
            )
            time.sleep(random.uniform(0.05, 0.22))
            driver.execute_script(
                "arguments[0].scrollIntoView({block:'center', inline:'nearest'});",
                el,
            )
    except Exception:
        try:
            driver.execute_script(
                "arguments[0].scrollIntoView({block:'center'});", el
            )
        except Exception:
            pass

def _human_click(driver, el, *, label: str = "") -> None:
    """Click a random unobstructed point with a short CDP pointer trajectory."""
    _human_scroll_to(driver, el)
    if not _browser_actions_enabled():
        el.click()
        return

    try:
        human_delay("click")
        point = driver.execute_script(
            r"""
            const el = arguments[0];
            const r = el.getBoundingClientRect();
            if (!r || r.width <= 0 || r.height <= 0) return {ok:false, reason:'empty_rect'};
            for (let i = 0; i < 6; i += 1) {
              const x = r.left + r.width * (0.25 + Math.random() * 0.50);
              const y = r.top + r.height * (0.28 + Math.random() * 0.44);
              const hit = document.elementFromPoint(x, y);
              if (hit && (hit === el || el.contains(hit))) {
                return {ok:true, x, y, viewportWidth:innerWidth, viewportHeight:innerHeight};
              }
            }
            const x = r.left + r.width / 2;
            const y = r.top + r.height / 2;
            const hit = document.elementFromPoint(x, y);
            return {
              ok: !!hit && (hit === el || el.contains(hit)),
              reason: 'target_obstructed',
              x,
              y,
              viewportWidth: innerWidth,
              viewportHeight: innerHeight
            };
            """,
            el,
        ) or {}
        x = float(point.get("x") or 0)
        y = float(point.get("y") or 0)
        if (
            bool(point.get("ok"))
            and hasattr(driver, "execute_cdp_cmd")
            and x > 0
            and y > 0
        ):
            viewport_width = max(1.0, float(point.get("viewportWidth") or x + 1))
            viewport_height = max(1.0, float(point.get("viewportHeight") or y + 1))
            previous = getattr(driver, "_roxy_pointer_position", None)
            if not (
                isinstance(previous, tuple)
                and len(previous) == 2
                and all(isinstance(value, (int, float)) for value in previous)
            ):
                previous = (
                    min(viewport_width - 1, max(1.0, x + random.uniform(-140, 140))),
                    min(viewport_height - 1, max(1.0, y + random.uniform(-100, 100))),
                )
            start_x, start_y = float(previous[0]), float(previous[1])
            steps = random.randint(3, 7)
            for index in range(1, steps + 1):
                progress = index / steps
                eased = progress * progress * (3.0 - 2.0 * progress)
                jitter = (1.0 - abs(2.0 * progress - 1.0)) * 1.8
                px = start_x + (x - start_x) * eased + random.uniform(-jitter, jitter)
                py = start_y + (y - start_y) * eased + random.uniform(-jitter, jitter)
                driver.execute_cdp_cmd(
                    "Input.dispatchMouseEvent",
                    {"type": "mouseMoved", "x": px, "y": py},
                )
                time.sleep(random.uniform(0.012, 0.038))
            driver.execute_cdp_cmd(
                "Input.dispatchMouseEvent",
                {
                    "type": "mousePressed",
                    "x": x,
                    "y": y,
                    "button": "left",
                    "clickCount": 1,
                },
            )
            time.sleep(random.uniform(0.035, 0.13))
            driver.execute_cdp_cmd(
                "Input.dispatchMouseEvent",
                {
                    "type": "mouseReleased",
                    "x": x,
                    "y": y,
                    "button": "left",
                    "clickCount": 1,
                },
            )
            driver._roxy_pointer_position = (x, y)
            return
        if point.get("reason"):
            logger.debug(
                "%s 随机鼠标落点不可用，回退 Selenium click：label=%s reason=%s",
                _log_prefix(driver),
                label,
                point.get("reason"),
            )
    except Exception as exc:
        logger.debug(
            "%s 随机鼠标点击失败，回退 Selenium click：label=%s err=%s",
            _log_prefix(driver),
            label,
            type(exc).__name__,
        )

    try:
        el.click()
    except Exception:
        driver.execute_script("arguments[0].click();", el)

def _human_send_keys(el, value: str) -> None:
    """Send text as bounded characters/chunks without logging its contents."""
    text = str(value)
    if not _browser_actions_enabled():
        el.send_keys(text)
        return

    index = 0
    while index < len(text):
        step = 2 if random.random() < 0.12 and index + 1 < len(text) else 1
        el.send_keys(text[index : index + step])
        index += step
        human_delay("keystroke")
        if index < len(text) and random.random() < 0.08:
            human_delay("typing_pause")

def _human_type_text(driver, el, value: str, *, clear: bool = True) -> None:
    """Use real key events with a native-value fallback for controlled inputs."""
    if not _browser_actions_enabled():
        if clear:
            try:
                el.clear()
            except Exception:
                pass
        el.send_keys(value)
        return

    try:
        _human_scroll_to(driver, el)
        try:
            _human_click(driver, el, label="input_focus")
        except Exception:
            driver.execute_script("arguments[0].focus();", el)
        if clear:
            from selenium.webdriver.common.keys import Keys

            modifier = Keys.COMMAND
            try:
                import platform

                if platform.system().lower() != "darwin":
                    modifier = Keys.CONTROL
            except Exception:
                pass
            try:
                el.send_keys(modifier, "a")
                time.sleep(random.uniform(0.04, 0.16))
                el.send_keys(Keys.BACKSPACE)
            except Exception:
                try:
                    el.clear()
                except Exception:
                    pass
        _human_send_keys(el, str(value))
        driver.execute_script(
            "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
            "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
            el,
        )
    except Exception as exc:
        logger.debug(
            "%s 随机输入失败，回退原生 value setter：err=%s",
            _log_prefix(driver),
            type(exc).__name__,
        )
        _set_element_value(driver, el, value)

def _page_warmup(driver, *, reason: str = "") -> None:
    """Perform one bounded pointer observation after a fresh navigation."""
    if not _browser_actions_enabled():
        return
    try:
        human_delay("page_warmup")
        if hasattr(driver, "execute_cdp_cmd"):
            x = random.randint(80, 360)
            y = random.randint(80, 260)
            driver.execute_cdp_cmd(
                "Input.dispatchMouseEvent",
                {"type": "mouseMoved", "x": x, "y": y},
            )
            driver._roxy_pointer_position = (float(x), float(y))
    except Exception as exc:
        logger.debug(
            "%s 页面观察鼠标移动失败：reason=%s err=%s",
            _log_prefix(driver),
            reason,
            type(exc).__name__,
        )

def _find_any(driver, selectors: list[str], timeout: int | None = None):
    from selenium.webdriver.common.by import By

    end = time.time() + (timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))
    last = None
    while time.time() < end:
        for selector in selectors:
            try:
                by = By.XPATH if selector.startswith("//") else By.CSS_SELECTOR
                items = driver.find_elements(by, selector)
                for item in items:
                    if _visible(item):
                        return item
            except Exception as exc:
                last = exc
        time.sleep(0.4)
    raise RuntimeError(f"找不到页面元素: {selectors}; last={last}")

def _click_any(driver, selectors: list[str], timeout: int | None = None) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_click(driver, el, label="click_any")

def _type_any(driver, selectors: list[str], value: str, timeout: int | None = None, clear: bool = True) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_type_text(driver, el, value, clear=clear)
''')
def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
