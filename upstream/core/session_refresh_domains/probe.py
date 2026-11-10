"""ChatGPT session refresh probe domain implementation.

Loaded into core.chatgpt_session_refresh globals to preserve public names and test seams."""
from __future__ import annotations
from textwrap import dedent

_SOURCE = dedent(r'''
def _attach_dom_recorder(driver, *, task_kind: str, account_id: int):
    try:
        from core.roxy_dom_failure_diagnostic import attach_recorder

        return attach_recorder(driver, task_kind=task_kind, account_id=account_id)
    except Exception:
        return None


def _finalize_dom_recorder(
    recorder,
    driver,
    *,
    error_code: str,
    source_error_type: str,
    terminal_status: str = "failed",
):
    try:
        if recorder is not None:
            recorder.finalize(
                driver,
                terminal_status=terminal_status,
                error_code=error_code,
                source_error_type=source_error_type,
            )
    except Exception:
        pass


def _observe_exchange_dom(recorder, driver) -> None:
    if recorder is None:
        return
    try:
        recorder.observe(
            driver,
            stage="session_exchange_probe",
            event="exchange_navigation",
            force=True,
        )
    except Exception:
        pass


def _browser_probe_login_required(driver) -> bool:
    try:
        current = str(getattr(driver, "current_url", "") or "")
        parsed = urlparse(current)
        host = str(parsed.hostname or "").lower()
        path = str(parsed.path or "").lower()
    except Exception:
        return False
    if host == "auth.openai.com" or host.endswith(".auth.openai.com"):
        return True
    return host == "chatgpt.com" and path.startswith(
        ("/auth/login", "/log-in", "/login")
    )


def _navigate_hidden_exchange_page(driver, timeout: float) -> str:
    """Start ChatGPT navigation without waiting for every page resource.

    The verified Web exchange happens while the document is still loading.
    Selenium ``get`` can otherwise block until its page-load timeout even
    after the new AT has already appeared, making a successful exchange look
    unnecessarily slow.
    """
    url = "https://chatgpt.com/"
    try:
        driver.execute_cdp_cmd("Page.enable", {})
        result = driver.execute_cdp_cmd("Page.navigate", {"url": url}) or {}
        if str(result.get("errorText") or "").strip():
            raise RuntimeError("page_navigate_rejected")
        return "cdp_async"
    except Exception:
        from core.roxy_registration import _safe_get

        _safe_get(
            driver,
            url,
            timeout=min(15, max(5, int(timeout))),
            attempts=1,
            accept_hosts=("chatgpt.com", "auth.openai.com"),
        )
        return "selenium_fallback"


def _build_hidden_roxy_candidate(
    *,
    driver,
    current: dict,
    email: str,
    account_id: int,
    old_token: str,
    old_fingerprint: str,
    candidate_token: str,
    candidate_source: str,
    latest_session_info: dict,
    record: dict,
    resolved_route: dict,
    tracer,
) -> SessionTokenCandidate:
    candidate_fingerprint = _token_fingerprint(candidate_token)
    candidate_session_info = dict(latest_session_info)
    candidate_session_info["accessToken"] = candidate_token
    try:
        validate_session_identity(current, candidate_session_info, candidate_token)
    except ChatGPTSessionRefreshError as exc:
        _record_quiet_result(
            email,
            stage="browser_exchange_probe",
            outcome="session_exchange_identity_mismatch",
            old_token_fingerprint=old_fingerprint,
            new_token_fingerprint=candidate_fingerprint,
            token_changed=True,
            status="invalid",
            exchange_method="hidden_roxy",
        )
        raise ChatGPTSessionRefreshError(
            "session_exchange_identity_mismatch", exc.user_message
        ) from exc
    if candidate_source != "browser_session" and tracer is not None:
        tracer.observe_session_info(
            candidate_session_info,
            source="browser_network_candidate",
        )
    try:
        driver.execute_cdp_cmd("Page.stopLoading", {})
    except Exception:
        pass
    snapshot = capture_driver_snapshot(
        driver,
        email=email,
        account_id=account_id,
        session_info=candidate_session_info,
    )
    session_rotated = (
        _session_cookie_signature(snapshot.get("cookies") or [])
        != _session_cookie_signature(record.get("cookies") or [])
    )
    _record_quiet_result(
        email,
        stage="browser_exchange_probe",
        outcome="session_exchange_candidate_ready",
        old_token_fingerprint=old_fingerprint,
        new_token_fingerprint=candidate_fingerprint,
        token_changed=True,
        session_rotated=session_rotated,
        exchange_method="hidden_roxy",
    )
    return SessionTokenCandidate(
        account_id=account_id,
        email=email,
        old_token_fingerprint=old_fingerprint,
        new_token_fingerprint=candidate_fingerprint,
        session_rotated=session_rotated,
        probe_count=1,
        access_token=candidate_token,
        expected_old_token=old_token,
        session_info=candidate_session_info,
        snapshot=snapshot,
        route=dict(resolved_route or {}),
        exchange_method="hidden_roxy",
    )


def _cleanup_hidden_roxy_probe(
    *, client, opened, driver, tracer, network_candidates: list, network_candidates_lock
) -> None:
    if tracer is not None:
        try:
            tracer.stop()
        except Exception:
            pass
    if driver is not None:
        try:
            driver.quit()
        except Exception:
            pass
    if opened is not None and client is not None:
        _cleanup_refresh_profile(client, opened)
    with network_candidates_lock:
        network_candidates.clear()
    _ROXY_BROWSER_SLOTS.release()


def _prepare_hidden_roxy_probe_state(state: dict, account: dict, route: dict | None) -> None:
    """Open the pooled browser and restore the saved Session under the caller lock."""
    from config import roxybrowser as roxy_cfg
    from core.roxy_registration import (
        RoxyIdentityResetError,
        _build_driver,
        _reset_pooled_profile_identity,
    )
    from core.roxybrowser_client import RoxyBrowserClient

    account_id = int(state["account_id"])
    client = RoxyBrowserClient()
    state["client"] = client
    current = db.get_account(account_id)
    if not current:
        raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
    email = str(current.get("email") or "").strip()
    old_token = normalize_token(current.get("access_token") or "")
    old_fingerprint = _token_fingerprint(old_token)

    def capture_network_candidate(token: str, metadata: dict) -> None:
        fingerprint = _token_fingerprint(token)
        if not fingerprint or fingerprint == old_fingerprint:
            return
        with state["network_candidates_lock"]:
            if fingerprint in state["network_candidate_fingerprints"]:
                return
            state["network_candidate_fingerprints"].add(fingerprint)
            state["network_candidates"].append((token, dict(metadata or {})))

    expected_old = normalize_token(account.get("access_token") or "")
    if expected_old and old_token != expected_old:
        raise ChatGPTSessionRefreshError(
            "account_token_update_conflict",
            "账号 Token 已被另一任务更新，请重新查询",
        )
    record = get_session(email, account_id=account_id)
    if not isinstance(record, dict) or not has_complete_session_cookie(
        record.get("cookies") or []
    ):
        raise ChatGPTSessionRefreshError(
            "session_browser_cookie_restore_failed",
            "没有可用于网页换发的完整 Session Cookie，请刷新会话",
        )

    opened = client.open_profile(headless=None, proxy_country=_MAINTENANCE_PROXY_COUNTRY)
    state["opened"] = opened
    opened_proxy = str(
        getattr(opened, "task_proxy_url", "")
        or getattr(opened, "task_proxy_upstream_url", "")
        or ""
    ).strip()
    resolved_route = {
        "proxy": opened_proxy,
        "proxy_mode": "maintenance_us_sid",
        "network_route": "regional_proxy",
        "proxy_used": str(getattr(opened, "proxy_safe_label", "") or "") or None,
        "proxy_fallback_reason": None,
        "plan_region": _MAINTENANCE_PROXY_COUNTRY,
        "_validated_geo": dict(getattr(opened, "task_proxy_geo", {}) or {}),
    }
    driver = _build_driver(opened)
    state["driver"] = driver
    try:
        setattr(driver, "_turb_roxy_account_id", account_id)
        setattr(driver, "_turb_roxy_task_kind", "session_exchange_probe")
        from core.roxy_otp_observer import ensure_observer

        ensure_observer(
            driver,
            task_kind="session_exchange_probe",
            account_id=account_id,
        )
    except Exception:
        pass
    state["dom_recorder"] = _attach_dom_recorder(
        driver,
        task_kind="session_exchange_probe",
        account_id=account_id,
    )
    driver.set_page_load_timeout(
        int(getattr(roxy_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)
    )
    try:
        _reset_pooled_profile_identity(driver)
    except RoxyIdentityResetError:
        if bool(getattr(opened, "pooled", False)):
            opened.profile_cache_discard = True
        raise ChatGPTSessionRefreshError(
            "session_identity_cleanup_failed",
            "Roxy 身份数据清理失败，已停止网页换发",
        ) from None
    _restore_saved_session_to_driver(driver, record)
    trace_enabled = bool(
        getattr(roxy_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", False)
    )
    if trace_enabled:
        state["tracer"] = RoxyChatGPTContractTracer(
            driver,
            debugger_address=getattr(opened, "debugger_address", None),
            task_kind="session_exchange_probe",
            account_id=account_id,
            old_access_token=old_token,
            token_candidate_callback=capture_network_candidate,
        )
        state["tracer"].set_stage("session_exchange_probe")
        state["tracer"].start()
    state.update({
        "current": current,
        "email": email,
        "old_token": old_token,
        "old_fingerprint": old_fingerprint,
        "record": record,
        "resolved_route": resolved_route,
        "trace_enabled": trace_enabled,
    })


def _poll_hidden_roxy_probe(state: dict, timeout: float) -> SessionTokenCandidate:
    """Poll browser and network observations until a changed Session token appears."""
    driver = state["driver"]
    dom_recorder = state["dom_recorder"]
    tracer = state["tracer"]
    account_id = int(state["account_id"])
    email = state["email"]
    old_token = state["old_token"]
    old_fingerprint = state["old_fingerprint"]
    trace_enabled = state["trace_enabled"]
    logger.info(
        "[SessionRefresh][Roxy] 开始网页 AT 换发（可见性跟随配置）："
        "account_id=%s timeout=%ss trace=%s contract=%s",
        account_id,
        int(max(1.0, timeout)),
        str(trace_enabled).lower(),
        _SESSION_EXCHANGE_IMPLEMENTATION,
    )
    deadline = time.monotonic() + max(1.0, float(timeout))
    navigation_mode = _navigate_hidden_exchange_page(driver, timeout)
    _observe_exchange_dom(dom_recorder, driver)
    logger.info(
        "[SessionRefresh][Roxy] 网页换发已触发：account_id=%s navigation=%s",
        account_id,
        navigation_mode,
    )
    observed_fingerprints: set[str] = set()
    latest_session_info: dict = {}
    first_poll = True
    while first_poll or time.monotonic() < deadline:
        first_poll = False
        session_info = _read_browser_session_once(driver)
        if isinstance(session_info, dict):
            latest_session_info = dict(session_info)
            candidate_token = normalize_token(session_info.get("accessToken") or "")
            candidate_fingerprint = _token_fingerprint(candidate_token)
            if candidate_fingerprint not in observed_fingerprints:
                observed_fingerprints.add(candidate_fingerprint)
                if tracer is not None:
                    tracer.observe_session_info(
                        session_info,
                        source="browser_exchange_probe",
                    )
            if not candidate_token or candidate_token == old_token:
                candidate_token = ""
        else:
            candidate_token = ""

        candidate_source = "browser_session"
        if not candidate_token:
            with state["network_candidates_lock"]:
                network_candidate = (
                    state["network_candidates"].pop(0)
                    if state["network_candidates"]
                    else None
                )
            if network_candidate is not None:
                candidate_token = normalize_token(network_candidate[0])
                candidate_source = str(network_candidate[1].get("source") or "browser_network")

        if candidate_token and candidate_token != old_token:
            return _build_hidden_roxy_candidate(
                driver=driver,
                current=state["current"],
                email=email,
                account_id=account_id,
                old_token=old_token,
                old_fingerprint=old_fingerprint,
                candidate_token=candidate_token,
                candidate_source=candidate_source,
                latest_session_info=latest_session_info,
                record=state["record"],
                resolved_route=state["resolved_route"],
                tracer=tracer,
            )
        if _browser_probe_login_required(driver):
            _record_quiet_result(
                email,
                stage="browser_exchange_probe",
                outcome="session_browser_probe_login_required",
                old_token_fingerprint=old_fingerprint,
                status="stale",
                exchange_method="hidden_roxy",
            )
            raise ChatGPTSessionRefreshError(
                "session_browser_probe_login_required",
                "保存的 Session 已进入登录页，需刷新会话",
            )
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.75, remaining))
    _record_quiet_result(
        email,
        stage="browser_exchange_probe",
        outcome="session_browser_probe_no_rotation",
        old_token_fingerprint=old_fingerprint,
        new_token_fingerprint=old_fingerprint,
        token_changed=False,
        status="stale",
        exchange_method="hidden_roxy",
    )
    raise ChatGPTSessionRefreshError(
        "session_browser_probe_no_rotation",
        "ChatGPT 网页在限定时间内仍未换发新 Token，需刷新会话",
    )


def probe_access_token_candidate_in_hidden_roxy(
    account: dict,
    *,
    route: dict | None = None,
    timeout: float = 30.0,
) -> SessionTokenCandidate:
    """Let the real ChatGPT page perform the verified browser-state AT exchange.

    This formal fallback never submits a login form, requests an OTP or waits
    for user interaction.  Browser visibility follows ``ROXY_OPEN_HEADLESS``.
    A changed AT is returned as an uncommitted candidate and still requires
    the caller's business validation.  Contract tracing remains independently
    configurable.
    """
    account_id = int(account.get("id") or 0)
    if account_id <= 0:
        raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
    acquired = _ROXY_BROWSER_SLOTS.acquire(timeout=60)
    if not acquired:
        raise ChatGPTSessionRefreshError(
            "session_browser_probe_unavailable",
            "Roxy 会话换发探测队列繁忙，请稍后重试",
        )
    state = {
        "account_id": account_id,
        "client": None,
        "opened": None,
        "driver": None,
        "tracer": None,
        "dom_recorder": None,
        "network_candidates": [],
        "network_candidate_fingerprints": set(),
        "network_candidates_lock": threading.Lock(),
    }
    try:
        with _account_lock(account_id):
            _prepare_hidden_roxy_probe_state(state, account, route)
            return _poll_hidden_roxy_probe(state, timeout)
    except ChatGPTSessionRefreshError as exc:
        if exc.error_code != "session_window_close_requested":
            _finalize_dom_recorder(
                state["dom_recorder"],
                state["driver"],
                error_code=exc.error_code,
                source_error_type=type(exc).__name__,
            )
        raise
    except Exception as exc:
        _finalize_dom_recorder(
            state["dom_recorder"],
            state["driver"],
            error_code="session_browser_probe_unavailable",
            source_error_type=type(exc).__name__,
        )
        raise ChatGPTSessionRefreshError(
            "session_browser_probe_unavailable",
            "ChatGPT Session 换发探测失败，请重试",
        ) from exc
    finally:
        _cleanup_hidden_roxy_probe(
            client=state["client"],
            opened=state["opened"],
            driver=state["driver"],
            tracer=state["tracer"],
            network_candidates=state["network_candidates"],
            network_candidates_lock=state["network_candidates_lock"],
        )

def prepare_access_token_candidate_from_saved_session_http(
    account: dict,
    *,
    env: BrowserSession | None = None,
    route: dict | None = None,
) -> SessionTokenCandidate:
    """Build a candidate using only the saved HTTP Web Session.

    This entry point is intentionally browser-free.  Callers that want the
    Roxy fallback must opt into the legacy wrapper below; plan checks never do
    so.
    """
    return _prepare_access_token_candidate_from_saved_session_http(
        account,
        env=env,
        route=route,
    )


def prepare_access_token_candidate_from_saved_session(
    account: dict,
    *,
    env: BrowserSession | None = None,
    route: dict | None = None,
) -> SessionTokenCandidate:
    """Build a changed AT candidate with the verified hidden-page fallback."""
    if route is None and env is None:
        route = _resolve_maintenance_us_route()  # Browser-capable wrapper keeps US policy.
    try:
        return prepare_access_token_candidate_from_saved_session_http(
            account,
            env=env,
            route=route,
        )
    except ChatGPTSessionRefreshError as exc:
        if exc.error_code not in {
            "session_probe_same_token",
            "session_exchange_no_rotation",
        }:
            raise
        logger.info(
            "[SessionRefresh] HTTP Session 未换发 AT，转入 Roxy 网页换发："
            "account_id=%s reason=%s",
            int(account.get("id") or 0),
            exc.error_code,
        )
        return probe_access_token_candidate_in_hidden_roxy(
            account,
            route=route,
            timeout=30.0,
        )


def _is_plan_auth_rejection(result: dict | None) -> bool:
    payload = result if isinstance(result, dict) else {}
    try:
        status = int(payload.get("http_status") or 0)
    except (TypeError, ValueError):
        status = 0
    return (
        str(payload.get("auth_error_code") or "").strip().lower()
        in {"token_invalidated", "token_expired"}
        or status == 401
    )


def refresh_access_token_via_saved_session(
    account: dict,
    *,
    timeout: float | None = None,
) -> dict:
    """Try one HTTP Web-Session exchange and verify its AT before commit.

    No Roxy client, browser slot, login form or OTP is touched here.  The
    returned plan result is safe for the caller to persist; all candidate
    secrets remain in the in-memory candidate object and are discarded after
    this function returns.
    """
    candidate: SessionTokenCandidate | None = None
    verification_context = None
    try:
        # This HTTP-only refresh ignores registration country and reuses its
        # selected protocol route for both exchange and token verification.
        from core.protocol_country import protocol_route
        maintenance_route = protocol_route()
        candidate = prepare_access_token_candidate_from_saved_session_http(
            account,
            route=maintenance_route,
        )
        from core.plan_check_service import _new_context_for_route

        # ``prepare_access_token_candidate_from_saved_session_http`` closes
        # its probe client after capturing the rotated snapshot.  Rebuild a
        # short-lived client from that snapshot before business verification;
        # otherwise the new AT would be tested with a fresh device and no Web
        # Session Cookie, which is exactly the 403-prone path this flow fixes.
        verification_context = _new_context_for_route(
            region="",
            route=dict(candidate.route or {}),
            account=account,
            session_record=candidate.snapshot,
        )

        result = check_account_plan(
            candidate.access_token,
            proxy=None,
            timezone_offset_min="-",
            timeout=timeout,
            max_attempts=1,
            env=verification_context.env,
            resolved_route=candidate.route,
            context_mode=verification_context.context_mode,
            edge_retry=True,
        )
        if _is_plan_auth_rejection(result):
            record_access_token_candidate_result(
                candidate,
                outcome="session_exchange_token_rejected",
                http_status=result.get("http_status"),
                status="stale",
            )
            raise ChatGPTSessionRefreshError(
                "refreshed_token_rejected",
                "静默换发得到的新 Token 仍被拒绝，请通过当前配置的驱动重新登录",
            )
        if not result.get("ok"):
            record_access_token_candidate_result(
                candidate,
                outcome="session_exchange_unverified",
                http_status=result.get("http_status"),
            )
            raise ChatGPTSessionRefreshError(
                "session_exchange_unverified",
                "静默换发得到的新 Token 未通过套餐验证，请通过当前配置的驱动重新登录",
            )
        commit_access_token_candidate(candidate)
        result = dict(result)
        result.update({
            "token_refreshed": True,
            "token_refresh_status": "refreshed",
            "token_refresh_method": "http_session",
            "session_refresh_required": False,
        })
        return {
            "ok": True,
            "access_token": candidate.access_token,
            "plan_result": result,
            "token_refresh_method": "http_session",
        }
    except (ChatGPTSessionRefreshError, AccountUnusableError):
        raise
    except Exception as exc:
        # Do not expose transport details or candidate values to callers.
        raise ChatGPTSessionRefreshError(
            "session_refresh_network_error",
            "ChatGPT Session 静默换发请求失败",
        ) from exc
    finally:
        if verification_context is not None:
            try:
                verification_context.close()
            except Exception:
                pass
''')

def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
