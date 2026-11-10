"""Roxy Registration implementation domain.

Loaded into :mod:`core.roxy_registration` so its public compatibility module
retains one shared namespace, locks, and test seams.
"""
from __future__ import annotations
from textwrap import dedent
_SOURCE = dedent(r'''
def run_roxy_registration(
    email: str,
    name: str,
    birthday: str,
    proxy: str = None,
    otp_code: str = None,
    batch_dir: Path | None = None,
    proxy_country: str | None = None,
    proxy_wire_scope=None,
    raw_trace_sampled: bool = False,
    raw_trace_job_id: int | None = None,
    stop_check=None,
    saved_openai_password: str = "",
    auth_persist_callback=None,
    traffic_snapshot_callback=None,
) -> dict:
    """Roxy 指纹浏览器自动化注册入口。"""
    if bool(getattr(_cfg, "ROXY_REGISTRATION_LOW_TRAFFIC_MODE", False)):
        from core.roxy_headed_registration import run_roxy_headed_registration

        return run_roxy_headed_registration(
            email=email,
            name=name,
            birthday=birthday,
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            proxy_country=proxy_country,
            proxy_wire_scope=proxy_wire_scope,
            raw_trace_sampled=raw_trace_sampled,
            raw_trace_job_id=raw_trace_job_id,
            stop_check=stop_check,
            saved_openai_password=saved_openai_password,
            auth_persist_callback=auth_persist_callback,
            traffic_snapshot_callback=traffic_snapshot_callback,
        )

    # These hooks belong to the headed state machine.  Keeping them in the
    # public call shape lets the dispatcher remain lazy while the legacy
    # Selenium path stays byte-for-byte equivalent when the switch is off.
    del saved_openai_password, auth_persist_callback, traffic_snapshot_callback
    client = RoxyBrowserClient()
    opened: RoxyOpenResult | None = None
    driver = None
    traffic_meter: RoxyTrafficMeter | None = None
    contract_tracer: RoxyChatGPTContractTracer | None = None
    raw_trace = None
    dom_recorder = None
    dom_terminal_status = ""
    dom_error_code = ""
    dom_source_error_type = ""
    traffic_enabled = bool(getattr(_cfg, "ROXY_TRAFFIC_METERING", True))
    network_usage = empty_network_usage("disabled" if not traffic_enabled else "unavailable")
    if traffic_enabled:
        network_usage["error_code"] = "meter_not_started"
    result: dict | None = None
    create_started = False
    create_acknowledged = False
    existing_account_detected = False
    identity_pending = False
    auth_restart_count = 0
    registration_path = "new_signup"
    openai_password: str | None = None
    previous_stop_check = getattr(_STOP_CHECK_CONTEXT, "callback", None)
    _STOP_CHECK_CONTEXT.callback = stop_check
    try:
        if proxy is not None:
            open_kwargs = {"task_proxy": proxy, "headless": bool(_cfg.REGISTRATION_HEADLESS)}
            if proxy_country:
                open_kwargs["proxy_country"] = proxy_country
            if proxy_wire_scope is not None:
                open_kwargs["proxy_wire_scope"] = proxy_wire_scope
            if stop_check is not None:
                open_kwargs["stop_check"] = stop_check
            opened = client.open_profile(**open_kwargs)
        else:
            open_kwargs = {"headless": bool(_cfg.REGISTRATION_HEADLESS)}
            if proxy_country:
                open_kwargs["proxy_country"] = proxy_country
            if proxy_wire_scope is not None:
                open_kwargs["proxy_wire_scope"] = proxy_wire_scope
            if stop_check is not None:
                open_kwargs["stop_check"] = stop_check
            opened = client.open_profile(**open_kwargs)
        driver = _build_driver(opened)
        try:
            setattr(driver, "_turb_roxy_task_kind", "registration")
            from core.roxy_otp_observer import ensure_observer

            ensure_observer(driver, task_kind="registration")
        except Exception:
            pass
        try:
            from core.roxy_dom_failure_diagnostic import attach_recorder

            dom_recorder = attach_recorder(
                driver,
                task_kind="registration",
            )
        except Exception:
            dom_recorder = None

        def _dom_event(stage: str, event: str = "stage_change", **kwargs) -> None:
            if dom_recorder is None or driver is None:
                return
            try:
                dom_recorder.observe(
                    driver,
                    stage=stage,
                    event=event,
                    result=kwargs.get("result", ""),
                    source_error_type=kwargs.get("source_error_type", ""),
                    force=bool(kwargs.get("force", False)),
                )
            except Exception:
                pass

        _dom_event("opening", "browser_ready", force=True)
        _center_browser_window(driver)
        driver.set_page_load_timeout(int(_cfg.ROXY_SELENIUM_TIMEOUT))
        if bool(getattr(opened, "pooled", False)):
            try:
                _reset_pooled_profile_identity(driver)
            except RoxyIdentityResetError:
                # Identity storage could not be proven empty.  This is a
                # structural Profile failure, not a transient Roxy API issue;
                # cleanup_profile() must never return it to the reusable pool.
                opened.profile_cache_discard = True
                raise
        try:
            traffic_meter = RoxyTrafficMeter(
                driver,
                debugger_address=opened.debugger_address,
                enabled=traffic_enabled,
            )
            meter_started = traffic_meter.start()
            if traffic_enabled:
                logger.info("[Roxy流量] HTTP 流量计量%s", "已启动" if meter_started else "不可用，注册继续")
            else:
                logger.info("[Roxy流量] HTTP 流量计量已关闭")
        except Exception:
            traffic_meter = None
            network_usage = empty_network_usage("unavailable")
            network_usage["error_code"] = "meter_start_failed"
            logger.warning("[Roxy流量] HTTP 流量计量启动失败，注册继续")
        if bool(raw_trace_sampled):
            try:
                from core.roxy_raw_network_trace import RoxyRawNetworkTracer

                raw_trace = RoxyRawNetworkTracer(
                    debugger_address=opened.debugger_address,
                    job_id=raw_trace_job_id,
                    enabled=True,
                )
                if raw_trace.start():
                    logger.info(
                        "[RoxyRawTrace] 原始网络采样已启动：trace_id=%s",
                        raw_trace.trace_id,
                    )
                else:
                    logger.warning(
                        "[RoxyRawTrace] 原始网络采样不可用，注册继续："
                        "reason=roxy_raw_trace_start_failed"
                    )
            except Exception:
                raw_trace = None
                logger.warning(
                    "[RoxyRawTrace] 原始网络采样启动异常，注册继续："
                    "reason=roxy_raw_trace_start_failed"
                )
        if bool(getattr(_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", False)):
            try:
                contract_tracer = RoxyChatGPTContractTracer(
                    driver,
                    debugger_address=opened.debugger_address,
                    task_kind="registration",
                )
                contract_tracer.start()
            except Exception:
                contract_tracer = None
                logger.warning(
                    "[RoxyTrace] 注册脱敏契约追踪启动失败，注册继续："
                    "reason=trace_start_unexpected"
                )
        logger.info("[Roxy注册] 开始：%s，profile=%s", email, opened.profile_id)

        prepare_otp_context(email)
        otp_after_ts = time.time()
        _set_traffic_stage(traffic_meter, "login_page", raw_trace)
        _dom_event("login_page")
        if contract_tracer is not None:
            contract_tracer.set_stage("login_page")
        logger.info("[Roxy注册] 打开登录页：https://chatgpt.com/auth/login")
        _safe_get(
            driver,
            "https://chatgpt.com/auth/login",
            timeout=min(
                45,
                int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90),
            ),
            attempts=2,
            accept_hosts=("chatgpt.com", "auth.openai.com"),
        )
        human_delay("navigate")
        _page_warmup(driver, reason="registration_login")
        logger.info("[Roxy注册] 登录页加载完成，准备填写邮箱")
        _maybe_accept(driver)
        _check_manual_stop()

        # 填邮箱。OpenAI UI 会随出口 IP/语言变化；这里只按 DOM 技术属性找邮箱入口，
        # 并排除 Google/Apple/Microsoft 等第三方入口，不依赖按钮可见文字。
        _set_traffic_stage(traffic_meter, "email_submit", raw_trace)
        _dom_event("email_submit")
        if contract_tracer is not None:
            contract_tracer.set_stage("email_submit")
        next_state = _submit_email_and_wait_next(
            driver,
            email,
            attempts=1,
            refresh_retries=5,
            refresh_interval=5.0,
            allow_existing_account=True,
        )
        _check_manual_stop()

        # 新版注册流可能先进入 /create-account/password；参考 FlowPilot 的 fill-password 步骤，
        # 先设置密码并提交。/log-in/password 则是远端已有账号，优先复用本地保存
        # 密码，否则使用一次性验证码；绝不生成新密码覆盖登录页。
        _set_traffic_stage(traffic_meter, "password", raw_trace)
        _dom_event("password")
        if contract_tracer is not None:
            contract_tracer.set_stage("password")
        if next_state == "login_password":
            existing_account_detected = True
            registration_path = "existing_login"
            mark_registration_existing_account_detected(email)
            login_result = _continue_existing_account_login(
                driver,
                email,
                timeout=20,
            )
            next_state = str(login_result.get("state") or "unknown")
            openai_password = login_result.get("registration_password")
        elif next_state == "password":
            openai_password = _fill_password_page_if_present(
                driver,
                email,
                timeout=25,
            )
        elif next_state == "logged_in":
            existing_account_detected = True
            registration_path = "existing_login"
            mark_registration_existing_account_detected(email)
        _check_manual_stop()

        def _apply_auth_restart_result(restart_result: dict) -> str:
            nonlocal next_state, otp_after_ts, openai_password
            nonlocal existing_account_detected, registration_path
            restarted_state = str(restart_result.get("state") or "unknown")
            restarted_after_ts = restart_result.get("otp_after_ts")
            if restarted_after_ts is not None:
                otp_after_ts = float(restarted_after_ts)
            if restarted_state == "login_password":
                existing_account_detected = True
                registration_path = "existing_login"
                mark_registration_existing_account_detected(email)
                login_result = _continue_existing_account_login(
                    driver,
                    email,
                    timeout=20,
                )
                restarted_state = str(login_result.get("state") or "unknown")
                if login_result.get("registration_password") is not None:
                    openai_password = login_result.get("registration_password")
            elif restarted_state == "password":
                password = _fill_password_page_if_present(driver, email, timeout=25)
                if password is not None:
                    openai_password = password
                if _has_access_token(driver):
                    restarted_state = "logged_in"
                elif _is_email_verification_page(driver):
                    restarted_state = "otp"
                else:
                    restarted_state = _wait_existing_login_transition(
                        driver,
                        timeout=20,
                    )
            if restarted_state == "logged_in":
                existing_account_detected = True
                registration_path = "existing_login"
                mark_registration_existing_account_detected(email)
            if restarted_state not in {"logged_in", "profile", "otp"}:
                raise EmailOtpAuthRestartFailed(
                    "email_otp_auth_restart_failed: "
                    f"unexpected_next_state={restarted_state}"
                )
            next_state = restarted_state
            return restarted_state

        def _begin_next_otp_attempt(reason: str) -> str:
            nonlocal otp_after_ts, next_state, auth_restart_count
            nonlocal existing_account_detected, registration_path
            baseline = {}

            def before_resend() -> None:
                prepare_otp_context(email)
                baseline["after_ts"] = time.time()

            action = _click_resend_email_otp(
                driver,
                timeout=25,
                strict=True,
                before_send=before_resend,
            )
            status = str(action.get("status") or "")
            if status == "resent":
                otp_after_ts = float(baseline.get("after_ts") or time.time())
                next_state = "otp"
                human_delay("api")
                logger.info(
                    "[Roxy注册][OTP] 下一轮仍使用同一邮箱：reason=%s action=resend",
                    reason,
                )
                return "otp"
            if status == "auth_restart":
                if auth_restart_count >= 1:
                    raise EmailOtpAuthRestartFailed(
                        "email_otp_auth_restart_failed: restart_budget_exhausted"
                    )
                auth_restart_count += 1
                logger.warning(
                    "[Roxy注册][OTP] otp_transition=auth_restart，复用同一邮箱和 Profile 重启认证（1/1）：reason=%s",
                    reason,
                )
                return _apply_auth_restart_result(
                    _restart_roxy_email_auth(driver, email, timeout=35)
                )
            if status in {"logged_in", "profile"}:
                next_state = status
                if status == "logged_in":
                    existing_account_detected = True
                    registration_path = "existing_login"
                    mark_registration_existing_account_detected(email)
                return status
            raise EmailOtpResendUnavailable(
                f"email_otp_resend_unavailable: unexpected_status={status or 'missing'}"
            )

        _set_traffic_stage(traffic_meter, "otp", raw_trace)
        _dom_event("email_otp")
        if contract_tracer is not None:
            contract_tracer.set_stage("otp")
        email_otp_required = next_state == "otp" or (
            next_state not in {"logged_in", "profile"}
            and not _has_access_token(driver)
        )
        if email_otp_required:
            from core.otp_retry_policy import (
                OtpResendResult,
                OtpRetryConfig,
                OtpSubmitResult,
                run_email_otp_retry,
            )

            last_wait_error: list[BaseException] = []
            last_resend_error: list[BaseException] = []
            def wait_registration_otp(after_ts: float, _used_codes: set[str]) -> str:
                try:
                    from core.roxy_otp_observer import mark_mailbox

                    mark_mailbox(driver, "waiting", stage="email_otp")
                except Exception:
                    pass
                _dom_event("email_otp", "email_otp_waiting", force=True)
                try:
                    return str(
                        wait_for_otp(
                            email,
                            after_ts=after_ts,
                            stop_check=stop_check,
                        )
                        or ""
                    )
                except Exception as exc:
                    last_wait_error[:] = [exc]
                    try:
                        from core.roxy_otp_observer import mark_mailbox

                        provider_code = str(
                            getattr(exc, "error_code", "") or ""
                        ).strip().lower()
                        mark_mailbox(
                            driver,
                            "timeout" if provider_code == "otp_timeout" else "error",
                            stage="email_otp",
                        )
                    except Exception:
                        pass
                    raise

            def submit_registration_otp(code: str, _attempt: int) -> OtpSubmitResult:
                nonlocal identity_pending, next_state, existing_account_detected, registration_path
                try:
                    from core.roxy_otp_observer import mark_mailbox

                    mark_mailbox(driver, "received", stage="email_otp")
                except Exception:
                    pass
                logger.info(
                    "[Roxy注册][OTP] 收到验证码：length=%s",
                    len(str(code or "")),
                )
                _clear_otp_inputs(driver)
                _type_otp(driver, code)
                _dom_event("email_otp", "email_otp_input", force=True)
                logger.info("[Roxy注册][OTP] 已填写邮箱验证码")
                _check_manual_stop()
                human_delay("otp_input")
                _ensure_email_otp_value_before_submit(driver, code)
                identity_pending = True
                mark_registration_email_otp_submitted(email)
                _dom_event("email_otp", "email_otp_submit", force=True)
                try:
                    _click_continue(driver)
                    try:
                        from core.roxy_otp_observer import mark_submit

                        mark_submit(driver, "waiting", stage="email_otp")
                    except Exception:
                        pass
                    logger.info("[Roxy注册][OTP] 已提交邮箱验证码，等待资料页或登录态")
                except Exception as exc:
                    try:
                        from core.roxy_otp_observer import mark_submit

                        mark_submit(driver, "failed", stage="email_otp")
                    except Exception:
                        pass
                    _dom_event(
                        "email_otp",
                        "email_otp_submit_exception",
                        result="failed",
                        source_error_type=type(exc).__name__,
                        force=True,
                    )
                    logger.info(
                        "[Roxy注册][OTP] 未找到显式提交按钮，继续等待页面状态：%s",
                        str(exc)[:120],
                    )

                outcome = _wait_after_email_otp_submit(
                    driver,
                    timeout=45,
                    roxy_idempotent=True,
                )
                _dom_event(
                    "email_otp",
                    "email_otp_transition",
                    result="success"
                    if outcome in {"logged_in", "profile", "accepted"}
                    else "failed",
                    force=True,
                )
                if outcome in {"logged_in", "profile"}:
                    next_state = outcome
                    if outcome == "logged_in":
                        existing_account_detected = True
                        registration_path = "existing_login"
                        mark_registration_existing_account_detected(email)
                    return OtpSubmitResult("terminal", reason=outcome)
                if outcome == "accepted":
                    # Backward-compatible test/driver shim; the strict Roxy
                    # collector returns logged_in/profile in production.
                    return OtpSubmitResult("accepted")
                if outcome == "unconfirmed":
                    return OtpSubmitResult(
                        "unconfirmed",
                        reason="email_otp_submission_unconfirmed",
                    )
                if outcome == "auth_restart":
                    return OtpSubmitResult("invalid", reason="auth_restart")
                return OtpSubmitResult("invalid", reason="otp_invalid")

            def trigger_registration_retry(attempt: int, reason: str) -> OtpResendResult:
                nonlocal auth_restart_count, next_state, otp_after_ts
                try:
                    if reason == "auth_restart":
                        if auth_restart_count >= 1:
                            raise EmailOtpAuthRestartFailed(
                                "email_otp_auth_restart_failed: restart_budget_exhausted"
                            )
                        auth_restart_count += 1
                        logger.warning(
                            "[Roxy注册][OTP] otp_transition=auth_restart，复用同一邮箱和 Profile 重启认证（1/1）"
                        )
                        next_attempt_state = _apply_auth_restart_result(
                            _restart_roxy_email_auth(driver, email, timeout=35)
                        )
                    else:
                        logger.warning(
                            "[Roxy注册][OTP] otp_transition=%s，准备明确重发或同邮箱认证重启（%s/%s）",
                            reason,
                            attempt + 1,
                            3,
                        )
                        next_attempt_state = _begin_next_otp_attempt(reason)
                except Exception as exc:
                    if StopRequested and isinstance(exc, StopRequested):
                        raise
                    last_resend_error[:] = [exc]
                    return OtpResendResult("failed", reason="otp_resend_failed")
                if next_attempt_state in {"logged_in", "profile"}:
                    next_state = next_attempt_state
                    return OtpResendResult("terminal", reason=next_attempt_state)
                return OtpResendResult("sent", after_ts=float(otp_after_ts))

            def rethrow_registration_error(exc: BaseException, _reason: str):
                raise exc

            try:
                from core.registration_service import StopRequested
            except Exception:
                StopRequested = ()

            retry_result = run_email_otp_retry(
                config=OtpRetryConfig(
                    max_attempts=3,
                    max_resends=2,
                    retry_wait_reasons=frozenset({"otp_wait_failed"}),
                    retry_submit_reasons=frozenset({"otp_invalid", "auth_restart"}),
                    retry_unconfirmed=False,
                ),
                initial_after_ts=otp_after_ts,
                initial_code=otp_code,
                wait_code=wait_registration_otp,
                submit_code=submit_registration_otp,
                trigger_resend=trigger_registration_retry,
                classify_error=lambda _exc: "otp_wait_failed",
                is_stop_error=lambda exc: bool(
                    StopRequested and isinstance(exc, StopRequested)
                ),
                handle_error=rethrow_registration_error,
                validate_code=lambda value: bool(str(value or "")),
                on_event=lambda event: (
                    logger.info(
                        "[Roxy注册][OTP] 等待验证码：%s（第 %s/%s 次）",
                        email,
                        event.attempt,
                        event.max_attempts,
                    )
                    if event.event == "wait"
                    else None
                ),
            )
            if retry_result.status == "accepted" or retry_result.status == "terminal":
                pass
            elif retry_result.status == "ambiguous":
                raise RuntimeError(
                    "email_otp_submission_unconfirmed: 页面没有返回明确验证结果，已停止自动重发"
                )
            elif last_resend_error:
                raise last_resend_error[0]
            elif last_wait_error:
                raise last_wait_error[0]
            elif retry_result.reason == "auth_restart":
                raise EmailOtpAuthRestartFailed(
                    "email_otp_auth_restart_failed: otp_budget_exhausted"
                )
            else:
                raise RuntimeError(
                    "email_otp_invalid_max_attempts: 邮箱验证码连续错误/过期，已达到最大重试次数"
                )
        else:
            logger.info(
                "[Roxy注册][OTP] 页面已进入资料页或登录态，跳过邮箱验证码等待：state=%s",
                next_state,
            )

        # about-you / profile 信息页：必须完成或确认已有登录态，不能静默跳过。
        _set_traffic_stage(traffic_meter, "profile_session", raw_trace)
        _dom_event("profile_session")
        if contract_tracer is not None:
            contract_tracer.set_stage("profile_session")
        logger.info("[Roxy注册] 开始等待资料页/登录态")
        _dom_event("profile_session", "profile_session_waiting", force=True)
        _check_manual_stop()
        profile_submitted = False
        if next_state == "profile":
            identity_pending = False
        if next_state != "logged_in" and not _has_access_token(driver):
            mark_registration_profile_submission(email, submitted=False)
            create_started = True
            mark_registration_profile_submission(email, submitted=True)
            _dom_event("profile", "profile_action_start", force=True)
            try:
                profile_submitted = _complete_profile_page(
                    driver,
                    name,
                    birthday,
                    timeout=60,
                )
            except Exception as exc:
                _dom_event(
                    "profile",
                    "profile_action_exception",
                    result="failed",
                    source_error_type=type(exc).__name__,
                    force=True,
                )
                raise
            _dom_event(
                "profile",
                "profile_action_success" if profile_submitted else "profile_action_failed",
                result="success" if profile_submitted else "failed",
                force=True,
            )
        if profile_submitted:
            create_acknowledged = True
            registration_path = (
                "profile_resumed"
                if existing_account_detected
                else "new_signup"
            )
            # 给 OAuth 回调 / session cookie 写入一点时间。
            human_delay("post_auth")
        elif registration_path != "existing_login":
            registration_path = "existing_login"

        logger.info("[Roxy注册] 等待 ChatGPT 跳转并写入 session/accessToken")
        _check_manual_stop()
        session_info = _fetch_chatgpt_session(driver, timeout=120)
        if contract_tracer is not None:
            contract_tracer.observe_session_info(
                session_info,
                source="registration_session",
            )
        access_token = session_info["accessToken"]
        _validate_registration_session_identity(email, session_info)
        if not create_acknowledged:
            create_acknowledged = True
        mark_registration_account_created(email)
        logger.info(
            "[Roxy注册] 已拿到 accessToken：%s registration_path=%s",
            email,
            registration_path,
        )
        session_snapshot_saved = False
        try:
            session_snapshot = capture_driver_snapshot(
                driver,
                email=email,
                session_info=session_info,
            )
            save_chatgpt_session_snapshot(session_snapshot)
            session_snapshot_saved = True
            logger.info("[Roxy注册][Session] ChatGPT Web Session 已保存")
        except ChatGPTSessionStoreError as exc:
            logger.warning(
                "[Roxy注册][Session] 会话捕获失败，不影响注册结果：reason=%s",
                exc.error_code,
            )
        except Exception as exc:
            logger.warning(
                "[Roxy注册][Session] 会话捕获失败，不影响注册结果：reason=session_capture_unexpected error_type=%s",
                type(exc).__name__,
            )
        _check_manual_stop()

        if _twofa_cfg.ENABLE_2FA:
            logger.warning("[Roxy注册] 当前 Roxy 自动化路径暂不执行 2FA 设置，已跳过")
        totp_secret = None

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "ENABLE_CODEX_AUTO=False，跳过 Codex",
        }
        try:
            from config import codex as _codex_cfg
            if bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False)):
                # 注册流程本身已创建 Roxy 一号一环境。这里不能再新建第二个 Roxy 环境；
                # 复用当前注册窗口，先清理 Cookie/session/localStorage/cache，再开始 Codex 授权。
                from core.roxy_codex_oauth import run_roxy_codex_oauth
                logger.info("[Roxy注册][Codex] ENABLE_CODEX_AUTO=True，复用当前注册 Roxy 窗口执行 Codex 授权，不创建新环境")
                _check_manual_stop()
                _set_traffic_stage(traffic_meter, "codex_oauth", raw_trace)
                _dom_event("codex_oauth")
                if contract_tracer is not None:
                    contract_tracer.set_stage("codex_oauth")
                codex_result = run_roxy_codex_oauth(
                    email,
                    reuse_existing_profile=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    force=True,
                    clear_existing_state=True,
                )
            else:
                logger.info("[Roxy注册][Codex] ENABLE_CODEX_AUTO=False，注册后跳过 Codex OAuth")
        except Exception as exc:
            codex_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {str(exc)[:180]}"}

        _set_traffic_stage(traffic_meter, "other", raw_trace)
        _dom_event("other")
        if contract_tracer is not None:
            contract_tracer.set_stage("other")
        network_usage = _stop_traffic_meter(traffic_meter, network_usage)
        traffic_meter = None
        from core.proxy_sid import mask_proxy_url

        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=(
                str(getattr(opened, "proxy_safe_label", "") or "")
                or mask_proxy_url(proxy)
                or None
            ),
            batch_dir=batch_dir,
            registration_plan_route_hint=(
                registration_plan_route_hint_from_opened(
                    opened,
                    proxy_wire_scope=proxy_wire_scope,
                )
                if proxy_wire_scope is not None
                else registration_plan_route_hint_from_opened(opened)
            ),
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "roxybrowser": {"profile_id": opened.profile_id, "open_result": opened.raw},
                "registration_password": openai_password,
                "registration_path": registration_path,
                "codex": codex_result,
            },
        )
        if session_snapshot_saved:
            try:
                bind_chatgpt_session_account(email, account_id)
            except Exception as exc:
                logger.warning(
                    "[Roxy注册][Session] 会话关联账号失败，不影响注册结果：reason=session_bind_failed error_type=%s",
                    type(exc).__name__,
                )
        codex_ok = codex_result.get("ok") or codex_result.get("status") == "skipped"
        result = {
            "success": bool(codex_ok),
            "email": email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "registration_path": registration_path,
            "codex": codex_result,
            "error": None if codex_ok else f"Codex 未完成: {codex_result.get('message')}",
        }
        return result
    except Exception as exc:
        try:
            from core.registration_service import StopRequested
        except Exception:
            StopRequested = ()
        if StopRequested and isinstance(exc, StopRequested):
            # Let registration_service perform the single authoritative CAS
            # transition to ``stopped`` and release the claimed mailbox.  The
            # finally block below still closes the meter, browser and Profile.
            raise
        if proxy_wire_scope is not None:
            wire_code = str(
                getattr(exc, "code", "") or str(exc) or ""
            ).strip().lower()
            if wire_code.startswith("proxy_wire_meter_"):
                proxy_wire_scope.record_failure(wire_code)
        dom_terminal_status = "failed"
        dom_error_code = (
            "registration_session_identity_mismatch"
            if isinstance(exc, RegistrationSessionIdentityMismatch)
            else "registration_failed"
        )
        dom_source_error_type = type(exc).__name__
        if dom_recorder is not None:
            try:
                from core.roxy_dom_failure_diagnostic import finalize_recorder

                finalize_recorder(
                    dom_recorder,
                    driver,
                    terminal_status=dom_terminal_status,
                    error_code=dom_error_code,
                    source_error_type=dom_source_error_type,
                )
            except Exception:
                pass
        network_usage = _stop_traffic_meter(traffic_meter, network_usage)
        traffic_meter = None
        logger.error("[Roxy注册] 失败：%s: %s", type(exc).__name__, exc)
        logger.debug("[Roxy注册] 失败详情", exc_info=True)
        identity_mismatch = isinstance(exc, RegistrationSessionIdentityMismatch)
        if identity_mismatch and opened is not None:
            opened.profile_cache_discard = True
        mark_registration_failed(
            email,
            create_started=create_started,
            create_acknowledged=(create_acknowledged and not identity_mismatch),
            error=exc,
            existing_account_detected=existing_account_detected,
            identity_pending=identity_pending,
        )
        # 未确认创建前回收邮箱；确认后避免重复使用。
        try:
            from core.email_provider import registration_failure_email_status, release_email
            if identity_mismatch:
                status = (
                    "quarantined"
                    if resolve_email_source(email) == "icloud_hme"
                    else "failed"
                )
            else:
                status = registration_failure_email_status(
                    email,
                    create_started=create_started,
                    create_acknowledged=create_acknowledged,
                    existing_account_detected=existing_account_detected,
                    identity_pending=identity_pending,
                    email_source=resolve_email_source(email),
                )
            release_email(email, status=status, note=f"Roxy注册失败: {str(exc)[:180]}")
        except Exception:
            pass
        result = {"success": False, "email": email, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
        return result
    finally:
        if contract_tracer is not None:
            try:
                contract_tracer.stop()
            except Exception:
                logger.warning(
                    "[RoxyTrace] 注册脱敏契约追踪停止失败，清理继续："
                    "reason=trace_stop_unexpected"
                )
            contract_tracer = None
        if traffic_meter is not None:
            network_usage = _stop_traffic_meter(traffic_meter, network_usage)
            traffic_meter = None
        network_usage = _attach_profile_cache_context(network_usage, opened)
        if proxy_wire_scope is not None:
            try:
                proxy_wire_scope.attach_browser_http(network_usage)
                network_usage = proxy_wire_scope.checkpoint()
            except Exception:
                logger.warning(
                    "[ProxyWire] 浏览器诊断合并失败，线路计量继续: "
                    "reason=proxy_wire_meter_snapshot_failed"
                )
                network_usage = proxy_wire_scope.snapshot()
        if result is not None:
            result["network_usage"] = network_usage
        if raw_trace is not None and driver and not _effective_keep_browser_open():
            try:
                raw_trace.begin_browser_shutdown()
            except Exception:
                pass
        if driver and not _effective_keep_browser_open():
            _quit_driver_for_shutdown(driver)
        if raw_trace is not None:
            try:
                raw_network_usage = network_usage
                if proxy_wire_scope is not None:
                    try:
                        # Browser shutdown may close a few final tunnels after
                        # the normal task checkpoint.  Use the freshest safe
                        # proxy snapshot for the local diagnostic only.
                        raw_network_usage = proxy_wire_scope.snapshot()
                    except Exception:
                        raw_network_usage = network_usage
                raw_summary = raw_trace.stop(network_usage=raw_network_usage)
                logger.info(
                    "[RoxyRawTrace] 原始网络采样已封存：trace_id=%s state=%s errors=%s",
                    raw_trace.trace_id,
                    raw_summary.get("state", "unknown"),
                    len(raw_summary.get("error_codes") or []),
                )
            except Exception:
                logger.warning(
                    "[RoxyRawTrace] 原始网络采样收尾失败，注册结果不受影响："
                    "reason=roxy_raw_trace_stop_failed"
                )
            raw_trace = None
        if not _effective_keep_browser_open():
            try:
                client.cleanup_profile(opened)
            except Exception:
                # Cleanup is best-effort.  Never let an unavailable Roxy API
                # replace the authoritative stopped/failed registration state.
                logger.warning(
                    "[Roxy] Profile 清理未确认：reason=profile_cleanup_failed"
                )
        if previous_stop_check is None:
            try:
                delattr(_STOP_CHECK_CONTEXT, "callback")
            except AttributeError:
                pass
        else:
            _STOP_CHECK_CONTEXT.callback = previous_stop_check
''')
def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
