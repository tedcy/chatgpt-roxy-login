"""ChatGPT session refresh queue domain implementation.

Loaded into core.chatgpt_session_refresh globals to preserve public names and test seams."""
from __future__ import annotations
from textwrap import dedent

_SOURCE = dedent(r'''
from core.account_task_queue import AccountTaskSubmission, dispatch_account_targets
from core.icloud_hme_client import ICloudHmeError
from contextlib import nullcontext
from core.registration_verification_traffic import measurement, route_hint as metered_login_route

_QUIET_REFRESH_TERMINAL_CODES = frozenset({
    "account_missing",
    "account_token_update_conflict",
    "session_exchange_identity_mismatch",
    "session_refresh_storage_error",
    # A maintenance task must fail closed when the required US SID cannot be
    # selected; never fall through to a VN/legacy/direct Roxy route.
    "session_refresh_network_config_error",
})

# A bulk refresh may contain the whole cross-page account selection.  The
# actual task queue remains bounded by _QUEUE_SLOTS; this dispatcher only
# feeds the next account after a slot is released, so a large selection never
# turns into thousands of simultaneously-held queue leases.
_BULK_LIMIT = 10_000
_BULK_DISPATCHER = AdaptiveExecutor("session_refresh", thread_name_prefix="session-refresh-dispatch", dispatcher=True)
_BULK_FUTURES_LOCK = threading.Lock()
_BULK_FUTURES: set[object] = set()


def _quiet_refresh_blocks_roxy_login(error_code: str) -> bool:
    code = str(error_code or "").strip().lower()
    return (
        code in _QUIET_REFRESH_TERMINAL_CODES
        or code.startswith("session_identity_")
        or bool(detect_account_unusable_text(code))
    )


def _persist_refresh_plan_result(account_id: int, account: dict, result: dict) -> dict:
    plan_result = result.get("plan_result") if isinstance(result, dict) else None
    plan_ok = bool(isinstance(plan_result, dict) and plan_result.get("ok"))
    plan_saved = False
    plan_queued = False
    regional_enabled = False
    try:
        regional_enabled = bool(plan_check_region_settings(None).get("enabled"))
    except Exception as exc:
        logger.warning(
            "[SessionRefresh] 地区套餐配置无效：account_id=%s reason=plan_region_config_invalid error_type=%s",
            account_id,
            type(exc).__name__,
        )
    if regional_enabled:
        if isinstance(plan_result, dict):
            logger.log(
                logging.INFO if plan_ok else logging.WARNING,
                "[SessionRefresh] 认证后套餐诊断完成但不覆盖地区结果：account_id=%s ok=%s http_status=%s",
                account_id,
                str(plan_ok).lower(),
                plan_result.get("http_status"),
            )
        try:
            from core.plan_check_service import enqueue_account_plan_check

            queued = enqueue_account_plan_check(
                account_id=account_id,
                email=str(account.get("email") or ""),
                access_token=str(result.get("access_token") or ""),
                trigger="session_refresh_auto",
            )
            plan_queued = bool(queued.get("accepted"))
            if plan_queued:
                logger.info(
                    "[SessionRefresh] 地区套餐复查已入队：account_id=%s；详细过程请查看套餐查询日志",
                    account_id,
                )
            else:
                logger.warning(
                    "[SessionRefresh] 地区套餐复查未入队：account_id=%s reason=%s",
                    account_id,
                    "plan_check_busy" if queued.get("busy") else "plan_check_enqueue_failed",
                )
        except Exception as exc:
            logger.warning(
                "[SessionRefresh] 地区套餐复查入队异常：account_id=%s reason=plan_check_enqueue_failed error_type=%s",
                account_id,
                type(exc).__name__,
            )
    elif isinstance(plan_result, dict):
        try:
            plan_saved = bool(
                _session_storage_write(
                    account_id, "plan_result", db.update_account_plan_check,
                    acc_id=account_id, result=plan_result,
                )
            )
            if not plan_saved:
                logger.warning(
                    "[SessionRefresh] 套餐复查结果未保存：account_id=%s "
                    "reason=plan_check_account_missing",
                    account_id,
                )
            elif plan_ok:
                logger.info(
                    "[SessionRefresh] 认证后套餐复查成功：account_id=%s plan=%s",
                    account_id,
                    plan_result.get("current_plan_type") or "unknown",
                )
            else:
                logger.warning(
                    "[SessionRefresh] 认证后套餐复查失败：account_id=%s reason=%s http_status=%s",
                    account_id,
                    plan_result.get("error_code") or "plan_check_failed",
                    plan_result.get("http_status"),
                )
        except Exception as exc:
            logger.warning(
                "[SessionRefresh] 套餐复查结果保存失败：account_id=%s "
                "reason=plan_check_persist_failed error_type=%s",
                account_id,
                type(exc).__name__,
            )
    else:
        logger.warning(
            "[SessionRefresh] 套餐复查缺少结果：account_id=%s reason=plan_check_result_missing",
            account_id,
        )
    return {
        "plan_check_ok": plan_ok and plan_saved,
        "plan_check_queued": plan_queued,
        "regional_enabled": regional_enabled,
    }


def _run_headed_session_refresh(
    account: dict,
    *,
    headless: bool | None = None,
    allow_manual_login: bool = True,
    force_relogin: bool = False,
    driver: str = "headed_chrome",
    registration_route_hint=None,
) -> dict:
    """Run the headed browser owner through the neutral auth facade.

    The existing Roxy implementation remains untouched; the owner is selected
    by ``SESSION_REFRESH_DRIVER``.  Plan checking and persistence stay
    identical to the historical refresh result shape.
    """

    from core.auth_runtime import (
        open_existing_account_login,
        save_existing_account_login,
    )
    from core.session_candidate import save_driver_session_for_account

    try:
        lease = open_existing_account_login(
            account,
            **({"driver": driver} if driver != "headed_chrome" else {}),
            **({"registration_route_hint": registration_route_hint} if registration_route_hint is not None else {}),
            login_email=str(account.get("email") or ""),
            headless=headless,
            proxy_country=_MAINTENANCE_PROXY_COUNTRY,
            allow_manual_login=allow_manual_login,
            task_kind="session_refresh",
            slot_already_acquired=True,
            # Ordinary refresh restores first; forced login skips old Sessions.
            restore_saved_session=not force_relogin,
        )
    except Exception as exc:
        # The headed owner exposes credential-free HeadedChromeAuthError
        # values rather than the legacy refresh exception class.  Preserve
        # that fixed code at this boundary so the queue does not erase a
        # useful failure as ``session_refresh_unexpected``.
        code = str(getattr(exc, "error_code", "") or "").strip()
        if code:
            raise ChatGPTSessionRefreshError(code) from exc
        raise
    try:
        candidate = lease.candidate
        if candidate is None:
            # A valid saved Session may be restored without rotating its
            # access token.  The fresh-login candidate contract correctly
            # rejects that as ``session_exchange_no_rotation``; persist the
            # already validated browser Session through the neutral saver
            # instead of turning a successful restore into a refresh error.
            session_info = getattr(lease, "session_info", None)
            if not isinstance(session_info, dict):
                raise ChatGPTSessionRefreshError(
                    "session_refresh_empty",
                    "headed Chrome 未返回有效 Session",
                )
            persisted = save_driver_session_for_account(
                account,
                lease.driver,
                session_info,
            )
        else:
            persisted = save_existing_account_login(account, candidate)
        try:
            plan_result = check_account_plan_in_driver(
                lease.driver,
                persisted["access_token"],
            )
        except Exception as exc:
            logger.warning(
                "[SessionRefresh][HeadedChrome] 套餐探测异常：account_id=%s "
                "reason=plan_check_browser_unexpected error_type=%s",
                int(account.get("id") or 0),
                type(exc).__name__,
            )
            plan_result = {
                "ok": False,
                "checked_at": now_iso(),
                "http_status": None,
                "error": "套餐探测异常",
                "error_code": "plan_check_browser_unexpected",
                "proxy_mode": "headed_chrome",
                "network_route": "headed_chrome",
            }
        plan_result = dict(plan_result or {})
        plan_result["token_refreshed"] = True
        plan_result["token_refresh_status"] = "refreshed"
        plan_result["token_refresh_method"] = driver + "_login"
        plan_result["session_refresh_required"] = False
        return {
            "ok": True,
            "access_token": persisted["access_token"],
            "plan_result": plan_result,
            "token_refresh_method": driver + "_login",
            "login_evidence": getattr(getattr(lease.driver, "_turb_roxy_contract_tracer", None), "login_evidence", None),
        }
    finally:
        lease.close()


from core.protocol_task_observability import task_scope

@task_scope('session_refresh', enabled=True)
def _run_protocol_session_refresh(
    account: dict,
    *,
    allow_manual_login: bool = False,
    registration_route_hint=None,
) -> dict:
    """Refresh through the pure-protocol existing-account login kernel."""

    from core.auth_runtime import (
        run_existing_account_login,
        save_existing_account_login,
    )
    from core.chatgpt_plan import check_account_plan
    from core.protocol_auth_runtime import ProtocolAuthError

    try:
        candidate = run_existing_account_login(
            account,
            operation="session_refresh",
            driver="protocol",
            **({"proxy": registration_route_hint.proxy_url,
                "validated_geo": dict(registration_route_hint.validated_geo),
                "registration_route_hint": registration_route_hint} if registration_route_hint is not None else {}),
            login_email=str(account.get("email") or ""),
            proxy_country=_MAINTENANCE_PROXY_COUNTRY,
            allow_email_otp=True,
            require_password=False,
            require_backend_me=True,
            restore_saved_session=False,
            allow_manual_login=allow_manual_login,
            task_kind="session_refresh",
        )
        persisted = save_existing_account_login(account, candidate)
    except Exception as exc:
        code = str(getattr(exc, "error_code", "") or "").strip()
        upstream_code = getattr(exc, "upstream_code", None)
        if (
            isinstance(exc, ProtocolAuthError)
            and code == "protocol_auth_account_unusable"
            and upstream_code in ("account_deactivated", "account_deleted", "account_banned")
        ):
            raise AccountUnusableError(
                f"账号已废（{upstream_code}）", error_code=upstream_code,
            ) from exc
        raise ChatGPTSessionRefreshError(
            code or "session_refresh_protocol_login_failed",
            "纯协议登录失败",
        ) from exc

    plan_result = {
        "ok": False,
        "checked_at": now_iso(),
        "http_status": None,
        "error_code": "plan_check_not_run",
        "proxy_mode": "protocol",
        "network_route": "protocol",
    }
    route = dict(getattr(candidate, "route", {}) or {})
    env = None
    try:
        # Rehydrate the candidate snapshot so the business probe uses the
        # same authenticated Cookie/UA context rather than a fresh anonymous
        # client.  The protocol login lease itself has already been closed.
        env = BrowserSession(
            proxy=str(route.get("proxy") or ""),
            validated_geo=dict(route.get("_validated_geo") or {}),
            detect_exit_geo=False,
            force_locale_from_geo=True,
        )
        hydrate_browser_session(
            env,
            dict(getattr(candidate, "snapshot", {}) or {}),
            strip_transient_cookies=True,
        )
        plan_result = dict(
            check_account_plan(
                persisted.get("access_token") or candidate.access_token,
                proxy=None,
                env=env,
                resolved_route=route,
                context_mode="saved_session",
                edge_retry=True,
                max_attempts=1,
            )
            or plan_result
        )
    except Exception as exc:
        logger.warning(
            "[SessionRefresh][Protocol] 套餐探测异常：account_id=%s "
            "reason=plan_check_protocol_unexpected error_type=%s",
            int(account.get("id") or 0),
            type(exc).__name__,
        )
    finally:
        if env is not None:
            try:
                env.session.close()
            except Exception:
                pass
    plan_result.update(
        {
            "token_refreshed": True,
            "token_refresh_status": "refreshed",
            "token_refresh_method": "protocol_login",
            "session_refresh_required": False,
        }
    )
    return {
        "ok": True,
        "access_token": persisted.get("access_token") or candidate.access_token,
        "plan_result": plan_result,
        "token_refresh_method": "protocol_login",
        "login_evidence": getattr(candidate, "login_evidence", None),
    }


def _run_registration_session_login(account, *, driver, route_hint, revision, headless):
    from core import registration_login_route as routes
    from core.login_verification import credential_revision
    hint = route_hint
    for attempt in range(2):
        current = db.get_account(int(account["id"])) or {}
        if credential_revision(current) != revision or routes.problem(current, hint):
            raise ChatGPTSessionRefreshError("session_login_verification_stale", "账号身份或凭据已变化，保留待验证")
        if current.get("session_refresh_status") != "running":
            raise ChatGPTSessionRefreshError("account_refresh_state_changed", "会话刷新状态已变化，请重新提交")
        terminal = _stored_account_unusable_code(current)
        if terminal:
            raise AccountUnusableError("账号已废", error_code=terminal)
        logger.info(
            "[LoginVerification] 代理策略=%s country=%s route_fp=%s attempt=%s account_id=%s",
            "registration_reuse" if attempt == 0 else "same_country_fallback",
            hint.country or "unknown", routes.route_fingerprint(hint), attempt + 1, account["id"],
        )
        try:
            login_hint = metered_login_route(hint)
            if driver == "protocol":
                return _run_protocol_session_refresh(
                    current, allow_manual_login=False, registration_route_hint=login_hint,
                )
            return _run_headed_session_refresh(
                current, headless=headless, allow_manual_login=False, force_relogin=True,
                **({"driver": driver} if driver != "headed_chrome" else {}),
                registration_route_hint=login_hint,
            )
        except Exception as exc:
            if attempt or not routes.proxy_failure(exc):
                raise
            latest = db.get_account(int(account["id"])) or {}
            if credential_revision(latest) != revision or routes.problem(latest, hint):
                raise ChatGPTSessionRefreshError("session_login_verification_stale", "账号身份或凭据已变化，保留待验证") from exc
            if latest.get("session_refresh_status") != "running":
                raise ChatGPTSessionRefreshError("account_refresh_state_changed", "会话刷新状态已变化，请重新提交") from exc
            terminal = _stored_account_unusable_code(latest)
            if terminal:
                raise AccountUnusableError("账号已废", error_code=terminal) from exc
            if normalize_token(latest.get("access_token") or "") != normalize_token(current.get("access_token") or ""):
                raise ChatGPTSessionRefreshError("account_token_update_conflict", "账号 Token 已变化，请重新验证") from exc
            if not hint.country:
                raise ChatGPTSessionRefreshError("session_login_registration_country_unknown", "注册代理国家未知，保留待验证") from exc
            try:
                hint = routes.replacement(hint)
            except Exception as route_exc:
                raise ChatGPTSessionRefreshError(
                    "session_login_registration_proxy_unavailable", "没有可用的同国家代理，保留待验证",
                ) from route_exc


def _complete_refresh_task(account_id, account, result, *, verification, verification_revision):
    terminal_code = _stored_account_unusable_code(db.get_account(account_id))
    if terminal_code:
        logger.warning(
            "[SessionRefresh] 网络终态证据先于普通完成结果生效："
            "account_id=%s reason=%s",
            account_id,
            terminal_code,
        )
        return {
            "ok": False,
            "error_code": terminal_code,
            "deactivated": True,
        }
    if verification:
        from core.login_verification import accepted
        if not accepted(result.get("login_evidence")):
            raise ChatGPTSessionRefreshError("session_login_verification_incomplete", "未取得本轮无邮箱密码和 TOTP 登录成功证据")
    plan_state = _persist_refresh_plan_result(account_id, account, result)
    plan_completed = bool(plan_state["plan_check_ok"])
    plan_queued = bool(plan_state["plan_check_queued"])
    # The UI stops polling when the Session task leaves its active state,
    # so publish the plan result first and the Session completion second.
    completed = _session_storage_write(
        account_id, "completed", db.finish_account_session_refresh,
        account_id,
        ok=True,
        **({"verification_revision": verification_revision, "login_evidence": result.get("login_evidence")} if verification else {}),
        message=(
            "会话刷新成功，地区套餐复查已入队"
            if plan_queued
            else
            "会话刷新成功，套餐复查成功"
            if plan_completed
            else "会话刷新成功，套餐复查未成功"
        ),
    )
    if verification and not completed:
        raise ChatGPTSessionRefreshError("session_login_verification_stale", "账号身份或凭据已变化，保留待验证")
    logger.info("[SessionRefresh] 会话刷新成功：account_id=%s", account_id)
    task_result = {
        "ok": True,
        "plan_check_ok": plan_completed,
    }
    if plan_state["regional_enabled"]:
        task_result["plan_check_queued"] = plan_queued
    return task_result


def _run_refresh_task_impl(
    account_id: int,
    *,
    headless: bool | None = None,
    allow_manual_login: bool = True,
    force_relogin: bool = False,
    registration_route_hint=None,
    registration_auto_verification: bool = False,
    _hme_scope=None,
) -> dict:
    roxy_slot_acquired = False
    try:
        if not _session_storage_write(
            account_id, "running", db.mark_account_session_refresh_running, account_id,
        ):
            latest = db.get_account(account_id)
            terminal_code = _stored_account_unusable_code(latest)
            if terminal_code:
                return {
                    "ok": False,
                    "error_code": terminal_code,
                    "deactivated": True,
                }
            return {"ok": False, "error_code": "account_missing"}
        account = db.get_account(account_id)
        if not account:
            raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
        verification = force_relogin and account.get("login_verification_pending") is True
        if registration_auto_verification and not verification:
            raise ChatGPTSessionRefreshError("session_login_verification_stale", "验证状态已变化，请重新提交")
        verification_revision = None
        if verification:
            from core.auth_factors import load_chatgpt_auth_factors
            from core.login_verification import credential_revision
            if load_chatgpt_auth_factors(account).factor != "password_totp":
                raise ChatGPTSessionRefreshError("session_login_verification_credentials_missing", "待验证账号需要已保存的密码和有效 TOTP")
            verification_revision = credential_revision(account)
            allow_manual_login = False
        if registration_auto_verification:
            from core.registration_login_route import problem
            route_problem = problem(account, registration_route_hint)
            if route_problem:
                raise ChatGPTSessionRefreshError(route_problem, "注册代理上下文缺失或身份已变化，保留待验证")
        if _hme_scope is not None:
            try:
                from core.auth_factors import resolve_login_policy

                login_policy = resolve_login_policy(account)
            except Exception:
                login_policy = None
            if login_policy is None or login_policy.mailbox_access:
                _hme_scope.defer(account, "session_refresh")
            else:
                logger.info(
                    "[账号登录] Session 刷新使用密码和认证器验证，跳过邮箱服务 | "
                    "auth_factor=password_totp mailbox_access=disabled account_id=%s",
                    account_id,
                )
        quiet_error = None
        if not force_relogin:
            logger.info(
                "[SessionRefresh] 正在尝试 Web Session 静默换发：account_id=%s method=http_session",
                account_id,
            )
            try:
                result = refresh_access_token_via_saved_session(account)
                logger.info(
                    "[SessionRefresh] Web Session 静默换发并验证成功：account_id=%s method=http_session",
                    account_id,
                )
            except ChatGPTSessionRefreshError as quiet_exc:
                if quiet_exc.error_code == "session_refresh_storage_error":
                    raise
                quiet_error = quiet_exc
        if force_relogin or quiet_error is not None:
            latest = db.get_account(account_id)
            terminal_code = _stored_account_unusable_code(latest)
            if terminal_code:
                return {
                    "ok": False,
                    "error_code": terminal_code,
                    "deactivated": True,
                }
            if quiet_error is not None and _quiet_refresh_blocks_roxy_login(quiet_error.error_code):
                logger.warning(
                    "[SessionRefresh] Web Session 静默换发遇到安全终态，禁止继续登录："
                    "account_id=%s reason=%s",
                    account_id,
                    quiet_error.error_code,
                )
                raise quiet_error
            from core.auth_driver import resolve_operation_driver
            refresh_driver = resolve_operation_driver("session_refresh")
            login_stage = {"protocol": "protocol_login", "headed_chrome": "headed_chrome_login"}.get(refresh_driver, "roxy_login")
            if not _session_storage_write(
                account_id, "login_stage", db.update_account_session_refresh_stage,
                account_id, login_stage,
            ):
                latest = db.get_account(account_id)
                terminal_code = _stored_account_unusable_code(latest)
                if terminal_code:
                    return {
                        "ok": False,
                        "error_code": terminal_code,
                        "deactivated": True,
                    }
                raise ChatGPTSessionRefreshError(
                    "account_refresh_state_changed",
                    "会话刷新状态已变化，请重新提交",
                )
            if force_relogin:
                logger.info(
                    "[SessionRefresh] 强制登录，跳过 Web Session 静默换发：account_id=%s",
                    account_id,
                )
            else:
                logger.warning(
                    "[SessionRefresh] Web Session 静默换发失败，转入配置驱动登录："
                    "account_id=%s reason=%s",
                    account_id,
                    quiet_error.error_code,
                )
            acquired = _ROXY_BROWSER_SLOTS.acquire()
            if acquired is False:
                raise ChatGPTSessionRefreshError(
                    "session_roxy_slot_unavailable",
                    "会话登录队列繁忙，请稍后重试",
                )
            roxy_slot_acquired = True
            refresh_account = latest or account
            if verification and credential_revision(refresh_account) != verification_revision:
                raise ChatGPTSessionRefreshError(
                    "session_login_verification_stale", "账号身份或凭据已变化，保留待验证",
                )

            logger.info(
                "[SessionRefresh] 任务驱动已固定: account_id=%s operation=session_refresh driver=%s",
                account_id,
                refresh_driver,
            )
            if registration_auto_verification:
                result = _run_registration_session_login(
                    refresh_account, driver=refresh_driver, route_hint=registration_route_hint,
                    revision=verification_revision, headless=headless,
                )
            elif refresh_driver == "headed_chrome":
                result = _run_headed_session_refresh(
                    refresh_account,
                    headless=headless,
                    allow_manual_login=allow_manual_login,
                    force_relogin=force_relogin,
                )
            elif refresh_driver == "protocol":
                result = _run_protocol_session_refresh(
                    refresh_account,
                    allow_manual_login=False,
                )
            elif refresh_driver == "roxy":
                if verification:
                    result = _run_headed_session_refresh(
                        refresh_account, headless=headless, allow_manual_login=False,
                        force_relogin=True, driver="roxy",
                    )
                else:
                    result = run_roxy_session_refresh(
                        refresh_account, headless=headless, allow_manual_login=allow_manual_login,
                    )
            result = dict(result or {})
            result["token_refresh_method"] = login_stage
            if isinstance(result.get("plan_result"), dict):
                result["plan_result"].setdefault("token_refresh_method", login_stage)
        return _complete_refresh_task(
            account_id, account, result,
            verification=verification, verification_revision=verification_revision,
        )
    except AccountUnusableError as exc:
        error_code = detect_account_unusable_text(exc.error_code) or "account_deactivated"
        message = f"账号已废（{error_code}），无需刷新会话"
        logger.warning(
            "[SessionRefresh] 账号已废，停止会话刷新：account_id=%s reason=%s",
            account_id,
            error_code,
        )
        _session_storage_write(
            account_id, "unusable", db.finish_account_session_refresh_unusable,
            account_id, error_code=error_code, message=message,
        )
        return {
            "ok": False,
            "error_code": error_code,
            "deactivated": True,
        }
    except ChatGPTSessionRefreshError as exc:
        logger.warning(
            "[SessionRefresh] 会话刷新失败：account_id=%s reason=%s",
            account_id,
            exc.error_code,
        )
        _session_storage_write(
            account_id, "failed", db.finish_account_session_refresh,
            account_id, ok=False, error=exc.error_code, message=exc.user_message,
        )
        return {"ok": False, "error_code": exc.error_code}
    except ICloudHmeError as exc:
        # HME slot/group fencing failures are fixed, actionable task errors.
        # Keep them separate from the generic fallback so the account page
        # and operation log retain the actual Sidecar/context code.
        error_code = str(exc.error_code or "hme_task_failed").strip()
        message = {
            "hme_slot_contract_required": "HME 别名缺少槽位上下文，请重新同步账号",
            "hme_slot_identity_mismatch": "HME 别名槽位身份不一致，请查看服务日志",
            "hme_group_lease_stale": "HME 认证租约已失效，请重新提交",
            "hme_group_busy": "HME 认证组正在使用，请稍后重试",
            "hme_group_cooling_down": "HME 认证组仍在冷却，请稍后重试",
        }.get(error_code, "HME 认证租约失败，请查看服务日志")
        logger.warning(
            "[SessionRefresh] HME 认证上下文失败：account_id=%s reason=%s",
            account_id,
            error_code,
        )
        _session_storage_write(
            account_id, "failed", db.finish_account_session_refresh,
            account_id, ok=False, error=error_code, message=message,
        )
        return {"ok": False, "error_code": error_code}
    except Exception as exc:
        storage_error = isinstance(exc, (sqlite3.Error, db.AccountStoreError, ChatGPTSessionStoreError))
        error_code = "session_refresh_storage_error" if storage_error else "session_refresh_unexpected"
        _, sqlite_name = _session_storage_details(exc)
        logger.warning(
            "[SessionRefresh] 会话刷新异常：account_id=%s stage=worker "
            "error_type=%s sqlite_errorname=%s",
            account_id, type(exc).__name__, sqlite_name,
        )
        _session_storage_write(
            account_id, "failed", db.finish_account_session_refresh,
            account_id, ok=False, error=error_code,
            message="会话结果保存失败，请重试" if storage_error else "会话刷新失败，请查看服务日志",
        )
        return {"ok": False, "error_code": error_code}
    finally:
        try:
            if roxy_slot_acquired:
                _ROXY_BROWSER_SLOTS.release()
        finally:
            _QUEUE_SLOTS.release()


from core.protocol_task_observability import task_scope

@task_scope('session_refresh')
def _run_refresh_task(
    account_id: int,
    *,
    headless: bool | None = None,
    allow_manual_login: bool = True,
    force_relogin: bool = False,
    registration_route_hint=None,
    registration_auto_verification: bool = False,
    action_run_id: str | None = None,
    action_target_key: str | None = None,
) -> dict:
    with account_operation_log.task_log_context(account_id, "session_refresh"):
        logger.info(
            "[SessionRefresh] 会话刷新任务开始：account_id=%s",
            account_id,
        )
        if action_run_id and action_target_key:
            try:
                action_progress.update_target(
                    action_run_id,
                    action_target_key,
                    "running",
                    return_snapshot=False,
                )
            except Exception:
                logger.warning(
                    "[SessionRefresh] 批次进度启动更新失败："
                    "account_id=%s reason=action_progress_update_failed",
                    account_id,
                )
        result: dict = {"ok": False}
        from core.hme_task_scope import HmeTaskScope
        hme_scope = HmeTaskScope()
        try:
            with (measurement(registration_route_hint, account_id)
                  if registration_auto_verification else nullcontext()):
                result = _run_refresh_task_impl(
                    account_id,
                    headless=headless,
                    allow_manual_login=allow_manual_login,
                    force_relogin=force_relogin,
                    **({"registration_route_hint": registration_route_hint,
                        "registration_auto_verification": True} if registration_auto_verification else {}),
                    _hme_scope=hme_scope,
                )
            return result
        except Exception as exc:
            error_code = (
                exc.error_code if isinstance(exc, ChatGPTSessionRefreshError)
                else "session_refresh_storage_error"
                if isinstance(exc, (sqlite3.Error, db.AccountStoreError, ChatGPTSessionStoreError))
                else "session_refresh_unexpected"
            )
            result = {"ok": False, "error_code": error_code}
            _, sqlite_name = _session_storage_details(exc)
            logger.warning(
                "[SessionRefresh] 会话刷新收尾异常：account_id=%s stage=worker_finalize "
                "reason=%s error_type=%s sqlite_errorname=%s",
                account_id, error_code, type(exc).__name__, sqlite_name,
            )
            try:
                _session_storage_write(
                    account_id, "failure_recovery", db.finish_account_session_refresh,
                    account_id, ok=False, error=error_code,
                    message="会话结果保存失败，请重试" if error_code == "session_refresh_storage_error"
                    else "会话刷新失败，请查看服务日志",
                )
            except Exception as persist_exc:
                logger.warning(
                    "[SessionRefresh] 失败状态未保存：account_id=%s stage=failure_recovery "
                    "reason=session_refresh_failure_state_not_saved error_type=%s sqlite_errorname=%s",
                    account_id, type(persist_exc).__name__, _session_storage_details(persist_exc)[1],
                )
            return result
        finally:
            try:
                hme_scope.close(result)
            except Exception as cleanup_exc:
                logger.warning(
                    "[SessionRefresh] 认证上下文清理失败：account_id=%s "
                    "reason=session_refresh_cleanup_failed error_type=%s",
                    account_id, type(cleanup_exc).__name__,
                )
            if action_run_id and action_target_key:
                try:
                    action_progress.update_target(
                        action_run_id,
                        action_target_key,
                        "succeeded" if result.get("ok") else "failed",
                        return_snapshot=False,
                        error_code=(
                            None
                            if result.get("ok")
                            else result.get("error_code") or "session_refresh_failed"
                        ),
                    )
                except Exception:
                    logger.warning(
                        "[SessionRefresh] 批次进度终态更新失败："
                        "account_id=%s reason=action_progress_update_failed",
                        account_id,
                    )
            logger.info(
                "[SessionRefresh] 会话刷新任务结束：account_id=%s",
                account_id,
            )


def _stored_account_unusable_code(account: dict | None) -> str:
    if not isinstance(account, dict):
        return ""
    code = detect_account_unusable_text(
        str(account.get("account_unusable_code") or "")
    )
    if code:
        return code
    if str(account.get("codex_status") or "").strip().lower() != "deactivated":
        return ""
    return (
        detect_account_unusable_text(str(account.get("session_refresh_error") or ""))
        or detect_account_unusable_text(str(account.get("codex_error") or ""))
        or "account_deactivated"
    )


def enqueue_account_session_refresh(
    account_id: int,
    *,
    headless: bool | None = None,
    allow_manual_login: bool = True,
    force_relogin: bool = False,
    registration_route_hint=None,
    executor: ThreadPoolExecutor | None = None,
    trigger: str = "manual",
    action_run_id: str | None = None,
    action_target_key: str | None = None,
    wait_for_queue_slot: bool = False,
    on_complete=None,
) -> dict:
    account_id = int(account_id)
    account = db.get_account(account_id)
    if not account:
        return {
            "accepted": False,
            "busy": False,
            "error_code": "account_missing",
            "error": "账号不存在",
        }
    initial_terminal_code = _stored_account_unusable_code(account)
    if initial_terminal_code:
        error_code = initial_terminal_code
        message = f"账号已废（{error_code}），无需刷新会话"
        db.finish_account_session_refresh_unusable(
            account_id,
            error_code=error_code,
            message=message,
        )
        return {
            "accepted": False,
            "busy": False,
            "skipped": True,
            "error_code": error_code,
            "error": "账号已废，无需刷新会话",
        }
    if not _QUEUE_SLOTS.acquire(blocking=bool(wait_for_queue_slot)):
        return {
            "accepted": False,
            "busy": False,
            "error_code": "session_refresh_queue_full",
            "error": "会话刷新队列已满",
        }
    try:
        claimed = db.claim_account_session_refresh(account_id, trigger=trigger)
    except Exception as exc:
        _QUEUE_SLOTS.release()
        _, sqlite_name = _session_storage_details(exc)
        logger.warning(
            "[SessionRefresh] 账号认领失败：account_id=%s stage=claim "
            "error_type=%s sqlite_errorname=%s",
            account_id, type(exc).__name__, sqlite_name,
        )
        raise
    if not claimed:
        _QUEUE_SLOTS.release()
        latest = db.get_account(account_id)
        try:
            window_active = bool(db.account_roxy_window_is_active(account_id))
        except Exception:
            window_active = False
        if window_active:
            return {
                "accepted": False,
                "busy": True,
                "error_code": "roxy_window_active",
                "error": "该账号的人工 Roxy 窗口仍在使用",
            }
        latest_terminal_code = _stored_account_unusable_code(latest)
        if latest_terminal_code:
            error_code = latest_terminal_code
            db.finish_account_session_refresh_unusable(
                account_id,
                error_code=error_code,
                message=f"账号已废（{error_code}），无需刷新会话",
            )
            return {
                "accepted": False,
                "busy": False,
                "skipped": True,
                "error_code": error_code,
                "error": "账号已废，无需刷新会话",
            }
        return {
            "accepted": False,
            "busy": True,
            "error_code": "session_refresh_busy",
            "error": "该账号正在刷新会话",
        }
    submission = AccountTaskSubmission(
        account_id=account_id, kind='session_refresh', slots=_QUEUE_SLOTS,
        operation_log=account_operation_log, progress=action_progress, logger=logger,
        trigger=trigger, run_id=action_run_id, target_key=action_target_key,
    )
    submission.begin()
    try:
        task_kwargs = {
            "headless": headless,
            "allow_manual_login": allow_manual_login,
        }
        if force_relogin:
            task_kwargs["force_relogin"] = True
        from core.registration_login_route import AUTO_TRIGGER
        if trigger == AUTO_TRIGGER:
            task_kwargs.update(registration_route_hint=registration_route_hint, registration_auto_verification=True)
        if action_run_id and action_target_key:
            task_kwargs.update(
                {
                    "action_run_id": action_run_id,
                    "action_target_key": action_target_key,
                }
            )
        selected_executor = executor or _AUTOMATIC_EXECUTOR
        future = selected_executor.submit(
            _run_refresh_task,
            account_id,
            **task_kwargs,
        )
    except Exception:
        submission.rollback()
        db.finish_account_session_refresh(
            account_id,
            ok=False,
            error="session_refresh_enqueue_failed",
            message="会话刷新入队失败",
        )
        submission.update_progress("failed", error_code="session_refresh_enqueue_failed")
        return {
            "accepted": False,
            "busy": False,
            "error_code": "session_refresh_enqueue_failed",
            "error": "会话刷新入队失败",
        }
    # Submission succeeded: ownership now belongs to the worker/cancel handler.
    def cancelled():
        try:
            db.finish_account_session_refresh(
                account_id, ok=False, error="session_refresh_enqueue_failed",
                message="会话刷新任务已取消")
        finally:
            if trigger == AUTO_TRIGGER:
                from core.registration_login_route import finish
                finish(registration_route_hint)
    submission.watch_cancellation(future, cancelled)
    if on_complete is not None:
        def completed(task):
            try:
                result = task.result()
            except Exception:
                result = {'ok': False, 'error_code': 'session_refresh_enqueue_failed'}
            try:
                on_complete(result)
            except Exception:
                logger.warning('会话刷新完成回调失败：account_id=%s', account_id)
        future.add_done_callback(completed)
    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "status": "queued",
    }


def _update_bulk_target(
    run_id: str,
    target_key: str,
    state: str,
    error_code: str,
) -> None:
    """Best-effort safe progress update for the large-batch feeder."""

    try:
        action_progress.update_target(
            run_id,
            target_key,
            state,
            error_code=error_code,
            return_snapshot=False,
        )
    except Exception:
        logger.warning(
            "[SessionRefresh] 批量分发进度更新失败：account_ref=%s "
            "reason=action_progress_update_failed",
            target_key,
        )


def _bulk_run_is_active(run_id: str) -> bool:
    """Stop feeding when the owning action was interrupted or completed."""

    try:
        state = action_progress.get_run_state(run_id)
    except Exception:
        raise RuntimeError("session_refresh_action_state_unavailable")
    return str(state or "").lower() in {
        "preparing",
        "running",
    }


def _dispatch_account_session_refreshes(*, selection, action_run_id, force_relogin=False) -> None:
    """Dispatch a fixed selection through the shared bounded-queue feeder."""
    logger.info("批量账号分发开始 kind=session_refresh count=%s", len(selection))
    from core.task_concurrency import current_budget
    budget = current_budget()
    if budget is not None:
        logger.info("[SessionRefresh] 批次固定并发：run_id=%s requested=%s effective=%s limit=%s",
                    action_run_id, budget.requested, budget.workers, operation_limit("session_refresh", budget.values))

    def update_target(key, state, code):
        _update_bulk_target(action_run_id, key, state, code)
        if state != "failed" or not str(key).isdigit():
            return
        try:
            _session_storage_write(
                int(key), "dispatch_failure", db.mark_account_session_refresh_dispatch_failed,
                int(key), failed_at=now_iso(), error_code=code,
            )
        except Exception as exc:
            logger.warning("[SessionRefresh] 分发失败标记未保存：account_id=%s error_type=%s",
                           key, type(exc).__name__)

    def enqueue(account_id, target_key):
        return enqueue_account_session_refresh(
            account_id, headless=None, allow_manual_login=False, trigger="manual_bulk",
            action_run_id=action_run_id, action_target_key=target_key, wait_for_queue_slot=True,
            **({"force_relogin": True} if force_relogin else {}),
        )

    counts = dispatch_account_targets(
        selection=selection, enqueue=enqueue,
        update_target=update_target,
        enqueue_error="session_refresh_enqueue_failed", dispatch_error="session_refresh_dispatch_failed",
        skipped_codes={"account_missing", "account_deactivated", "account_deleted", "account_banned", "account_closed"}, logger=logger,
        is_active=lambda: _bulk_run_is_active(action_run_id),
    )
    if counts is not None:
        logger.info("批量账号分发结束 kind=session_refresh total=%s accepted=%s skipped=%s failed=%s",
                    len(selection), counts["accepted"], counts["skipped"], counts["failed"])


def submit_account_session_refresh_bulk(
    *,
    selection: list[tuple[str, int | None]],
    action_run_id: str,
    force_relogin: bool = False,
) -> dict:
    """Start a bounded feeder for a cross-page session-refresh selection."""

    normalized = tuple(
        (
            str(target_key),
            int(account_id) if account_id is not None else None,
        )
        for target_key, account_id in selection
    )
    if not normalized or len(normalized) > _BULK_LIMIT:
        return {
            "accepted": False,
            "error_code": "session_refresh_limit_exceeded",
        }
    try:
        future = _BULK_DISPATCHER.submit(
            _dispatch_account_session_refreshes,
            selection=normalized,
            action_run_id=str(action_run_id),
            **({"force_relogin": True} if force_relogin else {}),
        )
    except Exception:
        return {
            "accepted": False,
            "error_code": "session_refresh_dispatch_failed",
        }

    with _BULK_FUTURES_LOCK:
        _BULK_FUTURES.add(future)

    def finish_dispatch(done_future) -> None:
        with _BULK_FUTURES_LOCK:
            _BULK_FUTURES.discard(done_future)
        try:
            failed_dispatch = (
                bool(done_future.cancelled())
                or done_future.exception() is not None
            )
        except Exception:
            failed_dispatch = True
        if not failed_dispatch:
            return
        try:
            action_progress.fail_run(
                action_run_id,
                "session_refresh_dispatch_failed",
            )
        except Exception:
            logger.error(
                "[SessionRefresh] 批量分发失败状态回写失败："
                "reason=session_refresh_dispatch_recovery_failed"
            )

    add_done_callback = getattr(future, "add_done_callback", None)
    if callable(add_done_callback):
        add_done_callback(finish_dispatch)
    return {
        "accepted": True,
        "scheduled_count": len(normalized),
    }


def queue_settings() -> dict:
    gate_snapshot = getattr(_ROXY_BROWSER_SLOTS, "snapshot", lambda: {})()
    if not isinstance(gate_snapshot, dict):
        gate_snapshot = {}
    with _BULK_FUTURES_LOCK:
        bulk_dispatchers = len(_BULK_FUTURES)
    return {
        "workers": operation_limit("session_refresh"),
        "default_workers": _SESSION_REFRESH_DEFAULT_WORKERS,
        "configured_workers": int(
            gate_snapshot.get("configured", _SESSION_REFRESH_DEFAULT_WORKERS)
        ),
        "active_workers": int(gate_snapshot.get("active", 0)),
        "interactive_workers": int(
            gate_snapshot.get("configured", _SESSION_REFRESH_DEFAULT_WORKERS)
        ),
        "queue_limit": _QUEUE_SLOTS.capacity() if isinstance(_QUEUE_SLOTS, QueueSlots) else 50,
        "bulk_limit": _BULK_LIMIT,
        "bulk_dispatchers": bulk_dispatchers,
        "manual_login_timeout": _MANUAL_LOGIN_TIMEOUT,
    }
''')

def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
