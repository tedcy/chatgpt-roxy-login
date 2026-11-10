"""Shared existing-account Roxy authentication candidate implementation.

Loaded into :mod:`core.chatgpt_session_refresh` globals to preserve public
names and test seams while keeping the implementation outside refresh business
logic.
"""
from __future__ import annotations
from textwrap import dedent

_SOURCE = dedent(r'''
def _acquire_roxy_resource(
    resource,
    *,
    stop_event: threading.Event | None,
    timeout: float = 60.0,
) -> bool:
    """Acquire a browser gate/lock while remaining responsive to cancellation."""

    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        if stop_event is not None and stop_event.is_set():
            raise ChatGPTSessionRefreshError(
                "session_window_close_requested",
                "��¼������ֹͣ",
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        wait_for = min(0.25, remaining)
        try:
            acquired = resource.acquire(timeout=wait_for)
        except TypeError:
            acquired = resource.acquire(True, wait_for)
        if acquired:
            return True


def _acquire_profile_operation_lock(
    lock,
    *,
    stop_event: threading.Event | None,
) -> None:
    """Serialize Roxy management calls without serializing login workers."""

    while True:
        if stop_event is not None and stop_event.is_set():
            raise ChatGPTSessionRefreshError(
                "session_window_close_requested",
                "��¼������ֹͣ",
            )
        try:
            acquired = lock.acquire(timeout=0.25)
        except TypeError:
            acquired = lock.acquire(True, 0.25)
        if acquired:
            return


def _read_browser_me_once(
    driver,
    *,
    access_token: str,
    account_id: str,
) -> tuple[int, dict]:
    """Read a credential-safe `/backend-api/me` result from the logged-in page."""

    try:
        result = driver.execute_async_script(
            """
            const token = arguments[0];
            const accountId = arguments[1];
            const done = arguments[2];
            const headers = {accept: 'application/json', authorization: `Bearer ${token}`};
            if (accountId) headers['chatgpt-account-id'] = accountId;
            fetch('/backend-api/me', {
              credentials: 'include',
              cache: 'no-store',
              headers,
            }).then(async response => {
              let data = null;
              try { data = await response.json(); } catch (_) {}
              done({status: response.status, data});
            }).catch(() => done({status: 0, data: null}));
            """,
            str(access_token or ""),
            str(account_id or ""),
        ) or {}
    except Exception as exc:
        raise ChatGPTSessionRefreshError(
            "session_login_liveness_failed",
            "��¼��ɵ��˺����ʧ��",
        ) from exc
    try:
        status = int(result.get("status") or 0)
    except (TypeError, ValueError, OverflowError):
        status = 0
    payload = result.get("data") if isinstance(result, dict) else None
    return status, payload if isinstance(payload, dict) else {}


def _build_roxy_login_candidate(
    account: dict,
    *,
    login_email: str,
    driver,
    session_info: dict,
) -> RoxyLoginCandidate:
    account_id = int(account.get("id") or 0)
    expected_email = str(login_email or "").strip().lower()
    expected_old_token = normalize_token(account.get("access_token") or "")
    new_token = normalize_token((session_info or {}).get("accessToken") or "")
    if account_id <= 0 or not expected_email or not expected_old_token or not new_token:
        raise ChatGPTSessionRefreshError(
            "session_refresh_empty",
            "��¼��ɵ�δȡ����Ч����",
        )
    expected = dict(account)
    expected["_diagnostic_old_email"] = account.get("email")
    expected["email"] = expected_email
    validate_session_identity(expected, session_info, new_token)
    if token_claims(new_token).get("token_expired") is True:
        raise ChatGPTSessionRefreshError(
            "token_expired",
            "��¼���ɵ� access token �ѹ���",
        )
    if new_token == expected_old_token:
        raise ChatGPTSessionRefreshError(
            "session_exchange_no_rotation",
            "��¼δ�����µ� access token",
        )

    expected_account_id = str(account.get("account_id") or "").strip()
    from core.email_change_identity_retry import read_target_identity
    from core.email_change_session_evidence import observed_me_reader
    identity_retry_kwargs = {}
    if bool(account.get("_email_change_target_login")):
        # A successful target login can briefly expose the pre-change email
        # through /backend-api/me while the account identity converges.  Give
        # this explicitly marked email-change flow a bounded extra window;
        # ordinary maintenance/session refresh keeps the shorter historical
        # probe.
        identity_retry_kwargs = {
            "max_attempts": 5,
            "retry_delays": (2, 5, 10, 20),
        }
        if account.get("_email_change_single_target_attempt") is True:
            identity_retry_kwargs = {"max_attempts": 1, "retry_delays": ()}
    me_status, remote = read_target_identity(
        account,
        target=expected_email,
        read_once=observed_me_reader(
            account,
            target=expected_email,
            session_info=session_info,
            token=new_token,
            driver=driver,
            read_once=lambda: _read_browser_me_once(
                driver, access_token=new_token, account_id=expected_account_id,
            ),
        ),
        **identity_retry_kwargs,
    )
    if me_status != 200:
        from core.session_identity_diagnostic import identity_failure
        identity_failure(expected, source="backend_me", code="session_login_liveness_failed", remote=remote, http_status=me_status)
        raise ChatGPTSessionRefreshError(
            "session_login_liveness_failed",
            "��¼��ɵ��˺����ʧ��",
        )
    remote_email = str(remote.get("email") or "").strip().lower()
    remote_user_id = str(remote.get("id") or "").strip()
    expected_user_id = str(account.get("user_id") or "").strip()
    if remote_email != expected_email:
        from core.session_identity_diagnostic import identity_failure
        identity_failure(expected, source="backend_me", code="session_identity_email_mismatch", remote=remote, http_status=me_status)
        error = ChatGPTSessionRefreshError(
            "session_identity_email_mismatch",
            "��¼�õ���������Ŀ�����䲻һ��",
        )
        setattr(
            error,
            "identity_relation",
            "old_email" if remote_email == str(account.get("_diagnostic_old_email") or "").strip().lower()
            else "other_email" if remote_email else "missing_email",
        )
        setattr(error, "remote_user_matches", bool(
            remote_user_id and expected_user_id and remote_user_id == expected_user_id
        ))
        claims = token_claims(new_token)
        setattr(error, "remote_account_matches", bool(
            expected_account_id and claims.get("account_id") == expected_account_id
        ))
        raise error
    if not remote_user_id or (expected_user_id and remote_user_id != expected_user_id):
        from core.session_identity_diagnostic import identity_failure
        identity_failure(expected, source="backend_me", code="session_identity_user_mismatch", remote=remote, http_status=me_status)
        raise ChatGPTSessionRefreshError(
            "session_identity_user_mismatch",
            "��¼�õ����û�������ԭ�˺Ų�һ��",
        )

    evidence = getattr(session_info, 'login_evidence', None)
    if getattr(evidence, 'totp_verified', False) and account.get('totp_secret'):
        db.confirm_account_totp(account_id, secret=account['totp_secret'], source='totp_challenge',
                                expected_identity_revision=db._account_twofa_identity_revision(account))
    try:
        snapshot = capture_driver_snapshot(
            driver,
            email=expected_email,
            account_id=account_id,
            session_info=session_info,
        )
    except ChatGPTSessionStoreError as exc:
        raise ChatGPTSessionRefreshError(
            exc.error_code,
            "��¼��ɵ� Session Cookie ����ʧ��",
        ) from exc
    snapshot["email"] = expected_email
    return RoxyLoginCandidate(
        account_id=account_id,
        login_email=expected_email,
        old_token_fingerprint=_token_fingerprint(expected_old_token),
        new_token_fingerprint=_token_fingerprint(new_token),
        session_rotated=True,
        access_token=new_token,
        expected_old_token=expected_old_token,
        session_info=dict(session_info or {}),
        snapshot=snapshot,
    )


def _configured_headed_login_on_roxy_profile(
    account: dict,
    *,
    opened,
    driver,
    login_email: str,
    stop_event: threading.Event | None,
    stage_callback: Callable[[str], None] | None,
    defer_email_otp_context: bool = False,
    mailbox_access: bool = True,
) -> dict | None:
    """Run the low-traffic headed auth kernel when the Roxy switch is on.

    ``None`` means the compatibility Selenium kernel should be used.  Once the
    headed path is selected, its capability/transport failure is propagated;
    silently falling back would create a second auth protocol and can submit
    credentials twice.
    """

    from config import roxybrowser as roxy_cfg

    if not bool(getattr(roxy_cfg, "ROXY_REGISTRATION_LOW_TRAFFIC_MODE", False)):
        return None
    from core.roxy_headed_registration import run_roxy_headed_login_on_profile

    login_account = dict(account or {})
    login_account["email"] = str(login_email or "").strip().lower()
    try:
        password = _registration_password(login_account)
    except Exception:
        password = ""
    secret = str(login_account.get("totp_secret") or "").strip()
    headed_kwargs = {
        "task_country": "US",
        "account": login_account,
        "opened": opened,
        "driver": driver,
        "saved_openai_password": password,
        "mfa_totp_secret": secret,
        "otp_only": False,
        "stop_check": (stop_event.is_set if stop_event is not None else None),
        "stage_callback": stage_callback,
        "mailbox_access": bool(mailbox_access),
    }
    if defer_email_otp_context:
        headed_kwargs["defer_email_otp_context"] = True
    return run_roxy_headed_login_on_profile(**headed_kwargs)


@contextmanager
def roxy_login_candidate_context(
    account: dict,
    *,
    login_email: str | None = None,
    headless: bool | None = None,
    proxy_country: str | None = None,
    registration_route_hint=None,
    allow_manual_login: bool = True,
    stop_event: threading.Event | None = None,
    task_kind: str = "session_refresh",
    stage_callback: Callable[[str], None] | None = None,
    slot_already_acquired: bool = False,
    excluded_profile_ids: set[str] | frozenset[str] | None = None,
    restore_saved_session: bool = False,
    allow_headed_auth: bool = True,
    operation_only: bool = False,
    defer_auth: bool = False,
    login_function: Callable[..., dict] | None = None,
    reset_profile_identity: bool = True,
    defer_email_otp_context: bool = False,
    mailbox_access: bool | None = None,
    strict_password: bool = False,
    profile_operation_lock=None,
) -> Iterator[tuple[RoxyLoginCandidate | None, object]]:
    """Yield one strict, uncommitted Roxy login candidate and its live driver."""

    from core.operation_country import maintenance_country
    if registration_route_hint is not None:
        from core.registration_login_route import selection
        proxy_country = selection(registration_route_hint).expected_country
    else:
        proxy_country = maintenance_country(proxy_country)

    from config import roxybrowser as roxy_cfg
    from core.roxy_registration import (
        RoxyIdentityResetError,
        _build_driver,
        _center_browser_window,
        _reset_pooled_profile_identity,
    )
    from core.roxybrowser_client import RoxyBrowserClient

    account_id = int(account.get("id") or 0)
    actual_email = str(login_email or account.get("email") or "").strip().lower()
    if account_id <= 0 or not actual_email:
        raise ChatGPTSessionRefreshError("account_missing", "�˺����ݲ�����")
    try:
        from core.auth_factors import resolve_login_policy

        login_policy = resolve_login_policy(account)
    except Exception:
        login_policy = None
    if login_policy is not None and login_policy.password_totp:
        # A permissive legacy keyword must not reopen mailbox access for a
        # strict account.  This function is a public compatibility entry and
        # can be called without the neutral auth facade.
        mailbox_access = False
    else:
        mailbox_access = login_policy.mailbox_access if login_policy is not None else True
    mailbox_access = bool(mailbox_access)
    if not mailbox_access:
        # This is a policy boundary, not a best-effort optimization: a
        # password+TOTP account must fail closed if the server asks for email.
        defer_email_otp_context = True
        strict_password = True
    effective_headless = _effective_headless(headless)
    effective_manual_login = bool(allow_manual_login) and not effective_headless
    slot_acquired = False
    client = None
    opened = None
    driver = None
    contract_tracer = None
    dom_recorder = None
    dom_terminal_status = ""
    dom_error_code = ""
    dom_source_error_type = ""
    browser_ready = False
    profile_operation_lock_acquired = False

    def publish(stage: str) -> None:
        if stage_callback is not None:
            stage_callback(str(stage or "login"))
        if dom_recorder is not None and driver is not None:
            try:
                dom_recorder.observe(
                    driver,
                    stage=str(stage or "login"),
                    event="stage_change",
                )
            except Exception:
                pass

    try:
        publish("waiting")
        if not slot_already_acquired:
            if not _acquire_roxy_resource(
                _ROXY_BROWSER_SLOTS,
                stop_event=stop_event,
            ):
                raise ChatGPTSessionRefreshError(
                    "session_roxy_slot_unavailable",
                    "Roxy ��¼���з�æ�����Ժ�����",
                )
            slot_acquired = True
        if stop_event is not None and stop_event.is_set():
            raise ChatGPTSessionRefreshError(
                "session_window_close_requested",
                "��¼������ֹͣ",
            )
        publish("login")
        logger.info(
            "[SessionRefresh][Roxy] ��¼��ѡ������account_id=%s task=%s headless=%s manual_wait=%s",
            account_id,
            str(task_kind or "unknown")[:48],
            str(effective_headless).lower(),
            str(effective_manual_login).lower(),
        )
        client = RoxyBrowserClient()
        open_kwargs = {"headless": effective_headless}
        if registration_route_hint is not None:
            open_kwargs["task_proxy"] = registration_route_hint.proxy_url
        if proxy_country:
            # Callers that need a country-pinned Sticky SID pass this
            # explicitly; the default remains the historical selection used
            # by registration and session-refresh callers.
            open_kwargs["proxy_country"] = str(proxy_country).strip().upper()
        if excluded_profile_ids:
            open_kwargs["excluded_profile_ids"] = {
                str(value or "").strip()
                for value in excluded_profile_ids
                if str(value or "").strip()
            }
        if profile_operation_lock is not None:
            _acquire_profile_operation_lock(
                profile_operation_lock,
                stop_event=stop_event,
            )
            profile_operation_lock_acquired = True
        try:
            opened = client.open_profile(**open_kwargs)
        finally:
            if profile_operation_lock_acquired:
                profile_operation_lock.release()
                profile_operation_lock_acquired = False
        driver = _build_driver(opened)
        try:
            setattr(driver, "_turb_roxy_account_id", account_id)
            setattr(driver, "_turb_roxy_task_kind", task_kind)
            from core.roxy_otp_observer import ensure_observer

            ensure_observer(
                driver,
                task_kind=task_kind,
                account_id=account_id,
            )
        except Exception:
            pass
        # Keep the in-memory Roxy route available to narrowly-scoped callers
        # that intentionally retain this context (currently only 2FA
        # re-auth).  The object is never serialized or logged.
        try:
            setattr(driver, "_turb_roxy_opened", opened)
        except Exception:
            pass
        try:
            from core.roxy_dom_failure_diagnostic import attach_recorder

            dom_recorder = attach_recorder(
                driver,
                task_kind=task_kind,
                account_id=account_id,
            )
        except Exception:
            dom_recorder = None
        _center_browser_window(driver, headless=effective_headless)
        driver.set_page_load_timeout(
            int(getattr(roxy_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)
        )
        if reset_profile_identity:
            try:
                _reset_pooled_profile_identity(driver)
            except RoxyIdentityResetError:
                if bool(getattr(opened, "pooled", False)):
                    opened.profile_cache_discard = True
                raise ChatGPTSessionRefreshError(
                    "session_identity_cleanup_failed",
                    "Roxy ������������ʧ�ܣ���ֹͣ��¼",
                ) from None
        browser_ready = True

        try:
            def persist_account_unusable(code: str, _metadata: dict) -> None:
                setattr(driver, "_turb_account_unusable_code", code)
                db.mark_account_unusable(
                    acc_id=account_id,
                    error_code=code,
                    evidence_source="cdp_email_otp_validate",
                )

            contract_tracer = RoxyChatGPTContractTracer(
                driver,
                debugger_address=getattr(opened, "debugger_address", None),
                task_kind=task_kind,
                account_id=account_id,
                old_access_token=str(account.get("access_token") or ""),
                account_unusable_callback=persist_account_unusable,
                verify_credentials=account.get("login_verification_pending") is True,
            )
            if str(task_kind or "").startswith("twofa_password"):
                trace_stage = "twofa_password"
            elif task_kind == "session_refresh":
                trace_stage = "session_refresh_login"
            else:
                trace_stage = "email_change_login"
            contract_tracer.set_stage(trace_stage)
            contract_tracer.start()
        except Exception:
            contract_tracer = None
            logger.warning(
                "[SessionRefresh][Roxy] ��¼��ѡ��̬�۲�����ʧ�ܣ�account_id=%s reason=account_terminal_observer_start_unexpected",
                account_id,
            )

        # A maintenance caller may need to hold a fresh Profile while it
        # injects a saved Session itself.  Yield the live Driver before any
        # login attempt so a rejected saved cookie can be followed by an
        # in-place re-login without closing this context and allocating a
        # second Profile.  Normal candidates never set this internal flag.
        if defer_auth:
            yield None, driver
            return

        login_account = dict(account)
        login_account["email"] = actual_email
        login_kwargs = {
            "allow_manual_wait": effective_manual_login,
        }
        if login_function is not None:
            login_kwargs["login_function"] = login_function
        if stop_event is not None:
            login_kwargs["stop_event"] = stop_event
        if stage_callback is not None:
            login_kwargs["on_manual_wait"] = lambda: publish("waiting_user")
        if defer_email_otp_context:
            login_kwargs["defer_email_otp_context"] = True
        session_info = None
        if allow_headed_auth:
            session_info = _configured_headed_login_on_roxy_profile(
                account,
                opened=opened,
                driver=driver,
                login_email=actual_email,
                stop_event=stop_event,
                stage_callback=stage_callback,
                defer_email_otp_context=defer_email_otp_context,
                mailbox_access=mailbox_access,
            )
        if session_info is None:
            # A saved Session is injected only after the pooled identity has
            # been cleared above.  If the browser probe rejects that saved
            # record, clear the just-injected cookies before entering the
            # real email/password login path.  Otherwise the stale
            # NextAuth cookie can keep publishing a misleading
            # ``/api/auth/session`` token and the login kernel may never
            # render the actual credential form.  The callback is invoked
            # only on a restore miss; a successful restore leaves the live
            # browser untouched.
            restore_reset = None
            if restore_saved_session:
                restore_reset = lambda: _reset_pooled_profile_identity(driver)
            session_info = ensure_roxy_session_on_driver(
                driver,
                login_account,
                account_id=account_id,
                restore_saved_session=bool(restore_saved_session),
                reset_identity=restore_reset,
                **login_kwargs,
                mailbox_access=mailbox_access,
                strict_password=bool(strict_password),
            )
        elif allow_headed_auth and not operation_only:
            # The headed worker owns a Playwright page in the same Roxy
            # Context.  Re-anchor Selenium on ChatGPT before the strict
            # /backend-api/me and Cookie snapshot checks run.
            from core.roxy_registration import _safe_get

            _safe_get(
                driver,
                "https://chatgpt.com/",
                timeout=45,
                attempts=2,
                accept_hosts=("chatgpt.com", "auth.openai.com"),
            )
        if contract_tracer is not None:
            contract_tracer.observe_session_info(
                session_info,
                source="session_refresh_result"
                if task_kind == "session_refresh"
                else "email_change_login_result",
            )
        if operation_only:
            # Maintenance operations need a live authenticated Driver but do
            # not rotate the access token.  The normal candidate contract
            # intentionally rejects an unchanged restored token.
            yield None, driver
        else:
            candidate = _build_roxy_login_candidate(
                account,
                login_email=actual_email,
                driver=driver,
                session_info=session_info,
            )
            yield candidate, driver
    except ChatGPTSessionRefreshError as exc:
        if exc.error_code != "session_window_close_requested":
            dom_terminal_status = "failed"
            dom_error_code = exc.error_code
            dom_source_error_type = type(exc).__name__
        # Internal callers may safely exclude the failed Profile on a bounded
        # retry.  Keep this identifier process-local: it is never serialized,
        # logged, or returned by a public API.
        if opened is not None:
            profile_id = str(getattr(opened, "profile_id", "") or "").strip()
            if profile_id:
                setattr(exc, "roxy_profile_id", profile_id)
        raise
    except AccountUnusableError as exc:
        if not (stop_event is not None and stop_event.is_set()):
            dom_terminal_status = "deactivated"
            dom_error_code = "session_account_unusable"
            dom_source_error_type = type(exc).__name__
        raise
    except Exception as exc:
        if stop_event is not None and stop_event.is_set():
            raise ChatGPTSessionRefreshError(
                "session_window_close_requested",
                "��¼������ֹͣ",
            ) from exc
        provider_code = str(getattr(exc, "error_code", "") or "").strip().lower()
        # Password-maintenance browser helpers use fixed twofa_* codes to
        # distinguish a re-auth failure, an add failure and a post-submit
        # verification timeout.  Preserve those codes across this shared
        # candidate context instead of collapsing every error into the
        # generic session_roxy_login_failed result.  This also lets the
        # account-level service retain the correct diagnostic stage.
        if provider_code in {
            "twofa_stopped",
            "twofa_password_reauth_failed",
            "twofa_password_add_failed",
            "twofa_password_already_set_unknown",
            "twofa_password_verify_failed",
        }:
            dom_terminal_status = "failed"
            dom_error_code = provider_code
            dom_source_error_type = type(exc).__name__
            raise ChatGPTSessionRefreshError(
                provider_code,
                "��¼��������δ���",
            ) from exc
        if provider_code in {
            "session_login_totp_secret_missing",
            "session_login_totp_secret_invalid",
            "session_login_totp_failed",
        }:
            dom_terminal_status = "failed"
            dom_error_code = provider_code
            dom_source_error_type = type(exc).__name__
            raise ChatGPTSessionRefreshError(
                provider_code,
                "��֤�� MFA �Զ���¼δ���",
            ) from exc
        if provider_code == "otp_timeout":
            dom_terminal_status = "failed"
            dom_error_code = "session_login_otp_timeout"
            dom_source_error_type = type(exc).__name__
            raise ChatGPTSessionRefreshError(
                "session_login_otp_timeout",
                "�ȴ���¼������֤�볬ʱ",
            ) from exc
        if provider_code in {
            "mailbox_otp_unavailable",
            "mailbox_unavailable",
        }:
            dom_terminal_status = "failed"
            dom_error_code = "session_login_mailbox_unavailable"
            dom_source_error_type = type(exc).__name__
            raise ChatGPTSessionRefreshError(
                "session_login_mailbox_unavailable",
                "��¼������ʱ�޷�������֤��",
            ) from exc
        dom_terminal_status = "failed"
        dom_error_code = (
            provider_code
            if provider_code.startswith(("session_", "twofa_", "email_change_"))
            else "session_roxy_login_failed" if browser_ready else "session_roxy_profile_failed"
        )
        dom_source_error_type = type(exc).__name__
        raise ChatGPTSessionRefreshError(
            "session_roxy_login_failed" if browser_ready else "session_roxy_profile_failed",
            "Roxy ��¼δ���" if browser_ready else "Roxy Profile ����ʧ��",
        ) from exc
    finally:
        if dom_recorder is not None and dom_terminal_status:
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
        if contract_tracer is not None:
            try:
                contract_tracer.stop()
            except Exception:
                logger.warning(
                    "[SessionRefresh][Roxy] ��¼��ѡ��̬�۲�ֹͣʧ�ܣ�account_id=%s reason=trace_stop_unexpected",
                    account_id,
                )
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        if opened is not None and client is not None:
            try:
                if profile_operation_lock is not None:
                    _acquire_profile_operation_lock(
                        profile_operation_lock,
                        stop_event=None,
                    )
                    try:
                        _cleanup_refresh_profile(client, opened)
                    finally:
                        profile_operation_lock.release()
                else:
                    _cleanup_refresh_profile(client, opened)
            except Exception:
                logger.warning(
                    "[SessionRefresh][Roxy] ��¼��ѡ Profile ����ʧ�ܣ�account_id=%s reason=profile_cleanup_unexpected",
                    account_id,
                )
        if slot_acquired:
            _ROXY_BROWSER_SLOTS.release()


class RoxyLoginCandidateLease:
    """Own a candidate context until the caller explicitly closes it.

    The normal helper deliberately closes the Profile as soon as it returns.
    A few maintenance flows (currently historical-account 2FA) need the
    browser that just passed Cloudflare to remain alive for a short follow-up
    request.  Keeping ownership here avoids changing the normal helper's
    lifecycle or return contract.
    """

    def __init__(self, manager, candidate, driver, *, account=None, stop_event=None):
        self._manager = manager
        self.candidate = candidate
        self.driver = driver
        self.account = dict(account or {})
        self.stop_event = stop_event
        self.opened = getattr(driver, "_turb_roxy_opened", None)
        # ``profile`` is an intentionally private alias used by callers that
        # need to keep the leased Profile alive.  It contains no serialized
        # credentials and is cleared only when the lease itself is released.
        self.profile = self.opened
        self._closed = False
        self._relogin_lock = threading.RLock()
        self.relogin_count = 0
        self.last_session_info = dict(
            getattr(candidate, "session_info", None) or {}
        )
        self.last_snapshot = dict(
            getattr(candidate, "snapshot", None) or {}
        )

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.close()
        return False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        manager = self._manager
        self._manager = None
        if manager is not None:
            try:
                manager.__exit__(None, None, None)
            except Exception:
                pass

    @property
    def closed(self) -> bool:
        return bool(self._closed)

    def relogin_in_place(
        self,
        account: dict | None = None,
        *,
        account_id: int | None = None,
        task_kind: str = "session_refresh",
        allow_manual_login: bool = False,
        restore_saved_session: bool = False,
        login_function: Callable[..., dict] | None = None,
        stage_callback: Callable[[str], None] | None = None,
    ) -> dict:
        """Re-authenticate on this lease without opening another Profile.

        The context manager behind a lease remains suspended at its yield, so
        its Driver, Profile, proxy and concurrency slot stay owned by the
        caller.  Only identity data is cleared; Chromium's HTTP cache and the
        original Sticky SID are retained.  A verified candidate is refreshed
        in memory for callers that need to persist the rotated Session.
        """

        with self._relogin_lock:
            if self._closed or self._manager is None:
                raise ChatGPTSessionRefreshError(
                    "session_roxy_relogin_failed",
                    "Roxy ��¼�����ѹر�",
                )
            driver = self.driver
            try:
                handles = getattr(driver, "window_handles", None)
                if handles is not None:
                    try:
                        handles = list(handles or [])
                    except TypeError:
                        # Lightweight test/remote adapters may expose a
                        # truthy sentinel rather than an iterable handle
                        # collection; only an explicit empty collection means
                        # that the browser is closed.
                        handles = None
                    if handles is not None and not handles:
                        raise RuntimeError("driver_window_closed")
            except ChatGPTSessionRefreshError:
                raise
            except Exception as exc:
                raise ChatGPTSessionRefreshError(
                    "session_roxy_relogin_failed",
                    "Roxy �����������",
                ) from exc
            if self.stop_event is not None and self.stop_event.is_set():
                raise ChatGPTSessionRefreshError(
                    "session_window_close_requested",
                    "������ر� Roxy ����",
                )

            login_account = dict(account or self.account or {})
            try:
                resolved_id = int(account_id or login_account.get("id") or 0)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ChatGPTSessionRefreshError(
                    "account_missing",
                    "�˺����ݲ�����",
                ) from exc
            if resolved_id <= 0:
                raise ChatGPTSessionRefreshError(
                    "account_missing",
                    "�˺����ݲ�����",
                )
            email = str(login_account.get("email") or "").strip().lower()
            if not email:
                raise ChatGPTSessionRefreshError(
                    "account_missing",
                    "�˺����ݲ�����",
                )
            self.account = dict(login_account)
            try:
                from core.roxy_registration import (
                    RoxyIdentityResetError,
                    _reset_pooled_profile_identity,
                )

                _reset_pooled_profile_identity(driver)
            except RoxyIdentityResetError as exc:
                if bool(getattr(self.opened, "pooled", False)):
                    try:
                        self.opened.profile_cache_discard = True
                    except Exception:
                        pass
                raise ChatGPTSessionRefreshError(
                    "session_identity_cleanup_failed",
                    "Roxy ������������ʧ�ܣ���ֹͣ��¼",
                ) from exc
            except Exception as exc:
                raise ChatGPTSessionRefreshError(
                    "session_identity_cleanup_failed",
                    "Roxy ������������ʧ�ܣ���ֹͣ��¼",
                ) from exc

            if stage_callback is not None:
                try:
                    stage_callback("relogin")
                except Exception:
                    pass
            try:
                session_info = ensure_roxy_session_on_driver(
                    driver,
                    login_account,
                    account_id=resolved_id,
                    restore_saved_session=bool(restore_saved_session),
                    # Identity was cleared above so the reset callback must
                    # not clear the same live Profile a second time.
                    reset_identity=None,
                    allow_manual_wait=bool(allow_manual_login),
                    stop_event=self.stop_event,
                    login_function=login_function,
                )
            except ChatGPTSessionRefreshError:
                raise
            except Exception as exc:
                raise ChatGPTSessionRefreshError(
                    "session_roxy_relogin_failed",
                    "Roxy ԭ�ص�¼δ���",
                ) from exc
            if not isinstance(session_info, dict):
                raise ChatGPTSessionRefreshError(
                    "session_roxy_relogin_failed",
                    "��¼��ɵ�δȡ����Ч Session",
                )
            token = normalize_token(session_info.get("accessToken") or "")
            if not token:
                raise ChatGPTSessionRefreshError(
                    "session_roxy_relogin_failed",
                    "��¼��ɵ�δȡ����Ч Session",
                )
            validate_session_identity(login_account, session_info, token)
            status, remote = _read_browser_me_once(
                driver,
                access_token=token,
                account_id=str(login_account.get("account_id") or ""),
            )
            if status != 200:
                raise ChatGPTSessionRefreshError(
                    "session_login_liveness_failed",
                    "��¼��ɵ��˺����ʧ��",
                )
            remote_email = str(remote.get("email") or "").strip().lower()
            if remote_email and remote_email != email:
                raise ChatGPTSessionRefreshError(
                    "session_identity_email_mismatch",
                    "��¼�õ���������Ŀ�����䲻һ��",
                )
            try:
                snapshot = capture_driver_snapshot(
                    driver,
                    email=email,
                    account_id=resolved_id,
                    session_info=session_info,
                )
            except ChatGPTSessionStoreError as exc:
                raise ChatGPTSessionRefreshError(
                    exc.error_code,
                    "��¼��ɵ� Session Cookie ����ʧ��",
                ) from exc
            try:
                save_snapshot(snapshot, refreshed=True)
            except ChatGPTSessionStoreError as exc:
                raise ChatGPTSessionRefreshError(
                    exc.error_code,
                    "��¼��ɵ� Session Cookie ����ʧ��",
                ) from exc
            self.last_session_info = dict(session_info)
            self.last_snapshot = dict(snapshot or {})
            self.relogin_count += 1
            old_token = normalize_token(login_account.get("access_token") or "")
            self.account["access_token"] = token
            if old_token and token != old_token:
                self.candidate = RoxyLoginCandidate(
                    account_id=resolved_id,
                    login_email=email,
                    old_token_fingerprint=_token_fingerprint(old_token),
                    new_token_fingerprint=_token_fingerprint(token),
                    session_rotated=True,
                    access_token=token,
                    expected_old_token=old_token,
                    session_info=dict(session_info),
                    snapshot=dict(snapshot or {}),
                )
            else:
                self.candidate = None
            return session_info


def open_roxy_login_candidate_lease(account: dict, **kwargs) -> RoxyLoginCandidateLease:
    """Open a candidate context without closing it at the first yield."""

    manager = roxy_login_candidate_context(account, **kwargs)
    try:
        candidate, driver = manager.__enter__()
    except Exception:
        # A real ``contextmanager`` normally unwinds itself when ``__enter__``
        # fails.  Calling ``__exit__`` as a best-effort fallback also keeps
        # lightweight adapters/test doubles from leaking a slot or Profile.
        try:
            manager.__exit__(None, None, None)
        except Exception:
            pass
        raise
    return RoxyLoginCandidateLease(
        manager,
        candidate,
        driver,
        account=account,
        stop_event=kwargs.get("stop_event"),
    )


def run_roxy_login_candidate(
    account: dict,
    *,
    login_email: str | None = None,
    headless: bool | None = None,
    proxy_country: str | None = None,
    registration_route_hint=None,
    allow_manual_login: bool = True,
    stop_event: threading.Event | None = None,
    task_kind: str = "session_refresh",
    stage_callback: Callable[[str], None] | None = None,
    slot_already_acquired: bool = False,
    excluded_profile_ids: set[str] | frozenset[str] | None = None,
    restore_saved_session: bool = False,
    allow_headed_auth: bool = True,
    operation_only: bool = False,
    login_function: Callable[..., dict] | None = None,
    reset_profile_identity: bool = True,
    defer_email_otp_context: bool = False,
    mailbox_access: bool | None = None,
    strict_password: bool = False,
    profile_operation_lock=None,
) -> RoxyLoginCandidate:
    context_kwargs = {
        "login_email": login_email,
        "headless": headless,
        "allow_manual_login": allow_manual_login,
        "stop_event": stop_event,
        "task_kind": task_kind,
        "stage_callback": stage_callback,
        "slot_already_acquired": slot_already_acquired,
        "restore_saved_session": restore_saved_session,
        "allow_headed_auth": allow_headed_auth,
        "operation_only": operation_only,
        "login_function": login_function,
        "reset_profile_identity": reset_profile_identity,
        "defer_email_otp_context": defer_email_otp_context,
        "mailbox_access": mailbox_access,
        "strict_password": strict_password,
        "profile_operation_lock": profile_operation_lock,
    }
    if registration_route_hint is not None:
        context_kwargs["registration_route_hint"] = registration_route_hint
    if proxy_country:
        context_kwargs["proxy_country"] = str(proxy_country).strip().upper()
    if excluded_profile_ids:
        context_kwargs["excluded_profile_ids"] = excluded_profile_ids
    with roxy_login_candidate_context(
        account,
        **context_kwargs,
    ) as (candidate, _driver):
        return candidate


def save_roxy_login_candidate_for_account(
    account: dict,
    candidate: RoxyLoginCandidate,
) -> dict:
    """Persist a candidate only when it still belongs to the current account."""

    account_id = int(account.get("id") or 0)
    if account_id <= 0 or int(candidate.account_id) != account_id:
        raise ChatGPTSessionRefreshError("account_missing", "�˺Ų�����")
    with _account_lock(account_id):
        current = db.get_account(account_id)
        if not current:
            raise ChatGPTSessionRefreshError("account_missing", "�˺Ų�����")
        current_email = str(current.get("email") or "").strip().lower()
        if current_email != candidate.login_email:
            raise ChatGPTSessionRefreshError(
                "session_identity_email_mismatch",
                "��¼��ѡ����д����һ����������",
            )
        current_token = normalize_token(current.get("access_token") or "")
        if current_token != normalize_token(candidate.expected_old_token):
            if current_token == normalize_token(candidate.access_token):
                return {
                    "access_token": candidate.access_token,
                    "session_info": candidate.session_info,
                    "already_committed": True,
                }
            raise ChatGPTSessionRefreshError(
                "account_token_update_conflict",
                "�˺� Token �ѱ���һ������£������²�ѯ",
            )
        validate_session_identity(
            current,
            candidate.session_info,
            candidate.access_token,
        )
        snapshot = dict(candidate.snapshot)
        snapshot["last_quiet_refresh"] = _quiet_diagnostic(
            stage="roxy_login",
            outcome="refreshed",
            old_token_fingerprint=candidate.old_token_fingerprint,
            new_token_fingerprint=candidate.new_token_fingerprint,
            token_changed=True,
            session_rotated=True,
            http_status=200,
            exchange_method="roxy_login",
        )
        try:
            save_snapshot(snapshot, refreshed=True)
        except ChatGPTSessionStoreError as exc:
            raise ChatGPTSessionRefreshError(
                exc.error_code,
                "��¼��ɵ� Session Cookie ����ʧ��",
            ) from exc
        updated = db.replace_account_access_token(
            acc_id=account_id,
            email=current_email,
            new_access_token=candidate.access_token,
            expected_old_token=current_token,
            session_info=candidate.session_info,
        )
        if not updated:
            latest = db.get_account(account_id) or {}
            if normalize_token(latest.get("access_token") or "") != normalize_token(
                candidate.access_token
            ):
                raise ChatGPTSessionRefreshError(
                    "account_token_update_conflict",
                    "�˺� Token �ѱ���һ������£������²�ѯ",
                )
        return {
            "access_token": candidate.access_token,
            "session_info": candidate.session_info,
        }


def run_roxy_session_refresh(
    account: dict,
    *,
    headless: bool | None = None,
    allow_manual_login: bool = True,
) -> dict:
    account_id = int(account.get("id") or 0)
    effective_headless = _effective_headless(headless)
    effective_manual_login = bool(allow_manual_login) and not effective_headless
    logger.info(
        "[SessionRefresh][Roxy] ����������account_id=%s headless=%s source=%s manual_wait=%s",
        account_id,
        effective_headless,
        "global_config" if headless is None else "caller_override",
        effective_manual_login,
    )
    lease = open_roxy_login_candidate_lease(
        account,
        login_email=str(account.get("email") or ""),
        headless=headless,
        proxy_country=_MAINTENANCE_PROXY_COUNTRY,
        allow_manual_login=allow_manual_login,
        task_kind="session_refresh",
        slot_already_acquired=True,
    )
    try:
        candidate = lease.candidate
        driver = lease.driver
        persisted = save_roxy_login_candidate_for_account(account, candidate)
        try:
            plan_result = check_account_plan_in_driver(
                driver,
                persisted["access_token"],
            )
        except Exception as exc:
            # Session persistence has already succeeded.  A diagnostic query
            # must never turn that success into a failed login task.
            logger.warning(
                "[SessionRefresh][Roxy] ��������ײ͸����쳣��account_id=%s "
                "reason=plan_check_browser_unexpected error_type=%s",
                account_id,
                type(exc).__name__,
            )
            plan_result = {
                "ok": False,
                "checked_at": now_iso(),
                "http_status": None,
                "error": "��������ײͲ�ѯ�쳣",
                "error_code": "plan_check_browser_unexpected",
                "proxy_mode": "roxy_browser",
                "network_route": "roxy_browser",
            }
        plan_result = dict(plan_result or {})
        plan_result["token_refreshed"] = True
        plan_result["token_refresh_status"] = "refreshed"
        plan_result["token_refresh_method"] = "roxy_login"
        plan_result["session_refresh_required"] = False
        return {
            "ok": True,
            "access_token": persisted["access_token"],
            "plan_result": plan_result,
            "token_refresh_method": "roxy_login",
        }
    finally:
        lease.close()
''')

def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
