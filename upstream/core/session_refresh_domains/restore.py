"""ChatGPT session refresh restore domain implementation.

Loaded into core.chatgpt_session_refresh globals to preserve public names and test seams."""
from __future__ import annotations
from textwrap import dedent

_SOURCE = dedent(r'''
def _cdp_cookie_payload(item: dict) -> dict:
    """Build a Chromium CookieParam while preserving prefix semantics.

    Chromium rejects a ``__Host-`` cookie when a Domain attribute is present.
    Session snapshots are intentionally normalized for HTTP-cookie-jar use,
    so those records can legitimately contain ``domain=chatgpt.com``.  CDP
    needs the host-only form instead; supplying a URL expresses the host
    without sending an illegal Domain field.  This conversion never logs or
    otherwise exposes the cookie value.
    """

    name = str(item.get("name") or "")
    domain = str(item.get("domain") or ".chatgpt.com").strip().lower()
    host = domain.lstrip(".").rstrip(".") or "chatgpt.com"
    cookie = {
        "name": name,
        "value": str(item.get("value") or ""),
        "path": str(item.get("path") or "/"),
        "secure": bool(item.get("secure", True)),
        "httpOnly": bool(item.get("httpOnly", False)),
    }
    if name.startswith("__Host-"):
        # The prefix also requires Secure, Path=/ and a host-only cookie;
        # enforce those rules even if an old snapshot was captured with
        # incomplete metadata.
        cookie["secure"] = True
        cookie["path"] = "/"
        cookie["url"] = f"https://{host}/"
    else:
        if name.startswith("__Secure-"):
            # Chromium applies the __Secure- prefix contract at write time.
            # Older snapshots occasionally omitted the flag, so normalize it
            # rather than allowing one stale record to abort restoration.
            cookie["secure"] = True
        if item.get("hostOnly") is True:
            scheme = "https" if cookie["secure"] else "http"
            cookie["url"] = f"{scheme}://{host}{cookie['path']}"
        else:
            cookie["domain"] = domain
    same_site = str(item.get("sameSite") or "").strip().lower()
    if same_site in {"strict", "lax", "none"}:
        cookie["sameSite"] = same_site.title()
    expires = item.get("expires")
    if expires not in (None, "", -1):
        try:
            cookie["expires"] = float(expires)
        except (TypeError, ValueError):
            pass
    return cookie


def _cdp_cookie_set_succeeded(result: object) -> bool:
    """Interpret CDP cookie-write responses without depending on driver quirks."""

    if result is False:
        return False
    if isinstance(result, dict) and "success" in result:
        return bool(result.get("success"))
    return True


def _restore_saved_session_to_driver(driver, record: dict) -> None:
    """Restore a saved ChatGPT Cookie jar without logging any values.

    The critical Session Cookie family is written and verified separately from
    optional route/telemetry cookies.  A malformed optional cookie (including
    an old ``__Host-`` record) therefore cannot invalidate an otherwise usable
    login.  If a batch write is rejected, the critical cookies are retried one
    by one so the failure surface is limited to the exact cookie Chromium
    refused.
    """

    cookies = normalise_cookies((record or {}).get("cookies") or [])
    if not has_complete_session_cookie(cookies):
        raise ChatGPTSessionRefreshError(
            "session_browser_cookie_restore_failed",
            "保存的 ChatGPT Session Cookie 不完整，请刷新会话",
        )

    payload = [_cdp_cookie_payload(item) for item in cookies]
    critical_payload = [
        cookie
        for cookie in payload
        if has_session_cookie([cookie])
    ]
    optional_payload = [
        cookie
        for cookie in payload
        if not has_session_cookie([cookie])
    ]
    if not critical_payload:
        raise ChatGPTSessionRefreshError(
            "session_browser_cookie_restore_failed",
            "保存的 ChatGPT Session Cookie 不完整，请刷新会话",
        )

    optional_failures = 0

    def _read_back_cookies() -> list[dict]:
        try:
            restored = driver.execute_cdp_cmd("Network.getAllCookies", {}) or {}
            return normalise_cookies(restored.get("cookies") or [])
        except Exception as exc:
            raise ChatGPTSessionRefreshError(
                "session_browser_cookie_restore_failed",
                "恢复 ChatGPT Session 后回读校验失败，请刷新会话",
            ) from exc

    try:
        driver.execute_cdp_cmd("Network.enable", {})

        # Keep the fast path for the normal Session family.  The payload is
        # already restricted to valid Session Cookie names, so an optional
        # telemetry/CSRF cookie cannot abort this write.
        critical_batch_ok = False
        try:
            result = driver.execute_cdp_cmd(
                "Network.setCookies",
                {"cookies": critical_payload},
            )
            critical_batch_ok = _cdp_cookie_set_succeeded(result)
        except Exception:
            critical_batch_ok = False

        if not critical_batch_ok:
            for cookie in critical_payload:
                try:
                    result = driver.execute_cdp_cmd(
                        "Network.setCookie",
                        cookie,
                    )
                    if not _cdp_cookie_set_succeeded(result):
                        raise RuntimeError("cookie_write_rejected")
                except Exception as exc:
                    raise ChatGPTSessionRefreshError(
                        "session_browser_cookie_restore_failed",
                        "无法恢复保存的 ChatGPT Session，请刷新会话",
                    ) from exc

        # Optional cookies are useful for a smoother browser hand-off but are
        # never allowed to make a valid Session unusable.
        for cookie in optional_payload:
            try:
                result = driver.execute_cdp_cmd(
                    "Network.setCookie",
                    cookie,
                )
                if not _cdp_cookie_set_succeeded(result):
                    raise RuntimeError("cookie_write_rejected")
            except Exception:
                optional_failures += 1

    except ChatGPTSessionRefreshError:
        raise
    except Exception as exc:
        raise ChatGPTSessionRefreshError(
            "session_browser_cookie_restore_failed",
            "无法恢复保存的 ChatGPT Session，请刷新会话",
        ) from exc

    # A few Chromium versions report success for Network.setCookies while
    # silently dropping one malformed member.  Read back first, then retry
    # only the missing critical members one by one before declaring the whole
    # saved Session unusable.  This keeps a bad legacy cookie from forcing an
    # unnecessary OTP login while retaining strict identity verification.
    restored_cookies = _read_back_cookies()
    expected = set(_session_cookie_signature(cookies))
    actual = set(_session_cookie_signature(restored_cookies))
    if expected and not expected.issubset(actual):
        missing_payload: list[dict] = []
        for original, candidate in zip(cookies, payload):
            if not has_session_cookie([candidate]):
                continue
            signature = _session_cookie_signature([original])
            if signature and signature[0] not in actual:
                missing_payload.append(candidate)
        for candidate in missing_payload:
            try:
                result = driver.execute_cdp_cmd(
                    "Network.setCookie",
                    candidate,
                )
                if not _cdp_cookie_set_succeeded(result):
                    raise RuntimeError("cookie_write_rejected")
            except Exception:
                # The final read-back below turns this into the fixed public
                # restore error without exposing the rejected cookie.
                pass
        if missing_payload:
            restored_cookies = _read_back_cookies()
            actual = set(_session_cookie_signature(restored_cookies))
    if not expected or not expected.issubset(actual):
        raise ChatGPTSessionRefreshError(
            "session_browser_cookie_restore_failed",
            "恢复 ChatGPT Session 后回读校验失败，请刷新会话",
        )
    if optional_failures:
        logger.info(
            "[SessionRefresh][Roxy] 可选 Session Cookie 写入部分跳过：count=%s",
            optional_failures,
        )


def _check_roxy_login_stop(
    driver,
    stop_event: threading.Event | None,
) -> None:
    """Raise a safe terminal error when the caller stopped/closed the Driver."""

    if stop_event is not None and stop_event.is_set():
        raise ChatGPTSessionRefreshError(
            "session_window_close_requested",
            "已请求关闭 Roxy 窗口",
        )
    if stop_event is None or not hasattr(driver, "window_handles"):
        return
    try:
        if list(getattr(driver, "window_handles", []) or []):
            return
    except Exception:
        raise ChatGPTSessionRefreshError(
            "roxy_window_browser_closed",
            "Roxy 窗口已关闭",
        ) from None
    raise ChatGPTSessionRefreshError(
        "roxy_window_browser_closed",
        "Roxy 窗口已关闭",
    )


def _browser_session_expired_notice(driver) -> bool:
    """Detect the explicit ChatGPT expired-session modal after cookie restore.

    ``/api/auth/session`` can briefly return the old token while the SPA has
    already rejected the browser cookie and rendered its ``Your session has
    expired`` dialog.  Treating that page as restored makes maintenance flows
    click controls behind the modal and eventually time out.  Only fixed UI
    phrases are inspected; no page content is logged or persisted.
    """

    try:
        text = driver.execute_script(
            "return String((document.body && (document.body.innerText || document.body.textContent)) || '');"
        )
    except Exception:
        return False
    compact = " ".join(str(text or "").lower().split())
    return bool(
        "your session has expired" in compact
        or "session has expired" in compact
        or "会话已过期" in compact
        or "会話が期限切れ" in compact
    )


def _restore_saved_session_probe(
    driver,
    account: dict,
    *,
    account_id: int,
    stop_event: threading.Event | None = None,
    timeout: float = _SAVED_SESSION_PROBE_TIMEOUT,
) -> tuple[dict | None, str]:
    """Try one saved Session on an already-open Roxy Driver.

    The returned reason is a fixed diagnostic label only; no URL, cookie,
    token or response body is ever included.  A missing/expired/wrong Session
    is deliberately reported as a recoverable miss so the caller can execute
    the normal email/password/OTP login path.
    """

    email = str(account.get("email") or "").strip().lower()
    if not email:
        return None, "account_email_missing"
    try:
        record = get_session(email, account_id=account_id)
    except Exception:
        return None, "session_record_read_failed"
    if not record:
        return None, "session_record_missing"
    try:
        from core.roxy_registration import _page_warmup, _safe_get

        _check_roxy_login_stop(driver, stop_event)
        _restore_saved_session_to_driver(driver, record)
        _safe_get(
            driver,
            "https://chatgpt.com/",
            timeout=45,
            attempts=2,
            accept_hosts=("chatgpt.com", "auth.openai.com"),
        )
        _page_warmup(driver, reason="session_refresh_session_restore")
        deadline = time.monotonic() + max(1.0, float(timeout or 1.0))
        # The SPA may publish the old /api/auth/session payload immediately
        # after navigation and render its expired-session modal a few seconds
        # later.  Do not accept the first token as proof of a usable browser
        # Session; require a short, continuously healthy observation window.
        # This is deliberately bounded by the existing probe timeout so a
        # genuinely missing Session still falls through promptly.
        stable_for = min(5.0, max(1.5, float(timeout or 1.0) / 3.0))
        valid_since: float | None = None
        last_token = ""
        while time.monotonic() < deadline:
            _check_roxy_login_stop(driver, stop_event)
            if _browser_session_expired_notice(driver):
                return None, "session_not_published"
            info = _find_session_in_windows(driver)
            token = normalize_token((info or {}).get("accessToken") or "")
            if info and token:
                try:
                    validate_session_identity(account, info, token)
                except ChatGPTSessionRefreshError:
                    return None, "session_identity_mismatch"
                now = time.monotonic()
                if token != last_token:
                    last_token = token
                    valid_since = now
                elif valid_since is None:
                    valid_since = now
                if valid_since is not None and now - valid_since >= stable_for:
                    # Recheck the visible modal immediately before accepting
                    # the record; it can appear between the two probes.
                    if _browser_session_expired_notice(driver):
                        return None, "session_not_published"
                    if not _browser_session_business_ready(driver, account, info):
                        return None, "session_business_invalid"
                    return info, "restored"
            time.sleep(0.8)
        return None, "session_not_published"
    except ChatGPTSessionRefreshError as exc:
        if str(exc.error_code or "") in {
            "session_window_close_requested",
            "roxy_window_browser_closed",
        }:
            raise
        return None, _safe_session_restore_reason(exc.error_code)
    except Exception:
        return None, "session_restore_failed"


from core.hme_task_scope import deferred_hme_auth


@deferred_hme_auth(account_arg=1)
def ensure_roxy_session_on_driver(
    driver,
    account: dict,
    *,
    account_id: int | None = None,
    restore_saved_session: bool = True,
    reset_identity: Callable[[], None] | None = None,
    allow_manual_wait: bool = True,
    manual_wait_timeout: float | None = _MANUAL_LOGIN_TIMEOUT,
    on_restore_miss: Callable[[str], None] | None = None,
    on_manual_wait: Callable[[], None] | None = None,
    stop_event: threading.Event | None = None,
    login_function: Callable[..., dict] | None = None,
    defer_email_otp_context: bool = False,
    mailbox_access: bool | None = None,
    strict_password: bool = False,
) -> dict:
    """Ensure the requested account is authenticated on one existing Driver.

    This is the common authentication kernel for ordinary Session refresh and
    long-lived ``turb_browser`` windows.  The caller owns Profile creation and
    cleanup; this function only restores/logs in and returns a validated
    browser Session.  ``restore_saved_session=False`` is used by token-refresh
    candidates that must force a fresh login and rotate the access token.
    """

    try:
        resolved_account_id = int(account_id or account.get("id") or 0)
    except (TypeError, ValueError, OverflowError):
        resolved_account_id = 0
    if resolved_account_id <= 0:
        raise ChatGPTSessionRefreshError("account_missing", "账号身份不完整")
    if not str(account.get("email") or "").strip():
        raise ChatGPTSessionRefreshError("account_missing", "账号身份不完整")

    try:
        from core.auth_factors import resolve_login_policy

        login_policy = resolve_login_policy(account)
    except Exception:
        login_policy = None
    if login_policy is not None and login_policy.password_totp:
        # This lower-level compatibility entry may be called without the
        # neutral facade.  Do not allow a legacy ``mailbox_access=True`` to
        # reopen the mailbox fallback for a strict account.
        mailbox_access = False
    else:
        mailbox_access = login_policy.mailbox_access if login_policy is not None else True
    mailbox_access = bool(mailbox_access)
    if not mailbox_access:
        # Do not merely defer mailbox setup.  The strict policy also prevents
        # an email challenge from lazily opening a provider later in login.
        defer_email_otp_context = True
        strict_password = True

    if restore_saved_session:
        session_info, restore_reason = _restore_saved_session_probe(
            driver,
            account,
            account_id=resolved_account_id,
            stop_event=stop_event,
        )
        if session_info is not None:
            logger.info(
                "[SessionRefresh][Roxy] 已在现有 Driver 恢复 Session：account_id=%s",
                resolved_account_id,
            )
            return session_info
        safe_reason = _safe_session_restore_reason(restore_reason)
        # The browser can publish the Session in the small gap between the
        # bounded probe's final poll and this fallback branch.  Take one last
        # live browser observation before clearing the Profile or submitting
        # the email again.  This is deliberately restricted to the delayed
        # publication case; missing/invalid records still follow the normal
        # login path.
        if safe_reason == "session_not_published":
            try:
                late_info = _find_session_in_windows(driver)
                late_token = normalize_token(
                    (late_info or {}).get("accessToken") or ""
                )
                if late_info and late_token and _browser_session_business_ready(
                    driver,
                    account,
                    late_info,
                ):
                    validate_session_identity(account, late_info, late_token)
                    logger.info(
                        "[SessionRefresh][Roxy] 延迟检测到已登录 Session，继续当前流程：account_id=%s",
                        resolved_account_id,
                    )
                    return late_info
            except ChatGPTSessionRefreshError:
                # Identity/session validation failures must not be hidden by
                # the late observation; the regular safe fallback below owns
                # those outcomes.
                pass
            except Exception:
                pass
        logger.info(
            "[SessionRefresh][Roxy] 保存 Session 未恢复，进入账号登录：account_id=%s reason=%s",
            resolved_account_id,
            safe_reason,
        )
        if on_restore_miss is not None:
            try:
                on_restore_miss(safe_reason)
            except Exception:
                # State/lifecycle reporting is diagnostic only.  A failed
                # callback must never strand the browser before the existing
                # password/OTP login path gets a chance to run.
                logger.warning(
                    "[SessionRefresh][Roxy] Session 恢复失败回调未写入："
                    "account_id=%s reason=session_restore_callback_failed",
                    resolved_account_id,
                )

    # A stop/close request can arrive while the bounded restore probe is
    # unwinding.  Do not clear the Profile or start a fresh login after that
    # point; the caller's cleanup path owns the browser shutdown.
    _check_roxy_login_stop(driver, stop_event)
    if reset_identity is not None:
        try:
            reset_identity()
        except ChatGPTSessionRefreshError:
            raise
        except Exception as exc:
            raise ChatGPTSessionRefreshError(
                "session_identity_cleanup_failed",
                "Roxy 身份数据清理失败，已停止登录",
            ) from exc
    _check_roxy_login_stop(driver, stop_event)
    from core.hme_task_scope import needs_hme_scope
    if mailbox_access and needs_hme_scope(account):
        # We are past the saved-session path. Let the locked login kernel
        # prepare its mailbox before a submission can generate an email.
        defer_email_otp_context = False
    if login_function is not None:
        login_runner = login_function
    elif str(
        getattr(driver, "_turb_auth_driver", "") or ""
    ).strip().lower() == "headed_chrome":
        # A headed Driver must never fall through to the legacy login landing
        # page.  Keep this lazy import to avoid a module cycle while allowing
        # narrow legacy callers that have a raw Driver instead of a lease to
        # use the same locked Roxy runner.
        from core.headed_chrome_auth_runtime import run_headed_auth_on_existing_driver

        def login_runner(driver_arg, account_arg, **_runner_kwargs):
            return run_headed_auth_on_existing_driver(
                driver_arg,
                account_arg,
                opened=getattr(driver_arg, "_turb_roxy_opened", None),
                stop_event=stop_event,
                defer_email_otp_context=bool(defer_email_otp_context),
            )
    else:
        login_runner = _wait_for_visible_login
    login_kwargs = {
        "account_id": resolved_account_id,
        "allow_manual_wait": allow_manual_wait,
    }
    if manual_wait_timeout != _MANUAL_LOGIN_TIMEOUT:
        login_kwargs["manual_wait_timeout"] = manual_wait_timeout
    if on_manual_wait is not None:
        login_kwargs["on_manual_wait"] = on_manual_wait
    if stop_event is not None:
        login_kwargs["stop_event"] = stop_event
    if defer_email_otp_context:
        login_kwargs["defer_email_otp_context"] = True
    if not mailbox_access:
        login_kwargs["mailbox_access"] = False
    if strict_password:
        login_kwargs["strict_password"] = True
    session_info = login_runner(driver, account, **login_kwargs)
    if not isinstance(session_info, dict):
        raise ChatGPTSessionRefreshError(
            "session_refresh_empty",
            "登录完成但未取得有效 Session",
        )
    token = normalize_token((session_info or {}).get("accessToken") or "")
    if not token:
        raise ChatGPTSessionRefreshError(
            "session_refresh_empty",
            "登录完成但未取得 access token",
        )
    validate_session_identity(account, session_info, token)
    return session_info
''')

def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
