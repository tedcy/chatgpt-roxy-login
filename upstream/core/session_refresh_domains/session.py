"""ChatGPT session refresh session domain implementation.

Loaded into core.chatgpt_session_refresh globals to preserve public names and test seams."""
from __future__ import annotations
from textwrap import dedent

_SOURCE = dedent(r'''
import sqlite3


def _session_storage_details(exc: Exception) -> tuple[bool, str]:
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, sqlite3.Error):
            code = getattr(current, "sqlite_errorcode", None)
            name = getattr(current, "sqlite_errorname", "unknown")
            if not isinstance(name, str) or not name.startswith("SQLITE_") or not all(
                char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for char in name
            ):
                name = "unknown"
            if isinstance(code, int):
                return (code & 0xff) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}, name
            # Older Python versions and synthetic errors may lack SQLite metadata.
            return str(current) in {
                "database is locked", "database table is locked", "database schema is locked",
            }, name
        current = current.__cause__ or current.__context__
    return False, "unknown"


def _session_storage_write(account_id: int, stage: str, operation: Callable, *args, **kwargs):
    """Retry only a database mutation, never its authentication/network caller."""
    for attempt in range(3):
        try:
            return operation(*args, **kwargs)
        except (sqlite3.Error, db.AccountStoreError, ChatGPTSessionStoreError) as exc:
            retryable, sqlite_name = _session_storage_details(exc)
            retry = retryable and attempt < 2
            logger.warning(
                "[SessionRefresh] 会话保存异常：account_id=%s stage=%s "
                "attempt=%s/3 retry=%s error_type=%s sqlite_errorname=%s",
                account_id, stage, attempt + 1, str(retry).lower(),
                type(exc).__name__, sqlite_name,
            )
            if not retry:
                raise ChatGPTSessionRefreshError(
                    "session_refresh_storage_error", "会话结果保存失败，请重试",
                ) from exc
            time.sleep((0.5, 1.0)[attempt])


def _session_cookie_signature(cookies: list[dict]) -> tuple:
    prefixes = (
        "__Secure-next-auth.session-token",
        "__Host-next-auth.session-token",
        "next-auth.session-token",
        "__Secure-authjs.session-token",
        "__Host-authjs.session-token",
        "authjs.session-token",
    )
    return tuple(
        sorted(
            (
                str(item.get("name") or ""),
                str(item.get("value") or ""),
                (
                    str(item.get("domain") or "").lstrip(".")
                    if str(item.get("name") or "").startswith("__Host-")
                    else str(item.get("domain") or "")
                ),
                str(item.get("path") or "/"),
            )
            for item in cookies or []
            if any(
                str(item.get("name") or "") == prefix
                or str(item.get("name") or "").startswith(prefix + ".")
                for prefix in prefixes
            )
        )
    )


def _token_fingerprint(token: str) -> str:
    value = normalize_token(token)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12] if value else ""


_SAFE_EXCHANGE_METHODS = frozenset({
    "http_session",
    "hidden_roxy",
    "roxy_login",
    "unknown",
})


def _normalise_exchange_method(value: object, *, default: str = "unknown") -> str:
    method = str(value or "").strip().lower()
    return method if method in _SAFE_EXCHANGE_METHODS else default


def _quiet_diagnostic(
    *,
    stage: str,
    outcome: str,
    old_token_fingerprint: str,
    new_token_fingerprint: str = "",
    token_changed: bool = False,
    session_rotated: bool = False,
    http_status: int | None = None,
    exchange_method: str = "unknown",
) -> dict:
    payload = {
        "attempted_at": now_iso(),
        "stage": str(stage or "session_probe"),
        "outcome": str(outcome or "session_refresh_failed"),
        "old_token_fingerprint": str(old_token_fingerprint or ""),
        "new_token_fingerprint": str(new_token_fingerprint or ""),
        "token_changed": bool(token_changed),
        "session_rotated": bool(session_rotated),
        "exchange_method": _normalise_exchange_method(exchange_method),
    }
    if http_status is not None:
        payload["http_status"] = int(http_status)
    return payload


def _record_quiet_result(
    email: str,
    *,
    stage: str,
    outcome: str,
    old_token_fingerprint: str,
    new_token_fingerprint: str = "",
    token_changed: bool = False,
    session_rotated: bool = False,
    http_status: int | None = None,
    status: str | None = None,
    exchange_method: str = "unknown",
) -> None:
    try:
        record_quiet_refresh(
            email,
            stage=stage,
            outcome=outcome,
            old_token_fingerprint=old_token_fingerprint,
            new_token_fingerprint=new_token_fingerprint,
            token_changed=token_changed,
            session_rotated=session_rotated,
            http_status=http_status,
            status=status,
            exchange_method=exchange_method,
        )
    except Exception:
        logger.warning(
            "[SessionRefresh] 静默换发诊断写入失败：reason=session_refresh_diagnostic_write_failed"
        )


def _session_identity(session_info: dict, token: str) -> dict:
    info = session_info if isinstance(session_info, dict) else {}
    user = info.get("user") if isinstance(info.get("user"), dict) else {}
    account = info.get("account") if isinstance(info.get("account"), dict) else {}
    claims = token_claims(token)
    return {
        "emails": {
            str(value or "").strip().lower()
            for value in (user.get("email"), claims.get("email"))
            if str(value or "").strip()
        },
        "user_ids": {
            str(value or "").strip()
            for value in (user.get("id"), claims.get("user_id"))
            if str(value or "").strip()
        },
        "account_ids": {
            str(value or "").strip()
            for value in (account.get("id"), claims.get("account_id"))
            if str(value or "").strip()
        },
    }


def validate_session_identity(account: dict, session_info: dict, token: str) -> None:
    """Compatibility wrapper for the shared Session candidate validator."""
    from core.session_candidate import validate_session_identity as _validate

    _validate(account, session_info, token)


def _read_session(env: BrowserSession) -> tuple[dict, int]:
    headers = env.get_nextauth_headers(referer="https://chatgpt.com/")
    headers.update({"cache-control": "no-cache", "pragma": "no-cache"})
    try:
        from config import proxy as proxy_cfg

        timeout = max(3.0, min(60.0, float(getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0) or 15.0)))
    except Exception:
        timeout = 15.0
    try:
        response = env.session.get(
            _SESSION_URL,
            headers=headers,
            allow_redirects=False,
            timeout=timeout,
        )
    except Exception as exc:
        raise ChatGPTSessionRefreshError(
            "session_refresh_network_error",
            "ChatGPT Session 读取请求失败",
        ) from exc
    status = int(getattr(response, "status_code", 0) or 0)
    if status in {401, 403}:
        raise ChatGPTSessionRefreshError(
            "session_auth_invalid",
            "本地 ChatGPT Session 已失效，请重新登录",
        )
    if not 200 <= status < 300:
        raise ChatGPTSessionRefreshError(
            "session_refresh_http_error",
            f"ChatGPT Session 读取返回 HTTP {status or 'unknown'}",
        )
    try:
        data = response.json()
    except Exception as exc:
        raise ChatGPTSessionRefreshError(
            "session_refresh_invalid_json",
            "ChatGPT Session 刷新响应格式无效",
        ) from exc
    if not isinstance(data, dict) or not normalize_token(data.get("accessToken") or ""):
        raise ChatGPTSessionRefreshError(
            "session_refresh_empty",
            "本地 ChatGPT Session 已失效，请重新登录",
        )
    try:
        apply_session_cookie_rotation(env.session, response, data)
    except ChatGPTSessionStoreError as exc:
        raise ChatGPTSessionRefreshError(
            "session_exchange_contract_mismatch",
            "ChatGPT Web Session 换发契约已变化，请刷新会话",
        ) from exc
    return data, status


def _prepare_access_token_candidate_from_saved_session_http(
    account: dict,
    *,
    env: BrowserSession | None = None,
    route: dict | None = None,
) -> SessionTokenCandidate:
    """Read one Session snapshot without pretending that GET exchanges an AT."""
    account_id = int(account.get("id") or 0)
    if account_id <= 0:
        raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
    owns_env = env is None
    with _account_lock(account_id):
        current = db.get_account(account_id)
        if not current:
            raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
        email = str(current.get("email") or "").strip()
        old_token = normalize_token(current.get("access_token") or "")
        old_fingerprint = _token_fingerprint(old_token)
        if not old_token:
            raise ChatGPTSessionRefreshError(
                "session_refresh_stale_token",
                "本地账号没有可用于换发校验的旧 access token",
            )
        record = get_session(email, account_id=account_id)
        status = record_status(record)
        allow_revalidation = can_revalidate_session(record)
        if status != "ready" and not allow_revalidation:
            stored_reason = str((record or {}).get("status_reason") or "").strip()
            raise ChatGPTSessionRefreshError(
                stored_reason or f"session_{status}",
                "没有可用的 ChatGPT Session，请点击“刷新会话”",
            )
        try:
            protocol_only = (env is None and route is None) or (route or {}).get('country_policy') == 'protocol'
            if protocol_only:
                from core.protocol_country import protocol_route
                resolved_route = route or protocol_route()
            elif route is not None and str(route.get("plan_region") or "").upper() != "US":
                raise ValueError("maintenance_proxy_country_invalid")
            if env is not None and route is None:
                raise ValueError("maintenance_route_required")
            if not protocol_only:
                resolved_route = route or _resolve_maintenance_us_route()
                from core.operation_country import validate_maintenance_route
                validate_maintenance_route(resolved_route)
        except Exception as exc:
            raise ChatGPTSessionRefreshError(
                "session_refresh_network_config_error",
                "US 维护路由未验证或国家不匹配，无法刷新 Session",
            ) from exc
        if env is None:
            env = BrowserSession(proxy=resolved_route.get("proxy") or "", detect_exit_geo=protocol_only)
        try:
            hydrate_browser_session(
                env,
                record,
                allow_revalidation=allow_revalidation,
                strip_transient_cookies=True,
            )
            before_signature = _session_cookie_signature(record.get("cookies") or [])
            try:
                session_info, session_http_status = _read_session(env)
            except ChatGPTSessionRefreshError as exc:
                _record_quiet_result(
                    email,
                    stage="session_probe",
                    outcome=exc.error_code,
                    old_token_fingerprint=old_fingerprint,
                    status=(
                        "invalid"
                        if exc.error_code in {"session_auth_invalid", "session_refresh_empty"}
                        else None
                    ),
                    exchange_method="http_session",
                )
                if exc.error_code in {"session_auth_invalid", "session_refresh_empty"}:
                    mark_invalid(email, reason=exc.error_code)
                raise
            new_token = normalize_token(session_info.get("accessToken") or "")
            try:
                validate_session_identity(current, session_info, new_token)
            except ChatGPTSessionRefreshError as exc:
                _record_quiet_result(
                    email,
                    stage="session_probe",
                    outcome="session_exchange_identity_mismatch",
                    old_token_fingerprint=old_fingerprint,
                    new_token_fingerprint=_token_fingerprint(new_token),
                    token_changed=new_token != old_token,
                    http_status=session_http_status,
                    status="invalid",
                    exchange_method="http_session",
                )
                raise ChatGPTSessionRefreshError(
                    "session_exchange_identity_mismatch",
                    exc.user_message,
                ) from exc
            snapshot = snapshot_from_http_session(
                env,
                previous=record,
                session_info=session_info,
                account_id=account_id,
            )
            after_signature = _session_cookie_signature(snapshot.get("cookies") or [])
            session_rotated = before_signature != after_signature
            probe_count = 1

            if new_token == old_token:
                _record_quiet_result(
                    email,
                    stage="session_probe",
                    outcome="session_probe_same_token",
                    old_token_fingerprint=old_fingerprint,
                    new_token_fingerprint=old_fingerprint,
                    token_changed=False,
                    session_rotated=session_rotated,
                    http_status=session_http_status,
                    status="stale",
                    exchange_method="http_session",
                )
                raise ChatGPTSessionRefreshError(
                    "session_probe_same_token",
                    "Session 仍返回旧 Token，需刷新会话",
                )

            new_fingerprint = _token_fingerprint(new_token)
            _record_quiet_result(
                email,
                stage="candidate_ready",
                outcome="session_exchange_candidate_ready",
                old_token_fingerprint=old_fingerprint,
                new_token_fingerprint=new_fingerprint,
                token_changed=True,
                session_rotated=session_rotated,
                http_status=session_http_status,
                exchange_method="http_session",
            )
            logger.info(
                "[SessionRefresh] 已生成待验证的新 Token：account_id=%s "
                "old_fp=%s new_fp=%s session_rotated=%s probe_count=%s",
                account_id,
                old_fingerprint,
                new_fingerprint,
                str(session_rotated).lower(),
                probe_count,
            )
            return SessionTokenCandidate(
                account_id=account_id,
                email=email,
                old_token_fingerprint=old_fingerprint,
                new_token_fingerprint=new_fingerprint,
                session_rotated=session_rotated,
                probe_count=probe_count,
                access_token=new_token,
                expected_old_token=old_token,
                session_info=session_info,
                snapshot=snapshot,
                route=resolved_route,
                exchange_method="http_session",
            )
        except ChatGPTSessionStoreError as exc:
            raise ChatGPTSessionRefreshError(exc.error_code, "本地 ChatGPT Session 无效，请重新登录") from exc
        finally:
            if owns_env and env is not None:
                try:
                    env.session.close()
                except Exception:
                    pass


def record_access_token_candidate_result(
    candidate: SessionTokenCandidate,
    *,
    outcome: str,
    stage: str = "business_recheck",
    http_status: int | None = None,
    status: str | None = None,
) -> None:
    _record_quiet_result(
        candidate.email,
        stage=stage,
        outcome=outcome,
        old_token_fingerprint=candidate.old_token_fingerprint,
        new_token_fingerprint=candidate.new_token_fingerprint,
        token_changed=True,
        session_rotated=candidate.session_rotated,
        http_status=http_status,
        status=status,
        exchange_method=getattr(candidate, "exchange_method", "unknown"),
    )


def commit_access_token_candidate(candidate: SessionTokenCandidate) -> dict:
    """Persist a candidate only after its caller has completed business validation."""
    if not isinstance(candidate, SessionTokenCandidate):
        raise ChatGPTSessionRefreshError(
            "session_exchange_contract_mismatch",
            "ChatGPT Web Session 换发结果格式无效",
        )
    if normalize_token(candidate.access_token) == normalize_token(candidate.expected_old_token):
        raise ChatGPTSessionRefreshError(
            "session_exchange_no_rotation",
            "Session 未生成新的 access token",
        )
    if _token_fingerprint(candidate.access_token) != str(candidate.new_token_fingerprint or "").strip().lower():
        raise ChatGPTSessionRefreshError(
            "session_exchange_contract_mismatch",
            "ChatGPT Web Session 换发结果格式无效",
        )
    with _account_lock(candidate.account_id):
        current = db.get_account(candidate.account_id)
        if not current:
            raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
        current_token = normalize_token(current.get("access_token") or "")
        if current_token != candidate.expected_old_token:
            if current_token == candidate.access_token:
                return {
                    "ok": True,
                    "access_token": candidate.access_token,
                    "already_committed": True,
                }
            raise ChatGPTSessionRefreshError(
                "account_token_update_conflict",
                "账号 Token 已被另一任务更新，请重新查询",
            )

        snapshot = dict(candidate.snapshot)
        snapshot["last_quiet_refresh"] = _quiet_diagnostic(
            stage="committed",
            outcome="refreshed",
            old_token_fingerprint=candidate.old_token_fingerprint,
            new_token_fingerprint=candidate.new_token_fingerprint,
            token_changed=True,
            session_rotated=candidate.session_rotated,
            http_status=200,
            exchange_method=getattr(candidate, "exchange_method", "unknown"),
        )
        _session_storage_write(
            candidate.account_id, "session_snapshot", save_snapshot, snapshot, refreshed=True,
        )
        updated = _session_storage_write(
            candidate.account_id, "account_token", db.replace_account_access_token,
            acc_id=candidate.account_id,
            email=candidate.email,
            new_access_token=candidate.access_token,
            expected_old_token=candidate.expected_old_token,
            session_info=candidate.session_info,
        )
        if not updated:
            latest = db.get_account(candidate.account_id) or {}
            if normalize_token(latest.get("access_token") or "") != candidate.access_token:
                raise ChatGPTSessionRefreshError(
                    "account_token_update_conflict",
                    "账号 Token 已被另一任务更新，请重新查询",
                )
        logger.info(
            "[SessionRefresh] 新 Token 已通过业务验证并提交：account_id=%s "
            "old_fp=%s new_fp=%s session_rotated=%s",
            candidate.account_id,
            candidate.old_token_fingerprint,
            candidate.new_token_fingerprint,
            str(candidate.session_rotated).lower(),
        )
        return {
            "ok": True,
            "access_token": candidate.access_token,
            "session_info": candidate.session_info,
            "session_rotated": candidate.session_rotated,
            "token_changed": True,
        }


def save_driver_session_for_account(account: dict, driver, session_info: dict) -> dict:
    account_id = int(account.get("id") or 0)
    if account_id <= 0:
        raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
    with _account_lock(account_id):
        current = db.get_account(account_id)
        if not current:
            raise ChatGPTSessionRefreshError("account_missing", "账号不存在")
        new_token = normalize_token((session_info or {}).get("accessToken") or "")
        if not new_token:
            raise ChatGPTSessionRefreshError("session_refresh_empty", "登录完成但未取得 access token")
        if token_claims(new_token).get("token_expired") is True:
            raise ChatGPTSessionRefreshError(
                "token_expired",
                "登录完成但 access token 已过期",
            )
        try:
            validate_session_identity(current, session_info, new_token)
        except ChatGPTSessionRefreshError:
            mark_invalid(
                current.get("email") or "",
                reason="session_identity_mismatch",
            )
            raise
        try:
            snapshot = capture_driver_snapshot(
                driver,
                email=current.get("email") or "",
                account_id=account_id,
                session_info=session_info,
            )
            old_token = normalize_token(current.get("access_token") or "")
            snapshot["last_quiet_refresh"] = _quiet_diagnostic(
                stage="roxy_login",
                outcome="refreshed",
                old_token_fingerprint=_token_fingerprint(old_token),
                new_token_fingerprint=_token_fingerprint(new_token),
                token_changed=new_token != old_token,
                session_rotated=True,
                http_status=200,
                exchange_method="roxy_login",
            )
            _session_storage_write(
                account_id, "session_snapshot", save_snapshot, snapshot, refreshed=True,
            )
        except ChatGPTSessionStoreError as exc:
            raise ChatGPTSessionRefreshError(exc.error_code, "登录完成但 Session Cookie 保存失败") from exc
        old_token = normalize_token(current.get("access_token") or "")
        updated = _session_storage_write(
            account_id, "account_token", db.replace_account_access_token,
            acc_id=account_id,
            email=current.get("email") or "",
            new_access_token=new_token,
            expected_old_token=old_token,
            session_info=session_info,
        )
        if not updated:
            latest = db.get_account(account_id) or {}
            if normalize_token(latest.get("access_token") or "") != new_token:
                raise ChatGPTSessionRefreshError(
                    "account_token_update_conflict",
                    "账号 Token 已被另一任务更新，请重新查询",
                )
        return {"access_token": new_token, "session_info": session_info}
''')

def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
