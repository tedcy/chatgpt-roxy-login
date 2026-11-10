"""Bindings around an unmodified production source snapshot.

Only storage, configuration and explicitly excluded services live here. Browser
actions, auth state machines and Session validation are loaded from upstream/.
"""
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from copy import deepcopy
from datetime import datetime, timezone
import ast
import base64
import hashlib
import importlib
import json
import logging
import os
from pathlib import Path
import re
import sys
import symtable
import threading
import time
import types
from urllib.parse import urlparse, urlsplit, urlunsplit, quote, unquote
from uuid import uuid4


PROJECT = Path(__file__).resolve().parent.parent
UPSTREAM = PROJECT / "upstream"
_active = ContextVar("roxy_demo_kernel", default=None)
_default = None
_booted = False
_boot_lock = threading.RLock()
LOADED_SLICES = []

def state():
    value = _active.get() or _default
    if value is None:
        raise RuntimeError("kernel_storage_not_bound")
    return value


@contextmanager
def bound(store, config=None):
    config = config or store.get_settings()
    token = _active.set(types.SimpleNamespace(store=store, config=config))
    try:
        yield
    finally:
        _active.reset(token)


def module(name, **values):
    result = types.ModuleType(name)
    result.__dict__.update(values)
    sys.modules[name] = result
    parent, _, child = name.rpartition(".")
    if parent in sys.modules:
        setattr(sys.modules[parent], child, result)
    return result


def disabled(*args, **kwargs):
    raise RuntimeError("This service is outside the standalone browser login scope")


def noop(*args, **kwargs):
    return None


class DisabledService:
    enabled = False
    def __init__(self, *args, **kwargs):
        pass
    def __getattr__(self, name):
        return noop
    def start(self, *args, **kwargs):
        return False
    def stop(self, *args, **kwargs):
        return {}


def load_slices(name, filename, names, extra=None):
    """Execute exact source segments, including nested imports, without AST rewriting."""
    path = UPSTREAM / filename
    source = path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source)
    wrapper = next((node for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(item, ast.Name) and item.id == "_SOURCE" for item in node.targets)), None)
    if wrapper:
        source = ast.literal_eval(wrapper.value.args[0])
        tree = ast.parse(source)
    # Include each selected definition's same-file globals verbatim. This closes
    # constants/helpers without importing the facade's unrelated service startup.
    definitions = {}
    for node in tree.body:
        symbol = getattr(node, "name", None)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            items = node.targets if isinstance(node, ast.Assign) else [node.target]
            symbol = next((item.id for item in items if isinstance(item, ast.Name)), None)
        if symbol:
            definitions[symbol] = node
    names = set(names)
    pending = list(names)
    def global_references(table):
        result = {item.get_name() for item in table.get_symbols() if item.is_global() and item.is_referenced()}
        for child in table.get_children():
            result.update(global_references(child))
        return result
    while pending:
        node = definitions.get(pending.pop())
        if node is None:
            continue
        segment = ast.get_source_segment(source, node)
        for dependency in global_references(symtable.symtable(segment, str(path), "exec")):
            if dependency in definitions and dependency not in names:
                names.add(dependency)
                pending.append(dependency)
    target = sys.modules.get(name) or module(name)
    common = dict(__file__=str(path), __package__=name.rpartition(".")[0],
                  base64=base64, hashlib=hashlib, json=json, logging=logging, os=os,
                  re=re, threading=threading, time=time, datetime=datetime, timezone=timezone,
                  Path=Path, urlparse=urlparse, urlsplit=urlsplit, urlunsplit=urlunsplit,
                  quote=quote, unquote=unquote, deepcopy=deepcopy,
                  logger=logging.getLogger(name))
    target.__dict__.update(common)
    target.__dict__.update(extra or {})
    found = set()
    for node in tree.body:
        symbol = getattr(node, "name", None)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            items = node.targets if isinstance(node, ast.Assign) else [node.target]
            symbol = next((item.id for item in items if isinstance(item, ast.Name)), None)
        if symbol not in names:
            continue
        segment = ast.get_source_segment(source, node)
        exec(compile("from __future__ import annotations\n" + segment, str(path), "exec"), target.__dict__)
        LOADED_SLICES.append({"module": name, "source": filename, "symbol": symbol,
                              "sha256": hashlib.sha256(segment.encode()).hexdigest()})
        found.add(symbol)
    missing = set(names) - found
    if missing:
        raise RuntimeError(f"Missing upstream definitions: {filename}: {sorted(missing)}")
    return target


def config_module(name):
    target = module(name)
    def read(key):
        config = state().config
        from .settings import FIXED_CONFIG
        if key in config:
            value = deepcopy(config[key])
            if key == "ROXY_RANDOM_OS_CHOICES" and isinstance(value, list):
                return ",".join(value)
            if key == "ROXY_OPEN_EXTRA_PARAMS":
                value["args"] = list(value.get("args") or []) + list(config.get("ROXY_BROWSER_ARGS") or [])
            return value
        values = FIXED_CONFIG.get(name.rsplit(".", 1)[1], {})
        if key in values:
            return deepcopy(values[key])
        raise AttributeError(key)
    target.__getattr__ = read
    return target


def _kernel_account(row):
    if row is None:
        return None
    result = deepcopy(row)
    result["id"] = row["kernel_account_id"]
    result["registration_password"] = row["password"]
    result["access_token"] = ((row.get("session") or {}).get("info") or {}).get("accessToken", "")
    result.update(row.get("kernel_fields") or {})
    return result


def get_account(account_id):
    store = state().store
    with store.lock:
        row = next((row for row in store._accounts()["accounts"] if row["kernel_account_id"] == int(account_id)), None)
        return _kernel_account(row)


def mutate_account(account_id, callback):
    store = state().store
    with store.lock:
        data = store._accounts()
        row = next((row for row in data["accounts"] if row["kernel_account_id"] == int(account_id)), None)
        if row is None:
            return False
        previous = deepcopy(row)
        result = callback(row)
        if result is not False and row != previous:
            store._write("accounts.json", data)
        return result


def update_window(account_id, run_id, **values):
    def change(row):
        fields = row.setdefault("kernel_fields", {})
        if fields.get("roxy_window_run_id") != run_id:
            return False
        for key, value in values.items():
            fields["roxy_window_" + key] = value
        return True
    return mutate_account(account_id, change)


def claim_window(account_id, **options):
    def change(row):
        fields = row.setdefault("kernel_fields", {})
        if fields.get("roxy_window_status") in {"queued", "opening", "ready", "automatic_login", "restoring_session", "waiting_user", "closing", "interrupted"}:
            return {"accepted": False, "busy": True, "error_code": "manual_window_busy"}
        run_id = uuid4().hex
        fields.update(roxy_window_status="queued", roxy_window_run_id=run_id,
                      roxy_window_driver=options.get("window_driver", "roxy"),
                      roxy_window_error_code=None, roxy_window_message="")
        return {"accepted": True, "run_id": run_id}
    return mutate_account(account_id, change) or {"accepted": False, "error_code": "account_not_found"}


def replace_token(*, acc_id, email, new_access_token, expected_old_token=None, session_info=None):
    new_token = str(new_access_token or "").strip()
    target_email = str(email or "").strip().lower()
    if not new_token or not target_email:
        return False
    def change(row):
        current = ((row.get("session") or {}).get("info") or {}).get("accessToken", "")
        if row["email"].strip().lower() != target_email:
            return False
        if expected_old_token is not None and str(current).strip() != str(expected_old_token).strip():
            return False
        info = session_info if isinstance(session_info, dict) else {}
        snapshot = row.setdefault("session", None) or {"cookies": []}
        snapshot["info"] = {**deepcopy(info), "accessToken": new_token}
        row["session"] = snapshot
        fields = row.setdefault("kernel_fields", {})
        evidence = getattr(session_info, "login_evidence", None)
        if evidence is not None:
            fields["last_login_evidence"] = {key: bool(getattr(evidence, key, False))
                                             for key in ("password_verified", "totp_verified", "email_otp_verified")}
        if new_token != str(current).strip():
            fields["session_refresh_required"] = False
        user = info.get("user") if isinstance(info.get("user"), dict) else {}
        remote = info.get("account") if isinstance(info.get("account"), dict) else {}
        for key, value in (("user_id", user.get("id")), ("user_name", user.get("name")),
                           ("account_id", remote.get("id")), ("plan_type", remote.get("planType")),
                           ("expires_at", info.get("expires"))):
            if value:
                fields[key] = value
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        fields.update(token_updated_at=now, updated_at=now)
        row["last_result"] = "会话已保存"
        return True
    return mutate_account(acc_id, change)


class SessionDbError(RuntimeError):
    def __init__(self, error_code):
        self.error_code = error_code
        super().__init__(error_code)


class JsonSessions:
    """Compatibility with the production Session backend; never opens SQLite."""
    def __init__(self, path, **options):
        self.record_status = options["record_status"]
    def initialize(self):
        return {"backend": "json", "current_count": len(state().store.list())}
    def get(self, email):
        store = state().store
        with store.lock:
            row = next((row for row in store._accounts()["accounts"] if row["email"] == email), None)
            if not row or not row.get("session"):
                return None
            value = deepcopy(row["session"])
            value.update(email=email, account_id=row["kernel_account_id"])
            value.setdefault("status", "ready")
            value.setdefault("session_expires_at", (value.get("info") or {}).get("expires", ""))
            return value
    def save(self, record, *, refreshed=False):
        store = state().store
        with store.lock:
            data = store._accounts()
            key = str(record.get("email") or "").strip().lower()
            row = next((row for row in data["accounts"] if row["email"] == key), None)
            if row is None:
                raise SessionDbError("session_account_missing")
            old = row.get("session") or {}
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            value = deepcopy(record)
            value.update(email=key, updated_at=now, status="ready")
            value.pop("status_reason", None)
            if old:
                value["captured_at"] = str(old.get("captured_at") or value.get("captured_at"))
                if not refreshed and old.get("last_refresh_at"):
                    value["last_refresh_at"] = old["last_refresh_at"]
                if not value.get("last_quiet_refresh") and old.get("last_quiet_refresh"):
                    value["last_quiet_refresh"] = deepcopy(old["last_quiet_refresh"])
            if refreshed:
                value["last_refresh_at"] = now
            # The Session write completes here, before the separate account
            # Token CAS, exactly as in the production save sequence. The info
            # wrapper represents account fields, not the Session backend.
            row["session"] = {**old, **value, "info": deepcopy(old.get("info") or {}), "saved_at": now}
            row["session"].pop("status_reason", None)
            store._write("accounts.json", data)
            return deepcopy(value)
    def bind(self, email, account_id):
        return bool(self.get(email))
    def mark(self, email, status, *, reason=""):
        store = state().store
        with store.lock:
            data = store._accounts()
            row = next((row for row in data["accounts"] if row["email"] == email), None)
            if not row or not row.get("session"):
                return False
            row["session"].update(status=status, status_reason=reason)
            store._write("accounts.json", data)
            return True
    def update_record(self, email, callback):
        store = state().store
        with store.lock:
            data = store._accounts()
            row = next((row for row in data["accounts"] if row["email"] == email), None)
            if not row or not row.get("session"):
                return False
            record = self.get(email)
            value = callback(record)
            row["session"].update(value if isinstance(value, dict) else record)
            store._write("accounts.json", data)
            return True
    def status_map(self, *, email=None):
        result = {}
        for row in state().store.list():
            if email is None or email == row["email"]:
                record = self.get(row["email"])
                result[row["email"]] = {"status": self.record_status(record)}
        return result


def bootstrap(store):
    global _default, _booted
    _default = types.SimpleNamespace(store=store, config=store.get_settings())
    with _boot_lock:
        if _booted:
            return
        if "core" in sys.modules:
            raise RuntimeError("Production core already imported from another checkout; start a separate standalone process")
        core = module("core")
        core.__path__ = [str(UPSTREAM / "core")]
        config = module("config")
        config.__path__ = []
        for name in ("roxybrowser", "humanize", "twofa", "browser", "proxy", "codex"):
            config_module("config." + name)
        sys.modules["config.proxy"].pick_proxy = disabled
        _install_boundaries()
        _load_facades()
        _booted = True


def _install_boundaries():
    from .storage import StoreError
    module("core.db", get_account=get_account, AccountStoreError=StoreError,
           account_registration_password=lambda row: row.get("registration_password", ""),
           claim_account_roxy_window=claim_window, update_account_roxy_window=update_window,
           finish_account_roxy_window=update_window, replace_account_access_token=replace_token,
           list_roxy_window_states=lambda: [get_account(row["kernel_account_id"]) for row in state().store._accounts()["accounts"]],
           mark_account_session_refresh_waiting=lambda account_id: None,
           mark_account_unusable=lambda account_id, **kwargs: mutate_account(account_id, lambda row: row.setdefault("kernel_fields", {}).update(unusable=True)),
           confirm_account_totp=lambda *args, **kwargs: True, _account_twofa_identity_revision=lambda row: row.get("twofa_identity_revision", 0))
    module("core.chatgpt_session_db", ChatGPTSessionSQLiteStore=JsonSessions, SessionDbError=SessionDbError)
    module("core.account_operation_log", begin_run=noop, rollback_run=noop, task_log_context=lambda *a, **k: nullcontext())
    module("core.action_progress", progress=noop, update=noop)
    module("core.account_export", save_account_data=disabled)
    module("core.email_provider", **{name: disabled for name in (
        "mark_registration_failed", "mark_registration_account_created", "mark_registration_existing_account_detected",
        "mark_registration_email_otp_submitted", "mark_registration_profile_submission", "prepare_otp_context",
        "resolve_email_source", "wait_for_otp", "registration_failure_email_status", "release_email")})
    module("core.registration_verification_traffic", metered_browser_driver=lambda driver: driver)
    module("core.roxy_traffic_meter", RoxyTrafficMeter=DisabledService, empty_network_usage=lambda: {})
    module("core.roxy_chatgpt_contract_trace", RoxyChatGPTContractTracer=DisabledService)
    module("core.roxy_otp_observer", ensure_observer=noop, get_observer=noop, mark_mailbox=noop, mark_submit=noop)
    module("core.roxy_dom_failure_diagnostic", create_recorder=DisabledService, get_recorder=noop, attach_recorder=noop,
           finalize_recorder=noop, record_dom_event=noop, RoxyFailureDomRecorder=DisabledService,
           DEFAULT_DIAGNOSTIC_DIR=PROJECT / "data" / "disabled_diagnostics", MAX_FILE_BYTES=0,
           _cleanup_old_files=noop, _safe_route=lambda value: "")
    module("core.roxy_raw_network_trace", configured_raw_trace_sample_percent=lambda: 0)
    module("core.hme_task_scope", deferred_hme_auth=lambda *a, **k: (lambda func: func), needs_hme_scope=lambda *args: False)
    module("core.registration_service", check_stop=lambda: None)
    module("core.session", BrowserSession=DisabledService)
    module("core.task_queue_helpers", AdjustableConcurrencyGate=DisabledService)
    module("core.task_concurrency", operation_limit=lambda key: 15, query_default=lambda *a, **k: 15)
    module("core.session_identity_diagnostic", identity_failure=noop)
    module("core.registration_login_route", selection=disabled)


def _load_facades():
    from collections.abc import Callable, Iterator
    from contextlib import contextmanager
    from concurrent.futures import ThreadPoolExecutor
    openai = load_slices("core.openai_auth", "source_facades/openai_auth.py", {
        "EmailOtpInvalidError", "AccountUnusableError", "detect_account_unusable_text", "detect_account_unusable_response_body", "_extract_error_code"})
    from core.plan_promo import first_plus_free_trial_campaign, normalize_plan_promo_campaigns
    from core.account_grace_period import parse_entitlement
    plan = load_slices("core.chatgpt_plan", "source_facades/chatgpt_plan.py", {
        "now_iso", "normalize_token", "decode_jwt_payload_unverified", "token_claims", "normalize_promo_check_region",
        "check_account_plan_in_driver"}, extra={"first_plus_free_trial_campaign": first_plus_free_trial_campaign,
        "normalize_plan_promo_campaigns": normalize_plan_promo_campaigns, "parse_grace_period": parse_entitlement})
    plan.check_account_promos = lambda *args, **kwargs: {"ok": False, "error_code": "promo_check_unknown"}
    for name in ("check_account_plan", "plan_check_region_settings", "resolve_plan_check_route", "resolve_plan_check_region_route"):
        setattr(plan, name, disabled)
    proxy = load_slices("core.proxy_sid", "source_facades/proxy_sid.py", {
        "mask_proxy_url", "_redact_proxy_text", "redact_proxy_metadata", "RegistrationProxyCountryError",
        "normalize_registration_proxy_countries"})
    proxy.validate_headed_chrome_proxy_country_runtime = disabled
    proxy.select_default_proxy = disabled
    proxy.ProxySelection = DisabledService
    # Bind the original facade's standard-library globals, constants and error/lock definitions.
    candidate_types = importlib.import_module("core.session_candidate")
    session_store = importlib.import_module("core.chatgpt_session_store")
    refresh = module("core.chatgpt_session_refresh")
    for source in (plan, session_store, candidate_types):
        refresh.__dict__.update({key: value for key, value in vars(source).items() if not key.startswith("__")})
    refresh.__dict__.update(db=sys.modules["core.db"], Callable=Callable, Iterator=Iterator,
                            contextmanager=contextmanager, ThreadPoolExecutor=ThreadPoolExecutor,
                            AccountUnusableError=openai.AccountUnusableError,
                            detect_account_unusable_text=openai.detect_account_unusable_text,
                            BrowserSession=DisabledService, RoxyChatGPTContractTracer=DisabledService,
                            _ACCOUNT_LOCKS_GUARD=threading.Lock(), _ACCOUNT_LOCKS={},
                            _SESSION_AFTER_OTP_TIMEOUT=40, _SAVED_SESSION_PROBE_TIMEOUT=60,
                            _MANUAL_LOGIN_TIMEOUT=300)
    load_slices("core.chatgpt_session_refresh", "source_facades/chatgpt_session_refresh.py", {
        "ChatGPTSessionRefreshError", "_safe_session_restore_reason", "_SAFE_SESSION_RESTORE_REASONS", "_account_lock"})
    from core.roxy_login_primitives import PASSWORD_SUBMIT_TRANSITION_TIMEOUT
    refresh.PASSWORD_SUBMIT_TRANSITION_TIMEOUT = PASSWORD_SUBMIT_TRANSITION_TIMEOUT
    for name in ("session_refresh_domains.session", "roxy_auth_domains.login", "session_refresh_domains.restore", "roxy_auth_domains.candidate"):
        importlib.import_module("core." + name).register(refresh.__dict__)
