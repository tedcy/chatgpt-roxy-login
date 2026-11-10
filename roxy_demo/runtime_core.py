"""Web/task ownership around the unchanged production Roxy window manager."""
from queue import Empty, Queue
import threading

from .kernel_bridge import bootstrap, bound, get_account


MESSAGES = {"queued": "等待打开", "opening": "正在打开 Roxy", "restoring_session": "正在恢复已有会话",
            "automatic_login": "正在执行主项目登录流程", "waiting_user": "请在 Roxy 窗口中完成额外验证",
            "ready": "会话已保存", "closing": "正在保存会话并关闭", "closed": "窗口已关闭", "failed": "任务失败",
            "interrupted": "环境关闭未确认，可重试关闭"}


class Manager:
    def __init__(self, store, browser_factory=None):
        self.store = store
        self.lock = threading.RLock()
        self.owner = None
        self.commands = {}
        self.temporary = set()
        self.configs = {}
        self.closing = False
        self.messages = {}

    def _initialize(self):
        if self.owner is not None:
            return
        bootstrap(self.store)
        from core.roxy_manual_window import RoxyManualWindowManager
        host = self

        class WindowOwner(RoxyManualWindowManager):
            def _run(self, ctx):
                command_queue = host.commands.get(ctx.account_id)
                with bound(host.store, host.configs[ctx.account_id]):
                    try:
                        return super()._run(ctx)
                    finally:
                        with host.lock:
                            if host.commands.get(ctx.account_id) is command_queue:
                                host.commands.pop(ctx.account_id, None)
                                host.temporary.discard(ctx.account_id)

            def _wait_until_closed(self, ctx):
                # Host ownership hook: browser commands stay on the original owner thread.
                # The authentication, validation and save calls remain production functions.
                if ctx.account_id in host.temporary:
                    host.messages[ctx.account_id] = "会话刷新并保存成功"
                    return
                while not ctx.stop_event.wait(2.0):
                    if not self._check_driver_alive(ctx):
                        return
                    try:
                        command = host.commands[ctx.account_id].get_nowait()
                    except Empty:
                        command = None
                    if command == "refresh":
                        from core.chatgpt_session_refresh import ensure_roxy_session_on_driver, ChatGPTSessionRefreshError
                        from core.roxy_registration import _reset_pooled_profile_identity
                        from .kernel_bridge import state
                        account = get_account(ctx.account_id)
                        fresh = [False]
                        self._set_state(ctx, status="restoring_session", stage="session_refresh")
                        try:
                            ctx.driver.refresh()
                            info = ensure_roxy_session_on_driver(
                                ctx.driver, account, account_id=ctx.account_id, stop_event=ctx.stop_event,
                                restore_saved_session=True, reset_identity=lambda: _reset_pooled_profile_identity(ctx.driver),
                                on_restore_miss=lambda reason: fresh.__setitem__(0, True),
                                on_manual_wait=lambda: self._set_state(ctx, status="waiting_user", stage="waiting_user"),
                                manual_wait_timeout=None,
                                login_function=lambda driver, row, **kwargs: self._run_automatic_fresh_login(
                                    ctx, row, use_headed=bool(state().config["ROXY_REGISTRATION_LOW_TRAFFIC_MODE"])))
                            if fresh[0] and account.get("access_token"):
                                self._persist_fresh_login(ctx, account, info)
                            else:
                                self._persist_session(ctx, account, info)
                            host.messages[ctx.account_id] = "会话刷新并保存成功"
                            self._set_state(ctx, status="ready", stage="ready", error_code=None)
                        except ChatGPTSessionRefreshError as exc:
                            host.messages[ctx.account_id] = exc.user_message
                            self._set_state(ctx, status="waiting_user", stage="waiting_user", error_code=exc.error_code)

        self.owner = WindowOwner()

    @property
    def jobs(self):
        if self.owner is None:
            return {}
        with self.owner._lock:
            contexts = dict(self.owner._contexts)
        with self.store.lock:
            accounts = self.store._accounts()["accounts"]
        return {row["id"]: contexts[row["kernel_account_id"]]
                for row in accounts if row["kernel_account_id"] in contexts}

    def import_accounts(self, text):
        with self.lock:
            return self.store.import_accounts(text, self._busy_accounts())

    def _busy_accounts(self):
        return set(self.jobs) | {row["id"] for row in self.store._accounts()["accounts"]
            if (row.get("kernel_fields") or {}).get("roxy_window_status") in {
                "queued", "opening", "ready", "automatic_login", "restoring_session", "waiting_user", "closing", "interrupted"}}

    def set_proxy(self, account_id, proxy):
        with self.lock:
            if account_id in self._busy_accounts():
                raise ValueError("该账号有窗口或任务，请先关闭再修改代理")
            self.store.set_proxy(account_id, proxy)

    def status(self):
        with self.lock:
            rows = self.store.list()
            for row in rows:
                account = self.store.get(row["id"])
                fields = account.get("kernel_fields") or {}
                kernel_id = account["kernel_account_id"]
                raw = fields.get("roxy_window_status") or "closed"
                status = {"automatic_login": "logging_in", "restoring_session": "refreshing", "interrupted": "cleanup_failed"}.get(raw, raw)
                message = self.messages.get(kernel_id) or fields.get("roxy_window_error_code") or MESSAGES.get(raw, raw)
                row.update(state=status, message=message)
            return rows

    def action(self, account_id, action):
        with self.lock:
            if self.closing:
                raise ValueError("服务正在退出")
            account = self.store.get(account_id)
            if action != "close" and not account["proxy"]:
                raise ValueError("请先为该账号设置代理")
            config = self.store.get_settings()
            if action != "close" and not all(config[key] for key in ("ROXY_API_TOKEN", "ROXY_WORKSPACE_ID", "ROXY_PROJECT_ID")):
                raise ValueError("请先在配置页填写 Roxy API Key，并获取、选择团队和项目")
            self._initialize()
            kernel_id = account["kernel_account_id"]
            with bound(self.store, config):
                if action == "close":
                    return self.owner.close(kernel_id)
                if kernel_id in self.owner._contexts:
                    current = next(row["state"] for row in self.status() if row["id"] == account_id)
                    if action == "refresh" and current in {"ready", "waiting_user"}:
                        self.commands[kernel_id].put("refresh")
                        return
                    raise ValueError("该账号已有窗口或任务，请等待或先关闭")
                self.configs[kernel_id] = config
                self.commands[kernel_id] = Queue()
                self.messages.pop(kernel_id, None)
                if action == "refresh":
                    self.temporary.add(kernel_id)
                result = self.owner.open(kernel_id, proxy=account["proxy"], window_driver="roxy", raw_trace=False)
                if not result.get("accepted"):
                    raise ValueError(result.get("error_code") or "窗口无法打开")

    def shutdown(self):
        self.closing = True
        if self.owner is None:
            return
        contexts = list(self.owner._contexts.values())
        for ctx in contexts:
            ctx.stop_event.set()
        for ctx in contexts:
            if ctx.thread and ctx.thread.is_alive():
                ctx.thread.join(5)
