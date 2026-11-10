from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request

from .runtime import Manager
from .roxy import Roxy, RoxyError
from .settings import POLICIES, SCHEMA, validate
from .storage import Store, StoreError


def create_app(data_dir=None, browser_factory=None):
    root = Path(__file__).resolve().parent.parent
    app = Flask(__name__, template_folder=str(root / "templates"), static_folder=str(root / "static"))
    app.json.sort_keys = False
    app.config.update(MAX_CONTENT_LENGTH=2 * 1024 * 1024)
    store = Store(data_dir if data_dir is not None else root / "data")
    manager = Manager(store, **({"browser_factory": browser_factory} if browser_factory else {}))
    app.extensions.update(demo_store=store, demo_manager=manager)

    @app.before_request
    def local_only():
        if request.remote_addr not in {"127.0.0.1", "::1", None}:
            return jsonify(error="仅供本机使用"), 403
        if urlsplit(request.host_url).hostname not in {"127.0.0.1", "localhost", "::1"}:
            return jsonify(error="请通过本机地址访问"), 403
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not request.is_json:
            return jsonify(error="操作请求必须为 JSON"), 415
        # The UI sends same-origin JSON; cross-origin requests are rejected without CORS.
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            return jsonify(error="请求来源无效"), 403

    @app.after_request
    def no_store(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(StoreError)
    def storage_error(exc):
        return jsonify(error=str(exc)), 503

    @app.errorhandler(RoxyError)
    def roxy_error(exc):
        return jsonify(error=str(exc)), 503

    @app.errorhandler(413)
    def too_large(_exc):
        return jsonify(error="请求不能超过 2 MB"), 413

    def body():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise ValueError("请求内容必须是 JSON 对象")
        return value

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/settings")
    def get_settings():
        values = store.get_settings()
        # Never return the API Token in the settings response. Blank means preserve on save.
        present = bool(values.pop("ROXY_API_TOKEN"))
        extra = dict(values["ROXY_OPEN_EXTRA_PARAMS"])
        extra["args"] = list(extra.get("args") or []) + values["ROXY_BROWSER_ARGS"]
        effective = {"ROXY_OPEN_EXTRA_PARAMS": extra,
                     "ROXY_RANDOM_OS_CHOICES": ",".join(values["ROXY_RANDOM_OS_CHOICES"])}
        return jsonify(schema=SCHEMA, policies=POLICIES, values=values, effective=effective, api_token_set=present)

    @app.put("/api/settings")
    def save_settings():
        values = body()
        if not values.get("ROXY_API_TOKEN"):
            values["ROXY_API_TOKEN"] = store.get_settings()["ROXY_API_TOKEN"]
        store.save_settings(values)
        return jsonify(ok=True, message="配置已保存，新窗口使用新配置；端口变更需重启服务")

    @app.post("/api/roxy/workspaces")
    def get_workspaces():
        saved = store.get_settings()
        values = {**saved, **body()}
        if not values.get("ROXY_API_TOKEN"):
            values["ROXY_API_TOKEN"] = saved["ROXY_API_TOKEN"]
        config = validate(values)
        if not config["ROXY_API_TOKEN"]:
            raise ValueError("请先从 Roxy 客户端的 API 设置复制 API Key，填入 API Token")
        client = Roxy(config, store)
        try:
            # Query with the current form; do not persist draft credentials or IDs here.
            return jsonify(workspaces=client.list_workspaces())
        finally:
            client.http.close()

    @app.get("/api/accounts")
    def list_accounts():
        return jsonify(accounts=manager.status())

    @app.post("/api/accounts/import")
    def import_accounts():
        return jsonify(ok=True, **manager.import_accounts(body().get("text")))

    @app.put("/api/accounts/<account_id>/proxy")
    def set_proxy(account_id):
        manager.set_proxy(account_id, body().get("proxy"))
        return jsonify(ok=True)

    @app.get("/api/accounts/<account_id>/proxy")
    def get_proxy(account_id):
        # Only an explicit edit action requests this secret, never the list poll.
        return jsonify(proxy=store.get(account_id)["proxy"])

    @app.get("/api/accounts/<account_id>/token")
    def get_token(account_id):
        token = store.token(account_id)
        if not token:
            raise ValueError("该账号尚未保存 Token，请先打开或刷新会话")
        return jsonify(token=token)

    @app.post("/api/accounts/<account_id>/<action>")
    def account_action(account_id, action):
        if action not in {"open", "refresh", "close"}:
            raise ValueError("操作不存在")
        body()
        manager.action(account_id, action)
        return jsonify(ok=True), 202

    return app
