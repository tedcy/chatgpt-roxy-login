"""The complete inventory of editable settings, also rendered by the UI."""
from copy import deepcopy
import json
import math
from pathlib import Path
from urllib.parse import urlsplit


def field(group, label, default, kind="str", minimum=None, maximum=None, choices=None):
    return dict(group=group, label=label, default=default, kind=kind,
                minimum=minimum, maximum=maximum, choices=choices)


SCHEMA = {
    "ROXY_API_BASE": field("Roxy 连接", "本地 API 地址", "http://127.0.0.1:50000"),
    "ROXY_API_TOKEN": field("Roxy 连接", "API Token", "", "secret"),
    "ROXY_WORKSPACE_ID": field("Roxy 连接", "团队 / Workspace ID", ""),
    "ROXY_PROJECT_ID": field("Roxy 连接", "项目 / Project ID", ""),
    "ROXY_WORKSPACE_LIST_PATH": field("Roxy 接口", "获取团队/项目路径", "/browser/workspace"),
    "ROXY_WORKSPACE_LIST_METHOD": field("Roxy 接口", "获取团队/项目方法", "GET", choices=["GET", "POST"]),
    "ROXY_LIST_PATH": field("Roxy 接口", "缓存环境列表路径", "/browser/list_v3"),
    "ROXY_LIST_METHOD": field("Roxy 接口", "缓存环境列表方法", "GET", choices=["GET", "POST"]),
    "ROXY_DETAIL_PATH": field("Roxy 接口", "环境详情路径", "/browser/detail"),
    "ROXY_DETAIL_METHOD": field("Roxy 接口", "环境详情方法", "GET", choices=["GET", "POST"]),
    "ROXY_CONFIGURATION_PATH": field("Roxy 接口", "完整指纹配置回读路径", "/browser/list"),
    "ROXY_CONFIGURATION_METHOD": field("Roxy 接口", "完整指纹配置回读方法", "GET", choices=["GET", "POST"]),
    "ROXY_MODIFY_PATH": field("Roxy 接口", "修改环境路径", "/browser/mdf"),
    "ROXY_MODIFY_METHOD": field("Roxy 接口", "修改环境方法", "POST", choices=["POST"]),
    "ROXY_RANDOMIZE_PATH": field("Roxy 接口", "刷新环境指纹路径", "/browser/random_env"),
    "ROXY_RANDOMIZE_METHOD": field("Roxy 接口", "刷新环境指纹方法", "POST", choices=["POST"]),
    "ROXY_PROFILE_CACHE_REUSE": field("Roxy 原生指纹", "优先复用空闲缓存环境；无可用环境时创建", True, "bool"),
    "ROXY_REGISTRATION_LOW_TRAFFIC_MODE": field("Roxy 登录内核", "使用主项目 Playwright/CDP 登录内核", True, "bool"),
    "ROXY_SELENIUM_TIMEOUT": field("超时与限流", "主项目 Selenium/管理请求超时（秒）", 90, "int", 1, 300),
    "ROXY_CREATE_PATH": field("Roxy 接口", "创建路径", "/browser/create"),
    "ROXY_CREATE_METHOD": field("Roxy 接口", "创建方法", "POST", choices=["POST"]),
    "ROXY_OPEN_PATH": field("Roxy 接口", "打开路径", "/browser/open"),
    "ROXY_OPEN_METHOD": field("Roxy 接口", "打开方法", "POST", choices=["GET", "POST"]),
    "ROXY_CLOSE_PATH": field("Roxy 接口", "关闭路径", "/browser/close"),
    "ROXY_CLOSE_METHOD": field("Roxy 接口", "关闭方法", "POST", choices=["GET", "POST"]),
    "ROXY_DELETE_PATH": field("Roxy 接口", "删除路径", "/browser/delete"),
    "ROXY_DELETE_METHOD": field("Roxy 接口", "删除方法", "POST", choices=["GET", "POST"]),
    "ROXY_PROFILE_CREATE_PAYLOAD": field("Roxy 接口", "附加创建参数（JSON 对象）", {}, "object"),
    "ROXY_OPEN_EXTRA_PARAMS": field("Roxy 接口", "附加打开参数（JSON 对象）", {}, "object"),
    "ROXY_BROWSER_ARGS": field("Roxy 接口", "启动参数（JSON 字符串数组）", ["--disable-http2", "--disable-component-update"], "strings"),
    "ROXY_API_RETRIES": field("超时与限流", "幂等 API 最大尝试次数（创建只尝试一次）", 3, "int", 1, 6),
    "ROXY_API_RETRY_DELAY": field("超时与限流", "API 重试间隔（秒）", 2, "float", 0.5, 30),
    "ROXY_API_RATE_LIMIT_PER_MINUTE": field("超时与限流", "每分钟 API 请求上限", 90, "int", 1, 1000),
    "ROXY_API_MAX_IN_FLIGHT": field("超时与限流", "API 最大在途请求数", 25, "int", 1, 100),
    "REGISTRATION_WORKER_TIMEOUT_SECONDS": field("超时与限流", "主项目浏览器任务超时（秒）", 900, "int", 30, 7200),
    "BROWSER_OTP_READY_TIMEOUT_SECONDS": field("超时与限流", "主项目验证码页面就绪超时（秒）", 60, "int", 10, 300),
    "PLAN_CHECK_TIMEOUT": field("超时与限流", "浏览器内业务健康校验超时（秒）", 15, "float", 1, 60),
    "ROXY_RANDOM_OS_ON_CREATE": field("Roxy 原生指纹", "随机操作系统", True, "bool"),
    "ROXY_RANDOM_OS_CHOICES": field("Roxy 原生指纹", "随机系统候选（JSON 数组）", ["Windows", "macOS"], "strings"),
    "ROXY_DEFAULT_OS": field("Roxy 原生指纹", "非随机时的操作系统", "macOS", choices=["Windows", "macOS", "Linux"]),
    "ROXY_DEFAULT_OS_VERSION": field("Roxy 原生指纹", "非随机时的系统版本（可空）", ""),
    "ROXY_RANDOM_PROFILE_NAME_ON_CREATE": field("Roxy 原生指纹", "随机环境名称", True, "bool"),
    "ROXY_PROFILE_NAME_PREFIX": field("Roxy 原生指纹", "环境名称前缀（缓存池使用原版名称）", "rb"),
    "ROXY_WEBRTC_REPLACE": field("Roxy 原生指纹", "WebRTC 使用代理出口", False, "bool"),
    "ROXY_MAC_M3_WEBGL": field("Roxy 原生指纹", "macOS 使用 Apple M3 WebGL", False, "bool"),
    "ENABLE_HUMANIZE_BROWSER_ACTIONS": field("模拟操作", "主项目共用/Selenium 人工操作总开关", True, "bool"),
    "ENABLE_HUMANIZE_DELAY": field("模拟操作", "启用随机停顿", True, "bool"),
    "HUMANIZE_DELAY_FACTOR": field("模拟操作", "停顿倍率", 1.0, "float", 0, 5),
    "HUMANIZE_DELAYS": field("模拟操作", "各类停顿秒数区间（JSON 对象）", {
        "click": [0.15, 0.85], "keystroke": [0.035, 0.18],
        "typing_pause": [0.18, 0.75], "page_warmup": [0.7, 2.2],
        "navigate": [1.2, 3.2]}, "delays"),
    "WEB_PORT": field("网页", "网页端口（服务重启生效）", 8765, "int", 1024, 65535),
}

UPSTREAM_DEFAULTS = json.loads((Path(__file__).resolve().parent.parent / "upstream/config_defaults.json").read_text(encoding="utf-8"))
SCHEMA["HUMANIZE_DELAYS"]["default"] = UPSTREAM_DEFAULTS["humanize"]["HUMANIZE_DELAYS"]
# Every configuration binding has an explicit UI entry: editable above or fixed
# below. No environment variable or parent-project configuration is consulted.
FIXED_CONFIG = deepcopy(UPSTREAM_DEFAULTS)
FIXED_CONFIG["roxybrowser"].update({
    "REGISTRATION_DRIVER": "roxy", "ROXY_OPEN_HEADLESS": False,
    "ROXY_PROFILE_ID": "", "ROXY_ONE_PROFILE_PER_ACCOUNT": True,
    "ROXY_DELETE_PROFILE_AFTER_RUN": True, "ROXY_KEEP_BROWSER_OPEN": False,
    "ROXY_CREATE_USE_PROXY_POOL": False, "ROXY_BLOCK_IMAGES": True,
    "ROXY_PROXY_CHECK_CHANNEL": "", "ROXY_TRAFFIC_METERING": False,
    "ROXY_TRAFFIC_METER_MODE": "browser_http", "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED": False,
    "ROXY_RAW_TRACE_SAMPLE_PERCENT": 0,
})
FIXED_CONFIG["twofa"].update(ENABLE_2FA=False, TOTP_ISSUER="OpenAI", TOTP_DIGITS=6, TOTP_INTERVAL=30)
FIXED_CONFIG["proxy"] = {"PROXY_SID_TEMPLATE": "", "REGISTRATION_PROXY_COUNTRIES": [], "PLAN_CHECK_MAX_ATTEMPTS": 1, "PLAN_CHECK_RETRY_DELAY": 0}
FIXED_CONFIG["codex"] = {"ENABLE_CODEX_AUTO": False}
for values in FIXED_CONFIG.values():
    for key in list(values):
        if key in SCHEMA:
            del values[key]
RETIRED_KEYS = {"ROXY_API_TIMEOUT", "PAGE_LOAD_TIMEOUT", "LOGIN_TIMEOUT", "REFRESH_TIMEOUT",
                "BROWSER_POLL_SECONDS", "CDP_TIMEOUT", "TOTP_SAFETY_MARGIN", "AUTOSAVE_SECONDS"}


def upgrade_saved(values):
    if not isinstance(values, dict):
        return values
    values = deepcopy(values)
    for key in RETIRED_KEYS:
        values.pop(key, None)
    if isinstance(values.get("HUMANIZE_DELAYS"), dict):
        values["HUMANIZE_DELAYS"] = {**SCHEMA["HUMANIZE_DELAYS"]["default"], **values["HUMANIZE_DELAYS"]}
    return values

POLICIES = {
    "浏览器": "固定显示 Roxy 窗口；优先独占复用当前项目已关闭的缓存环境，无可用环境才创建",
    "缓存环境": "沿用主项目 profile-cache:v1 标记；运行中的环境不领取，不接管其它项目或未标记的个人环境",
    "环境数据": "原版缓存池：代理重绑、指纹刷新、完整配置回读；清理 Cookie/站点身份存储，保留 HTTP 缓存；失败环境隔离",
    "图片": "沿用原项目 Roxy 3.9.2 原生禁图：forbidImage=false、forbiddenPictureSize=0",
    "附加参数": "账号代理、工作区/项目、系统、名称、禁图及可见窗口由对应配置接管，附加 JSON 不能覆盖这些字段",
    "业务请求": "仅浏览器网页登录；保留原版浏览器内 /api/auth/session、/backend-api/me 及恢复所需 accounts/check 读取与校验；禁用 Python/Go 协议登录、邮箱取码和请求回放",
    "Token": "原版 Session、身份、有效期及轮换校验后保存；复制只读取 JSON 中已保存的 Token",
    "抓包与统计": "关闭，不写请求、响应或流量记录",
    "存储": "本项目 data/accounts.json 与 data/settings.json；单服务进程",
    "监听地址": "127.0.0.1",
    "启动端口": "配置端口不可用时自动选择并保存可用端口；同目录只运行一个服务实例",
}
for namespace, values in FIXED_CONFIG.items():
    for key, value in values.items():
        POLICIES[f"config.{namespace}.{key}"] = "固定生效值 / 默认值：" + json.dumps(value, ensure_ascii=False)
POLICIES["原版 Session 固定等待"] = "Session after OTP=40s；saved Session probe=60s；manual login=300s。页面选择器、点击重试及各分支内部等待均按所附原版源码执行。"
POLICIES["原版密码/TOTP 固定节奏"] = "密码控件发现 5s、轮询 0.2s、提交后转换等待 8s；OTP 页已存密码入口同页搜索最多 3s；TOTP 周期 30s、安全余量 2s；Playwright 密码逐字输入 delay=8ms。HUMANIZE 配置作用于原版调用该配置的共用/Selenium 段。"
POLICIES["原版保存/创建重试"] = "仅原版认定可重试的保存错误最多 3 次、退避 0.5/1s；创建 busy 使用原版同载荷最多 3 次、退避 2/4s；结果不明的创建不回放。"
POLICIES["config.proxy"] = "固定：PROXY_SID_TEMPLATE=''，REGISTRATION_PROXY_COUNTRIES=[]；禁用代理池 pick_proxy，仅使用每账号保存的代理。"
POLICIES["页面超时重试"] = "沿用原版 Try again 点击、等待和最多 3 次重试；重试成功后清除上一文档的密码/验证码提交标记，按恢复后的页面继续登录。"


def defaults():
    return {key: deepcopy(spec["default"]) for key, spec in SCHEMA.items()}


def local_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or
            parsed.hostname not in {"localhost", "127.0.0.1", "::1"} or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment):
        raise ValueError("地址必须是本机 HTTP/HTTPS 地址")
    if parsed.port is not None and not 0 < parsed.port < 65536:
        raise ValueError("本地地址端口无效")
    return value.rstrip("/")


def validate(values):
    if not isinstance(values, dict) or set(values) - set(SCHEMA):
        raise ValueError("配置包含未知字段")
    result = defaults()
    result.update(deepcopy(values))
    for key, spec in SCHEMA.items():
        value, kind = result[key], spec["kind"]
        valid = True
        if kind in {"str", "secret"}:
            valid = isinstance(value, str) and len(value) <= 4096 and not any(ord(c) < 32 for c in value)
        elif kind == "bool":
            valid = isinstance(value, bool)
        elif kind in {"float", "int"}:
            valid = (type(value) in ({int} if kind == "int" else {int, float})
                     and math.isfinite(value) and spec["minimum"] <= value <= spec["maximum"])
        elif kind in {"object", "delays"}:
            valid = isinstance(value, dict)
        elif kind == "strings":
            valid = isinstance(value, list) and all(isinstance(item, str) and len(item) <= 4096 for item in value)
        if not valid or (spec["choices"] and value not in spec["choices"]):
            raise ValueError(f"配置无效：{spec['label']}")
        if key.endswith("_PATH") and (not value.startswith("/") or value.startswith("//") or "?" in value or "#" in value or "\\" in value):
            raise ValueError(f"路径无效：{spec['label']}")
    result["ROXY_API_BASE"] = local_url(result["ROXY_API_BASE"])
    if not result["ROXY_RANDOM_OS_CHOICES"] or set(result["ROXY_RANDOM_OS_CHOICES"]) - {"Windows", "macOS", "Linux"}:
        raise ValueError("随机操作系统候选无效")
    for arg in result["ROXY_BROWSER_ARGS"]:
        if arg.startswith(("--proxy", "--no-proxy", "--headless", "--user-data-dir", "--load-extension")):
            raise ValueError("启动参数不能覆盖代理、可见窗口或隔离环境")
    ranges = result["HUMANIZE_DELAYS"]
    if set(ranges) != set(SCHEMA["HUMANIZE_DELAYS"]["default"]):
        raise ValueError("停顿区间必须包含全部预定义动作")
    for pair in ranges.values():
        if not isinstance(pair, list) or len(pair) != 2 or not all(type(x) in {int, float} and math.isfinite(x) for x in pair) or not 0 <= pair[0] <= pair[1] <= 30:
            raise ValueError("停顿区间必须是 0–30 秒内的 [最小值, 最大值]")
    return result
