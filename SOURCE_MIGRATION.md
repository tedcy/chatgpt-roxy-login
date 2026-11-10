# 源码来源与适配边界

UPSTREAM_MANIFEST.json 记录原文件、独立副本路径、文件 SHA-256，以及函数/类正文指纹和原始行号。upstream/ 中生产源码和迁入测试夹具保持原文件字节一致。

| 职责 | 主项目源码（独立副本保留同名路径） |
| --- | --- |
| 窗口、恢复失败登录、保存、关闭 | core/roxy_manual_window.py |
| Playwright/CDP 登录 | core/roxy_headed_registration.py、core/headed_chrome_reference/ |
| Selenium 登录与选择器 | core/roxy_registration.py、core/roxy_domains/、core/roxy_auth_domains/login.py |
| Profile 池、租约、Roxy API | core/roxy_profile_pool.py、core/roxybrowser_client.py、core/roxybrowser_domains/ |
| Cookie 恢复和 Session 校验 | core/session_refresh_domains/、core/roxy_auth_domains/candidate.py、core/chatgpt_session_store.py |

kernel_bridge.py 创建独立 core/config 命名空间。完整核心模块从本目录 upstream/core 加载；四个重型 facade 从 upstream/source_facades 加载所需原始定义及其同文件依赖。定义正文不经过 AST 改写，运行时指纹保存在 LOADED_SLICES。未进入依赖闭包的协议/队列等定义不执行；源码归档中的其它入口不构成 Demo 公开功能。

允许差异仅在以下边界：

| 边界 | 适配内容 |
| --- | --- |
| 配置 | config.roxybrowser/humanize/twofa/browser/proxy/codex 绑定 JSON 和界面展示的固定策略；不读父项目或 .env。保留原始内核选择规则。 |
| 账号 | core.db 的账号、密码、窗口条件更新、Token CAS 接口映射到 JSON。网页 UUID 不变，另加稳定正整数内核 ID。 |
| Session 后端 | ChatGPTSessionSQLiteStore 的接口名映射到 JsonSessions；不创建或打开数据库。保留原版先写 Session 快照、再条件更新账号 Token 的两步顺序；不暂存候选后合并提交。每个文件写入独立原子替换。 |
| 生命周期 | runtime_core.WindowOwner 仅绑定任务配置和命令队列，调用原版入口执行刷新和临时窗口关闭。保存沿用原版成功/关闭时机，不增加窗口空闲期间的定时保存。 |
| 网页 | 原版状态投影到原有接口；Token 复制只读保存文件。 |
| 禁用钩子 | Python/Go 协议登录、邮箱取码、新绑定 2FA、Codex、独立套餐/优惠查询、导出、流量统计、抓包和 DOM 文件诊断。保留认证器 TOTP 登录。 |
| 日志 | 沿用主项目自身的日志和脱敏函数，不增加全局 Formatter，不额外屏蔽完整邮箱。 |

恢复依赖原版浏览器内 accounts/check 健康校验，必须保留；它与浏览器内 /api/auth/session、/backend-api/me 一起运行。Demo 不把这些请求搬到 Python/Go，也不回放登录请求。

迁移前备份 data/accounts.pre-upstream.json。密码、2FA、代理、Token、Cookie、旧浏览器存储字段及有效期保留。恢复按主项目入口执行，不另写一套浏览器存储恢复算法。

本轮共享内核修正：vendor/app.py 的页面超时重试成功后清除旧密码/验证码提交标记。该通用修正先在主项目落地，Demo 原样同步。原始参考 commit/blob/hash 保留；安装源码指纹由 VENDORED_CANONICAL_SHA256 独立校验，LOCAL_PATCHES 列明修正，未将修改后的源码冒充原始参考源码。

verify_upstream.py 可校验副本，附加 --source-root 参数可对照源仓库；parity_probe.py 可分别对两份实现输入同一组离线浏览器事件，对比动作、结果和异常。snapshot_upstream.py 仅供源仓库重新生成快照，独立运行不使用它。
