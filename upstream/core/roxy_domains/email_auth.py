"""Roxy Email Auth implementation domain.

Loaded into :mod:`core.roxy_registration` so its public compatibility module
retains one shared namespace, locks, and test seams.
"""
from __future__ import annotations
from textwrap import dedent
_SOURCE = dedent(r'''
_EMAIL_INPUT_SELECTORS = [
    "input[type='email']",
    "input[name='email']",
    "input[name='username']",
    "input#email-input",
    "input[autocomplete='email']",
]

def _roxy_otp_observer(driver, *, task_kind: str = "roxy_email_auth", account_id=None):
    """Return the per-driver OTP observer without affecting auth flow."""
    try:
        from core.roxy_otp_observer import ensure_observer

        task_kind = getattr(driver, "_turb_roxy_task_kind", None) or task_kind
        if account_id is None:
            account_id = getattr(driver, "_turb_roxy_account_id", None)
        return ensure_observer(
            driver,
            task_kind=task_kind,
            account_id=account_id,
        )
    except Exception:
        return None


def _roxy_otp_observe_page(driver, *, stage: str = "email_otp") -> None:
    observer = _roxy_otp_observer(driver, task_kind=stage)
    if observer is None:
        return
    try:
        observer.install_browser_hooks(driver)
        observer.drain_browser_hooks(driver, stage=stage)
        observer.mark_challenge_page(stage=stage)
    except Exception:
        pass


def _roxy_otp_submit_result(driver, result: str, *, stage: str = "email_otp") -> None:
    observer = _roxy_otp_observer(driver, task_kind=stage)
    if observer is None:
        return
    try:
        observer.drain_browser_hooks(driver, stage=stage)
        observer.mark_submit_result(result, stage=stage)
    except Exception:
        pass

def _email_entry_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const attrText = el => [
          el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
          el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
          el.getAttribute('data-auth-provider'), el.getAttribute('href'), el.getAttribute('action'),
          el.getAttribute('formaction'), el.getAttribute('value')
        ].filter(Boolean).join(' ').toLowerCase();
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', value: el.value || ''
        })).slice(0, 30);
        const actions = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')]
          .filter(visible).map(el => ({tag: el.tagName, type: el.getAttribute('type') || '', attrs: attrText(el)})).slice(0, 40);
        return {url: location.href, title: document.title, inputs, actions};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}

def _find_visible_email_input_js(driver):
    return driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const selectors = [
      'input[type="email"]',
      'input[name="email"]',
      'input[name="username"]',
      'input#email-input',
      'input[autocomplete="email"]'
    ];
    for (const sel of selectors) {
      const el = [...document.querySelectorAll(sel)].find(visible);
      if (el) return el;
    }
    return null;
    """)

def _email_input_present_js(driver) -> bool:
    """A mounted email form must hydrate before trying a method chooser."""
    return driver.execute_script(r"""
    return [...document.querySelectorAll(
      'input[type="email"],input[name="email"],input[name="username"],input#email-input,input[autocomplete="email"]'
    )].some(el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none');
    """) is True

def _click_other_account_chooser_if_present(driver) -> bool:
    """Leave the remembered-account chooser without selecting an account.

    ChatGPT can render a profile-local "Welcome back" chooser before the
    email form.  Selecting the remembered card would silently authenticate a
    different account, so only the explicit "use another account" action is
    considered here.  The DOM probe intentionally returns no page text to the
    caller or logs.
    """
    try:
        current_url = str(getattr(driver, "current_url", "") or "")
        host = (urlparse(current_url).hostname or "").lower()
        if host not in {"chatgpt.com", "auth.openai.com"} and not (
            host.endswith(".chatgpt.com") or host.endswith(".openai.com")
        ):
            return False
    except Exception:
        return False
    try:
        target = driver.execute_script(r"""
        const visible = el => !!el
          && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden'
          && getComputedStyle(el).display !== 'none'
          && !el.disabled
          && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const compact = value => String(value || '').replace(/\s+/g, '').toLowerCase();
        const attrs = el => [
          el.id, el.getAttribute('name'), el.getAttribute('value'),
          el.getAttribute('aria-label'), el.getAttribute('title'),
          el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
          el.getAttribute('href'), el.getAttribute('formaction'), el.className,
        ].filter(Boolean).join(' ').toLowerCase();
        const candidates = [...document.querySelectorAll(
          'button,a,[role="button"],[role="link"],input[type="button"],input[type="submit"]'
        )].filter(visible);
        const target = candidates.find(el => {
          const text = compact(el.innerText || el.textContent || '');
          const metadata = compact(attrs(el));
          const combined = `${text} ${metadata}`;
          const explicitEnglish = /loginto(?:an?other|a?different|a?new)account/.test(combined)
            || /loginwith(?:an?other|a?different|a?new)account/.test(combined)
            || /continuewith(?:an?other|a?different|a?new)account/.test(combined)
            || /use(?:an?other|a?different|a?new)account/.test(combined)
            || /signinto(?:an?other|a?different|a?new)account/.test(combined);
          const localized = [
            '使用其他账号', '使用其他账户', '使用其他帳戶',
            '使用其它账号', '使用其它账户', '使用其它帳戶',
            '使用另一个账号', '使用另一个账户', '使用另一個帳戶',
            '用其他账号登录', '用其他账户登录', '用其他帳戶登入',
            '別のアカウントでログイン',
            '別のアカウントを使用', '他のアカウントでログイン',
            '다른계정으로로그인', '다른계정사용',
          ].some(token => text.includes(token));
          const semantic = /(?:another|other|different|switch|new)[-_ ]*account/.test(metadata)
            && /(?:log|sign|use|switch|account)/.test(metadata);
          return explicitEnglish || localized || semantic;
        });
        if (!target) return null;
        target.scrollIntoView({block:'center', inline:'nearest'});
        return target;
        """)
        if not target:
            return False
        _human_click(driver, target, label="other_account_chooser")
        return True
    except Exception:
        return False

def _is_oauth_consent_like(driver) -> bool:
    """检测是否已到 OAuth 授权/consent 页。这里不能再点任何邮箱分支或全局提交按钮。"""
    try:
        return bool(driver.execute_script(r"""
        const url = String(location.href || '').toLowerCase();
        if (/oauth|authorize|consent/.test(url) && !/login|signup|identifier|email-verification/.test(url)) return true;
        const formsWithEmail = [...document.querySelectorAll('form')]
          .some(form => form.querySelector('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]'));
        if (formsWithEmail) return false;
        const actions = [...document.querySelectorAll('button,a,[role="button"],input[type="submit"],input[type="button"]')]
          .map(el => [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
            el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('href'),
            el.getAttribute('formaction'), el.value, el.className].filter(Boolean).join(' ').toLowerCase())
          .join(' ');
        return /oauth|authorize|consent|grant|allow/.test(actions) && !/email|username/.test(actions);
        """))
    except Exception:
        return False

def _is_external_idp_url(url: str) -> bool:
    u = str(url or '').lower()
    return any(x in u for x in (
        'accounts.google.', 'google.com/o/oauth', 'appleid.apple.', 'login.microsoftonline.',
        'login.live.', 'github.com/login/oauth', 'facebook.com/', 'saml', 'sso'
    ))

def _assert_not_external_idp(driver, label: str = '') -> None:
    try:
        current = str(driver.current_url or '')
    except Exception:
        current = ''
    if _is_external_idp_url(current):
        raise RuntimeError(f"误入第三方账号授权页（{label}）：{current}")

def _click_email_entry_option(driver) -> bool:
    """点击“邮箱方式”入口；只看 DOM 技术属性，不看按钮可见文案，并显式排除 Google 等第三方。"""
    if _is_oauth_consent_like(driver):
        logger.info("%s 当前疑似 OAuth 授权页，跳过邮箱入口兜底点击", _log_prefix(driver))
        return False
    target = driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
    const emailMounted = [...document.querySelectorAll(
      'input[type="email"],input[name="email"],input[name="username"],input#email-input,input[autocomplete="email"]'
    )].some(el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none');
    if (emailMounted) return null;
    const submitsForm = el => {
      const type = String(el.getAttribute('type') || '').toLowerCase();
      if (type === 'submit' || type === 'image') return true;
      // The DOM type property includes HTML's default/invalid button type.
      return el.tagName === 'BUTTON' && !!el.form && el.type === 'submit';
    };
    const attrText = el => {
      const own = [
        el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
        el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
        el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'), el.getAttribute('href'), el.getAttribute('action'),
        el.getAttribute('formaction'), el.getAttribute('value'), el.getAttribute('aria-label'), el.className
      ].filter(Boolean).join(' ');
      const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
        .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
          x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
          .filter(Boolean).join(' ')).join(' ');
      return `${own} ${desc}`.toLowerCase();
    };
    const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
    const good = /(^|[^a-z])(email|mail|username|passwordless|otp|magic)([^a-z]|$)/;
    const candidates = [...document.querySelectorAll('button,a,[role="button"],input[type="button"],input[type="submit"]')]
      .filter(el => visible(el) && !submitsForm(el))
      .map(el => ({el, attrs: attrText(el), hasLogo: !!el.querySelector('img,svg,use')}))
      .filter(x => good.test(x.attrs) && !bad.test(x.attrs) && !x.hasLogo);
    if (candidates.length !== 1) return null;
    candidates[0].el.scrollIntoView({block:'center'});
    return candidates[0].el;
    """)
    if not target:
        return False
    _human_click(driver, target, label="email_entry")
    return True

def _type_email_address(driver, email: str, timeout: int | None = None) -> None:
    """进入邮箱登录/注册方式并填写邮箱。全程不依赖页面可见文字，避免非日本出口本地化后误点 Google。"""
    end = time.monotonic() + (timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))
    last_state = None
    clicked_email_option = False
    chooser_attempts = 0
    while time.monotonic() < end:
        el = _find_visible_email_input_js(driver)
        if el:
            _human_type_text(driver, el, email, clear=True)
            return
        if _email_input_present_js(driver):
            time.sleep(min(0.4, max(0.0, end - time.monotonic())))
            continue
        if chooser_attempts < 2 and _click_other_account_chooser_if_present(driver):
            chooser_attempts += 1
            _assert_not_external_idp(driver, "选择其他账号后")
            # A chooser click is asynchronous on the Auth0 page.  Do not
            # report success until the target email input is actually visible;
            # retry the explicit chooser once if the first click was swallowed
            # by a delayed render/iframe transition.
            confirm_end = min(end, time.monotonic() + 5.0)
            while time.monotonic() < confirm_end:
                el = _find_visible_email_input_js(driver)
                if el:
                    _human_type_text(driver, el, email, clear=True)
                    return
                _assert_not_external_idp(driver, "选择其他账号后")
                time.sleep(0.2)
            continue
        last_state = _email_entry_state(driver)
        if not clicked_email_option and _click_email_entry_option(driver):
            clicked_email_option = True
            time.sleep(1.0)
            _assert_not_external_idp(driver, "点击邮箱入口后")
            continue
        time.sleep(0.4)
    raise RuntimeError(f"找不到邮箱输入框/邮箱入口（未使用文字识别），state={last_state}")

def _submit_nearest_form_for_active_input(driver, *, expected_email: str | None = None) -> bool:
    if _is_oauth_consent_like(driver):
        logger.info("%s 当前疑似 OAuth 授权页，禁止执行邮箱提交", _log_prefix(driver))
        return False
    result = driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly && el.getAttribute('aria-disabled') !== 'true';
    const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]')]
      .find(visible);
    if (!input) return {ok:false, reason:'missing_email_input'};
    const value = String(input.value || '').trim();
    if (!value || !value.includes('@')) return {ok:false, reason:'email_value_not_ready', value};
    const expected = String(arguments[0] || '').trim().toLowerCase();
    if (expected && value.toLowerCase() !== expected) return {ok:false, reason:'email_value_mismatch'};
    const form = input.closest('form');
    if (!form) return {ok:false, reason:'missing_form'};

    const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|sso|saml|idp|provider|authorize|consent|grant|allow/;
    const attrText = el => {
      const own = [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
        el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
        el.getAttribute('aria-label'), el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className]
        .filter(Boolean).join(' ');
      const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
        .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
          x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
          .filter(Boolean).join(' '))
        .join(' ');
      return `${own} ${desc}`.toLowerCase();
    };
    const inputRect = input.getBoundingClientRect();
    const formId = form.getAttribute('id') || '';
    const scopedButtons = [
      ...form.querySelectorAll('button,input[type="submit"]'),
      ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
    ].filter((el, idx, arr) => arr.indexOf(el) === idx);
    const rawButtons = scopedButtons
      .filter(visible)
      .map((el, idx) => {
        const r = el.getBoundingClientRect();
        const attrs = attrText(el);
        const hasLogo = !!el.querySelector('img,svg,use');
        const isBad = bad.test(attrs) || hasLogo;
        const belowInput = r.top >= inputRect.bottom - 10;
        const distance = Math.max(0, r.top - inputRect.bottom) + Math.abs((r.left + r.right) / 2 - (inputRect.left + inputRect.right) / 2) / 10;
        const cls = String(el.className || '').toLowerCase();
        const type = String(el.getAttribute('type') || '').toLowerCase();
        // ChatGPT 新版邮箱页的主按钮形如：
        // <button class="... btn-primary ... w-full ..." type="submit"><div>続行</div></button>
        // 优先选择同 form 下的 primary submit，而不是因为多个按钮距离接近误判歧义。
        const isPrimarySubmit = (el.tagName === 'BUTTON' || el.tagName === 'INPUT') && type === 'submit'
          && (/\bbtn-primary\b/.test(cls) || /\b_primary_/.test(cls) || /\bw-full\b/.test(cls));
        const score = (isPrimarySubmit ? 1000 : 0) + (type === 'submit' ? 100 : 0) - distance;
        return {el, idx, attrs, isBad, hasLogo, belowInput, distance, score, isPrimarySubmit, tag: el.tagName, type};
      });
    const safe = rawButtons.filter(x => !x.isBad && x.belowInput)
      .sort((a,b) => b.score - a.score || a.distance - b.distance || a.idx - b.idx);
    if (!safe.length) {
      return {ok:false, reason:'no_safe_submit', buttons: rawButtons.map(x => ({idx:x.idx, isBad:x.isBad, hasLogo:x.hasLogo, belowInput:x.belowInput, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
    }
    // 多个安全按钮时，若没有明确 primary submit，且距离接近，才认为页面歧义。
    if (!safe[0].isPrimarySubmit && safe.length > 1 && Math.abs(safe[0].distance - safe[1].distance) < 8) {
      return {ok:false, reason:'ambiguous_submit', buttons: safe.slice(0,3).map(x => ({idx:x.idx, distance:x.distance, score:x.score, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
    }
    const target = safe[0].el;
    target.scrollIntoView({block:'center'});
    window.__roxy_email_submit_debug = {at: Date.now(), targetAttrs: safe[0].attrs.slice(0,240), buttonCount: rawButtons.length, primary:safe[0].isPrimarySubmit};
    return {ok:true, reason:safe[0].isPrimarySubmit ? 'primary_submit' : 'safe_submit', target, targetAttrs:safe[0].attrs.slice(0,160), primary:safe[0].isPrimarySubmit};
    """, expected_email) or {}
    if result.get("ok"):
        target = result.get("target")
        if not target:
            logger.warning("%s 邮箱提交未返回目标元素，拒绝执行不确定兜底", _log_prefix(driver))
            return False
        _human_click(driver, target, label="email_submit")
        result = {key: value for key, value in result.items() if key != "target"}
        logger.info("%s 邮箱表单安全提交：%s", _log_prefix(driver), result)
        time.sleep(0.8)
        _assert_not_external_idp(driver, "提交邮箱后")
        return True
    logger.warning("%s 未执行邮箱提交：%s", _log_prefix(driver), result)
    return False

def _submit_email_step(driver, *, expected_email: str | None = None) -> None:
    observer = _roxy_otp_observer(driver)
    if observer is not None:
        try:
            observer.install_browser_hooks(driver)
            observer.mark_send_start(stage="email_otp")
        except Exception:
            pass
    if _submit_nearest_form_for_active_input(driver, expected_email=expected_email):
        return
    raise RuntimeError(f"无法提交邮箱步骤（拒绝按页面文字或首个 submit 兜底，避免误点第三方登录），state={_email_entry_state(driver)}")

def _email_input_value_state(driver) -> dict:
    """读取当前可见邮箱框状态，用于提交后确认是否真的进入下一步。"""
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .filter(visible)
          .map(el => ({type: el.getAttribute('type') || '', name: el.name || '', id: el.id || '', autocomplete: el.getAttribute('autocomplete') || '', value: el.value || ''}));
        return {url: location.href, inputs};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}

def _is_email_login_page_still_present(driver) -> bool:
    state = _email_input_value_state(driver)
    return bool(state.get("inputs"))

def _wait_email_submit_next_state(driver, email: str, timeout: int = 18) -> str:
    """邮箱提交后等待进入 password / otp / logged_in；仍停留邮箱页则返回 email_page。

    部分 Chromium 页面点击 submit 后会先发生一次 SPA 导航：
    `chatgpt.com/auth/login?email=...`，同时 React 会短暂把 email input 清空。
    旧逻辑一看到空 input 就立刻返回 `email_cleared`，导致在真正跳到
    `auth.openai.com/...` 前过早重填，形成“提交 -> 清空 -> 重填”的循环。
    这里对 email_cleared 做去抖：只记录并继续观察几秒；若期间进入
    password/otp/login_password/logged_in 则按真实状态返回，持续清空才让上层重试。
    """
    end = time.time() + timeout
    last = None
    cleared_seen_at: float | None = None
    cleared_last_log_at = 0.0
    expected_email = str(email or "").strip().lower()
    while time.time() < end:
        if _has_access_token(driver):
            return "logged_in"
        if _is_login_password_page(driver):
            return "login_password"
        if _is_email_verification_page(driver):
            _roxy_otp_observe_page(driver, stage="email_otp")
            return "otp"
        if _is_signup_password_page(driver):
            return "password"
        state = _email_input_value_state(driver)
        last = state
        inputs = state.get("inputs") or []
        if inputs:
            values = [str(i.get("value") or "") for i in inputs]
            url = str(state.get("url") or "")
            has_blank = any(v == "" for v in values)
            has_expected = any(v.strip().lower() == expected_email for v in values)
            if has_blank and not has_expected:
                now = time.time()
                if cleared_seen_at is None:
                    cleared_seen_at = now
                # URL 已带 email 查询参数时更像是提交后的中间态，给它更长观察窗口。
                debounce = 6.0 if ("/auth/login" in url and "email=" in url) else 3.5
                if now - cleared_last_log_at > 2.0:
                    logger.info(
                        "%s 邮箱提交后检测到输入框短暂清空，继续等待跳转：elapsed=%.1fs debounce=%.1fs url=%s",
                        _log_prefix(driver), now - cleared_seen_at, debounce, url[:180],
                    )
                    cleared_last_log_at = now
                if now - cleared_seen_at >= debounce:
                    return "email_cleared"
            else:
                cleared_seen_at = None
            # 仍是当前邮箱页，继续短等。
        time.sleep(0.8)
    logger.info("%s 邮箱提交后等待下一步超时，最后邮箱页状态=%s", _log_prefix(driver), last)
    return "email_page" if _is_email_login_page_still_present(driver) else "unknown"

def _refresh_email_page_for_retry(
    driver,
    *,
    refresh_number: int,
    refresh_total: int,
    interval_seconds: float,
) -> None:
    """在同一浏览器窗口普通刷新邮箱页，不重建 Profile 或切换代理。"""
    delay_seconds = max(0.0, float(interval_seconds or 0.0))
    logger.warning(
        "%s 邮箱页未进入下一步，%.1f 秒后在同一窗口普通刷新（%s/%s，不切换代理）",
        _log_prefix(driver),
        delay_seconds,
        refresh_number,
        refresh_total,
    )
    _check_manual_stop()
    if delay_seconds:
        time.sleep(delay_seconds)
    try:
        driver.refresh()
    except Exception as exc:
        # 页面资源不稳定时，Selenium 可能在刷新已经开始后抛出加载超时；此时页面仍可
        # 继续恢复。只容忍 TimeoutException，driver/session 失效等错误仍立即向上抛出。
        if type(exc).__name__ != "TimeoutException":
            raise
        logger.warning("%s 普通刷新等待页面加载超时，继续检查当前页面", _log_prefix(driver))
    human_delay("navigate")
    _maybe_accept(driver)
    _check_manual_stop()

def _email_submit_terminal_state(driver) -> str | None:
    """返回邮箱步骤之后已经到达的终态；仍需填写邮箱时返回 None。"""
    if _has_access_token(driver):
        return "logged_in"
    if _is_login_password_page(driver):
        return "login_password"
    if _is_email_verification_page(driver):
        return "otp"
    if _is_signup_password_page(driver):
        return "password"
    return None

def _submit_email_and_wait_next(
    driver,
    email: str,
    attempts: int = 3,
    *,
    refresh_retries: int = 0,
    refresh_interval: float = 5.0,
    allow_existing_account: bool = False,
) -> str:
    """填写并提交邮箱，必须确认进入 password/otp/logged_in 才返回。

    ``attempts`` 保留原有的不刷新重试次数；``refresh_retries`` 会在这些尝试之后
    增加同一窗口、同一 Profile 下的普通刷新重试，不会重新选择代理。
    """
    base_attempts = max(1, int(attempts or 1))
    refresh_total = max(0, int(refresh_retries or 0))
    total_attempts = base_attempts + refresh_total
    last_state = None
    refresh_count = 0
    for attempt in range(1, total_attempts + 1):
        terminal_state = _email_submit_terminal_state(driver)
        if terminal_state == "login_password":
            if allow_existing_account:
                logger.info(
                    "%s 已进入已有账号登录页，切换到幂等登录流程",
                    _log_prefix(driver),
                )
                return terminal_state
            raise RuntimeError(f"邮箱提交后进入登录密码页，按已注册/不可用邮箱处理并停用: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
        if terminal_state in ("password", "otp", "logged_in"):
            logger.info("%s 刷新后已进入下一步：%s", _log_prefix(driver), terminal_state)
            return terminal_state
        _type_email_address(driver, email, timeout=20)
        state = _email_input_value_state(driver)
        last_state = state
        values = [str(i.get("value") or "") for i in (state.get("inputs") or [])]
        if not any(v.strip().lower() == email.strip().lower() for v in values):
            logger.warning("%s 邮箱写入校验失败，准备重试：attempt=%s/%s state=%s", _log_prefix(driver), attempt, total_attempts, state)
        else:
            logger.info("%s 已填写邮箱并校验通过：%s", _log_prefix(driver), email)
            human_delay("form")
            _submit_email_step(driver)
            logger.info("%s 已提交邮箱，等待进入密码页或验证码页（%s/%s）", _log_prefix(driver), attempt, total_attempts)
            state_name = _wait_email_submit_next_state(driver, email, timeout=20)
            if state_name == "login_password":
                if allow_existing_account:
                    logger.info(
                        "%s 邮箱对应已有账号，切换到幂等登录流程",
                        _log_prefix(driver),
                    )
                    return state_name
                raise RuntimeError(f"邮箱提交后进入登录密码页，按已注册/不可用邮箱处理并停用: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
            if state_name in ("password", "otp", "logged_in"):
                logger.info("%s 邮箱提交后已进入下一步：%s", _log_prefix(driver), state_name)
                return state_name
            logger.warning("%s 邮箱提交后仍未进入下一步：%s，准备恢复重试 state=%s", _log_prefix(driver), state_name, _email_input_value_state(driver))

        if attempt >= total_attempts:
            break
        if attempt >= base_attempts and refresh_count < refresh_total:
            refresh_count += 1
            _refresh_email_page_for_retry(
                driver,
                refresh_number=refresh_count,
                refresh_total=refresh_total,
                interval_seconds=refresh_interval,
            )
        else:
            time.sleep(1.0)
    raise RuntimeError(f"邮箱提交后未进入密码页/验证码页，最后状态={last_state}")

def _email_otp_value_state(driver, expected_code: str) -> dict:
    """Read the live email OTP controls without exposing the code in diagnostics."""
    return driver.execute_script(r"""
    const expected = String(arguments[0] || '').trim();
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
    const inputs = [...document.querySelectorAll('input')].filter(el => {
      if (!visible(el) || el.disabled || el.readOnly) return false;
      const type = String(el.getAttribute('type') || '').toLowerCase();
      if (['hidden','submit','button','radio','checkbox'].includes(type)) return false;
      const attrs = [type, el.getAttribute('name'), el.id, el.getAttribute('autocomplete'),
        el.getAttribute('inputmode'), el.getAttribute('aria-label'), el.getAttribute('placeholder')]
        .map(value => String(value || '').toLowerCase()).join(' ');
      return /one-time|otp|code|numeric|tel/.test(attrs);
    });
    const digitsOnly = /^\d+$/.test(expected);
    const normalize = value => {
      const text = String(value || '').trim();
      return digitsOnly ? text.replace(/\D+/g, '') : text.replace(/\s+/g, '');
    };
    const values = inputs.map(el => String(el.value || ''));
    const normalized = values.map(normalize);
    const combined = normalized.join('');
    const normalizedExpected = normalize(expected);
    const form = inputs[0]?.form || document.querySelector('form');
    const submit = form?.querySelector('button[type="submit"],input[type="submit"]');
    return {
      expectedLength: normalizedExpected.length,
      candidateCount: inputs.length,
      valueLengths: normalized.map(value => value.length),
      combinedLength: combined.length,
      matchesExpected: normalized.some(value => value === normalizedExpected)
        || combined === normalizedExpected,
      anyInvalid: inputs.some(el => String(el.getAttribute('aria-invalid') || '').toLowerCase() === 'true'),
      submitDisabled: submit
        ? !!submit.disabled || String(submit.getAttribute('aria-disabled') || '').toLowerCase() === 'true'
        : null,
    };
    """, str(expected_code or "").strip()) or {}

def _email_otp_state_summary(state: dict) -> dict:
    return {
        "expected_length": state.get("expectedLength"),
        "candidate_count": state.get("candidateCount"),
        "value_lengths": state.get("valueLengths") or [],
        "combined_length": state.get("combinedLength"),
        "matches_expected": bool(state.get("matchesExpected")),
        "any_invalid": bool(state.get("anyInvalid")),
        "submit_disabled": state.get("submitDisabled"),
    }

def _type_otp_with_webdriver(driver, code: str) -> None:
    from selenium.webdriver.common.by import By

    # 单输入框
    for selector in [
        "input[autocomplete='one-time-code']",
        "input[name='code']",
        "input[inputmode='numeric']",
        "input[type='tel']",
    ]:
        els = [e for e in driver.find_elements(By.CSS_SELECTOR, selector) if _visible(e)]
        if len(els) == 1:
            _human_type_text(driver, els[0], code, clear=True)
            return

    # 6 个分格输入框
    boxes = [e for e in driver.find_elements(By.CSS_SELECTOR, "input") if _visible(e)]
    numeric_boxes = []
    for e in boxes:
        attrs = " ".join(str(e.get_attribute(k) or "") for k in ("inputmode", "autocomplete", "aria-label", "name", "id", "type"))
        if any(x in attrs.lower() for x in ("numeric", "one-time", "code", "otp", "tel")):
            numeric_boxes.append(e)
    if len(numeric_boxes) >= len(code):
        for e, ch in zip(numeric_boxes, code):
            if _browser_actions_enabled():
                _human_scroll_to(driver, e)
                time.sleep(random.uniform(0.04, 0.18))
            try:
                e.clear()
            except Exception:
                pass
            _human_send_keys(e, ch)
        return

    raise EmailOtpInputNotCommitted("email_otp_input_missing")

def _type_otp_with_native_setter(driver, code: str) -> None:
    result = driver.execute_script(r"""
    const code = String(arguments[0] || '').trim();
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
    const inputs = [...document.querySelectorAll('input')].filter(el => {
      if (!visible(el) || el.disabled || el.readOnly) return false;
      const type = String(el.getAttribute('type') || '').toLowerCase();
      if (['hidden','submit','button','radio','checkbox'].includes(type)) return false;
      const attrs = [type, el.getAttribute('name'), el.id, el.getAttribute('autocomplete'),
        el.getAttribute('inputmode'), el.getAttribute('aria-label'), el.getAttribute('placeholder')]
        .map(value => String(value || '').toLowerCase()).join(' ');
      return /one-time|otp|code|numeric|tel/.test(attrs);
    });
    if (!inputs.length) return {ok:false, reason:'email_otp_input_missing'};
    if (inputs.length > 1 && inputs.length < code.length) {
      return {ok:false, reason:'email_otp_input_count_mismatch', count:inputs.length};
    }
    const setValue = (el, value) => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      el.focus();
      if (setter) setter.call(el, value); else el.value = value;
      try {
        el.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:value}));
      } catch (_) {
        el.dispatchEvent(new Event('input', {bubbles:true}));
      }
      el.dispatchEvent(new Event('change', {bubbles:true}));
    };
    if (inputs.length === 1) {
      setValue(inputs[0], code);
    } else {
      inputs.forEach((input, index) => setValue(input, code[index] || ''));
    }
    inputs[Math.min(inputs.length, code.length) - 1]?.blur?.();
    return {ok:true, count:inputs.length};
    """, code) or {}
    if not result.get("ok"):
        raise EmailOtpInputNotCommitted(
            str(result.get("reason") or "email_otp_native_write_failed")
        )

def _type_otp(driver, code: str, *, prefer_native: bool = False) -> None:
    """Type an email OTP and prove that the current DOM retained the value."""
    code = str(code or "").strip()
    if not code:
        raise EmailOtpInputNotCommitted("email_otp_empty")

    strategies = (
        (("native", _type_otp_with_native_setter), ("webdriver", _type_otp_with_webdriver))
        if prefer_native
        else (("webdriver", _type_otp_with_webdriver), ("native", _type_otp_with_native_setter))
    )
    last_error = "email_otp_input_not_committed"
    for strategy, writer in strategies:
        try:
            writer(driver, code)
            time.sleep(0.35)
            state = _email_otp_value_state(driver, code)
            summary = _email_otp_state_summary(state)
            logger.info(
                "%s[OTP] 输入诊断：strategy=%s state=%s",
                _log_prefix(driver),
                strategy,
                summary,
            )
            if state.get("matchesExpected"):
                return
            last_error = f"email_otp_value_not_committed strategy={strategy} state={summary}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:180]}"

    raise EmailOtpInputNotCommitted(last_error)

def _ensure_email_otp_value_before_submit(driver, code: str) -> dict:
    """Recheck after React rerenders; retry only the same code with the native setter."""
    try:
        state = _email_otp_value_state(driver, code)
    except Exception as exc:
        raise EmailOtpInputNotCommitted(
            f"email_otp_pre_submit_check_failed: {type(exc).__name__}"
        ) from exc
    if state.get("matchesExpected"):
        logger.info(
            "%s[OTP] 提交前校验通过：state=%s",
            _log_prefix(driver),
            _email_otp_state_summary(state),
        )
        return state

    logger.warning(
        "%s[OTP] 提交前验证码值已丢失，复用同一验证码执行 native 重填：state=%s",
        _log_prefix(driver),
        _email_otp_state_summary(state),
    )
    _type_otp(driver, code, prefer_native=True)
    state = _email_otp_value_state(driver, code)
    if not state.get("matchesExpected"):
        raise EmailOtpInputNotCommitted(
            f"email_otp_input_not_committed state={_email_otp_state_summary(state)}"
        )
    logger.info(
        "%s[OTP] native 重填后提交前校验通过：state=%s",
        _log_prefix(driver),
        _email_otp_state_summary(state),
    )
    return state

def _email_otp_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', inputmode: el.getAttribute('inputmode') || '',
          ariaInvalid: el.getAttribute('aria-invalid') || '', value: el.value || ''
        }));
        const buttons = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')].filter(visible).map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', value: el.getAttribute('value') || '',
          action: el.getAttribute('data-dd-action-name') || '', aria: el.getAttribute('aria-label') || '',
          disabled: !!el.disabled || String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
          text: (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120)
        }));
        const errors = [...document.querySelectorAll('.react-aria-FieldError,[slot="errorMessage"],[id$="-error"],[aria-invalid="true"] + *,[class*="error"]')]
          .filter(visible).map(el => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean);
        return {url: location.href, title: document.title, inputs, buttons, errors, text: (document.body?.innerText || '').slice(0, 1200)};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, 'current_url', ''), "error": f"{type(exc).__name__}: {exc}"}

_OTP_ERROR_WORD_RE = re.compile(
    r"(?:\binvalid\b|\bincorrect\b|\bwrong\b|\bexpired\b|\bnot\s+valid\b|"
    r"错误|无效|过期|不正确|間違|正しくありません|無効|期限切れ|"
    r"incorrect|invalide|expir[ée]|incorrecto|inválido|caducad|ungültig|falsch|abgelaufen)",
    re.IGNORECASE,
)

_OTP_CONTEXT_RE = re.compile(
    r"(?:\bcode\b|\botp\b|verif(?:y|ication)|验证码|認証コード|確認コード|"
    r"code\s+(?:de\s+)?vérification|código|code\s+de\s+verificación|bestätigungscode)",
    re.IGNORECASE,
)

_GENERIC_AUTH_RETRY_TEXTS = frozenset({
    "try again",
    "retry",
    "重试",
    "再试一次",
    "もう一度試す",
    "もう一度",
    "réessayer",
    "reessayer",
    "inténtalo de nuevo",
    "intentalo de nuevo",
    "erneut versuchen",
})

_GENERIC_AUTH_ERROR_RE = re.compile(
    r"(?:something\s+went\s+wrong|an\s+(?:unexpected\s+)?error\s+occurred|"
    r"we\s+(?:ran|have\s+run)\s+into\s+(?:an?\s+)?(?:error|issue|problem)|"
    r"出了?点问题|发生(?:了)?(?:一个)?错误|エラーが発生しました|問題が発生しました|"
    r"une\s+erreur\s+s['’]est\s+produite|un\s+probl[eè]me\s+est\s+survenu|"
    r"algo\s+sali[oó]\s+mal|ocurri[oó]\s+un\s+error|"
    r"etwas\s+ist\s+schiefgelaufen|ein\s+fehler\s+ist\s+aufgetreten)",
    re.IGNORECASE,
)

def _roxy_email_otp_page_state(driver) -> dict:
    """Collect only structured OTP diagnostics; never include the OTP value/body."""
    try:
        return driver.execute_script(r"""
        const visible = el => {
          if (!el || !(el.offsetWidth || el.offsetHeight || el.getClientRects().length)) return false;
          const style = getComputedStyle(el);
          return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
        };
        const norm = value => String(value || '').replace(/\s+/g, ' ').trim();
        const attrs = el => [
          el.getAttribute('type'), el.getAttribute('name'), el.id,
          el.getAttribute('autocomplete'), el.getAttribute('inputmode'),
          el.getAttribute('aria-label'), el.getAttribute('placeholder')
        ].map(norm).join(' ').toLowerCase();
        const allInputs = [...document.querySelectorAll('input')].filter(visible);
        const otpInputs = allInputs.filter(el => /one-time|otp|verification|code|numeric|tel/.test(attrs(el)));
        const describedIds = new Set();
        for (const input of otpInputs) {
          norm(input.getAttribute('aria-describedby')).split(/\s+/).filter(Boolean).forEach(id => describedIds.add(id));
        }
        const errorCandidates = [];
        const seen = new Set();
        const addError = (el, source, linkedToOtp=false) => {
          if (!visible(el) || seen.has(el) || ['HTML','BODY','MAIN','FORM'].includes(el.tagName)) return;
          const text = norm(el.innerText || el.textContent);
          if (!text || text.length > 2000 || el.querySelectorAll('*').length > 50) return;
          seen.add(el);
          errorCandidates.push({
            source,
            linkedToOtp: !!linkedToOtp,
            tag: el.tagName.toLowerCase(),
            id: el.id || '',
            class: typeof el.className === 'string' ? el.className : norm(el.getAttribute('class')),
            role: el.getAttribute('role') || '',
            ariaLive: el.getAttribute('aria-live') || '',
            color: getComputedStyle(el).color || '',
            text,
          });
        };
        for (const id of describedIds) addError(document.getElementById(id), 'aria_describedby', true);
        for (const input of otpInputs) {
          if (String(input.getAttribute('aria-invalid') || '').toLowerCase() !== 'true') continue;
          addError(input.nextElementSibling, 'aria_invalid_sibling', true);
          const scope = input.closest('[role=group],fieldset,label,div');
          if (scope) {
            [...scope.querySelectorAll('[slot="errorMessage"],.react-aria-FieldError,[role="alert"],[aria-live]')]
              .forEach(el => addError(el, 'aria_invalid_scope', true));
          }
        }
        [...document.querySelectorAll('[role="alert"],[aria-live],[slot="errorMessage"],.react-aria-FieldError,[data-error]')]
          .forEach(el => addError(el, el.getAttribute('role') === 'alert' ? 'role_alert' : (el.getAttribute('aria-live') ? 'aria_live' : 'error_node'), describedIds.has(el.id)));
        const buttons = [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')]
          .filter(visible).map(el => ({
            tag: el.tagName.toLowerCase(),
            type: el.getAttribute('type') || '',
            value: el.getAttribute('value') || '',
            name: el.getAttribute('name') || '',
            action: el.getAttribute('data-dd-action-name') || '',
            aria: el.getAttribute('aria-label') || '',
            title: el.getAttribute('title') || '',
            testid: el.getAttribute('data-testid') || '',
            disabled: !!el.disabled || String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
            text: norm(el.innerText || el.textContent).slice(0, 240),
          }));
        return {
          url: location.href,
          title: document.title,
          isVerification: /email-verification/i.test(location.href) || otpInputs.length > 0,
          emailInputPresent: allInputs.some(el => /email/.test(attrs(el))),
          otpInputs: otpInputs.map(el => ({
            type: el.getAttribute('type') || '',
            name: el.getAttribute('name') || '',
            id: el.id || '',
            autocomplete: el.getAttribute('autocomplete') || '',
            inputmode: el.getAttribute('inputmode') || '',
            ariaInvalid: el.getAttribute('aria-invalid') || '',
            ariaDescribedby: el.getAttribute('aria-describedby') || '',
            valueLength: String(el.value || '').length,
          })),
          buttons,
          errorCandidates,
        };
        """) or {}
    except Exception as exc:
        return {
            "url": getattr(driver, "current_url", ""),
            "error": f"{type(exc).__name__}: {exc}",
            "otpInputs": [],
            "buttons": [],
            "errorCandidates": [],
        }

def _effective_roxy_otp_errors(state: dict) -> list[dict]:
    result = []
    for candidate in state.get("errorCandidates") or []:
        text = str(candidate.get("text") or "").strip()
        if not text or not _OTP_ERROR_WORD_RE.search(text):
            continue
        if candidate.get("linkedToOtp") or _OTP_CONTEXT_RE.search(text):
            result.append(dict(candidate))
    return result

def _generic_roxy_auth_retry_button(state: dict) -> dict | None:
    for button in state.get("buttons") or []:
        if button.get("disabled"):
            continue
        values = (
            button.get("action"),
            button.get("aria"),
            button.get("title"),
            button.get("text"),
            button.get("value"),
        )
        for value in values:
            normalized = re.sub(r"\s+", " ", str(value or "")).strip().lower()
            if normalized in _GENERIC_AUTH_RETRY_TEXTS:
                return dict(button)
    return None

def _generic_roxy_auth_errors(state: dict) -> list[dict]:
    """Return structured generic auth errors without scanning page body text."""
    result = []
    for candidate in state.get("errorCandidates") or []:
        text = str(candidate.get("text") or "").strip()
        if text and _GENERIC_AUTH_ERROR_RE.search(text):
            result.append(dict(candidate))
    return result

def _roxy_otp_location_summary(state: dict) -> dict:
    raw_url = str(state.get("url") or "")
    try:
        parsed = urlparse(raw_url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
    except Exception:
        host, path = "", ""
    return {
        "host": host,
        "path": path,
        "is_verification": bool(state.get("isVerification")),
        "email_input": bool(state.get("emailInputPresent")),
        "otp_input_count": len(state.get("otpInputs") or []),
        "error_nodes": _effective_roxy_otp_errors(state),
        "auth_error_nodes": _generic_roxy_auth_errors(state),
        "generic_retry": bool(_generic_roxy_auth_retry_button(state)),
    }

def _is_roxy_email_login_state(state: dict) -> bool:
    try:
        parsed = urlparse(str(state.get("url") or ""))
        path = (parsed.path or "").rstrip("/").lower()
    except Exception:
        path = ""
    if path.endswith("/log-in/password") or state.get("isVerification"):
        return False
    return path.endswith("/log-in") or bool(state.get("emailInputPresent"))

def _is_roxy_chatgpt_session_candidate(state: dict) -> bool:
    try:
        parsed = urlparse(str(state.get("url") or ""))
        host = str(parsed.hostname or "").lower()
        path = str(parsed.path or "/").lower()
    except Exception:
        return False
    return host in {"chatgpt.com", "www.chatgpt.com"} and not path.startswith("/auth/login")

def _roxy_email_otp_transition_state(driver) -> tuple[str, dict]:
    """Return a success-first state for the idempotent Roxy OTP flow."""
    if _has_access_token(driver):
        state = _roxy_email_otp_page_state(driver)
        return "logged_in", state
    snapshot = _page_snapshot(driver)
    if _is_profile_like(snapshot):
        state = _roxy_email_otp_page_state(driver)
        return "profile", state
    state = _roxy_email_otp_page_state(driver)
    if _is_roxy_chatgpt_session_candidate(state):
        # A ChatGPT navigation can precede Session cookie/accessToken writes.
        # It is a success candidate, not proof of an authenticated identity.
        return "session_pending", state
    if _is_login_password_page(driver):
        return "login_password", state
    if _is_signup_password_page(driver):
        return "password", state
    errors = _effective_roxy_otp_errors(state)
    if errors:
        state = dict(state)
        state["effectiveErrors"] = errors
        return "otp_invalid_candidate", state
    if (
        _is_roxy_email_login_state(state)
        or _generic_roxy_auth_retry_button(state)
        or _generic_roxy_auth_errors(state)
    ):
        return "auth_restart_candidate", state
    return "pending", state

def _wait_after_roxy_email_otp_submit(driver, timeout: int = 45) -> str:
    _roxy_otp_submit_result(driver, "waiting", stage="email_otp")
    end = time.time() + max(1, int(timeout or 1))
    stable_kind = None
    stable_signature = None
    stable_since = None
    stable_count = 0
    last_state = {}
    while time.time() < end:
        time.sleep(0.5)
        transition, state = _roxy_email_otp_transition_state(driver)
        last_state = state
        if transition in {"logged_in", "profile"}:
            logger.info(
                "%s[OTP] otp_transition=%s stable_error=false location=%s",
                _log_prefix(driver),
                transition,
                _roxy_otp_location_summary(state),
            )
            _roxy_otp_submit_result(driver, "accepted", stage="email_otp")
            return transition

        if transition == "otp_invalid_candidate":
            signature = tuple(
                str(item.get("text") or "")
                for item in state.get("effectiveErrors") or []
            )
            kind = "otp_invalid"
        elif transition == "auth_restart_candidate":
            retry = _generic_roxy_auth_retry_button(state) or {}
            signature = (
                str(state.get("url") or ""),
                str(retry.get("action") or retry.get("text") or ""),
            )
            kind = "auth_restart"
        else:
            stable_kind = None
            stable_signature = None
            stable_since = None
            stable_count = 0
            continue

        if kind == stable_kind and signature == stable_signature:
            stable_count += 1
        else:
            stable_kind = kind
            stable_signature = signature
            stable_since = time.time()
            stable_count = 1
        if stable_count >= 2 and stable_since is not None and time.time() - stable_since >= 1.0:
            logger.warning(
                "%s[OTP] otp_transition=%s stable_error=true location=%s",
                _log_prefix(driver),
                kind,
                _roxy_otp_location_summary(state),
            )
            _roxy_otp_submit_result(
                driver,
                "invalid" if kind == "otp_invalid" else "failed",
                stage="email_otp",
            )
            return kind

    logger.warning(
        "%s[OTP] otp_transition=unconfirmed stable_error=false reason=email_otp_submission_unconfirmed location=%s",
        _log_prefix(driver),
        _roxy_otp_location_summary(last_state),
    )
    _roxy_otp_submit_result(driver, "unconfirmed", stage="email_otp")
    return "unconfirmed"

def _is_email_verification_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if '/log-in/password' in url:
        return False
    if 'email-verification' in url:
        _roxy_otp_observe_page(driver, stage="email_otp")
        return True
    if '/mfa-challenge' in url or '/mfa/' in url:
        # OpenAI shares this route between email and authenticator challenges.
        # A generic numeric/code input is not sufficient evidence for email;
        # classify it through the shared MFA detector and fail closed when the
        # factor is unknown so callers never poll a mailbox for a TOTP page.
        try:
            from core.chatgpt_session_refresh import _authenticator_mfa_page_state

            mfa_state = _authenticator_mfa_page_state(driver)
        except Exception:
            return False
        if bool(mfa_state.get('authenticator')):
            return False
        result = bool(mfa_state.get('email'))
        if result:
            _roxy_otp_observe_page(driver, stage="email_otp")
        return result
    state = _email_otp_page_state(driver)
    attrs = ' '.join(' '.join(str(i.get(k) or '') for k in ('type','name','id','autocomplete','inputmode')) for i in (state.get('inputs') or [])).lower()
    result = 'one-time-code' in attrs or 'otp' in attrs or 'code' in attrs
    if result:
        _roxy_otp_observe_page(driver, stage="email_otp")
    return result

def _clear_otp_inputs(driver) -> None:
    try:
        driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const inputs = [...document.querySelectorAll('input')].filter(visible).filter(el => {
          const attrs = [el.type, el.name, el.id, el.autocomplete, el.inputMode, el.getAttribute('aria-label')].join(' ').toLowerCase();
          return /one-time|otp|code|numeric|tel/.test(attrs);
        });
        for (const el of inputs) {
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(el, ''); else el.value = '';
          el.dispatchEvent(new Event('input', {bubbles:true}));
          el.dispatchEvent(new Event('change', {bubbles:true}));
        }
        """)
    except Exception:
        pass

def _click_strict_roxy_email_otp_resend(
    driver,
    *,
    timeout: int = 20,
    before_send=None,
) -> dict:
    """Trigger only an explicit resend action, while honoring late success."""
    end = time.time() + max(1, int(timeout or 1))
    last_state = {}
    last_error = None
    while time.time() < end:
        transition, state = _roxy_email_otp_transition_state(driver)
        last_state = state
        if transition in {"logged_in", "profile"}:
            logger.info(
                "%s[OTP] 重发前发现终态，取消重发：otp_transition=%s location=%s",
                _log_prefix(driver),
                transition,
                _roxy_otp_location_summary(state),
            )
            return {"ok": True, "status": transition}
        if transition in {"login_password", "password"} or _is_roxy_email_login_state(state) or _generic_roxy_auth_retry_button(state):
            return {"ok": True, "status": "auth_restart", "state": state}
        try:
            button = driver.execute_script(r"""
            const visible = el => {
              if (!el || !(el.offsetWidth || el.offsetHeight || el.getClientRects().length)) return false;
              const style = getComputedStyle(el);
              return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
            };
            const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const norm = value => String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
            const candidates = [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')]
              .filter(el => visible(el) && enabled(el));
            return candidates.find(el => {
              const name = norm(el.getAttribute('name'));
              const value = norm(el.getAttribute('value'));
              if (name === 'intent' && value === 'resend') return true;
              const attrs = [el.id, name, value, el.getAttribute('data-dd-action-name'), el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid')]
                .map(norm).join(' ');
              if (/\bresend\b|send[\s_-]*(?:a[\s_-]*)?new[\s_-]*(?:code|email)|new[\s_-]*(?:verification[\s_-]*)?code/.test(attrs)) return true;
              const text = norm(el.innerText || el.textContent);
              return /\bresend(?:\s+(?:email|code))?\b|send\s+(?:a\s+)?new\s+code|send\s+again|重新发送(?:电子邮件|验证码)?|重发(?:验证码)?|再次发送(?:验证码)?|認証コードを再送|確認コードを再送|コードを再送|再送信|renvoyer(?:\s+le)?\s+code|reenviar(?:\s+el)?\s+código|code\s+erneut\s+senden/.test(text);
            }) || null;
            """)
            if button:
                observer = _roxy_otp_observer(driver)
                if observer is not None:
                    try:
                        observer.install_browser_hooks(driver)
                        observer.mark_resend_start(stage="email_otp")
                    except Exception:
                        pass
                if before_send is not None:
                    before_send()
                text = str(
                    button.text
                    or button.get_attribute("value")
                    or button.get_attribute("data-dd-action-name")
                    or ""
                ).strip()
                _human_click(driver, button, label="resend_otp")
                logger.info(
                    "%s[OTP] otp_transition=resend 已点击明确重新发送按钮：%s",
                    _log_prefix(driver),
                    text or "-",
                )
                time.sleep(
                    random.uniform(1.1, 2.4)
                    if _browser_actions_enabled()
                    else 1.5
                )
                if observer is not None:
                    try:
                        observer.drain_browser_hooks(driver, stage="email_otp")
                        observer.mark_resend_result("clicked", stage="email_otp")
                    except Exception:
                        pass
                return {"ok": True, "status": "resent", "text": text}
        except Exception as exc:
            last_error = exc
            observer = _roxy_otp_observer(driver)
            if observer is not None:
                try:
                    observer.mark_resend_result("failed", stage="email_otp")
                except Exception:
                    pass
        time.sleep(0.5)
    raise EmailOtpResendUnavailable(
        "email_otp_resend_unavailable: "
        f"last={type(last_error).__name__ if last_error else None} "
        f"location={_roxy_otp_location_summary(last_state)}"
    )

def _click_resend_email_otp(
    driver,
    timeout: int = 20,
    *,
    strict: bool = False,
    before_send=None,
) -> dict:
    """点击重新发送邮箱验证码。优先按 DOM 属性识别，文本仅兜底。"""
    if strict:
        return _click_strict_roxy_email_otp_resend(
            driver,
            timeout=timeout,
            before_send=before_send,
        )
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            btn = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const candidates = [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')].filter(visible);
            const attrHit = candidates.find(el => {
              if (!enabled(el)) return false;
              const attrs = [el.id, el.getAttribute('name'), el.getAttribute('value'), el.getAttribute('data-dd-action-name'), el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid')]
                .join(' ').toLowerCase();
              const name = String(el.getAttribute('name') || '').toLowerCase();
              const value = String(el.getAttribute('value') || '').toLowerCase();
              if (name === 'intent' && value === 'resend') return true;
              return /resend|send.*new|new.*code|again/.test(attrs);
            });
            if (attrHit) return attrHit;
            // 兜底：多语言文本，避免因页面没有稳定属性时卡死。
            return candidates.find(el => enabled(el) && /resend|send\s+(?:a\s+)?new\s+code|send\s+again|重新发送|重新发送电子邮件|重发|再次发送|再送信|新しい|届かない/.test((el.innerText || el.textContent || '').toLowerCase())) || null;
            """)
            if btn:
                observer = _roxy_otp_observer(driver)
                if observer is not None:
                    try:
                        observer.install_browser_hooks(driver)
                        observer.mark_resend_start(stage="email_otp")
                    except Exception:
                        pass
                text = str(btn.text or btn.get_attribute('value') or btn.get_attribute('data-dd-action-name') or '').strip()
                _human_click(driver, btn, label="resend_otp")
                logger.info("%s[OTP] 已点击重新发送验证码按钮：%s", _log_prefix(driver), text or '-')
                time.sleep(random.uniform(1.1, 2.4) if _browser_actions_enabled() else 1.5)
                if observer is not None:
                    try:
                        observer.drain_browser_hooks(driver, stage="email_otp")
                        observer.mark_resend_result("clicked", stage="email_otp")
                    except Exception:
                        pass
                return {"ok": True, "text": text}
        except Exception as exc:
            last = exc
            observer = _roxy_otp_observer(driver)
            if observer is not None:
                try:
                    observer.mark_resend_result("failed", stage="email_otp")
                except Exception:
                    pass
        time.sleep(0.5)
    raise RuntimeError(f"找不到可点击的重新发送验证码按钮: last={last}, state={_email_otp_page_state(driver)}")

def _wait_after_email_otp_submit(
    driver,
    timeout: int = 45,
    *,
    roxy_idempotent: bool = False,
) -> str:
    """Wait for a definitive email OTP result without treating a slow redirect as invalid."""
    if roxy_idempotent:
        return _wait_after_roxy_email_otp_submit(driver, timeout=timeout)
    _roxy_otp_submit_result(driver, "waiting", stage="email_otp")
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        time.sleep(0.5)
        if not _is_email_verification_page(driver):
            _roxy_otp_submit_result(driver, "accepted", stage="email_otp")
            return 'accepted'
        last = _email_otp_page_state(driver)
        invalid = any(str(i.get('ariaInvalid') or '').lower() == 'true' for i in (last.get('inputs') or []))
        if invalid or (last.get('errors') or []):
            _roxy_otp_submit_result(driver, "invalid", stage="email_otp")
            return 'invalid'
    if _is_email_verification_page(driver):
        logger.warning(
            "%s[OTP] 提交后仍停留验证码页但没有明确错误，停止重发并记录现场诊断："
            "reason=email_otp_submission_unconfirmed snapshot=%s",
            _log_prefix(driver),
            _email_otp_page_state(driver),
        )
        _roxy_otp_submit_result(driver, "unconfirmed", stage="email_otp")
        return 'unconfirmed'
    _roxy_otp_submit_result(driver, "accepted", stage="email_otp")
    return 'accepted'

def _click_roxy_generic_auth_retry(driver) -> dict:
    """Click only an exact generic auth retry action; this is never a resend."""
    button = driver.execute_script(r"""
    const visible = el => {
      if (!el || !(el.offsetWidth || el.offsetHeight || el.getClientRects().length)) return false;
      const style = getComputedStyle(el);
      return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
    };
    const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
    const norm = value => String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
    const allowed = new Set([
      'try again','retry','重试','再试一次','もう一度試す','もう一度',
      'réessayer','reessayer','inténtalo de nuevo','intentalo de nuevo','erneut versuchen'
    ]);
    return [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')]
      .filter(el => visible(el) && enabled(el))
      .find(el => [
        el.getAttribute('data-dd-action-name'), el.getAttribute('aria-label'),
        el.getAttribute('title'), el.innerText || el.textContent, el.getAttribute('value')
      ].some(value => allowed.has(norm(value)))) || null;
    """)
    if not button:
        return {"ok": False, "reason": "generic_auth_retry_missing"}
    text = str(
        button.text
        or button.get_attribute("data-dd-action-name")
        or button.get_attribute("aria-label")
        or ""
    ).strip()
    _human_click(driver, button, label="auth_try_again")
    logger.info(
        "%s[OTP] otp_transition=auth_restart 已点击通用认证重试：%s",
        _log_prefix(driver),
        text or "-",
    )
    return {"ok": True, "text": text}

def _restart_roxy_email_auth(driver, email: str, timeout: int = 35) -> dict:
    """Restart the auth flow once with the same Profile, email, and HME lease."""
    transition, state = _roxy_email_otp_transition_state(driver)
    if transition in {"logged_in", "profile", "login_password", "password"}:
        return {"state": transition, "otp_after_ts": None}

    otp_after_ts = None
    retry_button = _generic_roxy_auth_retry_button(state)
    fallback_login_at = time.time()
    fallback_login_opened = False
    if retry_button:
        # A generic retry can either navigate back to /log-in or directly
        # restart the verification action. Capture a baseline before clicking.
        prepare_otp_context(email)
        otp_after_ts = time.time()
        clicked = _click_roxy_generic_auth_retry(driver)
        if not clicked.get("ok"):
            raise EmailOtpAuthRestartFailed(
                "email_otp_auth_restart_failed: generic_retry_click_failed"
            )
        # Give the exact retry action time to navigate or dispatch a fresh OTP.
        # If it remains on the same generic error page, the same restart budget
        # may fall back to the normal login entry without creating a Profile.
        fallback_login_at = time.time() + 5.0

    end = time.time() + max(1, int(timeout or 1))
    last_state = state
    while time.time() < end:
        _check_manual_stop()
        transition, state = _roxy_email_otp_transition_state(driver)
        last_state = state
        if transition in {"logged_in", "profile", "login_password", "password"}:
            return {"state": transition, "otp_after_ts": otp_after_ts}
        if bool(state.get("isVerification")) and not _generic_roxy_auth_retry_button(state):
            return {"state": "otp", "otp_after_ts": otp_after_ts}
        if _is_roxy_email_login_state(state):
            prepare_otp_context(email)
            otp_after_ts = time.time()
            next_state = _submit_email_and_wait_next(
                driver,
                email,
                attempts=1,
                refresh_retries=1,
                refresh_interval=2.0,
                allow_existing_account=True,
            )
            logger.info(
                "%s[OTP] otp_transition=auth_restart 同邮箱重新提交完成：state=%s",
                _log_prefix(driver),
                next_state,
            )
            return {"state": next_state, "otp_after_ts": otp_after_ts}
        if (
            transition == "auth_restart_candidate"
            and _generic_roxy_auth_errors(state)
            and not fallback_login_opened
            and time.time() >= fallback_login_at
        ):
            fallback_login_opened = True
            logger.warning(
                "%s[OTP] otp_transition=auth_restart 通用认证错误页未自动返回登录页，"
                "复用当前 Profile 打开登录入口",
                _log_prefix(driver),
            )
            _safe_get(
                driver,
                "https://chatgpt.com/auth/login",
                timeout=min(35, max(10, int(timeout or 35))),
                attempts=1,
                accept_hosts=("chatgpt.com", "auth.openai.com"),
            )
            continue
        time.sleep(0.5)

    raise EmailOtpAuthRestartFailed(
        "email_otp_auth_restart_failed: transition_unconfirmed "
        f"location={_roxy_otp_location_summary(last_state)}"
    )

def _click_continue(driver) -> None:
    _click_any(driver, [
        "button[type='submit']",
        "//button[contains(., 'Continue')]",
        "//button[contains(., '继续')]",
        "//button[contains(., 'Sign up')]",
        "//button[contains(., 'Create')]",
        "//button[contains(., 'Next')]",
    ], timeout=20)

def _maybe_accept(driver) -> None:
    # 只处理明确的 cookie/consent 弹层按钮；不要用 “Continue” 兜底，
    # 非日本出口时 “Continue with Google” 也会命中，导致误点 Google 登录。
    for selectors in ([
        "button#onetrust-accept-btn-handler",
        "button[data-testid='cookie-accept']",
        "button[data-testid='accept-cookies']",
        "//button[contains(., 'Accept')]",
        "//button[contains(., '同意')]",
        "//button[contains(., 'Agree')]",
    ],):
        try:
            _click_any(driver, selectors, timeout=3)
            time.sleep(0.5)
        except Exception:
            pass

def _page_snapshot(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const inputs = [...document.querySelectorAll('input,select,textarea')].map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
          id: el.id || '', placeholder: el.getAttribute('placeholder') || '',
          autocomplete: el.getAttribute('autocomplete') || '', aria: el.getAttribute('aria-label') || '',
          value: el.value || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).filter(x => x.visible).slice(0, 30);
        const buttons = [...document.querySelectorAll('button,a[role=button],input[type=submit]')].map(el => ({
          text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
          type: el.getAttribute('type') || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
          disabled: !!el.disabled
        })).filter(x => x.visible).slice(0, 30);
        const widgets = [...document.querySelectorAll('[role=spinbutton], .react-aria-Select, [data-testid="hidden-select-container"] select')].map(el => ({
          tag: el.tagName, role: el.getAttribute('role') || '', dataType: el.getAttribute('data-type') || '',
          aria: el.getAttribute('aria-label') || '', text: (el.innerText || el.textContent || '').trim().slice(0, 80),
          visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        return {url: location.href, title: document.title, text: (document.body?.innerText || '').slice(0, 2000), inputs, buttons, widgets};
        """) or {}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "url": getattr(driver, 'current_url', '')}
''')
def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
