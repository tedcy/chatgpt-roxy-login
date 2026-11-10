"""Roxy Profile Auth implementation domain.

Loaded into :mod:`core.roxy_registration` so its public compatibility module
retains one shared namespace, locks, and test seams.
"""
from __future__ import annotations
from textwrap import dedent
_SOURCE = dedent(r'''
def _record_dom_event(driver, *, stage: str, event: str, result: str = "", source_error_type: str = "", force: bool = False) -> None:
    try:
        from core.roxy_dom_failure_diagnostic import record_dom_event

        record_dom_event(
            driver,
            stage=stage,
            event=event,
            result=result,
            source_error_type=source_error_type,
            force=force,
        )
    except Exception:
        pass


def _has_access_token(driver) -> bool:
    try:
        result = driver.execute_async_script(r"""
        const done = arguments[0];
        // Roxy profiles deliberately keep the HTTP disk cache between runs.
        // A cached /api/auth/session response can therefore make a freshly
        // cleared profile look logged in and skip the real email/password
        // flow.  This probe is only a transition hint, so always require a
        // network-backed response and never reuse an old body.
        const nonce = `?turb_session_probe=${Date.now()}_${Math.random().toString(36).slice(2)}`;
        fetch(`https://chatgpt.com/api/auth/session${nonce}`, {
          credentials:'include',
          cache:'no-store',
          headers:{'cache-control':'no-cache','pragma':'no-cache'},
        })
          .then(r => r.json()).then(j => done(Boolean(j && j.accessToken)))
          .catch(() => done(false));
        """)
        return bool(result)
    except Exception:
        return False

def _is_profile_like(snapshot: dict) -> bool:
    """资料页识别：兼容 about-you/profile；年龄/生日控件可能不是 input，而是 React Aria widget。"""
    url = str(snapshot.get('url') or '').lower()
    inputs = snapshot.get('inputs') or []
    widgets = snapshot.get('widgets') or []
    attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('name', 'id', 'placeholder', 'autocomplete', 'aria', 'type')).lower()
        for i in inputs
    )
    widget_attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('role', 'dataType', 'aria', 'text', 'tag')).lower()
        for i in widgets
    )
    has_profile_url = any(x in url for x in ('about-you', 'profile', 'signup/profile', 'create-account/profile'))
    has_name_field = (
        'autocomplete name' in attrs
        or ' name ' in f' {attrs} '
        or 'fullname' in attrs
        or 'full_name' in attrs
        or 'firstname' in attrs
        or 'lastname' in attrs
    )
    has_age_or_birth_field = any(x in f' {attrs} {widget_attrs} ' for x in (
        ' age', '-age', '_age', 'birth', 'birthday', 'birthdate',
        ' month', '-month', '_month', 'data-type month',
        ' day', '-day', '_day', 'data-type day',
        ' year', '-year', '_year', 'data-type year',
        'spinbutton', 'react-aria-select', 'type number',
    ))
    # about-you/profile URL 本身已经足够强；部分新版页面会用无 name 的 React Aria 控件。
    return has_profile_url and (has_name_field or has_age_or_birth_field or bool(inputs) or bool(widgets))

def _set_element_value(driver, el, value: str) -> None:
    """兼容 React 受控输入框：用原生 setter 设置值并派发 input/change。"""
    driver.execute_script(r"""
    const el = arguments[0];
    const value = String(arguments[1]);
    const tag = (el.tagName || '').toLowerCase();
    el.scrollIntoView({block:'center'});
    el.focus();
    if (tag === 'select') {
      el.value = value;
    } else {
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, value);
      else el.value = value;
    }
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
    el.blur();
    """, el, value)

def _select_or_type(driver, selectors: list[str], value: str, timeout: int = 3) -> bool:
    try:
        el = _find_any(driver, selectors, timeout=timeout)
    except Exception:
        return False
    try:
        tag = (el.tag_name or '').lower()
        if tag == 'select':
            from selenium.webdriver.support.ui import Select
            sel = Select(el)
            try:
                sel.select_by_value(str(int(value)))
            except Exception:
                try:
                    sel.select_by_visible_text(str(int(value)))
                except Exception:
                    # 月份 select 可能是 0-based，也可能是 1-based；先 value/text，不行再 index。
                    sel.select_by_index(max(0, int(value)-1))
            driver.execute_script("arguments[0].dispatchEvent(new Event('change', {bubbles:true}));", el)
        else:
            _human_type_text(driver, el, str(value), clear=True)
        return True
    except Exception as exc:
        logger.debug('%s 填写字段失败 selectors=%s value=%s err=%s', _log_prefix(driver), selectors, value, exc)
        return False

_BIRTHDAY_SPINBUTTONS = (
    ('[role="spinbutton"][data-type="year"]', "year"),
    ('[role="spinbutton"][data-type="month"]', "month"),
    ('[role="spinbutton"][data-type="day"]', "day"),
)

def _spinbutton_birthday_state(driver, birthday: str) -> dict:
    """Read the visible React Aria date segments; hidden inputs never prove success."""
    y, m, d = birthday.split('-')
    try:
        return driver.execute_script(r"""
        const expected = {
          year: Number(arguments[0]),
          month: Number(arguments[1]),
          day: Number(arguments[2]),
        };
        const readSegment = type => {
          const el = document.querySelector(`[role="spinbutton"][data-type="${type}"]`);
          if (!el) return {present:false, value:null, ariaValueNow:'', ariaValueText:'', text:''};
          const ariaValueNow = String(el.getAttribute('aria-valuenow') || '').trim();
          const ariaValueText = String(el.getAttribute('aria-valuetext') || '').trim();
          const value = 'value' in el ? String(el.value || '').trim() : '';
          const text = String(el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
          let number = null;
          for (const candidate of [ariaValueNow, ariaValueText, value, text]) {
            const parts = String(candidate || '').match(/\d+/g);
            if (parts) {
              number = Number(parts.join(''));
              break;
            }
          }
          return {present:true, value:Number.isFinite(number) ? number : null, ariaValueNow, ariaValueText, text};
        };
        const segments = {
          year: readSegment('year'),
          month: readSegment('month'),
          day: readSegment('day'),
        };
        const actual = {
          year: segments.year.value,
          month: segments.month.value,
          day: segments.day.value,
        };
        const hidden = document.querySelector('input[name="birthday"], input[name="birthdate"]');
        return {
          expected,
          actual,
          segments,
          hiddenValue: hidden ? String(hidden.value || '') : '',
          matchesExpected: Object.keys(expected).every(key => segments[key].present && actual[key] === expected[key]),
        };
        """, y, m, d) or {}
    except Exception as exc:
        return {
            "expected": {"year": int(y), "month": int(m), "day": int(d)},
            "actual": {},
            "matchesExpected": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

def _birthday_state_summary(state: dict) -> dict:
    return {
        "expected": state.get("expected") or {},
        "actual": state.get("actual") or {},
        "matches_expected": bool(state.get("matchesExpected")),
        "hidden_value": state.get("hiddenValue") or "",
        "error": state.get("error") or "",
    }

def _sync_hidden_birthday(driver, birthday: str) -> None:
    """Synchronize a hidden date input only after the visible segments are verified."""
    driver.execute_script(r"""
    const hidden = document.querySelector('input[name="birthday"], input[name="birthdate"]');
    if (!hidden) return;
    const value = String(arguments[0]);
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (setter) setter.call(hidden, value); else hidden.value = value;
    hidden.dispatchEvent(new Event('input', {bubbles:true}));
    hidden.dispatchEvent(new Event('change', {bubbles:true}));
    """, birthday)

def _type_spinbutton_segment_atomic(driver, selector: str, value: str) -> None:
    """Select and replace one semantic date segment in a single Selenium key call."""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys

    modifier = Keys.COMMAND
    try:
        import platform

        if platform.system().lower() != "darwin":
            modifier = Keys.CONTROL
    except Exception:
        pass

    # React Aria can replace a segment node after every edit, so callers must
    # locate it again for each segment and each retry.
    el = driver.find_element(By.CSS_SELECTOR, selector)
    try:
        _human_scroll_to(driver, el)
    except Exception:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
    driver.execute_script("arguments[0].focus();", el)
    if _browser_actions_enabled():
        time.sleep(random.uniform(0.04, 0.16))
    el.send_keys(modifier, "a")
    if _browser_actions_enabled():
        time.sleep(random.uniform(0.04, 0.16))
    # Do not send Backspace and do not split this value. React Aria date
    # segments can discard the first digit after a clear or between calls.
    el.send_keys(str(value))
    if _browser_actions_enabled():
        human_delay("keystroke")
    driver.execute_script(
        "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
        "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));"
        "arguments[0].blur();",
        el,
    )

def _fill_spinbutton_birthday(driver, birthday: str, attempts: int = 2) -> dict:
    """Atomically fill and prove the visible React Aria birthday segments."""
    y, m, d = birthday.split('-')
    values = {"year": y, "month": str(m).zfill(2), "day": str(d).zfill(2)}
    last_state: dict = {}
    last_error = ""

    for attempt in range(1, max(1, int(attempts)) + 1):
        try:
            for selector, key in _BIRTHDAY_SPINBUTTONS:
                _type_spinbutton_segment_atomic(driver, selector, values[key])
            last_state = _spinbutton_birthday_state(driver, birthday)
            if last_state.get("matchesExpected"):
                _sync_hidden_birthday(driver, birthday)
                # Synchronizing the hidden form value must not disturb the
                # visible React state that the user will submit.
                last_state = _spinbutton_birthday_state(driver, birthday)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            last_state = {"matchesExpected": False, "error": last_error}

        summary = _birthday_state_summary(last_state)
        if last_state.get("matchesExpected"):
            logger.info(
                "%s 生日 spinbutton 提交前回读通过：attempt=%s state=%s",
                _log_prefix(driver),
                attempt,
                summary,
            )
            return last_state
        if attempt < max(1, int(attempts)):
            logger.warning(
                "%s 生日 spinbutton 回读不匹配，原地原子重填：attempt=%s state=%s",
                _log_prefix(driver),
                attempt,
                summary,
            )

    detail = _birthday_state_summary(last_state)
    if last_error and not detail.get("error"):
        detail["error"] = last_error
    raise BirthdayInputNotCommitted(f"birthday_input_not_committed state={detail}")

def _fill_birthday_or_age(driver, birthday: str, age: int) -> str | None:
    """填写 about-you 的年龄/生日控件。

    参考 FlowPilot：优先处理直接年龄 input；否则兼容 hidden birthday/date、原生年月日
    select/input、React Aria hidden native select、role=spinbutton[data-type=year/month/day]。
    返回 age / birthday / ymd / react_select / spinbutton / None。
    """
    y, m, d = birthday.split('-')
    result = driver.execute_script(r"""
    const birthday = String(arguments[0]);
    const year = String(arguments[1]);
    const month = String(Number(arguments[2]));
    const month2 = String(arguments[2]).padStart(2, '0');
    const day = String(Number(arguments[3]));
    const day2 = String(arguments[3]).padStart(2, '0');
    const age = String(arguments[4]);
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const setValue = (el, value) => {
      if (!el) return false;
      el.scrollIntoView?.({block:'center'});
      el.focus?.();
      const tag = (el.tagName || '').toLowerCase();
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype
        : tag === 'select' ? HTMLSelectElement.prototype
        : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, String(value)); else el.value = String(value);
      if (tag === 'select') {
        [...el.options].forEach(opt => { opt.selected = String(opt.value) === String(value); });
      }
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
      el.blur?.();
      return true;
    };
    const ageInput = [...document.querySelectorAll('input[name="age"], input#age, input[id$="-age"], input[type="number"]')]
      .find(visible);
    if (ageInput && setValue(ageInput, age)) return {ok:true, mode:'age'};

    const dateInput = [...document.querySelectorAll('input[name="birthdate"], input[type="date"], input[name="birthday"]')]
      .find(el => visible(el) || String(el.getAttribute('type') || '').toLowerCase() === 'date');
    if (dateInput && setValue(dateInput, birthday)) return {ok:true, mode:'birthday'};

    const setFirst = (selectors, values) => {
      for (const sel of selectors) {
        for (const el of [...document.querySelectorAll(sel)]) {
          if (!visible(el)) continue;
          for (const val of values) {
            if (el.tagName === 'SELECT') {
              const has = [...el.options].some(o => String(o.value) === String(val) || String(o.textContent || '').trim() === String(val));
              if (!has) continue;
            }
            if (setValue(el, val)) return true;
          }
        }
      }
      return false;
    };
    const yOk = setFirst(['select[name="year"]','input[name="year"]','select[id*="year"]','input[id*="year"]'], [year]);
    const mOk = setFirst(['select[name="month"]','input[name="month"]','select[id*="month"]','input[id*="month"]'], [month, month2]);
    const dOk = setFirst(['select[name="day"]','input[name="day"]','select[id*="day"]','input[id*="day"]'], [day, day2]);
    if (yOk && mOk && dOk) {
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'ymd'};
    }

    // React Aria Select 通常有 hidden native select；不依赖标签文字，按 option 数值范围和 DOM 顺序推断年/月/日。
    const selects = [...document.querySelectorAll('[data-testid="hidden-select-container"] select, .react-aria-Select select, select')]
      .filter(el => !el.disabled);
    const nums = sel => [...sel.options].map(o => Number(o.value)).filter(Number.isFinite);
    const maxNum = sel => Math.max(...nums(sel), -Infinity);
    const minNum = sel => Math.min(...nums(sel), Infinity);
    const hasOption = (sel, val) => [...sel.options].some(o => String(o.value) === String(val));
    const yearSelects = selects.filter(sel => hasOption(sel, year) && maxNum(sel) > 1900);
    const smallSelects = selects.filter(sel => !yearSelects.includes(sel));
    const monthSelects = smallSelects.filter(sel => (hasOption(sel, month) || hasOption(sel, month2)) && minNum(sel) <= 1 && maxNum(sel) <= 12);
    const daySelects = smallSelects.filter(sel => (hasOption(sel, day) || hasOption(sel, day2)) && maxNum(sel) >= 28);
    if (yearSelects.length && monthSelects.length && daySelects.length) {
      const ys = yearSelects[0];
      let ms = monthSelects[0];
      let ds = daySelects.find(x => x !== ms) || daySelects[0];
      setValue(ys, year);
      setValue(ms, hasOption(ms, month) ? month : month2);
      setValue(ds, hasOption(ds, day) ? day : day2);
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'react_select'};
    }

    const spinYear = document.querySelector('[role="spinbutton"][data-type="year"]');
    const spinMonth = document.querySelector('[role="spinbutton"][data-type="month"]');
    const spinDay = document.querySelector('[role="spinbutton"][data-type="day"]');
    if (spinYear && spinMonth && spinDay) return {ok:false, mode:'spinbutton_needed'};
    return {ok:false, mode:'missing'};
    """, birthday, y, m, d, str(age)) or {}
    if result.get('ok'):
        return str(result.get('mode') or 'birthday')
    if result.get('mode') != 'spinbutton_needed':
        return None

    _fill_spinbutton_birthday(driver, birthday, attempts=2)
    return 'spinbutton'

def _generate_roxy_password() -> str:
    """参考 FlowPilot 密码策略：至少 14 位，含大小写、数字、符号。"""
    from core.account_password import generate_account_password

    return generate_account_password(16)

def _registration_password() -> str:
    # Roxy is a non-headed registration path.  Generate a fresh password for
    # every account instead of reusing the legacy global REGISTER_PASSWORD;
    # the headed-Chrome reference kernel keeps its own password semantics.
    return _generate_roxy_password()

def _saved_registration_password(email: str) -> str:
    """Return an existing local account password without logging its value."""
    try:
        from core import db
        account = db.get_account_by_email(email) or {}
        from core.auth_factors import load_chatgpt_auth_factors

        return load_chatgpt_auth_factors(account).password
    except Exception:
        return ""

def _submit_existing_login_password(driver, password: str) -> bool:
    """Submit a saved password on /log-in/password without exposing it."""
    from core.roxy_browser_kernel import submit_login_password

    return submit_login_password(
        driver,
        password,
        human_type=_human_type_text,
        human_click=_human_click,
        label="registration_existing_password",
        strategy="registration",
        delay=human_delay,
    )

def _wait_existing_login_transition(driver, timeout: int = 20) -> str:
    """Wait for an existing-account login to reach OTP, profile, or Session."""
    end = time.time() + max(1, int(timeout or 1))
    while time.time() < end:
        _check_manual_stop()
        if _has_access_token(driver):
            return "logged_in"
        if _is_email_verification_page(driver):
            return "otp"
        snapshot = _page_snapshot(driver)
        if _is_profile_like(snapshot):
            return "profile"
        time.sleep(0.5)
    if _is_login_password_page(driver):
        return "login_password"
    return "unknown"

def _continue_existing_account_login(
    driver,
    email: str,
    *,
    timeout: int = 20,
) -> dict:
    """Use the saved password or a passwordless OTP to resume one account."""
    saved_password = _saved_registration_password(email)
    if saved_password:
        logger.info(
            "%s 已检测到本地保存密码，尝试登录已有账号",
            _log_prefix(driver),
        )
        if _submit_existing_login_password(driver, saved_password):
            state = _wait_existing_login_transition(driver, timeout=timeout)
            if state in {"logged_in", "otp", "profile"}:
                logger.info(
                    "%s 已有账号密码登录进入下一步：state=%s",
                    _log_prefix(driver),
                    state,
                )
                return {
                    "state": state,
                    "method": "saved_password",
                    "registration_password": saved_password,
                }
        logger.warning(
            "%s 已有账号密码登录未完成，尝试一次邮箱验证码登录",
            _log_prefix(driver),
        )

    passwordless = _click_passwordless_signup_if_present(driver)
    if not passwordless.get("ok"):
        raise ExistingAccountLoginUnavailable(
            "existing_account_login_method_unavailable"
        )
    logger.info(
        "%s 已有账号已触发一次性验证码登录：reason=%s",
        _log_prefix(driver),
        passwordless.get("reason") or "passwordless_otp",
    )
    state = _wait_existing_login_transition(driver, timeout=timeout)
    if state not in {"logged_in", "otp", "profile"}:
        raise ExistingAccountLoginUnavailable(
            f"existing_account_login_transition_unconfirmed state={state}"
        )
    return {
        "state": state,
        "method": "email_otp",
        "registration_password": None,
    }

def _validate_registration_session_identity(email: str, session_info: dict) -> None:
    """Prove the fetched Session belongs only to the requested email."""
    from core.chatgpt_plan import token_claims

    expected = str(email or "").strip().lower()
    info = session_info if isinstance(session_info, dict) else {}
    user = info.get("user") if isinstance(info.get("user"), dict) else {}
    token = str(info.get("accessToken") or "").strip()
    claims = token_claims(token)
    observed = {
        str(value or "").strip().lower()
        for value in (user.get("email"), claims.get("email"))
        if str(value or "").strip()
    }
    if not expected or observed != {expected}:
        raise RegistrationSessionIdentityMismatch(
            "registration_session_identity_mismatch"
        )

def _password_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', visible: visible(el), value: el.type === 'password' ? '<password>' : (el.value || '')
        })).slice(0, 30);
        const forms = [...document.querySelectorAll('form')].map(f => ({action: f.getAttribute('action') || ''}));
        const buttons = [...document.querySelectorAll('button,input[type="submit"]')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          disabled: !!el.disabled, visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        return {url: location.href, inputs, forms, buttons};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}

def _is_signup_password_page(driver) -> bool:
    state = _password_page_state(driver)
    url = str(state.get('url') or '').lower()
    if any(x in url for x in ('/create-account/password', '/u/signup/password', '/signup/password')):
        return True
    if '/log-in/password' in url:
        return False
    inputs = state.get('inputs') or []
    return any(
        i.get('visible') and (
            str(i.get('type') or '').lower() == 'password'
            or 'password' in str(i.get('name') or '').lower()
            or str(i.get('autocomplete') or '').lower() == 'new-password'
        )
        for i in inputs
    )

def _is_login_password_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if '/log-in/password' in url:
        return True
    state = _password_page_state(driver)
    url = str(state.get('url') or '').lower()
    if '/log-in/password' in url:
        return True
    # Newer Auth0/ChatGPT builds keep the route at /log-in while replacing
    # the form in-place.  Detect only a visible current-password style field
    # on a login route; never classify a signup/new-password form as login.
    if any(marker in url for marker in (
        '/create-account/', '/u/signup/', '/signup/password',
    )):
        return False
    if not any(marker in url for marker in (
        '/log-in', '/u/login', '/login', '/auth/login',
    )):
        return False
    for item in state.get('inputs') or []:
        if not item.get('visible'):
            continue
        input_type = str(item.get('type') or '').lower()
        name = str(item.get('name') or '').lower()
        input_id = str(item.get('id') or '').lower()
        autocomplete = str(item.get('autocomplete') or '').lower()
        if autocomplete == 'new-password':
            continue
        if input_type == 'password' or autocomplete == 'current-password':
            return True
        if 'password' in name or 'password' in input_id:
            return True
    return False

def _click_passwordless_signup_if_present(driver) -> dict:
    """
    新版注册/登录流在 password 页可能默认要求密码。
    如果页面提供“使用一次性验证码”按钮，优先点击进入邮箱 OTP 页面。
    """
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const candidates = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')].filter(el => visible(el) && enabled(el));
        const isPasswordlessOtp = el => {
          const name = String(el.getAttribute('name') || '').toLowerCase();
          const value = String(el.getAttribute('value') || '').toLowerCase();
          const attrs = [
            el.id, name, value, el.getAttribute('aria-label'), el.getAttribute('title'),
            el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.className, el.textContent
          ].join(' ').toLowerCase();
          const text = norm(el.textContent || el.getAttribute('value') || '');
          return (
            (name === 'intent' && value.includes('passwordless') && value.includes('send_otp')) ||
            (name === 'intent' && value.includes('passwordless') && value.includes('otp')) ||
            (name === 'intent' && value === 'passwordless_signup_send_otp') ||
            (name === 'intent' && value === 'passwordless_login_send_otp') ||
            attrs.includes('passwordless_signup_send_otp') ||
            attrs.includes('passwordless_login_send_otp') ||
            /passwordless.*otp|otp.*passwordless|one[-_\s]?time.*code|code.*one[-_\s]?time/.test(attrs) ||
            text.includes('使用一次性验证码注册') ||
            text.includes('使用一次性验证码登录') ||
            text.includes('使用一次性验证码') ||
            text.includes('使用一次性驗證碼註冊') ||
            text.includes('使用一次性驗證碼登入') ||
            text.includes('一次性验证码') ||
            text.includes('一次性驗證碼') ||
            text.includes('メールでコード') ||
            text.includes('ワンタイムコード') ||
            text.includes('認証コード') ||
            text.includes('useonetimeregistrationcode') ||
            text.includes('useaone-timecodetosignup') ||
            text.includes('useaone-timecodetoregister') ||
            text.includes('useaone-timecodetologin') ||
            text.includes('continuewithaone-timecode') ||
            text.includes('loginwithaone-timecode') ||
            text.includes('signupwithaone-timecode') ||
            text.includes('one-timecode')
          );
        };
        const btn = candidates.find(isPasswordlessOtp);
        if (!btn) return {ok:false, reason:'missing_passwordless_button'};
        btn.scrollIntoView({block:'center'});
        return {
          ok:true,
          reason:'passwordless_send_otp_target',
          button:btn,
          name: btn.getAttribute('name') || '',
          value: btn.getAttribute('value') || '',
          text: (btn.textContent || '').trim().slice(0, 80)
        };
        """) or {"ok": False, "reason": "empty_result"}
        if result.get("ok") and result.get("button"):
            _human_click(driver, result["button"], label="passwordless_otp")
            result = {key: value for key, value in result.items() if key != "button"}
            result["reason"] = "clicked_passwordless_send_otp"
        return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}

def _fill_password_page_if_present(driver, email: str, timeout: int = 25) -> str | None:
    """邮箱提交后兼容 create-account/password。返回本次设置的 OpenAI 账号密码；未遇到密码页返回 None。"""
    end = time.time() + timeout
    password_submitted_at = 0.0
    password_transition_mark = 0
    last = {}
    while time.time() < end:
        if _is_email_verification_page(driver):
            return None
        if _has_access_token(driver):
            return None
        last = _password_page_state(driver)
        is_signup_password = _is_signup_password_page(driver)
        is_login_password = _is_login_password_page(driver)
        if not (is_signup_password or is_login_password):
            time.sleep(0.5)
            continue
        passwordless = _click_passwordless_signup_if_present(driver)
        if passwordless.get('ok'):
            logger.info("%s 检测到 password 页，已点击一次性验证码入口：email=%s detail=%s", _log_prefix(driver), email, passwordless)
            wait_end = time.time() + 20
            while time.time() < wait_end:
                if _is_email_verification_page(driver):
                    logger.info("%s 一次性验证码入口已进入邮箱验证码页", _log_prefix(driver))
                    return None
                if _has_access_token(driver):
                    logger.info("%s 一次性验证码入口后已检测到登录态", _log_prefix(driver))
                    return None
                time.sleep(0.5)
            logger.info("%s 已点击一次性验证码入口，未立即检测到 OTP 页，交给后续 OTP 阶段继续处理", _log_prefix(driver))
            return None
        if is_login_password:
            logger.info("%s 当前是登录密码页但未找到一次性验证码入口，跳过密码填写并交给 OTP 阶段：state=%s", _log_prefix(driver), last)
            return None
        password = _registration_password()
        _record_dom_event(driver, stage="password", event="password_control_probe", force=True)
        logger.info("%s 检测到 create-account/password，准备设置密码（%s 位）：email=%s", _log_prefix(driver), len(password), email)
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_password_input'};
        const form = input.closest('form');
        const scope = form || document;
        const buttons = [...scope.querySelectorAll('button,input[type="submit"]')]
          .filter(el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled && el.getAttribute('aria-disabled') !== 'true')
          .map((el, idx) => {
            const r = el.getBoundingClientRect();
            const ir = input.getBoundingClientRect();
            return {el, idx, below: r.top >= ir.bottom - 10, dist: Math.max(0, r.top - ir.bottom) + Math.abs((r.left+r.right-ir.left-ir.right)/2)/10};
          })
          .filter(x => x.below)
          .sort((a,b) => a.dist - b.dist || a.idx - b.idx);
        if (!buttons.length) return {ok:false, reason:'missing_submit'};
        buttons[0].el.scrollIntoView({block:'center'});
        return {ok:true, reason:'password_targets', input, button:buttons[0].el};
        """) or {}
        if not result.get('ok'):
            _record_dom_event(driver, stage="password", event="password_control_probe", result="failed", force=True)
            raise RuntimeError(f"密码页处理失败：{result} state={last}")
        _record_dom_event(driver, stage="password", event="password_action_start", force=True)
        try:
            _human_type_text(driver, result.get("input"), password, clear=True)
            human_delay("form", minimum=0.4, maximum=1.4)
            _human_click(driver, result.get("button"), label="password_submit")
        except Exception as exc:
            _record_dom_event(
                driver,
                stage="password",
                event="password_action_exception",
                result="failed",
                source_error_type=type(exc).__name__,
                force=True,
            )
            raise
        _record_dom_event(driver, stage="password", event="password_action_success", result="success", force=True)
        _record_dom_event(driver, stage="password", event="password_transition_waiting", result="waiting", force=True)
        password_submitted_at = time.time()
        logger.info("%s 已填写并提交密码页", _log_prefix(driver))
        # 提交密码后通常进入邮箱验证码页，最多等一段时间。
        wait_end = time.time() + 20
        while time.time() < wait_end:
            if password_submitted_at:
                mark = int(max(0.0, time.time() - password_submitted_at) // 2.0)
                if mark > password_transition_mark:
                    password_transition_mark = mark
                    _record_dom_event(
                        driver,
                        stage="password",
                        event="password_transition_waiting",
                        result="waiting",
                        force=True,
                    )
            if _is_email_verification_page(driver):
                logger.info("%s 密码提交后已进入邮箱验证码页", _log_prefix(driver))
                return password
            if _has_access_token(driver):
                logger.info("%s 密码提交后已检测到登录态", _log_prefix(driver))
                return password
            if not _is_signup_password_page(driver):
                return password
            time.sleep(0.5)
        _record_dom_event(
            driver,
            stage="password",
            event="password_transition_timeout",
            result="failed",
            force=True,
        )
        return password
    logger.info("%s 未检测到密码页，继续后续流程 last=%s", _log_prefix(driver), last)
    return None

def _accept_profile_consents(driver) -> int:
    """about-you/profile 下出现韩国/日本个人信息同意协议时，默认全部勾选。

    不依赖可见文字；优先处理 allCheckboxes，再处理所有必选 consent checkbox。
    """
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const isChecked = el => el.checked === true || String(el.getAttribute('aria-checked') || el.closest('[role="checkbox"]')?.getAttribute('aria-checked') || '').toLowerCase() === 'true';
        const mark = el => {
          if (!el || isChecked(el)) return false;
          const label = el.closest('label');
          try {
            (label && visible(label) ? label : el).scrollIntoView({block:'center'});
            (label && visible(label) ? label : el).click();
          } catch (_) {}
          if (!isChecked(el)) {
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set;
            if (setter) setter.call(el, true); else el.checked = true;
            el.dispatchEvent(new MouseEvent('click', {bubbles:true}));
            el.dispatchEvent(new Event('input', {bubbles:true}));
            el.dispatchEvent(new Event('change', {bubbles:true}));
          }
          return isChecked(el);
        };
        const all = [...document.querySelectorAll('input[type="checkbox"]')]
          .filter(el => visible(el) || visible(el.closest('label')));
        if (!all.length) return {count:0, names:[]};
        const byName = name => all.find(el => String(el.name || '').toLowerCase() === name.toLowerCase());
        const ordered = [];
        const add = el => { if (el && !ordered.includes(el)) ordered.push(el); };
        add(byName('allCheckboxes'));
        for (const name of ['personalInfoConsent', 'thirdPartyConsent', 'overseasTransferConsent']) add(byName(name));
        for (const el of all) {
          const n = String(el.name || '').toLowerCase();
          const id = String(el.id || '').toLowerCase();
          if (/consent|checkbox|agree|required|personal|third|overseas/.test(`${n} ${id}`)) add(el);
        }
        // about-you/profile 页面里的 checkbox 基本都是必选 consent；剩余可见 checkbox 也全部勾选。
        for (const el of all) add(el);
        const clicked = [];
        for (const el of ordered) {
          if (mark(el)) clicked.push(el.name || el.id || 'checkbox');
        }
        return {count: clicked.length, names: clicked};
        """) or {}
        count = int(result.get('count') or 0)
        if count:
            logger.info("%s 已勾选 about-you/profile 同意协议复选框：%s", _log_prefix(driver), result.get('names'))
        return count
    except Exception as exc:
        logger.debug('%s 勾选 profile consent 失败：%s', _log_prefix(driver), exc)
        return 0

_PROFILE_PROGRESS_TEXT_RE = re.compile(
    r"(?:creating\s+your\s+account|this\s+should\s+only\s+take\s+a\s+moment|"
    r"アカウントを作成|しばらくお待ち|création\s+de\s+votre\s+compte|"
    r"creando\s+tu\s+cuenta|konto\s+wird\s+erstellt|계정을\s*만들)",
    re.IGNORECASE,
)

_PROFILE_REJECTION_TEXT_RE = re.compile(
    r"(?:doesn['’]?t\s+look\s+right|something\s+went\s+wrong|unable\s+to\s+create|"
    r"couldn['’]?t\s+create|\binvalid\b|\brequired\b|\bnot\s+eligible\b|\btry\s+again\b|"
    r"错误|无效|不符合|もう一度|正しくありません|無効|"
    r"une\s+erreur|invalide|réessay|reessay|incorrect|ungültig|fehler)",
    re.IGNORECASE,
)

_PROFILE_EXPLICIT_ERROR_SOURCES = frozenset({
    "role_alert",
    "data_error",
    "field_error",
    "aria_errormessage",
    "nearby_red_text",
})

def _profile_submission_candidate_is_error(candidate: dict) -> bool:
    """Treat live-region copy as an error only when it has actual error semantics."""
    text = re.sub(r"\s+", " ", str(candidate.get("text") or "")).strip()
    if not text or _PROFILE_PROGRESS_TEXT_RE.search(text):
        return False
    sources = {str(item or "") for item in (candidate.get("sources") or [])}
    sources.add(str(candidate.get("source") or ""))
    if sources & _PROFILE_EXPLICIT_ERROR_SOURCES:
        return True
    hint = " ".join(
        str(candidate.get(key) or "")
        for key in ("id", "class", "role")
    )
    if re.search(r"(?:error|invalid|danger|destructive)", hint, re.IGNORECASE):
        return True
    return bool(_PROFILE_REJECTION_TEXT_RE.search(text))

def _normalize_profile_submission_error_state(state: dict) -> dict:
    normalized = dict(state or {})
    errors = []
    statuses = list(normalized.get("statusMessages") or [])
    for candidate in normalized.get("errors") or []:
        item = dict(candidate)
        if _profile_submission_candidate_is_error(item):
            errors.append(item)
        else:
            statuses.append(item)
    normalized["errors"] = errors
    normalized["statusMessages"] = statuses
    birthday_invalid = bool(normalized.get("birthdayInvalid"))
    normalized["birthdayRejected"] = birthday_invalid or any(
        bool(item.get("birthdayRelated")) for item in errors
    )
    return normalized

def _profile_submission_error_state(driver) -> dict:
    """Collect visible profile-form errors without treating ordinary page copy as an error."""
    try:
        state = driver.execute_script(r"""
        const rawText = el => String(el?.innerText || el?.textContent || '').trim();
        const normalizedText = el => rawText(el).replace(/\s+/g, ' ').trim();
        const className = el => typeof el?.className === 'string'
          ? el.className
          : String(el?.getAttribute?.('class') || '');
        const visible = el => {
          if (!el || !(el.offsetWidth || el.offsetHeight || el.getClientRects().length)) return false;
          const style = getComputedStyle(el);
          return style.display !== 'none' && style.visibility !== 'hidden'
            && Number.parseFloat(style.opacity || '1') > 0;
        };
        const isRed = color => {
          const match = String(color || '').match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
          if (!match) return false;
          const red = Number(match[1]);
          const green = Number(match[2]);
          const blue = Number(match[3]);
          return red >= 140 && red >= green * 1.25 && red >= blue * 1.25;
        };
        const segments = [...document.querySelectorAll('[role="spinbutton"][data-type="year"], [role="spinbutton"][data-type="month"], [role="spinbutton"][data-type="day"]')];
        const birthRoots = [...new Set(segments.map(el =>
          el.closest('[data-testid*="birth" i],[class*="field" i],fieldset,[role="group"]')
            || el.parentElement?.parentElement?.parentElement
            || el.parentElement
        ).filter(Boolean))];
        const nearBirthday = el => {
          if (!el || !segments.length) return false;
          if (segments.includes(el) || birthRoots.some(root => root.contains(el))) return true;
          const rect = el.getBoundingClientRect();
          return segments.some(segment => {
            const target = segment.getBoundingClientRect();
            const dx = Math.abs((rect.left + rect.width / 2) - (target.left + target.width / 2));
            const dy = Math.abs((rect.top + rect.height / 2) - (target.top + target.height / 2));
            return dx <= 420 && dy <= 220;
          });
        };
        const candidates = new Map();
        const add = (el, source, forceBirthday = false) => {
          if (!visible(el)) return;
          const text = normalizedText(el);
          if (!text) return;
          const rect = el.getBoundingClientRect();
          if (text.length > 800 || rect.height > 240 || el === document.body || el === document.documentElement) return;
          const birthdayRelated = forceBirthday || nearBirthday(el);
          const existing = candidates.get(el);
          if (existing) {
            if (!existing.sources.includes(source)) existing.sources.push(source);
            existing.birthdayRelated = existing.birthdayRelated || birthdayRelated;
            return;
          }
          candidates.set(el, {
            source,
            sources: [source],
            text: rawText(el),
            tag: String(el.tagName || '').toLowerCase(),
            id: el.id || '',
            class: className(el).slice(0, 240),
            role: el.getAttribute('role') || '',
            color: getComputedStyle(el).color || '',
            birthdayRelated,
          });
        };
        const selectors = [
          ['role_alert', '[role="alert"]'],
          ['aria_live', '[aria-live="assertive"], [aria-live="polite"]'],
          ['data_error', '[data-error], [data-testid*="error" i]'],
          ['field_error', '.react-aria-FieldError, [slot="errorMessage"], [id$="-error"], [class*="error" i]'],
        ];
        for (const [source, selector] of selectors) {
          for (const el of document.querySelectorAll(selector)) add(el, source);
        }
        for (const segment of segments) {
          const ids = `${segment.getAttribute('aria-describedby') || ''} ${segment.getAttribute('aria-errormessage') || ''}`
            .trim().split(/\s+/).filter(Boolean);
          for (const id of ids) {
            const target = document.getElementById(id);
            if (target) add(target, 'aria_describedby', true);
          }
        }
        for (const root of birthRoots) {
          for (const el of root.querySelectorAll('p,span,small,div')) {
            if (isRed(getComputedStyle(el).color || '')) add(el, 'nearby_red_text', true);
          }
        }
        const invalid = [...document.querySelectorAll('[aria-invalid="true"]')].filter(visible).map(el => ({
          tag: String(el.tagName || '').toLowerCase(),
          id: el.id || '',
          dataType: el.getAttribute('data-type') || '',
          birthdayRelated: nearBirthday(el),
        }));
        const errors = [...candidates.values()];
        const birthdayInvalid = invalid.some(item => item.birthdayRelated);
        return {
          url: location.href,
          errors,
          invalid,
          anyInvalid: invalid.length > 0,
          birthdayInvalid,
          birthdayRejected: birthdayInvalid || errors.some(item => item.birthdayRelated),
        };
        """) or {}
        return _normalize_profile_submission_error_state(state)
    except Exception as exc:
        return {"url": getattr(driver, 'current_url', ''), "error": f"{type(exc).__name__}: {exc}"}

def _profile_error_state_summary(state: dict) -> dict:
    errors = []
    for item in state.get("errors") or []:
        errors.append({
            "source": item.get("source") or "",
            "text": item.get("text") or "",
            "tag": item.get("tag") or "",
            "id": item.get("id") or "",
            "class": item.get("class") or "",
            "role": item.get("role") or "",
            "color": item.get("color") or "",
            "birthday_related": bool(item.get("birthdayRelated")),
        })
    return {
        "url": state.get("url") or "",
        "errors": errors,
        "any_invalid": bool(state.get("anyInvalid")),
        "birthday_invalid": bool(state.get("birthdayInvalid")),
        "birthday_rejected": bool(state.get("birthdayRejected")),
        "error": state.get("error") or "",
    }

def _log_profile_submission_errors(driver, state: dict, *, reason: str) -> None:
    errors = state.get("errors") or []
    if not errors:
        logger.warning(
            "%s 资料页提交被拒绝：reason=%s any_invalid=%s birthday_invalid=%s",
            _log_prefix(driver),
            reason,
            bool(state.get("anyInvalid")),
            bool(state.get("birthdayInvalid")),
        )
        return
    for item in errors:
        logger.warning(
            "%s 资料页提交被拒绝：reason=%s source=%s tag=%s id=%s class=%s role=%s "
            "color=%s birthday_related=%s error_text=%r",
            _log_prefix(driver),
            reason,
            item.get("source") or "",
            item.get("tag") or "",
            item.get("id") or "",
            item.get("class") or "",
            item.get("role") or "",
            item.get("color") or "",
            bool(item.get("birthdayRelated")),
            item.get("text") or "",
        )

def _wait_after_profile_submit(driver, deadline: float) -> tuple[str, dict]:
    """Wait for a proven transition or a visible profile-form rejection."""
    last_state: dict = {}
    while time.time() < deadline:
        time.sleep(0.5)
        _check_manual_stop()
        if _has_access_token(driver):
            return "accepted", last_state
        snapshot = _page_snapshot(driver)
        current_url = str(snapshot.get("url") or "").lower()
        still_on_profile_url = any(
            marker in current_url
            for marker in ("about-you", "signup/profile", "create-account/profile", "/profile")
        )
        if not still_on_profile_url and not _is_profile_like(snapshot):
            return "accepted", last_state
        last_state = _normalize_profile_submission_error_state(
            _profile_submission_error_state(driver)
        )
        if last_state.get("birthdayRejected"):
            _log_profile_submission_errors(driver, last_state, reason="profile_birthday_rejected")
            return "birthday_rejected", last_state
        if (last_state.get("errors") or []) or last_state.get("anyInvalid"):
            _log_profile_submission_errors(driver, last_state, reason="profile_submission_rejected")
            return "rejected", last_state
    return "unconfirmed", last_state

def _complete_profile_page(driver, name: str, birthday: str, timeout: int = 45) -> bool:
    """等待并完成姓名/生日页；若已经登录成功则返回 False，不把它当失败。"""
    end = time.time() + timeout
    y, m, d = birthday.split('-')
    from datetime import date
    today = date.today()
    age = today.year - int(y) - ((today.month, today.day) < (int(m), int(d)))
    last_snapshot = {}
    submit_attempts = 0
    while time.time() < end:
        time.sleep(1)
        if _has_access_token(driver):
            logger.info('%s 已检测到登录态，资料页可能已跳过', _log_prefix(driver))
            return False
        snap = _page_snapshot(driver)
        last_snapshot = snap
        if not _is_profile_like(snap):
            logger.info('%s 等待资料页中：url=%s', _log_prefix(driver), snap.get('url'))
            continue

        logger.info('%s 检测到资料页，开始填写姓名生日：url=%s inputs=%s', _log_prefix(driver), snap.get('url'), snap.get('inputs'))
        name_ok = False
        # 常见单姓名字段
        for selectors in [
            ["input[name='name']", "input[name='fullName']", "input[name='full_name']", "input[autocomplete='name']"],
            ["input[placeholder*='Name']", "input[placeholder*='name']", "input[aria-label*='Name']", "input[aria-label*='name']"],
        ]:
            if _select_or_type(driver, selectors, name, timeout=3):
                logger.info("%s 已填写姓名字段：%s", _log_prefix(driver), name)
                name_ok = True
                break
        # 兼容 first/last 分开
        if not name_ok:
            parts = name.split(' ', 1)
            first = parts[0]
            last = parts[1] if len(parts) > 1 else 'User'
            first_ok = _select_or_type(driver, ["input[name='firstName']", "input[name='first_name']", "input[placeholder*='First']", "input[aria-label*='First']"], first, timeout=2)
            last_ok = _select_or_type(driver, ["input[name='lastName']", "input[name='last_name']", "input[placeholder*='Last']", "input[aria-label*='Last']"], last, timeout=2)
            name_ok = first_ok or last_ok

        birth_mode = _fill_birthday_or_age(driver, birthday, age)
        birth_ok = bool(birth_mode)
        if birth_ok:
            if birth_mode == 'age':
                logger.info("%s 已填写年龄字段：%s", _log_prefix(driver), age)
            else:
                logger.info("%s 已填写生日字段 mode=%s value=%s", _log_prefix(driver), birth_mode, birthday)

        if not name_ok or not birth_ok:
            logger.warning('%s 资料页字段未填完整 name_ok=%s birth_ok=%s snapshot=%s', _log_prefix(driver), name_ok, birth_ok, snap)
            continue

        _accept_profile_consents(driver)
        human_delay('form')
        retry_profile = False
        for _ in range(3):
            if _click_if_enabled_submit(driver):
                submit_attempts += 1
                logger.info(
                    '%s 已点击资料页提交按钮，等待明确离开资料页：attempt=%s',
                    _log_prefix(driver),
                    submit_attempts,
                )
                outcome, error_state = _wait_after_profile_submit(driver, end)
                if outcome == "accepted":
                    logger.info('%s 资料页已明确通过，继续 OAuth/session 阶段', _log_prefix(driver))
                    return True
                if outcome == "birthday_rejected":
                    if submit_attempts < 2 and time.time() < end:
                        logger.warning(
                            '%s 资料页拒绝生日，复用同一页面原子重填并重交一次',
                            _log_prefix(driver),
                        )
                        retry_profile = True
                        break
                    summary = _profile_error_state_summary(error_state)
                    raise ProfileBirthdayRejected(f"profile_birthday_rejected state={summary}")
                if outcome == "rejected":
                    summary = _profile_error_state_summary(error_state)
                    raise RuntimeError(f"profile_submission_rejected state={summary}")
                summary = _profile_error_state_summary(error_state)
                raise RuntimeError(f"profile_submission_unconfirmed state={summary}")
            time.sleep(1)
        if retry_profile:
            continue
        logger.warning('%s 找不到可点击的资料页提交按钮 snapshot=%s', _log_prefix(driver), _page_snapshot(driver))
    raise RuntimeError(f'等待/填写资料页超时，最后页面：{last_snapshot}')
''')
def register(namespace: dict[str, object]) -> None:
    exec(compile(_SOURCE, __file__, "exec"), namespace, namespace)
