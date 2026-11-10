"""Select password login from an OTP-first chooser, without consuming email OTP."""
import time

_FIND = r"""
return Array.from(document.querySelectorAll('a,button,[role="button"]')).find(el => {
  const text = String(el.innerText || el.textContent || '').replace(/\s+/g,' ').trim();
  if (!/^(continue with password|use password|password instead|使用密码继续|使用密码|密码登录|使用密碼|パスワードで続行)$/i.test(text)) return false;
  if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
  const r = el.getBoundingClientRect();
  if (!r.width || !r.height) return false;
  for (let p=el; p; p=p.parentElement) {
    const s=getComputedStyle(p);
    if(s.display==='none'||s.visibility==='hidden'||s.pointerEvents==='none'||Number(s.opacity)===0) return false;
  }
  const hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);
  return !!hit && (hit===el||el.contains(hit));
}) || null;
"""


def select_password_login(driver, is_password_page, click, stop_event=None):
    deadline = time.monotonic() + 10
    clicked = False
    while time.monotonic() < deadline:
        if stop_event is not None and stop_event.is_set():
            return False
        if is_password_page(driver):
            return True
        if not clicked:
            control = driver.execute_script(_FIND)
            if control is not None:
                click(driver, control, label='strict_password_choice')
                clicked = True
        time.sleep(0.25)
    return False
