"""Form metadata and equality flags; raw field values are never returned."""
from core.registration_profile_diagnostic import PROFILE_SNAPSHOT_JS


# Read-only diagnostic presence check covering the two existing selectors.
# Selection still uses the original adapter/vendor actions.
PASSWORD_ENTRY_PRESENT = r"""() => {
 const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);
   return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none';};
 const primary=/continue with password|use password|sign up with password|create password|password instead|パスワードを使用|パスワードで続行|密码登录|使用密码|使用密碼|continuar con contraseña|continuer avec un mot de passe/i;
 const primaryExclude=/forgot|reset|忘れ|重置|找回|olvid|oubli/i;
 const fallback=/continue with password|use password|sign up with password|create password|password instead|password signup|mit passwort fortfahren|passwort verwenden|mit passwort registrieren|passwort erstellen|stattdessen passwort|registrieren mit passwort|密码注册|使用密码|使用密碼|パスワードを使用|パスワードで続行|パスワードで続ける/i;
 const vietnamese=/tiep tuc voi mat khau|tiep tuc bang mat khau|su dung mat khau|dang nhap bang mat khau/i;
 const fallbackExclude=/forgot|reset|password reset|passwort vergessen|passwort zurücksetzen|anmelden|einloggen|忘记|忘記|重置|找回|ログイン|log in|sign in/i;
 return [...document.querySelectorAll('button,a,[role="button"]')].some(e=>{
   if(e.disabled||e.getAttribute('aria-disabled')==='true')return false;
   const text=[e.textContent,e.getAttribute('aria-label')].join(' ').replace(/\s+/g,' ').trim();
   const full=[text,e.getAttribute('title'),e.getAttribute('data-testid')].join(' ');
   const folded=full.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
   return (visible(e)&&primary.test(text)&&!primaryExclude.test(text))
     ||((fallback.test(full)||vietnamese.test(folded))&&!fallbackExclude.test(full));
 });
}"""


EMAIL_STATE = r"""({expected}) => {
 const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);
   return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none';};
 const p=[...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]')].find(visible);
 const form=p?.form || p?.closest('form');
 const buttons=form?[...form.querySelectorAll('button[type="submit"],input[type="submit"],button:not([type])')]:[];
 return {host:location.hostname,path:location.pathname.replace(/\/$/,''),epoch:performance.timeOrigin,
   ready:!!p&&!!form&&p.isConnected&&!p.disabled&&!p.readOnly&&p.getAttribute('aria-disabled')!=='true',
   matches:!!p&&p.value.trim().toLowerCase()===expected.trim().toLowerCase(),
   valid:!!p&&p.validity.valid&&!!form&&!form.querySelector(':invalid,[aria-invalid="true"]'),
   submit:buttons.some(b=>visible(b)&&!b.disabled&&b.getAttribute('aria-disabled')!=='true')};
}"""


PROFILE_STATE = "expected => { const state=(" + PROFILE_SNAPSHOT_JS + r""")(expected);
 const controls=[...document.querySelectorAll('input,select,textarea,[role="spinbutton"],[contenteditable="true"]')];
 const usable=f=>{const e=controls[f.index];if(!e)return false;const s=getComputedStyle(e);
   return f.visible&&!f.disabled&&!f.readonly&&e.getAttribute('aria-disabled')!=='true'&&s.visibility!=='hidden'&&s.display!=='none'
     &&(e.matches('input,select,textarea')||e.isContentEditable);};
 const fields=state.fields.filter(usable), kinds=fields.map(f=>f.kind);
 const count=k=>kinds.filter(v=>v===k).length;
 const modes=[];
 if(count('age')===1)modes.push('age');
 if(count('date')===1)modes.push('date');
 if(count('year')===1&&count('month')===1&&count('day')===1)modes.push('segments');
 if(count('year')===1&&!count('month')&&!count('day'))modes.push('birth_year');
 const mode=modes.length===1?modes[0]:null;
 const selected=fields.filter(f=>f.kind==='name'||(mode==='segments'?['year','month','day'].includes(f.kind):f.kind===(mode==='birth_year'?'year':mode)));
 const submit=[...document.querySelectorAll('button[type="submit"],input[type="submit"],button:not([type])')].some(e=>{
   const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'
     &&!e.disabled&&e.getAttribute('aria-disabled')!=='true';});
 return {host:location.hostname,path:location.pathname.replace(/\/$/,''),epoch:performance.timeOrigin,
   ready:count('name')===1&&!!mode,mode,signature:[mode,...kinds.filter(k=>k!=='unknown').sort()].join('|'),today:state.today,
   filled:selected.length>1&&selected.every(f=>f.matches===true&&!f.invalid),
   valid:!state.form_invalid&&(mode!=='age'||state.age_consistent),submit};
}"""
