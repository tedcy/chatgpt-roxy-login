"""Value-free profile form evidence and a bounded post-submit wait."""
import json
import time
from datetime import date
from urllib.parse import urlsplit

PROFILE_WAIT_SECONDS = 60


def completed_age(birthdate, today):
    birth, current = date.fromisoformat(birthdate), date.fromisoformat(today)
    return current.year - birth.year - ((current.month, current.day) < (birth.month, birth.day))


class ProfileDiagnosticError(TimeoutError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _compact_fields(fields):
    """Keep one value-free line useful without flooding the task log."""
    result = []
    for index, field in enumerate(fields[:8]):
        item = {
            "i": index,
            "kind": field.get("kind"),
            "vis": field.get("visible") is True,
            "empty": field.get("empty") is True,
        }
        shape = field.get("value_shape")
        if shape and shape != "unknown":
            item["shape"] = shape
        digits = field.get("digit_count")
        if isinstance(digits, int) and digits:
            item["digits"] = digits
        matches = field.get("matches")
        if isinstance(matches, bool):
            item["match"] = matches
        aria_matches = field.get("aria_value_matches")
        if isinstance(aria_matches, bool):
            item["aria_match"] = aria_matches
        issues = [
            name
            for name in (
                "invalid", "missing", "range", "pattern", "bad_input",
                "aria_invalid", "native_invalid", "aria_range_invalid",
            )
            if field.get(name) is True
        ]
        if issues:
            item["issues"] = issues
        for source, target in (
            ("segmented", "seg"),
            ("editable", "edit"),
            ("focused", "focus"),
            ("disabled", "disabled"),
            ("readonly", "readonly"),
        ):
            if field.get(source) is True:
                item[target] = True
        result.append(item)
    return result


PROFILE_SNAPSHOT_JS = r"""expected => {
 const visible = e => {const r=e.getBoundingClientRect();return r.width>0 && r.height>0;};
 const norm = s => String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
 const controls = Array.from(document.querySelectorAll('input,select,textarea,[role="spinbutton"],[contenteditable="true"]'));
 const parts = expected.birthdate.split('-');
 const wanted = {year:parts[0],month:parts[1],day:parts[2]};
 const now = new Date();
 const today = expected.today || [now.getFullYear(),String(now.getMonth()+1).padStart(2,'0'),String(now.getDate()).padStart(2,'0')].join('-');
 const [ty,tm,td] = today.split('-').map(Number);
 const targetAge = expected.age ?? (ty-Number(parts[0])-(tm<Number(parts[1]) || (tm===Number(parts[1]) && td<Number(parts[2])) ? 1 : 0));
 const targetYear = ty-targetAge;
 const targetDay = Math.min(td,new Date(targetYear,tm,0).getDate());
 const ageBirthday = [targetYear,String(tm).padStart(2,'0'),String(targetDay).padStart(2,'0')].join('-');
 const role = e => {
   if (e.getAttribute('name')==='age') return 'age';
   const s=norm([e.getAttribute('aria-label'),e.getAttribute('autocomplete'),e.getAttribute('data-type'),e.getAttribute('data-testid'),e.getAttribute('name')].join(' '));
   if (e.type==='date') return 'date';
   if (/\byear\b|bday-year|\bnam\b|年/.test(s)) return 'year';
   if (/\bmonth\b|bday-month|thang|月/.test(s)) return 'month';
   if (/\bday\b|bday-day|ngay|日/.test(s)) return 'day';
   if (/birth|bday|dob/.test(s) || e.type==='date') return 'date';
   if (/name|ho va ten/.test(s)) return 'name';
   return 'unknown';
 };
 const ageControls = controls.filter(e=>visible(e)&&role(e)==='age');
 const ageMode = ageControls.length>0;
 const ageForm = ageControls.length===1 ? ageControls[0].form : null;
 const birthdayControls = controls.filter(e=>e.getAttribute('name')==='birthday' && e.type==='hidden' && ageForm && e.form===ageForm);
 const fields=controls.slice(0,24).map((e,index)=>{
   const kind=role(e), value=String(e.value ?? e.textContent ?? '').trim(), v=e.validity;
   const numeric=/^\d+$/.test(value);
   const aria=e.getAttribute('aria-valuenow');
   const lo=e.getAttribute('aria-valuemin'),hi=e.getAttribute('aria-valuemax');
   const n=numeric?Number(value):NaN;
   let matches=null;
   if (kind in wanted && /^\d+$/.test(value)) matches=Number(value)===Number(wanted[kind]);
   if (kind==='name') matches=value===expected.name;
   if (kind==='age') matches=numeric && Number(value)===targetAge;
   if (kind==='date') matches=value===(ageMode ? ageBirthday : expected.birthdate);
   return {index,kind,visible:visible(e),segmented:e.getAttribute('role')==='spinbutton',
     editable:e.isContentEditable===true,empty:!value,matches,
     value_shape:!value?'empty':numeric?'digits':/^[\d\s/.-]+$/.test(value)?'date_parts':'other',
     digit_count:numeric?Math.min(value.length,8):0,
     focused:document.activeElement===e,
     aria_invalid:e.getAttribute('aria-invalid')==='true',
     native_invalid:!!(v&&!v.valid),
     aria_value_matches:aria!==null&&numeric&&/^\d+$/.test(aria)?Number(aria)===n:null,
     aria_range_invalid:numeric&&((lo!==null&&n<Number(lo))||(hi!==null&&n>Number(hi))),
     disabled:e.disabled===true,readonly:e.readOnly===true,
     invalid:e.getAttribute('aria-invalid')==='true'||!!(v&&!v.valid),
     missing:!!v?.valueMissing,range:!!(v?.rangeUnderflow||v?.rangeOverflow),
     pattern:!!v?.patternMismatch,bad_input:!!v?.badInput};
 });
 return {fields,today,age_mode:ageMode,age_consistent:ageControls.length===1
   && /^\d+$/.test(String(ageControls[0].value)) && Number(ageControls[0].value)===targetAge
   && birthdayControls.length===1 && birthdayControls[0].value===ageBirthday,
   form_invalid:Array.from(document.forms).some(f=>f.matches(':invalid')),
   alert_present:Array.from(document.querySelectorAll('[role="alert"],[aria-live="assertive"]')).some(visible),
   submit_available:Array.from(document.querySelectorAll('button[type="submit"],input[type="submit"]')).some(e=>visible(e)&&!e.disabled)};
}"""


class ProfileWaitGuard:
    def __init__(self, log, recorder=None, clock=time.monotonic):
        self.log, self.recorder, self.clock = log, recorder, clock
        self.expected = {"name": "", "birthdate": ""}
        self.page = None
        self.submitted_at = None
        self.warned = False
        self._last_evidence = None

    def capture(self, page, event):
        try:
            raw = page.evaluate(PROFILE_SNAPSHOT_JS, self.expected)
            fields = []
            for f in raw.get("fields", [])[:24]:
                kind = f.get("kind")
                fields.append({"kind": kind if kind in {"year", "month", "day", "date", "name", "age"} else "unknown",
                    **{k: f.get(k) if type(f.get(k)) is bool else None for k in
                       ("visible", "segmented", "editable", "empty", "matches", "invalid", "missing", "range", "pattern", "bad_input",
                        "focused", "aria_invalid", "native_invalid", "aria_value_matches", "aria_range_invalid", "disabled", "readonly")},
                    "value_shape": f.get("value_shape") if f.get("value_shape") in {"empty", "digits", "date_parts", "other"} else "unknown",
                    "digit_count": f.get("digit_count") if type(f.get("digit_count")) is int and 0 <= f["digit_count"] <= 8 else None})
            safe = {"fields": fields, **{k: raw.get(k) is True for k in
                    ("form_invalid", "alert_present", "submit_available")}}
            compact = {
                "field_count": len(fields),
                "fields": _compact_fields(fields),
                "form_invalid": safe["form_invalid"],
                "alert": safe["alert_present"],
                "submit": safe["submit_available"],
            }
            if len(fields) > len(compact["fields"]):
                compact["truncated"] = len(fields) - len(compact["fields"])
            prefix = "[ProfileDiagnostic] event=" + event + " evidence="
            encoded = json.dumps(compact, separators=(",", ":"))
            while compact["fields"] and len(prefix) + len(encoded) >= 780:
                compact["fields"].pop()
                compact["truncated"] = len(fields) - len(compact["fields"])
                encoded = json.dumps(compact, separators=(",", ":"))
            if event != "before_submit_validation" or encoded != self._last_evidence:
                self.log(prefix + encoded)
            self._last_evidence = encoded
            if self.recorder is not None:
                self.recorder.observe(page, stage="profile", event=event, force=True)
            return raw
        except Exception:
            self.log("[ProfileDiagnostic] reason=profile_evidence_unavailable")
            return None

    def validate_filled(self, page) -> None:
        raw = self.capture(page, "before_submit_validation")
        if not isinstance(raw, dict):
            raise ProfileDiagnosticError("profile_submission_evidence_unavailable")
        invalid = [f for f in (raw.get("fields") or []) if f.get("visible") and (
            f.get("invalid") or f.get("missing") or f.get("range") or f.get("pattern")
        )]
        age_expected = self.expected.get("age_mode") or raw.get("age_mode")
        age_invalid = age_expected and (raw.get("age_mode") is not True or raw.get("age_consistent") is not True)
        if raw.get("form_invalid") or invalid or age_invalid:
            self.log("[ProfileDiagnostic] result=blocked_before_submit error_code=profile_fields_invalid")
            raise ProfileDiagnosticError("profile_fields_invalid")

    def submitted(self, page):
        self.page = page
        self.submitted_at = self.clock()
        self.capture(page, "after_submit")

    def check(self):
        if self.submitted_at is None:
            return
        if urlsplit(str(self.page.url)).path.rstrip('/') != '/about-you':
            self.submitted_at = None
            return
        elapsed = self.clock() - self.submitted_at
        if elapsed >= PROFILE_WAIT_SECONDS:
            self._log_cached("profile_timeout")
            raise ProfileDiagnosticError("profile_submission_timeout")
        if elapsed >= 30 and not self.warned:
            self.warned = True
            self._log_cached("profile_stalled")

    def _log_cached(self, event):
        try:
            self.log('[ProfileDiagnostic] event=' + event + ' cached=true evidence=' + (self._last_evidence or '{}'))
        except Exception:
            pass
