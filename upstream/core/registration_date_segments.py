"""Scoped, focus-checked date entry using real browser keyboard operations."""
import json
import time
from datetime import date
from contextlib import contextmanager

from core.headed_chrome_reference.diagnostics import emit

SEGMENT_SECONDS = 6.0
DATE_SECONDS = 18.0
_DOM = r"""
 const visible = e => {
   const r=e.getBoundingClientRect(), s=getComputedStyle(e);
   return r.width>0 && r.height>0 && s.display!=='none' && s.visibility!=='hidden';
 };
 const role = e => {
   const text=['aria-label','autocomplete','data-type','data-testid','name']
     .map(k=>e.getAttribute(k)||'').join(' ').normalize('NFD')
     .replace(/[\u0300-\u036f]/g,'').toLowerCase();
   const hits=[];
   if (/\byear\b|\byyyy\b|bday-year|\bnam\b|年/.test(text)) hits.push('year');
   if (/\bmonth\b|\bmm\b|bday-month|\bthang\b|月/.test(text)) hits.push('month');
   if (/\bday\b|\bdd\b|bday-day|\bngay\b|日/.test(text)) hits.push('day');
   return hits.length===1 ? hits[0] : 'unknown';
 };
 const scan = () => {
   const forms=[...document.querySelectorAll('form,[role="form"]')].filter(f=>
     [...f.querySelectorAll('input[name="name"],input[autocomplete="name"]')].some(visible));
   const scope=forms.length===1 ? forms[0] : document;
   const segments=[...scope.querySelectorAll(
     '[role="spinbutton"], [contenteditable="true"], [contenteditable="plaintext-only"],'
     + 'input[autocomplete="bday-day"],input[autocomplete="bday-month"],input[autocomplete="bday-year"]')]
     .filter(visible).filter(e=>e.getAttribute('role')==='spinbutton'||role(e)!=='unknown');
   const roots=new Set(segments.map(e=>e.closest('form,[role="form"]')||document));
   const roles=segments.map(role);
   const valid=forms.length<=1 && segments.length===3 && roots.size===1
     && ['year','month','day'].every(k=>roles.filter(r=>r===k).length===1);
   return {segments, root:roots.values().next().value, valid};
 };
 const usable = e => !!e?.isConnected && !e.disabled && !e.readOnly
   && e.getAttribute('aria-disabled')!=='true';
 // Whole-date validity may stay false until the final segment is entered.
 // Intermediate commits verify the segment value, not the unfinished date.
 const valueMatches = (e,value) => {
   const text=String(e?.value ?? e?.textContent ?? '').trim();
   return usable(e) && /^\d+$/.test(text) && Number(text)===Number(value);
 };
 const matches = (e,value) => valueMatches(e,value) && e.getAttribute('aria-invalid')!=='true';
"""
PROBE = "() => {" + _DOM + "const s=scan();return s.segments.map(e=>({kind:role(e),scope_valid:s.valid}));}"
_RESOLVE = "kind => {" + _DOM + "const s=scan();return s.valid?s.segments.find(e=>role(e)===kind):null;}"
_CHECK = "expected => {" + _DOM + r"""
 const s=scan();
 const fields=['day','month','year'].map(kind=>({kind,
   matches:s.valid && matches(s.segments.find(e=>role(e)===kind),expected[kind])}));
 const hidden=s.root ? [...s.root.querySelectorAll('input[name="birthday"]')] : [];
 return {fields, hidden_present:hidden.length>0,
   hidden_matches:hidden.every(e=>String(e.value||'')===expected.iso)};
}"""
_FOCUSED = """e => e.isConnected && !e.disabled && !e.readOnly
 && e.getAttribute('aria-disabled')!=='true'
 && (document.activeElement===e || e.contains(document.activeElement))"""
_VALUE = "(e,value) => {" + _DOM + "return valueMatches(e,value); }"
_INPUT_MODE = """e => {
 const min=e.getAttribute('aria-valuemin'), max=e.getAttribute('aria-valuemax');
 return !e.matches('input,textarea') && e.isContentEditable
   && e.getAttribute('role')==='spinbutton' && min!==null && max!==null
   && min.trim()!=='' && max.trim()!=='' && Number.isFinite(Number(min))
   && Number.isFinite(Number(max)) && Number(max)>Number(min) ? 'managed' : 'text';
}"""
_BLUR = """e => {
 if (document.activeElement===e || e.contains(document.activeElement)) document.activeElement.blur();
}"""
_ADVANCED = "(e,value) => {" + _DOM + r"""
 const s=scan(), index=s.segments.indexOf(e), next=s.segments[index+1];
 return s.valid && index>=0 && valueMatches(e,value) && usable(next)
   && (document.activeElement===next || next.contains(document.activeElement));
}"""


class DateSegmentError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _probe(page, *, required=False):
    segments = page.evaluate(PROBE)
    if not segments and not required:
        return []
    roles = [s.get("kind") for s in segments]
    if len(segments) < 3 and len(set(roles)) == len(roles) and set(roles) <= {"year", "month", "day"}:
        raise DateSegmentError("profile_date_segments_missing")
    if (len(segments) != 3 or any(not s.get("scope_valid") for s in segments)
            or {s.get("kind") for s in segments} != {"year", "month", "day"}):
        raise DateSegmentError("profile_date_segments_ambiguous")
    return segments


def _remaining(deadline, code="profile_date_segment_input_timeout"):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DateSegmentError(code)
    return max(1, int(remaining * 1000))


def _focus(control):
    if not control.evaluate(_FOCUSED):
        raise DateSegmentError("profile_date_segment_focus_lost")


@contextmanager
def _timed_action(log, kind, attempt, action, deadline):
    started = time.monotonic()
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        ended = time.monotonic()
        if failed or ended - started >= 0.1:
            emit(log, "date_segment_timing", field=kind, attempt=attempt,
                 action=action, failed=failed, elapsed_ms=int((ended - started) * 1000),
                 budget_remaining_ms=max(0, int((deadline - ended) * 1000)))


def _locate(page, kind, deadline, check_stop):
    while True:
        if check_stop:
            check_stop()
        _remaining(deadline, "profile_date_segment_locate_timeout")
        try:
            _probe(page, required=True)
        except DateSegmentError as exc:
            if exc.code != "profile_date_segments_missing":
                raise
        else:
            handle = page.evaluate_handle(_RESOLVE, kind)
            if handle.as_element() is not None:
                return handle
            handle.dispose()
        page.wait_for_timeout(min(50, _remaining(deadline, "profile_date_segment_locate_timeout")))


def fill_date_segments(page, birthdate, fill_name, log, *, check_stop=None):
    segments = _probe(page)
    if not segments:
        return False
    try:
        expected = date.fromisoformat(birthdate)
    except (TypeError, ValueError) as exc:
        raise DateSegmentError("profile_date_expected_invalid") from exc
    wanted = {"year": str(expected.year), "month": str(expected.month), "day": str(expected.day)}
    log("[ProfileDiagnostic] event=date_segment_mapping order=" + ",".join(s["kind"] for s in segments))
    if check_stop:
        check_stop()
    fill_name()
    # Name entry can replace the entire form. Never reuse pre-entry DOM indexes.
    date_deadline = time.monotonic() + DATE_SECONDS
    for segment in segments:
        kind = segment["kind"]
        deadline = min(date_deadline, time.monotonic() + SEGMENT_SECONDS)
        first_error = None
        for attempt in (1, 2):
            if check_stop:
                check_stop()
            control = handle = None
            stage = "locate"
            try:
                with _timed_action(log, kind, attempt, "locate", deadline):
                    handle = _locate(page, kind, deadline, check_stop)
                control = handle.as_element()
                if control is None:
                    raise DateSegmentError("profile_date_segments_not_committed")
                stage = "focus"
                with _timed_action(log, kind, attempt, "input_mode", deadline):
                    managed = control.evaluate(_INPUT_MODE) == "managed"
                if managed:
                    # Managed contenteditable spinbuttons reset their digit buffer
                    # on focus. Backspace deletes ONE digit, not the whole value.
                    # Force a fresh focus even after automatic advance or a retry.
                    with _timed_action(log, kind, attempt, "reset_focus", deadline):
                        control.evaluate(_BLUR)
                        handle.dispose()
                        handle = _locate(page, kind, deadline, check_stop)
                        control = handle.as_element()
                        if (control is None or control.evaluate(_INPUT_MODE) != "managed"
                                or control.evaluate(_FOCUSED)):
                            raise DateSegmentError("profile_date_segment_focus_lost")
                with _timed_action(log, kind, attempt, "click", deadline):
                    control.click(timeout=_remaining(deadline))
                with _timed_action(log, kind, attempt, "focus", deadline):
                    _focus(control)
                stage = "input"
                if not managed:
                    with _timed_action(log, kind, attempt, "clear", deadline):
                        control.press("Control+A", timeout=_remaining(deadline))
                        _focus(control)
                        control.press("Backspace", timeout=_remaining(deadline))
                        _focus(control)
                advanced = False
                for index, char in enumerate(wanted[kind]):
                    # Some widgets move focus or replace their node on input.
                    # Never send the remainder of a year to the name field.
                    if check_stop:
                        check_stop()
                    with _timed_action(log, kind, attempt, "type_digit", deadline):
                        _focus(control)
                        control.type(char, delay=60, timeout=_remaining(deadline))
                        if not control.evaluate(_FOCUSED):
                            advanced = (managed and index == len(wanted[kind]) - 1
                                        and control.evaluate(_ADVANCED, wanted[kind]))
                            if not advanced:
                                raise DateSegmentError("profile_date_segment_focus_lost")
                stage = "commit"
                # ElementHandle.press would refocus the old segment after a
                # legitimate advance. Only blur with Tab while it still owns focus.
                if not advanced:
                    with _timed_action(log, kind, attempt, "blur_commit", deadline):
                        _focus(control)
                        control.press("Tab", timeout=_remaining(deadline))
                # Blur can replace a segment; inspect a fresh semantic handle.
                with _timed_action(log, kind, attempt, "verify_commit", deadline):
                    handle.dispose()
                    handle = page.evaluate_handle(_RESOLVE, kind)
                    control = handle.as_element()
                    if control is None or not control.evaluate(_VALUE, wanted[kind]):
                        raise DateSegmentError("profile_date_segments_not_committed")
                log("[ProfileDiagnostic] event=date_segment_action field=%s stage=commit attempt=%d matches=true"
                    % (kind, attempt))
                break
            except Exception as exc:
                code = getattr(exc, "code", None)
                if not isinstance(code, str):
                    code = (("profile_date_segment_locate_timeout" if stage in {"locate", "focus"}
                             else "profile_date_segment_input_timeout") if type(exc).__name__ == "TimeoutError"
                            else "profile_date_segments_not_committed")
                if check_stop:
                    check_stop()  # Cancellation must not turn into a field retry.
                first_error = first_error or code
                log("[ProfileDiagnostic] event=date_segment_action field=%s stage=%s attempt=%d error_code=%s"
                    % (kind, stage, attempt, code))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    log("[ProfileDiagnostic] event=date_segment_action field=%s stage=%s reason=budget_exhausted first_error_code=%s"
                        % (kind, stage, first_error))
                    raise DateSegmentError(first_error) from exc
                if attempt == 2 or code == "profile_date_segments_ambiguous":
                    raise DateSegmentError(code) from exc
                page.wait_for_timeout(min(50, max(1, int(remaining * 1000))))
            finally:
                if handle is not None:
                    try:
                        handle.dispose()
                    except Exception:
                        pass
    validate_date_segments(page, birthdate, log, check_stop=check_stop)
    return True


def validate_date_segments(page, birthdate, log, *, check_stop=None):
    """Read-only fence, reused immediately before submitting an already filled form."""
    expected = date.fromisoformat(birthdate)
    wanted = {"year": str(expected.year), "month": str(expected.month), "day": str(expected.day)}
    # Allow a short blur/render commit, but never manufacture hidden form values.
    commit_deadline = time.monotonic() + 0.5
    while True:
        if check_stop:
            check_stop()
        checks = page.evaluate(_CHECK, {**wanted, "iso": expected.isoformat()})
        valid = all(f["matches"] for f in checks["fields"]) and checks["hidden_matches"]
        if valid or time.monotonic() >= commit_deadline:
            break
        page.wait_for_timeout(50)
    log("[ProfileDiagnostic] event=date_segment_verified evidence=" + json.dumps(checks, separators=(",", ":")))
    if not valid:
        raise DateSegmentError("profile_date_segments_not_committed")
