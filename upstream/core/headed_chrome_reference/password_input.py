"""Keep signup input and its submit on the same stable password document."""
import time

from .diagnostics import emit
from .form_readiness import FormWait, FormNotReady, DocumentChanged, read_state, AuthPageSnapshotFailed, AuthPageSnapshotTimeout


PASSWORD_STATE = r"""({expected}) => {
 const visible = e => { const r=e.getBoundingClientRect(), s=getComputedStyle(e);
   return r.width>0 && r.height>0 && s.display!=='none' && s.visibility!=='hidden'; };
 const p=[...document.querySelectorAll('input[type="password"]')].find(visible);
 const form=p?.closest('form');
 const buttons=form ? [...form.querySelectorAll('button[type="submit"],input[type="submit"],button:not([type])')] : [];
 return {host:location.hostname, path:location.pathname.replace(/\/$/,''), epoch:performance.timeOrigin,
   ready:document.readyState!=='loading' && !!p && !p.disabled && !p.readOnly && p.getAttribute('aria-disabled')!=='true',
   filled:!!p?.value, matches:!!p && p.value===expected,
   valid:!!p && p.validity.valid && !form?.querySelector(':invalid,[aria-invalid="true"]'),
   submit:buttons.some(b=>visible(b) && !b.disabled && b.getAttribute('aria-disabled')!=='true')};
}"""


def snapshot(page, expected="", *, worker, deadline):
    try:
        return read_state(worker, page, PASSWORD_STATE, args={"expected": expected},
                          deadline=deadline, clock=time.monotonic)
    except (AuthPageSnapshotFailed, AuthPageSnapshotTimeout):
        return {}


def document_key(state):
    return tuple(state.get(k) for k in ("host", "path", "epoch"))


def wait_ready(worker, page, error_type, *, expected="", submit=False, timeout=10, deadline=None):
    remaining = timeout if deadline is None else max(0, deadline-time.monotonic())
    baseline = getattr(worker, "_password_fill_document", None)
    wait = FormWait(worker, page, remaining, baseline=baseline, clock=time.monotonic,
                    pause=lambda seconds: page.wait_for_timeout(seconds*1000))
    def ready(state):
        key = document_key(state)
        if state and (state.get("host") != "auth.openai.com" or state.get("path") != "/create-account/password"
                      or (baseline is not None and key != baseline)):
            raise error_type("headed_chrome_password_page_changed")
        return state.get("ready") is True and (not submit or all(
            state.get(k) is True for k in ("filled", "matches", "valid", "submit")))
    try:
        state = wait.wait(lambda end: snapshot(page, expected, worker=worker, deadline=end), ready)
        return document_key(state)
    except DocumentChanged:
        raise error_type("headed_chrome_password_page_changed") from None
    except FormNotReady:
        raise error_type("headed_chrome_password_input_not_ready") from None


def validate_before_submit(worker, page, error_type):
    guard = worker._password_wait_guard
    expected = str(worker.openai_password or "")
    deadline = time.monotonic()+5
    state = snapshot(page, expected, worker=worker, deadline=deadline)
    if (state.get("ready") is True and state.get("filled") is False
            and document_key(state) == worker._password_fill_document
            and guard.started is None and not getattr(worker, "_password_local_refill", False)):
        worker._password_local_refill = True
        emit(worker.log, "password_input_recovery", result="refill_before_first_submit")
        inputs = worker._visible_inputs(page, ['input[type="password"]', 'input[name="password"]'])
        if not inputs or not all(worker._type_password_trusted(p, expected) for p in inputs):
            raise error_type("headed_chrome_password_input_not_ready")
    return wait_ready(worker, page, error_type, expected=expected, submit=True, deadline=deadline)


def fill_signup_password(worker, page, fill, error_type):
    worker._password_fill_document = wait_ready(worker, page, error_type)
    worker._password_fill_active = True
    worker._password_input_failed = False
    try:
        try:
            return fill(page)
        except Exception:
            # Retry local typing only after a diagnosed input failure, on the same
            # document and before any observed user/register request. Never repeat
            # an ambiguous click or a response-driven submission.
            guard = worker._password_wait_guard
            if guard.started is not None or not worker._password_input_failed:
                raise
            worker._raise_if_stopped()
            wait_ready(worker, page, error_type, timeout=5)
            emit(worker.log, "password_input_recovery", result="retry_local_typing")
            worker._password_input_failed = False
            return fill(page)
    finally:
        worker._password_fill_active = False
