"""Semantic profile controls share a post-fill deadline with submission."""
from .form_readiness import FormWait, FormNotReady, DocumentChanged
from .form_states import PROFILE_STATE
from .diagnostics import emit
from .flow_diagnostics import capture
from core.registration_profile_diagnostic import completed_age


def prepare(worker, page, clock):
    wait = FormWait(worker, page, 30, clock=clock)
    state = wait.wait(lambda _: wait.read(PROFILE_STATE, {"name": "", "birthdate": "2000-01-01"}),
                      lambda s: s.get("ready") is True, signature=lambda s: s.get("signature"))
    worker._profile_dispatch_ready = state


def fill_profile(worker, page, reference, error_type, clock):
    name, birthdate = reference.random_profile()
    expected = {"name": name, "birthdate": birthdate}
    wait = FormWait(worker, page, 30, clock=clock)
    try:
        prepared = getattr(worker, "_profile_dispatch_ready", None)
        worker._profile_dispatch_ready = None
        if prepared is not None:
            wait.baseline = tuple(prepared[k] for k in ("host", "path", "epoch"))
            state = wait.read(PROFILE_STATE, expected)
            if (tuple(state.get(k) for k in ("host", "path", "epoch")) != wait.baseline
                    or not state.get("ready") or state.get("signature") != prepared.get("signature")):
                raise DocumentChanged()
        else:
            state = wait.wait(lambda _: wait.read(PROFILE_STATE, expected),
                              lambda s: s.get("ready") is True,
                              signature=lambda s: s.get("signature"))
        worker._profile_form_active = True
        worker._profile_document = wait.baseline
        worker._profile_signature = state["signature"]
        worker._profile_submit_deadline = None
        age = str(completed_age(birthdate, state["today"]))
        worker._fill_about_you_inputs(page, name, birthdate, birthdate.split('-')[0], age)
        capture(worker, page, 'profile', 'before_submit')
        if not worker._submit_about_you(page):
            raise error_type("headed_chrome_profile_form_not_ready")
        capture(worker, page, 'profile', 'after_submit', True)
        guard = getattr(worker, "_profile_wait_guard", None)
        if guard is not None:
            guard.submitted(page)
        emit(worker.log, "profile_form_ready", result="submitted")
    except DocumentChanged:
        raise error_type("headed_chrome_profile_page_changed") from None
    except FormNotReady:
        raise error_type("headed_chrome_profile_form_not_ready") from None
    finally:
        worker._profile_form_active = False


def after_fill(worker, page, clock):
    worker._profile_submit_deadline = clock()+90
    worker._ensure_about_you_required_consents(page)
    worker._reactivate_about_you_inputs(page)
    before_submit(worker, page, clock)


def before_submit(worker, page, clock):
    remaining = worker._profile_submit_deadline-clock()
    wait = FormWait(worker, page, max(0, remaining), baseline=worker._profile_document, clock=clock)
    expected = worker._profile_wait_guard.expected
    def ready(state):
        if state.get("ready") is True and state.get("signature") != worker._profile_signature:
            raise DocumentChanged()
        return all(state.get(k) is True for k in ("ready", "filled", "valid", "submit"))
    def read(_):
        state = wait.read(PROFILE_STATE, expected)
        key = tuple(state.get(k) for k in ("host", "path", "epoch"))
        if (key == worker._profile_document and state.get("signature") == worker._profile_signature
                and state.get("filled") and not state.get("valid")):
            prepare = getattr(worker, "_ensure_about_you_required_consents", None)
            if callable(prepare):
                prepare(page)
        return state
    return wait.wait(read, ready,
                     signature=lambda s: s.get("signature"))
