"""Gate typing and submission without inventing a successful email request."""
from .form_readiness import FormWait, FormNotReady, DocumentChanged, document_key
from .form_states import EMAIL_STATE
from .diagnostics import emit


class EmailNotReady(FormNotReady):
    pass


def begin(worker, page, clock):
    wait = FormWait(worker, page, 1, clock=clock)
    state = wait.read(EMAIL_STATE, {"expected": worker.account.email})
    key = document_key(state)
    old = getattr(worker, "_email_fill_document", None)
    if old is not None and old != key:
        worker._email_submission_page_key = None
        worker._email_pending_start_key = None
        worker._reset_email_stall()
        worker._email_fill_document = None
        worker._email_submit_ambiguous = False
        raise DocumentChanged()
    wait.baseline = key
    worker._email_form_wait = wait
    worker._email_readiness_page = page


def hydrated(worker):
    wait = worker._email_form_wait
    try:
        state = wait.wait(lambda _: wait.read(EMAIL_STATE, {"expected": worker.account.email}),
                          lambda s: s.get("ready") is True)
    except FormNotReady:
        raise EmailNotReady() from None
    worker._email_fill_document = document_key(state)
    return {"ready": True, "timed_out": False}


def before_submit(worker, page, clock):
    baseline = getattr(worker, "_email_fill_document", None)
    wait = FormWait(worker, page, 2.5, baseline=baseline, clock=clock)
    wait.wait(lambda _: wait.read(EMAIL_STATE, {"expected": worker.account.email}),
              lambda s: all(s.get(k) is True for k in ("ready", "matches", "valid", "submit")))


def deferred(worker, reason):
    emit(worker.log, "email_form_ready", result="deferred", reason=reason)


def click_submit(worker, page):
    selector = ('form:has(input:is([type="email"],[name="email"],[name="username"],[autocomplete="email"])) '
                ':is(button[type="submit"],input[type="submit"],button:not([type]))')
    try:
        page.locator(selector).first.click(timeout=3000)
        return True
    except Exception:
        worker._raise_if_stopped()
        # A timed-out browser click can already have sent the request. Observe
        # the original recovery path instead of replaying it through requestSubmit.
        worker._email_submit_ambiguous = True
        deferred(worker, "submit_unconfirmed")
        return False
