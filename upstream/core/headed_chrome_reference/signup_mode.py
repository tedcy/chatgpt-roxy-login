"""Choose signup mode before the pinned kernel marks an OTP as submitted."""
from .form_readiness import FormWait, FormNotReady, DocumentChanged, document_key, AuthPageSnapshotTimeout
from .diagnostics import emit


OTP_PATHS = {"/email-verification", "/email-otp", "/email-code", "/verify-email"}


def _select_saved_password_mode(worker, page, *, timeout, clock):
    """Allow an OTP-first page to finish rendering its password alternative."""
    state = worker._auth_page_snapshot(page)
    if state.get("stage") != "email_otp" or state.get("path") not in OTP_PATHS:
        return worker._select_password_auth_mode_once(page, snapshot=state)
    baseline = document_key(state)
    # Match the existing signup password-entry search budget. Do not enter
    # mailbox handling between the OTP input and password-button React commits.
    deadline = clock() + min(3.0, max(0.0, timeout))
    while True:
        worker._raise_if_stopped()
        if worker._select_password_auth_mode_once(page, snapshot=state):
            return True
        remaining = deadline - clock()
        if remaining <= 0:
            return False
        worker._wait_or_stop(min(.25, remaining))
        state = worker._auth_page_snapshot(page)
        if document_key(state) != baseline or state.get("stage") != "email_otp":
            # The normal auth loop owns a new document or a password page.
            return True


def select_mode(worker, page, error_type, *, timeout, clock):
    if getattr(worker, "openai_password", ""):
        return _select_saved_password_mode(worker, page, timeout=timeout, clock=clock)
    if (getattr(worker, "_auth_screen_hint", "") != "signup"
            or getattr(worker, "_user_register_confirmed", False)):
        return worker._select_password_auth_mode_once(page)
    wait = FormWait(worker, page, timeout, clock=clock)
    wait.diagnostic_phase = 'initial_snapshot'
    evidence = dict(budget_ms=max(0, int(timeout*1000)), samples=0, last_read='unobserved',
                    document_changes=0, controls={})
    last_key = None
    def read(deadline):
        nonlocal last_key
        evidence['samples'] += 1
        try:
            state = worker._auth_page_snapshot(page, timeout=min(15, max(0, deadline-clock())))
        except AuthPageSnapshotTimeout:
            evidence['last_read'] = 'timeout'
            raise
        evidence['last_read'] = 'completed'
        evidence['last_stage'] = state.get('stage') if state.get('stage') in {
            'email_otp', 'transitioning', 'password', 'profile', 'unavailable', 'session_expired', 'other', 'challenge'} else 'unknown'
        controls = state.get('diagnostic_controls')
        evidence['controls'] = {key: value for key, value in (controls if isinstance(controls, dict) else {}).items()
                                if key in {'form', 'input', 'submit'} and type(value) is bool}
        key = document_key(state)
        if all(value is not None for value in key):
            if last_key is not None and key != last_key:
                evidence['document_changes'] += 1
            last_key = key
        if state.get("stage") == "session_expired":
            raise error_type("headed_chrome_auth_session_expired")
        if state.get("stage") == "unavailable":
            if page.is_closed():
                raise DocumentChanged()
            raise error_type("headed_chrome_auth_page_snapshot_failed")
        return state
    try:
        while True:
            try:
                initial = read(wait.deadline)
                break
            except AuthPageSnapshotTimeout:
                if clock() >= wait.deadline:
                    raise FormNotReady() from None
                wait.pause(min(.25, wait.deadline-clock()))
        key = document_key(initial)
        if initial.get("path") not in OTP_PATHS:
            return worker._select_password_auth_mode_once(page, snapshot=initial)
        if getattr(worker, "_password_entry_checked", None) == key:
            return False
        wait.baseline = key
        return _wait_and_choose(worker, page, wait, read, key, error_type)
    except DocumentChanged:
        diagnostic = getattr(worker, "_password_entry_dom_diagnostics", None)
        if diagnostic is not None:
            diagnostic.otp_ready(page, None, check_stop=worker._raise_if_stopped)
        worker._password_entry_checked = None
        worker._email_otp_decision_key = None
        emit(worker.log, "signup_mode_ready", result="redispatch", reason="document_changed")
        return True
    except FormNotReady:
        diagnostic = getattr(worker, '_flow_diagnostics', None)
        emit(worker.log, 'signup_mode_wait', result='timeout', phase=wait.diagnostic_phase,
             elapsed_ms=max(0, int((clock()-wait.started)*1000)), **evidence,
             network=getattr(diagnostic, 'network', {}))
        raise error_type("headed_chrome_auth_page_ready_timeout") from None


def _wait_and_choose(worker, page, wait, read, key, error_type):
    started = wait.started
    diagnostic = getattr(worker, "_password_entry_dom_diagnostics", None)
    def observe(state):
        if (wait.clock()-started >= 3 and document_key(state) == key and not state.get("password_entry_present")
                and diagnostic is not None and diagnostic.failed_key is None):
            diagnostic.recognition_failed(page, key, check_stop=worker._raise_if_stopped)
    def ready(state):
        if not state:
            return False
        if state.get("stage") not in {"transitioning", "email_otp", "snapshot_timeout"}:
            raise error_type("headed_chrome_auth_page_changed")
        return state.get("stage") == "email_otp"
    wait.diagnostic_phase = 'otp_controls'
    state = wait.wait(read, ready, observe=observe)
    if diagnostic is not None:
        diagnostic.otp_ready(page, key, check_stop=worker._raise_if_stopped)
    search_deadline = min(wait.deadline, wait.clock()+3)
    wait.diagnostic_phase = 'password_entry_search'
    while True:
        worker._raise_if_stopped()
        if wait.clock() > wait.deadline:
            raise FormNotReady()
        if worker._select_password_auth_mode_once(page, snapshot=state):
            emit(worker.log, "signup_mode_ready", result="password",
                 elapsed_ms=int((wait.clock()-started)*1000))
            return True
        remaining = search_deadline-wait.clock()
        if remaining <= 0:
            break
        wait.pause(min(.25, remaining))
        if wait.clock() >= search_deadline:
            break
        try:
            state = read(search_deadline)
        except AuthPageSnapshotTimeout:
            raise FormNotReady() from None
        if document_key(state) != key:
            raise DocumentChanged()
        if not ready(state):
            phase = FormWait(worker, page, max(0, search_deadline-wait.clock()),
                             baseline=key, clock=wait.clock, pause=wait.pause)
            state = phase.wait(read, ready, observe=observe)
        observe(state)
    observe(state)
    if diagnostic is not None:
        diagnostic.otp_ready(page, key, check_stop=worker._raise_if_stopped)
    worker._password_entry_checked = key
    worker._email_otp_decision_key = key
    worker.log("[认证] 页面就绪后仍未发现可用密码入口，继续邮箱验证码流程")
    emit(worker.log, "signup_mode_ready", result="email_otp",
         elapsed_ms=int((wait.clock()-started)*1000))
    return False
