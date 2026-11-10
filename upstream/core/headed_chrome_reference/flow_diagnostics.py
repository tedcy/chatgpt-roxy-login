"""Passive, attempt-local submission and network evidence with bounded reads."""
from contextlib import contextmanager
import json
from pathlib import Path
import time

from .diagnostics import emit
from .network_evidence import category, reason, sentinel_flow
from .page_snapshot import evaluate_snapshot, snapshot_observer, snapshot_purpose
from .page_read_evidence import PageReadEvidence


_DIR = Path(__file__).parent
_EVENTS = ('input', 'change', 'click', 'invalid', 'submit')
_BOOLEANS = ('password_visible', 'password_filled', 'password_valid',
             'otp_visible', 'otp_filled', 'otp_valid', 'otp_matches',
             'invalid_field_present', 'submit_visible', 'submit_enabled')


def _bools(value, keys):
    return {k: value[k] for k in keys if isinstance(value, dict) and type(value.get(k)) is bool}


def _counts(value, keys):
    return {k: min(65535, max(0, value[k])) for k in keys
            if isinstance(value, dict) and type(value.get(k)) is int}


def _timings(value):
    return {key: min(2147483647, max(0, value[key]))
            for key in ('count', 'inclusive_ms', 'exclusive_ms', 'overlap_ms', 'max_inclusive_ms')
            if isinstance(value, dict) and type(value.get(key)) is int}


def _button(value):
    safe = _bools(value, ('in_expected_form', 'submit_button', 'visible', 'enabled', 'center_hit'))
    if isinstance(value, dict):
        safe['button_type'] = value.get('button_type') if value.get('button_type') in {'submit', 'button', 'reset'} else 'other'
    return safe


def safe_state(raw):
    form = raw.get('form') or {}
    return dict(
        form={**_bools(form, _BOOLEANS + ('password_controls_complete', 'password_min12')),
            'frontend_error_marker': 'observed' if form.get('frontend_error_marker') == 'observed' else 'unobserved',
            'password_controls': {name: _bools((form.get('password_controls') or {}).get(name),
                ('present', 'filled', 'valid', 'matches')) for name in ('username', 'usernameKind', 'new-password')},
            **({'otp_shape': form['otp_shape']} if form.get('otp_shape') in {'single', 'segmented', 'other'} else {}), 'fields': [
            _bools(field, ('empty', 'valid', 'aria_invalid', 'matches'))
            for field in form.get('fields', [])[:12] if isinstance(field, dict)]},
        events={k: _counts((raw.get('events') or {}).get(k), ('count', 'trusted', 'canceled')) for k in _EVENTS},
        last_click=_button(raw.get('last_click')),
        last_submit={**_bools(raw.get('last_submit'), ('in_expected_form', 'submitter_present', 'submitter_in_expected_form')),
            **_button(raw.get('last_submit')),
            'branch': (raw.get('last_submit') or {}).get('branch') if (raw.get('last_submit') or {}).get('branch')
                in {'password_register', 'passwordless'} else 'unknown'},
        submit_candidates=[_button(item) for item in (raw.get('submit_candidates') or [])[:4] if isinstance(item, dict)],
        invalid=_bools(raw.get('invalid'), ('name', 'age', 'birthday', 'username', 'usernameKind', 'new-password', 'email_otp', 'other')),
        sdk={**_bools(raw.get('sdk'), ('present', 'token_available', 'init_available', 'requested', 'ready', 'load_failed')),
            **_counts(raw.get('sdk'), ('pending_init', 'pending_token')),
            'init_interface': (raw.get('sdk') or {}).get('init_interface') if (raw.get('sdk') or {}).get('init_interface')
                in {'absent', 'stub', 'replaced'} else 'unknown'},
        script_errors=_counts(raw.get('script_errors'), ('sentinel', 'auth')),
        runtime_errors=_counts(raw.get('runtime_errors'), ('Error', 'TypeError', 'RangeError', 'TimeoutError', 'other')),
    )


class FlowDiagnostics:
    def __init__(self, worker):
        self.worker = worker
        self.started = time.monotonic()
        self.network, self.requests, self.last, self.last_reads = {}, {}, {}, {}
        self.sentinel_flows = {}
        self.document = None
        self.failure_started = False
        self.read_failed = set()
        self.page = None
        self.csrf_failure = None
        self.csrf_final_failure = False
        self.terminal_seen = False
        self.read_states = {}
        self.failure_states = {}
        self.read_evidence = PageReadEvidence(
            lambda: getattr(self.worker, '_headed_auth_page', None) or self.page, self.elapsed)

    def install(self, context):
        try:
            original_log = getattr(self.worker, '_flow_original_log', self.worker.log)
            self.worker._flow_original_log = original_log
            def observed_log(message):
                if isinstance(message, str) and any(marker in message for marker in (
                    '浏览器 CSRF 小接口失败:', 'CSRF 小接口连接中断,',
                    'CSRF 小接口连接中断，', '获取 ChatGPT CSRF 接口两次失败:')):
                    label = reason(message)
                    if label not in {'unknown', 'blocked_telemetry', 'navigation_aborted'}:
                        self.csrf_failure = label
                        if '获取 ChatGPT CSRF 接口两次失败:' in message:
                            self.csrf_final_failure = True
                        emit(original_log, 'registration_network', endpoint='csrf',
                             reason=label, source='existing_csrf_attempt', since_start_ms=self.elapsed())
                return original_log(message)
            self.worker.log = observed_log
            context.add_init_script(script=_DIR.joinpath('submission_events.js').read_text(encoding='utf-8'))
            for name in ('request', 'response', 'requestfailed'):
                context.on(name, lambda item, name=name: self.network_event(name, item))
            self.read_evidence.install(context)
        except Exception:
            emit(self.worker.log, 'submission_diagnostic', result='install_failed')

    def network_event(self, event, item):
        try:
            request = item.request if event == 'response' else item
            page = getattr(self.worker, '_headed_auth_page', None) or self.page
            if page is None or request.frame.page != page:
                return
            name = category(request.url)
            if name == 'other':
                return
            data = self.network.setdefault(name, dict(requests=0, responses=0, failures=0, recovered=0))
            flow = None
            if name == 'sentinel_req':
                flow = sentinel_flow(request)
                self._flow_network_event(flow, event, item, request)
            at_ms = self.elapsed()
            if event == 'request':
                data['requests'] += 1
                self.requests[id(request)] = (name, time.monotonic())
                data.setdefault('first_request_ms', at_ms)
                data['last_request_ms'] = at_ms
                if len(self.requests) > 128:
                    self.requests.pop(next(iter(self.requests)))
            elif event == 'response':
                data['responses'] += 1
                data['status'] = int(item.status)
                data['last_response_ms'] = at_ms
                if 200 <= item.status < 400 and data.get('failed_since_success'):
                    data['recovered'] += 1
                    data['failed_since_success'] = False
                    data['last_recovery_ms'] = at_ms
            else:
                label = reason(request.failure)
                data['failures'] += 1
                data['last_failure_ms'] = at_ms
                data['reason'] = label
                data['failed_since_success'] = True
                data['after_failure'] = self.failure_started
                data['after_terminal'] = self.terminal_seen
                failure_state = (label, self.failure_started, self.terminal_seen)
                if (label != 'blocked_telemetry' and name not in {'telemetry', 'favicon'}
                        and self.failure_states.get(name) != failure_state):
                    emit(self.worker.log, 'registration_network', endpoint=name, reason=label,
                         after_failure=self.failure_started, after_terminal=self.terminal_seen,
                         since_start_ms=at_ms)
                self.failure_states[name] = failure_state
            if event != 'request':
                started = self.requests.pop(id(request), None)
                if started is not None:
                    data['duration_ms'] = max(0, int((time.monotonic()-started[1])*1000))
                if event == 'response' and 200 <= item.status < 400:
                    self.failure_states.pop(name, None)
            data['since_start_ms'] = at_ms
        except Exception:
            pass

    def _flow_network_event(self, flow, event, item, request):
        data = self.sentinel_flows.setdefault(flow, dict(requests=0, responses=0, failures=0, recovered=0))
        at_ms = self.elapsed()
        if event == 'request':
            data['requests'] += 1
            data['last_request_ms'] = at_ms
        elif event == 'response':
            data['responses'] += 1
            data.update(status=int(item.status), last_response_ms=at_ms)
            if 200 <= item.status < 400 and data.get('failed_since_success'):
                data['recovered'] += 1
                data['failed_since_success'] = False
        else:
            data['failures'] += 1
            data.update(reason=reason(request.failure), last_failure_ms=at_ms, failed_since_success=True,
                        after_failure=self.failure_started, after_terminal=self.terminal_seen)

    def elapsed(self):
        return max(0, int((time.monotonic()-self.started)*1000))

    def observe_read(self, event):
        # Called after cancellation has drained; no Playwright calls here.
        try:
            details = self.read_evidence.observe(event, self.elapsed())
            activity = getattr(self.worker, '_registration_trace_activity', None)
            if callable(activity):
                try:
                    raw_activity = activity(event.get('_started_monotonic'), event.get('_ended_monotonic'))
                    details['trace_activity'] = dict(
                        operations={name: _timings((raw_activity.get('operations') or {}).get(name))
                            for name in ('callback', 'headers', 'response_body')
                            if name in (raw_activity.get('operations') or {})},
                        **_bools(raw_activity, ('window_truncated',)))
                except Exception:
                    details['trace_activity'] = {'unavailable': True}
            self.document = self.read_evidence.document
            self.last_reads = self.read_evidence.last_success
            runtime = getattr(self.worker, '_registration_runtime', None)
            active = getattr(runtime, 'diagnostic_phase', None)
            phase = active[0] if active and active[0] in {'auth_flow', 'password_step', 'otp_poll_and_submit',
                                                        'otp_submit', 'failure_dom_finalize'} else 'other'
            read_state = (details['result'], details.get('elapsed_ms', 0) >= 1000, details['purpose'])
            previous = self.read_states.get(phase)
            self.read_states[phase] = read_state
            if (details['document_changed'] or (read_state != previous and
                    (details['result'] != 'completed' or read_state[1] or previous is not None))):
                emit(self.worker.log, 'registration_snapshot', **details,
                     phase=phase, network=self.network, since_start_ms=self.elapsed())
        except Exception:
            pass

    @contextmanager
    def reads(self):
        with snapshot_observer(self.observe_read):
            yield

    def capture(self, page, stage, point, result=None):
        try:
            if stage in self.read_failed:
                return
            from .adapter import _InitialAuthNavigationRetryPage
            source = page._page if isinstance(page, _InitialAuthNavigationRetryPage) else page
            expected = {}
            if stage == 'password':
                expected['new-password'] = str(getattr(self.worker, 'openai_password', '') or '')
                email = getattr(getattr(self.worker, 'account', None), 'email', None)
                if isinstance(email, str):
                    expected.update(username=email.strip().lower(), usernameKind='email')
            if stage == 'otp' and getattr(self.worker, '_email_otp_expected', None) is not None:
                expected['email_otp'] = self.worker._email_otp_expected
            guard = getattr(self.worker, '_profile_wait_guard', None)
            if stage == 'profile' and guard is not None and isinstance(guard.expected, dict):
                expected.update({k: str(v) for k, v in guard.expected.items() if k in {'name', 'age'}})
            script = _DIR.joinpath('submission_snapshot.js').read_text(encoding='utf-8')
            expression = '() => (' + script + ')(' + json.dumps(expected) + ')'
            runtime = getattr(self.worker, '_registration_runtime', None)
            check_stop = runtime.check_cancellation if runtime is not None else lambda: None
            with snapshot_purpose('submission_diagnostic'):
                raw = evaluate_snapshot(source, expression, timeout=2, check_stop=check_stop)
            state = safe_state(raw)
            key = tuple(raw.get(k) for k in ('host', 'path', 'epoch'))
            previous = self.last.get(stage)
            changed = previous is not None and previous['key'] != key
            self.last[stage] = dict(key=key, state=state, result=result)
            password = getattr(self.worker, '_password_wait_guard', None)
            if stage == 'password' and password is not None:
                password.diagnostic_form = dict(state['form'])
                password.diagnostic_form_at = password.clock()
            if (previous is None or previous['state'] != state or changed
                    or previous.get('result') != result or point == 'terminal'):
                emit(self.worker.log, 'submission_diagnostic', stage=stage, point=point,
                     result=result, document_changed=changed,
                     route_matches=raw.get('host') == 'auth.openai.com' and raw.get('stage') == stage,
                     **state, network=self.network, sentinel_flows=self.sentinel_flows)
        except Exception:
            self.read_failed.add(stage)
            emit(self.worker.log, 'submission_diagnostic', stage=stage, point=point, result='read_unavailable')

    def terminal(self, page, exc):
        try:
            self._terminal(page, exc)
        except Exception:
            emit(self.worker.log, 'submission_diagnostic', result='terminal_unavailable')

    def _terminal(self, page, exc):
        self.terminal_seen = True
        self.page = page
        self.failure_started = exc is not None
        from urllib.parse import urlsplit
        route = urlsplit(str(page.url)).path
        current = 'password' if route == '/create-account/password' else 'profile' if route == '/about-you' else 'otp' if route in {'/email-verification', '/email-otp', '/email-code', '/verify-email'} else None
        for stage, previous in tuple(self.last.items()):
            if stage == current:
                self.capture(page, stage, 'terminal', 'failed' if exc is not None else 'completed')
            else:
                emit(self.worker.log, 'submission_diagnostic', stage=stage, point='terminal',
                     cached=True, **previous['state'])
        emit(self.worker.log, 'registration_network_summary', network=self.network,
             sentinel_flows=self.sentinel_flows,
             lifecycle=self.read_evidence.lifecycle, last_success=self.last_reads,
             since_start_ms=self.elapsed(), failed=exc is not None)
        if exc is not None:
            self.capture_dom(page)

    def error_code(self, exc):
        if self.csrf_final_failure and self.csrf_failure and 'csrf' in str(exc).lower():
            return 'headed_chrome_auth_network_error'
        return None

    def capture_dom(self, page):
        gate = getattr(self.worker, '_password_entry_dom_diagnostics', None)
        if gate is None or self.document is None:
            return
        try:
            from .password_entry_diagnostics import PasswordEntryDomDiagnostics
            diagnostic = PasswordEntryDomDiagnostics(self.worker.log, job_id=gate.job_id,
                                                     trace_id=gate.trace_id, directory=gate.directory)
            diagnostic.failed_key, diagnostic.failed_at = self.document, time.monotonic()
            runtime = getattr(self.worker, '_registration_runtime', None)
            check = runtime.check_cancellation if runtime is not None else lambda: None
            diagnostic._save(page, 'submission_failure', check)
        except Exception:
            emit(self.worker.log, 'submission_diagnostic', result='dom_unavailable')


def capture(worker, page, stage, point, result=None):
    diagnostic = getattr(worker, '_flow_diagnostics', None)
    if diagnostic is not None:
        diagnostic.capture(page, stage, point, result)


def install(worker, context):
    try:
        diagnostic = FlowDiagnostics(worker)
        diagnostic.install(context)
        return diagnostic
    except Exception:
        emit(getattr(worker, 'log', None), 'submission_diagnostic', result='install_failed')
        return None
