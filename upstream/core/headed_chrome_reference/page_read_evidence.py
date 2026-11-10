"""Cached lifecycle and host scheduling evidence; never evaluate a page here."""
from urllib.parse import urlsplit


_TIMINGS = ('budget_ms', 'elapsed_ms', 'cancel_ms', 'dispatch_ms', 'polls',
            'max_poll_lag_ms', 'max_check_ms')
_ROUTES = {'/create-account/password': 'password', '/about-you': 'profile',
           '/email-verification': 'otp', '/email-otp': 'otp', '/email-code': 'otp',
           '/verify-email': 'otp', '/log-in': 'login', '/authorize': 'authorize'}


class PageReadEvidence:
    def __init__(self, current_page, clock):
        self.current_page, self.clock = current_page, clock
        self.document, self.last_success, self.lifecycle = None, {}, {}
        self.generation, self.read_id = 0, 0
        self.bound = set()

    def install(self, context):
        context.on('page', self.bind)
        pages = getattr(context, 'pages', ())
        if isinstance(pages, (list, tuple)):
            for page in pages:
                self.bind(page)

    def bind(self, page):
        try:
            if page in self.bound or len(self.bound) >= 32:
                return
            self.bound.add(page)
            for event, label in (('framenavigated', 'navigation'), ('domcontentloaded', 'dom_ready'),
                                 ('load', 'loaded'), ('crash', 'crashed'), ('close', 'closed')):
                page.on(event, lambda *args, page=page, label=label: self.record(page, label, *args))
        except Exception:
            pass

    def record(self, page, label, *args):
        try:
            if page != self.current_page():
                return
            if label == 'navigation' and (not args or args[0] != page.main_frame):
                return
            data = self.lifecycle.setdefault(label, {'count': 0})
            data['count'] = min(65535, data['count'] + 1)
            data['at_ms'] = self.clock()
            if label == 'navigation':
                # URL properties are Playwright caches, not protocol reads.
                data['route'] = _ROUTES.get(urlsplit(str(args[0].url)).path, 'other')
        except Exception:
            pass

    def observe(self, event, at_ms):
        self.read_id += 1
        result = event.get('result')
        result = result if result in {'completed', 'timeout', 'failed', 'aborted'} else 'unknown'
        safe = {key: max(0, event[key]) for key in _TIMINGS if type(event.get(key)) is int}
        safe.update({key: event[key] for key in ('evaluate_started', 'evaluate_done') if type(event.get(key)) is bool})
        safe['purpose'] = event.get('purpose') if event.get('purpose') in {
            'auth_page', 'form_readiness', 'submission_diagnostic', 'signup_readiness'} else 'other'
        state = event.get('state')
        changed, status = False, 'unobserved'
        if result == 'completed' and isinstance(state, dict) and all(k in state for k in ('host', 'path', 'epoch')):
            key = tuple(state[k] for k in ('host', 'path', 'epoch'))
            changed = self.document is not None and key != self.document
            if key != self.document:
                self.generation += 1
            status = 'changed' if changed else 'observed'
            self.document = key
        if result == 'completed':
            self.last_success = dict(at_ms=at_ms, elapsed_ms=safe.get('elapsed_ms', 0),
                                     purpose=safe['purpose'],
                                     read_id=self.read_id, document_generation=self.generation,
                                     route=_ROUTES.get(state.get('path'), 'other') if isinstance(state, dict) else 'unobserved')
        return dict(**safe, result=result, read_id=self.read_id,
                    start_ms=max(0, at_ms-safe.get('elapsed_ms', 0)), end_ms=at_ms,
                    document_changed=changed, document_status=status,
                    document_generation=self.generation, last_success=dict(self.last_success),
                    lifecycle={key: dict(value) for key, value in self.lifecycle.items()})
