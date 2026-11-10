"""Fixed network labels; raw URLs, headers and error messages never leave here."""
from urllib.parse import urlsplit
import json


def sentinel_flow(request):
    """Inspect only Playwright's cached postData; never fetch a body or token."""
    try:
        body = request.post_data
        if not isinstance(body, str) or len(body) > 65536:
            return 'unknown'
        payload = json.loads(body)
        value = payload.get('flow') if isinstance(payload, dict) else None
        return value if value in {'authorize_continue', 'username_password_create',
                                 'email_otp_validate', 'create_account'} else 'unknown'
    except Exception:
        return 'unknown'


def reason(value):
    text = str(value or '').lower()
    for marker, label in (
        ('inspector', 'blocked_telemetry'), ('err_aborted', 'navigation_aborted'),
        ('err_connection_closed', 'connection_closed'), ('err_connection_reset', 'connection_reset'),
        ('err_tunnel_connection_failed', 'proxy_tunnel'), ('err_proxy_connection_failed', 'proxy_connection'),
        ('before secure tls connection', 'tls_connect'), ('econnreset', 'connection_reset'),
        ('err_name_not_resolved', 'dns'), ('err_timed_out', 'network_timeout'),
        ('err_http2_protocol_error', 'http2_protocol'), ('err_failed', 'network_failed'),
    ):
        if marker in text:
            return label
    return 'unknown'


def category(url):
    parsed = urlsplit(str(url or ''))
    host, path = parsed.hostname, parsed.path
    if path.endswith(('favicon.ico', '.svg')):
        return 'favicon' if 'favicon' in path else 'other'
    if host == 'ab.chatgpt.com' or '/rum' in path or '/ces/' in path:
        return 'telemetry'
    if host == 'sentinel.openai.com':
        return 'sentinel_sdk' if path.endswith('/sdk.js') else 'sentinel_req' if path.endswith('/req') else 'sentinel_frame'
    if host == 'auth-cdn.oaistatic.com' and path.endswith('.js'):
        return 'auth_js'
    if host == 'chatgpt.com' and path in {'', '/', '/api/auth/csrf'}:
        return 'csrf'
    if host == 'auth.openai.com':
        from core.registration_terminal_response import registration_endpoint
        return registration_endpoint(url, 'GET' if path.endswith(('/send', '/authorize')) else 'POST') or 'auth_page'
    return 'other'


def exception_reason(exc):
    seen = set()
    while isinstance(exc, BaseException) and id(exc) not in seen and len(seen) < 4:
        seen.add(id(exc))
        label = reason(exc)
        if label not in {'unknown', 'blocked_telemetry', 'navigation_aborted'}:
            return label
        exc = exc.__cause__ if exc.__cause__ is not None else exc.__context__
    return None
