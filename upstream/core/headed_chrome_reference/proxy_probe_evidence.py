"""Project the existing kernel exception into fixed, credential-free labels."""
import re

from .network_evidence import reason


_SOURCES = re.compile(r'\b(ipwho\.is|ipinfo\.io|api\.myip\.com)\s+')


def _reason(text):
    label = reason(text)
    if label != 'unknown':
        return label
    lowered = text.lower()
    for marker, fixed in (('sslerror', 'tls_error'), ('ssleoferror', 'tls_error'),
                          ('proxyerror', 'proxy_connection'), ('readtimeout', 'network_timeout'),
                          ('connecttimeout', 'network_timeout'), ('timed out', 'network_timeout'),
                          ('nameresolutionerror', 'dns'), ('connectionreseterror', 'connection_reset'),
                          ('remote end closed connection', 'connection_closed'),
                          ('connectionerror', 'network_failed')):
        if marker in lowered:
            return fixed
    return 'provider_rejected' if '返回失败' in text else 'unknown'


def proxy_probe_evidence(exc):
    try:
        # Raw exception text is transient, never returned or logged.
        text = str(exc)[:16384]
        stage = 'exit' if '检测失败[出口]' in text else 'chatgpt' if '检测失败[ChatGPT]' in text else 'unknown'
        matches = list(_SOURCES.finditer(text))[:4]
        probes, seen = [], set()
        for index, match in enumerate(matches[:3]):
            source = match.group(1)
            if source in seen:
                continue
            seen.add(source)
            section = text[match.end():matches[index+1].start() if index+1 < len(matches) else len(text)]
            http = re.match(r'HTTP\s+([1-5]\d{2})\b', section)
            probes.append(dict(source=source, reason='http_status' if http else _reason(section),
                               **({'http_status': int(http.group(1))} if http else {})))
        return dict(stage=stage, source='existing_exception', probes=probes or [dict(source='unknown', reason=_reason(text))])
    except Exception:
        return dict(stage='unknown', source='existing_exception', probes=[dict(source='unknown', reason='unknown')])
