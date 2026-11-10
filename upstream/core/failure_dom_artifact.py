"""Failure-only DOM artifacts; bounded and inert compressed JSON, never HTML execution."""
import gzip
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_DOM_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 ** 3
_LOCK = threading.RLock()
_ID = re.compile(r'[a-f0-9]{32}')
_SCRIPT = Path(__file__).with_name('failure_dom_capture.js').read_text(encoding='utf-8')


def capture(source, directory, diagnostic_id):
    meta = {'captured_at': datetime.now(timezone.utc).isoformat(), 'state': 'unavailable',
            'file_name': None, 'complete': False, 'source': 'unavailable'}
    temp = None
    try:
        if source is None:
            raise RuntimeError()
        execute = getattr(source, 'execute_script', None)
        meta['source'] = 'selenium' if callable(execute) else 'playwright'
        raw = execute('return (' + _SCRIPT + ');') if callable(execute) else source.evaluate(_SCRIPT)
        if not isinstance(raw, dict) or raw.get('format') != 'rendered-dom-v1':
            raise RuntimeError()
        if raw.get('error'):
            meta['error_code'] = 'dom_full_size_limit' if raw['error'] == 'dom_full_size_limit' else 'dom_full_capture_failed'
            return meta
        if not isinstance(raw.get('nodes'), list) or not raw['nodes']:
            raise RuntimeError()
        encoded = json.dumps(raw, ensure_ascii=False).encode('utf-8')
        if len(encoded) > MAX_DOM_BYTES:
            meta['error_code'] = 'dom_full_size_limit'
            return meta
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / (diagnostic_id + '.dom.json.gz')
        temp = directory / ('.' + diagnostic_id + '.dom.tmp')
        temp.write_bytes(gzip.compress(encoded))
        temp.replace(path)
        meta.update(state='saved', file_name=path.name, complete=bool(raw.get('complete')),
                    completeness_scope='accessible_dom_after_redaction',
                    limitations=['closed_shadow_roots_cannot_be_detected_reliably'],
                    raw_bytes=len(encoded), gap_count=len(raw.get('gaps') or []))
        return meta
    except Exception:
        meta['error_code'] = 'dom_full_capture_or_write_failed'
        return meta
    finally:
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass


def remove_package(summary):
    summary = Path(summary)
    summary.with_suffix('.dom.json.gz').unlink(missing_ok=True)
    summary.unlink(missing_ok=True)


def cleanup(directory, protected=None):
    """Enforce byte cap and remove orphan artifacts after summary retention."""
    directory = Path(directory)
    with _LOCK:
        try:
            for artifact in directory.glob('*.dom.json.gz'):
                key = artifact.name.removesuffix('.dom.json.gz')
                if _ID.fullmatch(key) and not (directory / (key + '.json')).exists():
                    # Grace period protects artifacts being committed by other threads.
                    if time.time() - artifact.stat().st_mtime > 300:
                        artifact.unlink(missing_ok=True)
            packages = []
            for summary in directory.glob('*.json'):
                if not _ID.fullmatch(summary.stem):
                    continue
                artifact = summary.with_suffix('.dom.json.gz')
                size = summary.stat().st_size + (artifact.stat().st_size if artifact.exists() else 0)
                packages.append((summary.stat().st_mtime, summary, size))
            total = sum(p[2] for p in packages)
            for _, summary, size in sorted(packages):
                if total <= MAX_TOTAL_BYTES:
                    break
                if summary == protected:
                    continue
                remove_package(summary)
                total -= size
        except OSError:
            pass
