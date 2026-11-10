"""Evidence for the current authenticator, independent of task/password state."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

SOURCES = frozenset({'activation', 'totp_challenge'})


def secret_digest(secret):
    return hashlib.sha256(''.join(str(secret or '').split()).upper().encode()).hexdigest()


def make_confirmation(account, secret, source):
    from core import db
    if source not in SOURCES or not secret:
        raise ValueError('twofa_confirmation_invalid')
    return {'source': source, 'confirmed_at': datetime.now(timezone.utc).isoformat(),
            'secret_digest': secret_digest(secret),
            'identity_revision': db._account_twofa_identity_revision(account)}


def totp_state(account):
    from core import db
    secret = account.get('totp_secret')
    if not secret:
        return 'pending' if account.get('twofa_pending_secret') else 'unbound'
    proof = account.get('twofa_totp_confirmation') or {}
    if (isinstance(proof, dict) and proof.get('source') in SOURCES and proof.get('confirmed_at')
            and proof.get('secret_digest') == secret_digest(secret)
            and proof.get('identity_revision') == db._account_twofa_identity_revision(account)):
        return 'confirmed'
    return 'pending'


def public_fields(account):
    # Safe page-cache rows no longer contain the material used to derive proof.
    if 'has_totp' in account and not any(key in account for key in (
            'totp_secret', 'twofa_pending_secret', 'twofa_totp_confirmation')):
        return {'twofa_bound': account.get('twofa_bound') is True and bool(account['has_totp'])}
    return {'twofa_bound': totp_state(account) == 'confirmed'}


def persist_registration_evidence(account_id, email, secret, activated_secret, *, error_code=None):
    from core import db
    row = db.get_account(account_id)
    if (not row or str(row.get('email') or '').casefold() != str(email).casefold()
            or not secret or row.get('totp_secret') != secret):
        return False
    confirmed = False
    if activated_secret == secret:
        confirmed = db.confirm_account_totp(account_id, secret=secret, source='activation',
                                           expected_identity_revision=db._account_twofa_identity_revision(row))
    if error_code in {'twofa_activate_failed', 'twofa_enroll_failed', 'twofa_remote_status_failed'}:
        with db._account_store().write() as tx:
            current = tx.get(account_id)
            if (not current or current.get('totp_secret') != secret
                    or db._account_twofa_identity_revision(current) != db._account_twofa_identity_revision(row)):
                return False
            current['twofa_error_code'] = error_code
            changed = tx.update(current)
        if changed:
            db._after_account_store_change(refresh_viewer=False)
    return confirmed


def backup_disabled(account, directory):
    """Persist recoverable material before clearing an obsolete local factor."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    keys = ('id', 'email', 'twofa_run_id', 'twofa_claim_identity_revision', 'totp_secret',
            'twofa_totp_confirmation', 'twofa_pending_secret', 'twofa_pending_session_id', 'twofa_pending_at')
    snapshot = {key: account.get(key) for key in keys}
    encoded = json.dumps(snapshot, sort_keys=True, ensure_ascii=True)
    path = directory / (hashlib.sha256(encoded.encode()).hexdigest() + '.json')
    if path.exists():
        if path.read_text(encoding='utf-8') != encoded:
            raise ValueError('twofa_backup_conflict')
        return
    # An interrupted write cannot be mistaken for a completed backup.
    temp = path.with_suffix('.tmp')
    with temp.open('w', encoding='utf-8') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temp, 0o600)
    os.replace(temp, path)
