"""Bounded read-only convergence checks after an email change."""
import logging
import time

logger = logging.getLogger(__name__)


def read_target_identity(
    account,
    *,
    target,
    read_once,
    sleep=time.sleep,
    max_attempts=3,
    retry_delays=(2, 5),
):
    """Read ``/me`` until a known old-email/stale-user result converges.

    Only the exact ``same user + old email`` relation is retried.  A different
    user, missing identity, or non-200 response remains fail-closed and is
    returned immediately.  ``max_attempts`` and ``retry_delays`` are bounded
    caller controls so the normal session-refresh path keeps its historical
    timing while the post-email-change target path can allow a little more
    time for remote identity convergence.
    """

    old = str(account.get("email") or "").strip().lower()
    user = str(account.get("user_id") or "").strip()
    pending = str(account.get("email_change_pending_email") or "").strip().lower()
    target = str(target or "").strip().lower()
    eligible = bool(old and old != target and pending == target and user)
    try:
        attempts = max(1, min(8, int(max_attempts)))
    except (TypeError, ValueError, OverflowError):
        attempts = 3
    delays = tuple(retry_delays or ())
    for attempt in range(attempts):
        status, remote = read_once()
        remote_email = str(remote.get("email") or "").strip().lower() if isinstance(remote, dict) else ""
        remote_user = str(remote.get("id") or "").strip() if isinstance(remote, dict) else ""
        stale = (eligible and status == 200
                 and remote_email == old
                 and remote_user == user)
        if not stale or attempt >= attempts - 1:
            return status, remote
        logger.warning(
            "[EmailChangeIdentityRetry] account_id=%s attempt=%s/%s "
            "http_status=%s me_email=old_email me_user=match "
            "reason=backend_me_old_email",
            int(account.get("id") or 0),
            attempt + 1,
            attempts,
            status,
        )
        try:
            delay = float(delays[attempt])
        except (IndexError, TypeError, ValueError, OverflowError):
            delay = 0.0
        sleep(max(0.0, delay))
