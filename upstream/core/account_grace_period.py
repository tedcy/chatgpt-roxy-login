"""Shared grace-period parsing and account-page predicates."""
from datetime import datetime, timezone


FILTERS = frozenset({'all', 'gt_3d', '1_to_3d', 'le_1d', 'expired', 'none', 'unknown'})
FIELDS = ('grace_period_end_timestamp', 'grace_period_checked_at')


def normalize_filter(value):
    value = str(value or 'all').strip().lower() or 'all'
    if value not in FILTERS:
        raise ValueError('grace_period_invalid')
    return value


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def utc_iso(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def parse_entitlement(entitlement):
    unknown = dict.fromkeys(FIELDS)
    if not isinstance(entitlement, dict):
        return unknown
    value = entitlement.get(FIELDS[0])
    deadline = parse_time(value)
    if value is not None and deadline is None:
        return unknown
    return {
        FIELDS[0]: utc_iso(deadline) if deadline is not None else None,
        FIELDS[1]: utc_iso(datetime.now(timezone.utc)),
    }


def query_facts(row):
    checked = parse_time(row.get(FIELDS[1]))
    raw = row.get(FIELDS[0])
    deadline = parse_time(raw)
    known = checked is not None and (raw is None or deadline is not None)
    return int(known), deadline.timestamp() if known and deadline is not None else None


def public_fields(row, *, now=None):
    known, deadline = query_facts(row)
    reference = now or datetime.now(timezone.utc)
    status = 'unknown'
    if known:
        status = 'none' if deadline is None else ('active' if deadline > reference.timestamp() else 'expired')
    return {
        FIELDS[0]: utc_iso(parse_time(row.get(FIELDS[0]))) if deadline is not None else None,
        FIELDS[1]: utc_iso(parse_time(row.get(FIELDS[1]))) if known else None,
        'grace_period_status': status,
    }


def matches(row, value, *, now):
    value = normalize_filter(value)
    if value == 'all':
        return True
    plan = str(row.get('current_plan_type') or row.get('plan_type') or '').strip().lower()
    if 'plus' not in plan or 'free' in plan:
        return False
    known, deadline = query_facts(row)
    if value == 'unknown':
        return not known
    if value == 'none':
        return bool(known and deadline is None)
    if not known or deadline is None:
        return False
    remaining = deadline - now.timestamp()
    return {
        'gt_3d': remaining > 259200,
        '1_to_3d': 86400 < remaining <= 259200,
        'le_1d': 0 < remaining <= 86400,
        'expired': remaining <= 0,
    }[value]
