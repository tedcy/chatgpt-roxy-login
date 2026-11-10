# -*- coding: utf-8 -*-
"""安全的 Plus/Go/Pro 优惠活动字段处理。

套餐接口返回的优惠对象包含标题、摘要和其它上游 metadata。账号页只需要
产品类型、活动 ID 和命中的地区，因此所有入口都先经过这里的白名单清洗。
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable

_ALLOWED_PLAN_TYPES = frozenset({"plus", "go", "pro"})
_CAMPAIGN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REGION_RE = re.compile(r"^[A-Z]{2}$")
_PLUS_FREE_TRIAL_RE = re.compile(
    r"^plus-[1-9][0-9]*-months?-free$",
    re.IGNORECASE,
)
_PERCENT_DISCOUNT_RE = re.compile(
    r"^(?:plus|pro)-[1-9][0-9]*-months?-(?:[1-9][0-9]?|100)-pct-off$",
    re.IGNORECASE,
)
_MAX_CAMPAIGNS = 32
_MAX_REGIONS_PER_CAMPAIGN = 8
_PROMO_METADATA_FIELDS = frozenset({
    "eligible_promo_campaigns",
    "plus_trial_discount_percentage",
    "plus_trial_duration_num_periods",
    "plus_trial_duration_period",
    "plus_trial_promotion_type_label",
    "plus_trial_summary",
    "plus_trial_title",
})


def _safe_plan(value: object) -> str | None:
    plan = str(value or "").strip().lower()
    return plan if plan in _ALLOWED_PLAN_TYPES else None


def _safe_campaign_id(value: object) -> str | None:
    campaign_id = "".join(
        char
        for char in str(value or "")
        if not unicodedata.category(char).startswith("C")
    ).strip()
    if not campaign_id or not _CAMPAIGN_ID_RE.fullmatch(campaign_id):
        return None
    # Keep the identifier as returned by the service; aggregation below uses
    # a case-insensitive key while the first-seen spelling remains visible.
    return campaign_id


def _safe_regions(value: object) -> list[str]:
    if isinstance(value, str):
        values: Iterable[object] = re.split(r"[\s,;，；]+", value)
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = ()
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        region = str(raw or "").strip().upper()
        if not _REGION_RE.fullmatch(region) or region in seen:
            continue
        seen.add(region)
        result.append(region)
        if len(result) >= _MAX_REGIONS_PER_CAMPAIGN:
            break
    return result


def _candidate_records(value: object) -> list[tuple[str | None, dict]]:
    """Flatten the two known response shapes without retaining metadata."""

    records: list[tuple[str | None, dict]] = []
    if isinstance(value, (list, tuple)):
        for candidate in value:
            if isinstance(candidate, dict):
                records.append((str(candidate.get("plan") or ""), candidate))
        return records
    if not isinstance(value, dict):
        return records
    # A normalized/list-style record may be passed back by a regional scan.
    if "id" in value or "campaign_id" in value:
        records.append((str(value.get("plan") or ""), value))
        return records
    for raw_plan, raw_campaigns in value.items():
        plan = _safe_plan(raw_plan)
        if plan is None:
            continue
        candidates = raw_campaigns if isinstance(raw_campaigns, list) else [raw_campaigns]
        for candidate in candidates:
            if isinstance(candidate, str):
                candidate = {"id": candidate}
            if isinstance(candidate, dict):
                records.append((plan, candidate))
    return records


def normalize_plan_promo_campaigns(
    value: object,
    *,
    default_regions: object = (),
    max_campaigns: int | None = _MAX_CAMPAIGNS,
) -> list[dict[str, object]]:
    """Return only ``plan``, ``campaign_id`` and safe ``regions`` fields."""

    fallback_regions = _safe_regions(default_regions)
    result: list[dict[str, object]] = []
    seen: dict[tuple[str, str], int] = {}
    for raw_plan, candidate in _candidate_records(value):
        plan = _safe_plan(candidate.get("plan") or raw_plan)
        campaign_id = _safe_campaign_id(
            candidate.get("campaign_id") or candidate.get("id")
        )
        if plan is None or campaign_id is None:
            continue
        regions = _safe_regions(candidate.get("regions")) or list(fallback_regions)
        key = (plan, campaign_id.casefold())
        existing_index = seen.get(key)
        if existing_index is None:
            seen[key] = len(result)
            result.append({
                "plan": plan,
                "campaign_id": campaign_id,
                "regions": regions,
            })
            if max_campaigns is not None and len(result) >= max_campaigns:
                break
            continue
        existing = result[existing_index]
        existing_regions = existing.get("regions")
        if not isinstance(existing_regions, list):
            existing_regions = []
            existing["regions"] = existing_regions
        for region in regions:
            if region not in existing_regions and len(existing_regions) < _MAX_REGIONS_PER_CAMPAIGN:
                existing_regions.append(region)
    return result


def plan_promo_campaign_kind(value: object) -> str:
    """Classify one sanitized campaign without trusting upstream labels.

    ``eligible_promo_campaigns.plus`` is a generic Plus promotion bucket.  It
    may contain a free trial or a paid discount, so bucket presence alone is
    never sufficient to grant ``plus_trial_eligible``.
    """

    if not isinstance(value, dict):
        return "other"
    plan = _safe_plan(value.get("plan"))
    campaign_id = _safe_campaign_id(
        value.get("campaign_id") or value.get("id")
    )
    if plan == "plus" and campaign_id and _PLUS_FREE_TRIAL_RE.fullmatch(campaign_id):
        return "free_trial"
    if campaign_id and _PERCENT_DISCOUNT_RE.fullmatch(campaign_id):
        return "discount"
    return "other"


def first_plus_free_trial_campaign(value: object) -> dict[str, object] | None:
    """Return the first explicitly free Plus campaign, if any."""

    return next(
        (
            item
            for item in normalize_plan_promo_campaigns(value)
            if plan_promo_campaign_kind(item) == "free_trial"
        ),
        None,
    )


def merge_plan_promo_campaigns(*values: object) -> list[dict[str, object]]:
    """Merge already-safe or raw campaign collections in first-seen order."""

    merged: list[dict[str, object]] = []
    for value in values:
        for item in normalize_plan_promo_campaigns(value):
            merged = normalize_plan_promo_campaigns(merged + [item])
    return merged[:_MAX_CAMPAIGNS]


def merge_plan_promo_campaigns_history(*values: object) -> list[dict[str, object]]:
    """Keep all distinct historical campaigns, using the same safe fields."""

    records = [
        item
        for value in values
        for item in normalize_plan_promo_campaigns(value, max_campaigns=None)
    ]
    return normalize_plan_promo_campaigns(records, max_campaigns=None)


def successful_plan_promo_campaigns_by_region(result: dict) -> dict[str, list[dict[str, object]]]:
    """Use only successful regional responses, attaching their actual route."""

    regions = result.get("plan_region_results")
    if not isinstance(regions, dict):
        return {}
    observed = {}
    for region, item in regions.items():
        safe_regions = _safe_regions([region])
        if not safe_regions or not isinstance(item, dict) or item.get("ok") is not True:
            continue
        source = public_plan_promo_campaigns(item)
        if "plan_promo_campaigns" not in item and "plus_trial_campaign_id" not in item:
            # Older callers may send only regional diagnostics. Missing offers
            # are not an explicit empty response; use attributed aggregate
            # offers on success, otherwise leave this route's snapshot alone.
            source = [
                campaign
                for campaign in public_plan_promo_campaigns(result)
                if result.get("ok") is True and safe_regions[0] in campaign["regions"]
            ]
            if not source:
                continue
        observed[safe_regions[0]] = plan_promo_campaigns_for_region(
            source, safe_regions[0],
        )
    return observed


def plan_promo_campaigns_for_region(
    value: object,
    region: object,
) -> list[dict[str, object]]:
    """Attach only the region that produced this successful response.

    Region scans must not trust a region list supplied by a nested result:
    the caller already knows which route actually completed the request.
    """

    regions = _safe_regions([region])
    result = normalize_plan_promo_campaigns(value)
    for item in result:
        item["regions"] = list(regions)
    return result


def replace_plan_promo_campaigns_for_region(
    existing: object,
    replacement: object,
    region: object,
) -> list[dict[str, object]]:
    """Replace only one region while preserving other successful regions.

    Historical campaign rows without a region cannot safely be attributed to
    the queried route, so a regional refresh leaves them untouched.  Records
    carrying the target region lose only that region; empty records are then
    discarded before the newly observed campaigns are merged in.
    """

    safe_regions = _safe_regions([region])
    if not safe_regions:
        return normalize_plan_promo_campaigns(existing)
    target = safe_regions[0]
    retained: list[dict[str, object]] = []
    for item in normalize_plan_promo_campaigns(existing):
        regions = list(item.get("regions") or [])
        if not regions:
            retained.append(item)
            continue
        remaining = [candidate for candidate in regions if candidate != target]
        if not remaining:
            continue
        kept = dict(item)
        kept["regions"] = remaining
        retained.append(kept)
    observed = plan_promo_campaigns_for_region(replacement, target)
    return merge_plan_promo_campaigns(retained, observed)


def sanitize_plan_result_promos(value: object) -> dict[str, Any]:
    """Remove upstream promo metadata from one persisted plan result.

    Normal query code already emits the safe list.  This defensive boundary
    also covers tests, legacy callers, and malformed nested regional results
    before either result snapshot is written to SQLite.
    """

    if not isinstance(value, dict):
        return {}
    result = dict(value)
    had_campaign_list = "plan_promo_campaigns" in result
    for key in _PROMO_METADATA_FIELDS:
        result.pop(key, None)
    campaigns = normalize_plan_promo_campaigns(result.get("plan_promo_campaigns"))
    legacy_campaigns = legacy_plan_promo_campaigns(result)
    if not had_campaign_list and not campaigns:
        campaigns = legacy_campaigns
    result["plan_promo_campaigns"] = campaigns
    trial_campaign = first_plus_free_trial_campaign(campaigns)
    if "plus_trial_campaign_id" in result:
        if had_campaign_list:
            result["plus_trial_campaign_id"] = (
                trial_campaign.get("campaign_id") if trial_campaign else None
            )
        else:
            legacy_trial = first_plus_free_trial_campaign(legacy_campaigns)
            result["plus_trial_campaign_id"] = (
                legacy_trial.get("campaign_id") if legacy_trial else None
            )
    if "plus_trial_eligible" in result:
        plan = str(
            result.get("current_plan_type")
            or result.get("plan_type")
            or ""
        ).strip().lower()
        subscription_plan = str(result.get("subscription_plan") or "").strip().lower()
        account_is_free = bool(result.get("account_is_free")) or (
            plan == "free" or subscription_plan == "chatgptfreeplan"
        )
        result["plus_trial_eligible"] = bool(account_is_free and trial_campaign)

    raw_regions = result.get("plan_region_results")
    if isinstance(raw_regions, dict):
        safe_regions: dict[object, object] = {}
        for region, raw_item in raw_regions.items():
            if not isinstance(raw_item, dict):
                safe_regions[region] = raw_item
                continue
            item = dict(raw_item)
            had_item_campaign_list = "plan_promo_campaigns" in item
            for key in _PROMO_METADATA_FIELDS:
                item.pop(key, None)
            item_campaigns = normalize_plan_promo_campaigns(
                item.get("plan_promo_campaigns")
            )
            legacy_item_campaigns = legacy_plan_promo_campaigns(item)
            if not had_item_campaign_list and not item_campaigns:
                item_campaigns = legacy_item_campaigns
            if had_item_campaign_list or item_campaigns:
                item["plan_promo_campaigns"] = item_campaigns
            if "plus_trial_campaign_id" in item:
                if had_item_campaign_list:
                    item_trial = first_plus_free_trial_campaign(item_campaigns)
                    item["plus_trial_campaign_id"] = (
                        item_trial.get("campaign_id") if item_trial else None
                    )
                else:
                    legacy_item_trial = first_plus_free_trial_campaign(
                        legacy_item_campaigns
                    )
                    item["plus_trial_campaign_id"] = (
                        legacy_item_trial.get("campaign_id")
                        if legacy_item_trial
                        else None
                    )
            if "plus_trial_eligible" in item:
                item_trial = first_plus_free_trial_campaign(item_campaigns)
                item_plan = str(
                    item.get("current_plan_type") or item.get("plan_type") or ""
                ).strip().lower()
                item_subscription = str(
                    item.get("subscription_plan") or ""
                ).strip().lower()
                item["plus_trial_eligible"] = bool(
                    (item_plan == "free" or item_subscription == "chatgptfreeplan")
                    and item_trial
                )
            safe_regions[region] = item
        result["plan_region_results"] = safe_regions
    return result


def legacy_plan_promo_campaigns(row: dict[str, Any]) -> list[dict[str, object]]:
    """Build a Plus display item for rows written before the new field existed."""

    campaign_id = _safe_campaign_id(row.get("plus_trial_campaign_id"))
    if campaign_id is None:
        return []
    return [{
        "plan": "plus",
        "campaign_id": campaign_id,
        "regions": _safe_regions(row.get("plus_trial_region")),
    }]


def public_plan_promo_campaigns(row: dict[str, Any]) -> list[dict[str, object]]:
    """Normalize an account row and apply the historical Plus fallback."""

    if "plan_promo_campaigns" in row and row.get("plan_promo_campaigns") is not None:
        return normalize_plan_promo_campaigns(row.get("plan_promo_campaigns"))
    return legacy_plan_promo_campaigns(row)


def public_plan_promo_campaigns_history(row: dict[str, Any]) -> list[dict[str, object]]:
    """Seed legacy rows from their current campaigns without mutating on read."""

    return merge_plan_promo_campaigns_history(
        row.get("plan_promo_campaigns_history"), public_plan_promo_campaigns(row),
    )


__all__ = [
    "first_plus_free_trial_campaign",
    "legacy_plan_promo_campaigns",
    "merge_plan_promo_campaigns",
    "merge_plan_promo_campaigns_history",
    "normalize_plan_promo_campaigns",
    "plan_promo_campaigns_for_region",
    "plan_promo_campaign_kind",
    "public_plan_promo_campaigns",
    "public_plan_promo_campaigns_history",
    "replace_plan_promo_campaigns_for_region",
    "sanitize_plan_result_promos",
    "successful_plan_promo_campaigns_by_region",
]
