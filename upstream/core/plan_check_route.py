# -*- coding: utf-8 -*-
"""注册后任务使用的进程内代理上下文。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RegistrationPlanRouteHint:
    """Keep a verified registration route in memory without exposing secrets."""

    proxy_url: str = field(default="", repr=False)
    validated_geo: dict[str, Any] = field(default_factory=dict, repr=False)
    proxy_resolved: bool = False
    country: str = ""
    proxy_safe_label: str = ""
    proxy_wire_scope: Any = field(default=None, repr=False, compare=False)
    account_identity: tuple = field(default=(), repr=False)
    registration_job_id: int | None = field(default=None, repr=False)
    registration_job_started_at: str = field(default="", repr=False)


def registration_plan_route_hint_from_opened(
    opened: Any,
    *,
    proxy_wire_scope: Any = None,
) -> RegistrationPlanRouteHint | None:
    """Capture only the live Roxy route needed by the immediate plan task."""

    if opened is None:
        return None
    proxy_url = str(
        getattr(opened, "task_proxy_upstream_url", "")
        or getattr(opened, "task_proxy_url", "")
        or ""
    ).strip()
    geo_value = getattr(opened, "task_proxy_geo", None)
    validated_geo = dict(geo_value) if isinstance(geo_value, dict) else {}
    country = str(
        validated_geo.get("country")
        or validated_geo.get("country_code")
        or ""
    ).strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        country = ""

    # Recompute the label from the raw route. Never trust an arbitrary display
    # value to be safe enough for plan results or logs.
    proxy_safe_label = ""
    if proxy_url:
        if proxy_wire_scope is not None:
            proxy_safe_label = "registration_proxy"
        else:
            from core.proxy_sid import mask_proxy_url

            proxy_safe_label = mask_proxy_url(proxy_url)

    return RegistrationPlanRouteHint(
        proxy_url=proxy_url,
        validated_geo=validated_geo,
        proxy_resolved=bool(getattr(opened, "task_proxy_resolved", False)),
        country=country,
        proxy_safe_label=proxy_safe_label,
        proxy_wire_scope=proxy_wire_scope,
    )


__all__ = [
    "RegistrationPlanRouteHint",
    "registration_plan_route_hint_from_opened",
]
