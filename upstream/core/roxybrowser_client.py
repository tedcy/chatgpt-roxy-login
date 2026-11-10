# -*- coding: utf-8 -*-
"""Compatibility facade for the split RoxyBrowser Local API client.

Production callers keep importing this module.  Implementations live under
``core.roxybrowser_domains`` so transport, configuration validation, inventory,
and lifecycle work can be inspected independently.
"""
from __future__ import annotations

# Keep these module objects available for historical tests and local patches.
# The domain modules import the same singleton modules, so patching
# ``core.roxybrowser_client.random`` or ``time.sleep`` retains its old effect.
import logging
import random
import re
import threading
import time

import requests

from config import roxybrowser as _cfg
from core.roxybrowser_domains.inventory import RoxyProfileInventoryMixin
from core.roxybrowser_domains.lifecycle import RoxyProfileLifecycleMixin
from core.roxybrowser_domains.profile_config import (
    _ROXY_M3_FINGERPRINT_VALUES,
    _ROXY_RANDOM_OS_ALIASES,
    _ROXY_RANDOM_OS_DEFAULTS,
    _bool_value,
    _constant_time_text_equal,
    _dig,
    _expected_roxy_locale,
    _first,
    _language_matches,
    _locale_readback_issues,
    _mask_proxy,
    _merge_configured_fingerprint,
    _noproxy_info,
    _normalized_language,
    _normalized_proxy_protocol,
    _project_id_value,
    _proxy_readback_issues,
    _proxy_url_to_roxy_info,
    _random_roxy_os,
    _random_roxy_profile_name,
    _roxy_info_runtime_proxy,
    _roxy_info_to_proxy_url,
    _roxy_random_os_choices,
    _timezone_matches,
    _validated_proxy_country,
    _workspace_id_value,
)
from core.roxybrowser_domains.shared import (
    RoxyCreateBusyError,
    RoxyOpenResult,
    RoxyProfileValidationError,
    RoxyRateLimitError,
    _CREATE_BUSY_DELAYS,
    _MAX_RETRY_AFTER_SECONDS,
    _PROFILE_CREATE_LOCK,
    _PROFILE_OPERATION_LOCKS,
    _PROFILE_OPERATION_LOCKS_GUARD,
    _PROFILE_READBACK_DELAYS,
    _RATE_LIMIT_DELAYS,
    _merge_roxy_open_args,
    _profile_operation_slot,
)
from core.roxybrowser_domains.transport import (
    RoxyTransportMixin,
    _API_REQUEST_GATE,
    _RoxyApiRequestGate,
    _api_rate_settings,
    _bounded_retry_after,
    _is_create_busy_message,
    _is_rate_limit_message,
    _jittered_backoff,
    _join_url,
    _response_retry_after,
    _safe_api_endpoint,
    _safe_roxy_diagnostic,
    _sanitized_roxy_exception,
    _strip_slashes,
    get_roxy_api_runtime_status,
    reset_roxy_api_request_gate_for_tests,
)


logger = logging.getLogger(__name__)


class RoxyBrowserClient(
    RoxyProfileLifecycleMixin,
    RoxyProfileInventoryMixin,
    RoxyTransportMixin,
):
    """Stable public client composed from focused internal domains."""


__all__ = [
    "RoxyBrowserClient",
    "RoxyCreateBusyError",
    "RoxyOpenResult",
    "RoxyProfileValidationError",
    "RoxyRateLimitError",
    "get_roxy_api_runtime_status",
    "reset_roxy_api_request_gate_for_tests",
]
