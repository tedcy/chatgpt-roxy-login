# -*- coding: utf-8 -*-
"""通过 RoxyBrowser 指纹浏览器 + Selenium 执行 ChatGPT 注册。"""

from __future__ import annotations

import json

import logging

import random

import re

import string

import threading

import time

from pathlib import Path

from urllib.parse import urlparse

from config import roxybrowser as _cfg

from config import twofa as _twofa_cfg

from core.account_export import save_account_data

from core.chatgpt_session_store import (
    ChatGPTSessionStoreError,
    bind_account as bind_chatgpt_session_account,
    capture_driver_snapshot,
    save_snapshot as save_chatgpt_session_snapshot,
)

from core.email_provider import (
    mark_registration_failed,
    mark_registration_account_created,
    mark_registration_existing_account_detected,
    mark_registration_email_otp_submitted,
    mark_registration_profile_submission,
    prepare_otp_context,
    resolve_email_source,
    wait_for_otp,
)

from core.humanize import delay as human_delay

from core.plan_check_route import registration_plan_route_hint_from_opened

from core.roxybrowser_client import RoxyBrowserClient, RoxyOpenResult

from core.roxy_chatgpt_contract_trace import RoxyChatGPTContractTracer

from core.roxy_traffic_meter import RoxyTrafficMeter, empty_network_usage

logger = logging.getLogger(__name__)

_STOP_CHECK_CONTEXT = threading.local()

_OPENAI_IDENTITY_ORIGINS = (
    "https://auth.openai.com",
    "https://chatgpt.com",
    "https://openai.com",
    "https://platform.openai.com",
)

class RoxyIdentityResetError(RuntimeError):
    """A pooled Profile could not be safely detached from the previous account."""

class EmailOtpInputNotCommitted(RuntimeError):
    """The email OTP was not proven present in the live verification form."""

class EmailOtpAuthRestartFailed(RuntimeError):
    """A same-email authentication restart did not reach a safe next state."""

class EmailOtpResendUnavailable(RuntimeError):
    """An explicit resend action was required but was not safely available."""

class BirthdayInputNotCommitted(RuntimeError):
    """The requested birthday was not proven present in the visible date widget."""

class ProfileBirthdayRejected(RuntimeError):
    """The profile page explicitly rejected the submitted birthday."""

class ExistingAccountLoginUnavailable(RuntimeError):
    """An existing account was detected but no safe automatic login path worked."""

class RegistrationSessionIdentityMismatch(RuntimeError):
    """The authenticated ChatGPT identity did not match the requested email."""

def _log_prefix(driver=None) -> str:
    """返回 Roxy 注册日志前缀。"""
    return "[Roxy注册]"

# The implementation domains are evaluated in this module's globals in their
# historical dependency order.  Existing imports and monkey-patches therefore
# remain compatible while each domain has an independently navigable source.
from .roxy_domains import browser, email_auth, profile_auth, session, registration
for _domain_module in (browser, email_auth, profile_auth, session, registration):
    _domain_module.register(globals())
del _domain_module

# Compatibility source markers used by older diagnostics and integrations.
# The actual implementations live in core/roxy_domains/*.py.
# def run_roxy_registration(
# run_roxy_headed_registration(
# client = RoxyBrowserClient()
# https://chatgpt.com/auth/login
# mark_registration_profile_submission
# mark_registration_failed
# mark_registration_account_created
