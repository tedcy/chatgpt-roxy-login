"""Public browser/login kernel shared by Roxy workflows.

The historical implementation is still owned by ``roxy_registration`` so
existing registration semantics and test seams remain untouched.  This
module is the stable, non-private boundary for Session refresh, manual
windows, and Codex OAuth.  Wrappers resolve the
implementation at call time deliberately: deployments and tests that patch
the legacy module continue to affect every caller.
"""
from __future__ import annotations

from typing import Any, Callable


def _implementation():
    from core import roxy_registration

    return roxy_registration


def _forward(name: str, *args: Any, **kwargs: Any) -> Any:
    return getattr(_implementation(), name)(*args, **kwargs)


def build_driver(*args: Any, **kwargs: Any) -> Any:
    return _forward("_build_driver", *args, **kwargs)


def center_browser_window(*args: Any, **kwargs: Any) -> Any:
    return _forward("_center_browser_window", *args, **kwargs)


def reset_pooled_profile_identity(*args: Any, **kwargs: Any) -> Any:
    return _forward("_reset_pooled_profile_identity", *args, **kwargs)


def safe_get(*args: Any, **kwargs: Any) -> Any:
    return _forward("_safe_get", *args, **kwargs)


def page_warmup(*args: Any, **kwargs: Any) -> Any:
    return _forward("_page_warmup", *args, **kwargs)


def human_click(*args: Any, **kwargs: Any) -> Any:
    return _forward("_human_click", *args, **kwargs)


def human_type_text(*args: Any, **kwargs: Any) -> Any:
    return _forward("_human_type_text", *args, **kwargs)


def human_send_keys(*args: Any, **kwargs: Any) -> Any:
    return _forward("_human_send_keys", *args, **kwargs)


def visible(*args: Any, **kwargs: Any) -> Any:
    return _forward("_visible", *args, **kwargs)


def find_any(*args: Any, **kwargs: Any) -> Any:
    return _forward("_find_any", *args, **kwargs)


def click_any(*args: Any, **kwargs: Any) -> Any:
    return _forward("_click_any", *args, **kwargs)


def type_any(*args: Any, **kwargs: Any) -> Any:
    return _forward("_type_any", *args, **kwargs)


def maybe_accept(*args: Any, **kwargs: Any) -> Any:
    return _forward("_maybe_accept", *args, **kwargs)


def click_continue(*args: Any, **kwargs: Any) -> Any:
    return _forward("_click_continue", *args, **kwargs)


def click_email_entry_option(*args: Any, **kwargs: Any) -> Any:
    return _forward("_click_email_entry_option", *args, **kwargs)


def type_email_address(*args: Any, **kwargs: Any) -> Any:
    return _forward("_type_email_address", *args, **kwargs)


def submit_email_step(*args: Any, **kwargs: Any) -> Any:
    return _forward("_submit_email_step", *args, **kwargs)


def submit_email_and_wait_next(*args: Any, **kwargs: Any) -> Any:
    return _forward("_submit_email_and_wait_next", *args, **kwargs)


def type_otp(*args: Any, **kwargs: Any) -> Any:
    return _forward("_type_otp", *args, **kwargs)


def clear_otp_inputs(*args: Any, **kwargs: Any) -> Any:
    return _forward("_clear_otp_inputs", *args, **kwargs)


def ensure_email_otp_value_before_submit(*args: Any, **kwargs: Any) -> Any:
    return _forward("_ensure_email_otp_value_before_submit", *args, **kwargs)


def click_resend_email_otp(*args: Any, **kwargs: Any) -> Any:
    return _forward("_click_resend_email_otp", *args, **kwargs)


def wait_after_email_otp_submit(*args: Any, **kwargs: Any) -> Any:
    # OTP transition handling is shared with the Codex OAuth adapter; keeping
    # the forwarding point here avoids making callers import its private
    # implementation name.
    from core import roxy_codex_oauth

    return roxy_codex_oauth._wait_after_email_otp_submit(*args, **kwargs)


def email_otp_page_state(*args: Any, **kwargs: Any) -> Any:
    return _forward("_email_otp_page_state", *args, **kwargs)


def is_email_verification_page(*args: Any, **kwargs: Any) -> Any:
    return _forward("_is_email_verification_page", *args, **kwargs)


def is_login_password_page(*args: Any, **kwargs: Any) -> Any:
    return _forward("_is_login_password_page", *args, **kwargs)


def click_passwordless_signup_if_present(*args: Any, **kwargs: Any) -> Any:
    return _forward("_click_passwordless_signup_if_present", *args, **kwargs)


def fill_password_page_if_present(*args: Any, **kwargs: Any) -> Any:
    return _forward("_fill_password_page_if_present", *args, **kwargs)


def complete_profile_page(*args: Any, **kwargs: Any) -> Any:
    return _forward("_complete_profile_page", *args, **kwargs)


def fetch_chatgpt_session(*args: Any, **kwargs: Any) -> Any:
    return _forward("_fetch_chatgpt_session", *args, **kwargs)


def check_manual_stop(*args: Any, **kwargs: Any) -> Any:
    return _forward("_check_manual_stop", *args, **kwargs)


def submit_email(*args: Any, **kwargs: Any) -> Any:
    """Alias used by adapters that describe the email step generically."""
    return submit_email_and_wait_next(*args, **kwargs)


def click_other_account_chooser_if_present(*args: Any, **kwargs: Any) -> Any:
    return _forward("_click_other_account_chooser_if_present", *args, **kwargs)


def validate_registration_session_identity(*args: Any, **kwargs: Any) -> Any:
    return _forward("_validate_registration_session_identity", *args, **kwargs)


def set_traffic_stage(*args: Any, **kwargs: Any) -> Any:
    return _forward("_set_traffic_stage", *args, **kwargs)


def stop_traffic_meter(*args: Any, **kwargs: Any) -> Any:
    return _forward("_stop_traffic_meter", *args, **kwargs)


def attach_profile_cache_context(*args: Any, **kwargs: Any) -> Any:
    return _forward("_attach_profile_cache_context", *args, **kwargs)


def submit_login_password(*args: Any, **kwargs: Any) -> Any:
    """Submit a saved ChatGPT password using the shared login primitive."""
    from core.roxy_login_primitives import submit_login_password as _submit

    return _submit(*args, **kwargs)


def normalise_totp_secret(*args: Any, **kwargs: Any) -> Any:
    from core.roxy_login_primitives import normalise_totp_secret as _normalise

    return _normalise(*args, **kwargs)


def wait_for_totp_window(*args: Any, **kwargs: Any) -> Any:
    from core.roxy_login_primitives import wait_for_totp_window as _wait

    return _wait(*args, **kwargs)


def fill_totp_inputs(*args: Any, **kwargs: Any) -> Any:
    from core.roxy_login_primitives import fill_totp_inputs as _fill

    return _fill(*args, **kwargs)


def __getattr__(name: str) -> Any:
    """Expose exception classes/constants through the public namespace only."""
    aliases = {
        "RoxyIdentityResetError": "RoxyIdentityResetError",
        "EmailOtpInputNotCommitted": "EmailOtpInputNotCommitted",
        "EmailOtpAuthRestartFailed": "EmailOtpAuthRestartFailed",
        "EmailOtpResendUnavailable": "EmailOtpResendUnavailable",
        "BirthdayInputNotCommitted": "BirthdayInputNotCommitted",
        "ProfileBirthdayRejected": "ProfileBirthdayRejected",
        "ExistingAccountLoginUnavailable": "ExistingAccountLoginUnavailable",
        "RegistrationSessionIdentityMismatch": "RegistrationSessionIdentityMismatch",
    }
    target = aliases.get(name)
    if target:
        return getattr(_implementation(), target)
    raise AttributeError(name)


__all__ = [
    "build_driver", "center_browser_window", "reset_pooled_profile_identity",
    "safe_get", "page_warmup", "human_click", "human_type_text",
    "human_send_keys", "visible", "find_any", "click_any", "type_any",
    "maybe_accept", "click_continue", "click_email_entry_option",
    "type_email_address", "submit_email_step", "submit_email_and_wait_next",
    "type_otp", "clear_otp_inputs", "ensure_email_otp_value_before_submit",
    "click_resend_email_otp", "wait_after_email_otp_submit", "email_otp_page_state",
    "is_email_verification_page", "is_login_password_page",
    "click_passwordless_signup_if_present", "fill_password_page_if_present",
    "complete_profile_page", "fetch_chatgpt_session", "check_manual_stop",
    "click_other_account_chooser_if_present", "validate_registration_session_identity",
    "set_traffic_stage", "stop_traffic_meter", "attach_profile_cache_context",
    "submit_login_password", "normalise_totp_secret", "wait_for_totp_window",
    "fill_totp_inputs",
    "RoxyIdentityResetError",
]
