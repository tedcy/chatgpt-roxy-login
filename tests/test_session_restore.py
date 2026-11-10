"""Load the production cookie/restore regression methods unchanged."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).parent / "fixtures/source_session_refresh.py"
spec = importlib.util.spec_from_file_location("production_restore_fixtures", path)
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)

METHODS = (
    "test_saved_driver_cookie_restore_is_written_and_read_back_exactly",
    "test_saved_driver_cookie_restore_keeps_host_cookie_host_only_and_optional_failure_is_non_blocking",
    "test_saved_driver_cookie_restore_retries_critical_members_after_batch_failure",
    "test_shared_roxy_session_restores_without_login_or_identity_reset",
    "test_shared_roxy_session_reports_restore_miss_before_login_fallback",
    "test_shared_roxy_session_can_defer_mailbox_context_until_email_factor",
    "test_saved_session_probe_does_not_accept_token_before_expired_modal_settles",
    "test_saved_session_probe_requires_short_healthy_window",
    "test_restore_miss_callback_failure_does_not_block_login",
)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(source.ChatGPTQuietRefreshTests(method) for method in METHODS)
    candidate_path = Path(__file__).parent / "fixtures/source_roxy_candidates.py"
    candidate_spec = importlib.util.spec_from_file_location("production_candidate_fixtures", candidate_path)
    candidate = importlib.util.module_from_spec(candidate_spec)
    candidate_spec.loader.exec_module(candidate)
    for method in ("test_candidate_is_strict_and_remains_uncommitted",
                   "test_candidate_rejects_unrotated_token_before_liveness",
                   "test_candidate_rejects_expired_rotated_token_before_liveness",
                   "test_candidate_rejects_backend_me_identity_mismatch",
                   "test_cancelled_gate_wait_never_acquires_browser_slot"):
        suite.addTest(candidate.RoxyLoginCandidateTests(method))
    return suite
