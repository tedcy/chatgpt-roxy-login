# -*- coding: utf-8 -*-
import itertools
import json
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, Mock, call, patch

from config import roxybrowser as roxy_cfg
from core import chatgpt_session_refresh as refresh
from core.openai_auth import AccountUnusableError
from tests.helpers.session_fixtures import _account, _jwt, _record, _session_info


class _FakeEnv:
    def __init__(self):
        self.session = SimpleNamespace(close=Mock(), cookies=SimpleNamespace())
        self.device_id = "device"
        self.browser_profile = {}
class RoxyLoginCandidateTests(unittest.TestCase):
    def setUp(self):
        # Keep candidate unit tests deterministic when the developer's .env
        # enables the production headed fresh-login switch.  The headed
        # dispatch itself is covered by dedicated adapter tests.
        self._low_traffic_patch = patch.object(
            roxy_cfg,
            "ROXY_REGISTRATION_LOW_TRAFFIC_MODE",
            False,
        )
        self._low_traffic_patch.start()

    def tearDown(self):
        self._low_traffic_patch.stop()

    def test_candidate_is_strict_and_remains_uncommitted(self):
        account = _account()
        info = _session_info()
        driver = Mock()
        snapshot = {**_record(), "email": account["email"]}
        with patch.object(
            refresh,
            "_read_browser_me_once",
            return_value=(
                200,
                {"id": account["user_id"], "email": account["email"]},
            ),
        ) as read_me, patch.object(
            refresh,
            "capture_driver_snapshot",
            return_value=snapshot,
        ) as capture, patch.object(
            refresh,
            "save_snapshot",
        ) as save:
            candidate = refresh._build_roxy_login_candidate(
                account,
                login_email=account["email"],
                driver=driver,
                session_info=info,
            )

        self.assertEqual(candidate.login_email, account["email"])
        self.assertEqual(candidate.access_token, info["accessToken"])
        self.assertEqual(candidate.snapshot["email"], account["email"])
        self.assertNotIn(info["accessToken"], repr(candidate))
        self.assertNotIn("session-secret", repr(candidate))
        read_me.assert_called_once_with(
            driver,
            access_token=info["accessToken"],
            account_id=account["account_id"],
        )
        capture.assert_called_once()
        save.assert_not_called()

    def test_candidate_rejects_unrotated_token_before_liveness(self):
        account = _account()
        info = _session_info(token=account["access_token"])
        with patch.object(refresh, "_read_browser_me_once") as read_me, patch.object(
            refresh,
            "capture_driver_snapshot",
        ) as capture:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as raised:
                refresh._build_roxy_login_candidate(
                    account,
                    login_email=account["email"],
                    driver=Mock(),
                    session_info=info,
                )
        self.assertEqual(raised.exception.error_code, "session_exchange_no_rotation")
        read_me.assert_not_called()
        capture.assert_not_called()

    def test_candidate_rejects_expired_rotated_token_before_liveness(self):
        account = _account()
        info = _session_info(token=_jwt(marker="new", exp=1))
        with patch.object(refresh, "_read_browser_me_once") as read_me, patch.object(
            refresh,
            "capture_driver_snapshot",
        ) as capture:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as raised:
                refresh._build_roxy_login_candidate(
                    account,
                    login_email=account["email"],
                    driver=Mock(),
                    session_info=info,
                )
        self.assertEqual(raised.exception.error_code, "token_expired")
        read_me.assert_not_called()
        capture.assert_not_called()

    def test_candidate_rejects_backend_me_identity_mismatch(self):
        account = _account()
        with patch.object(
            refresh,
            "_read_browser_me_once",
            return_value=(
                200,
                {"id": "other-user", "email": account["email"]},
            ),
        ), patch.object(refresh, "capture_driver_snapshot") as capture:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as raised:
                refresh._build_roxy_login_candidate(
                    account,
                    login_email=account["email"],
                    driver=Mock(),
                    session_info=_session_info(),
                )
        self.assertEqual(raised.exception.error_code, "session_identity_user_mismatch")
        capture.assert_not_called()

    def test_cancelled_gate_wait_never_acquires_browser_slot(self):
        stop = threading.Event()
        stop.set()
        resource = Mock()
        with self.assertRaises(refresh.ChatGPTSessionRefreshError) as raised:
            refresh._acquire_roxy_resource(
                resource,
                stop_event=stop,
                timeout=1,
            )
        self.assertEqual(raised.exception.error_code, "session_window_close_requested")
        resource.acquire.assert_not_called()

    def test_profile_cleanup_failure_does_not_override_candidate_or_leak_slot(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened
        client.cleanup_profile.side_effect = RuntimeError("cleanup failed")
        gate = Mock()
        gate.acquire.return_value = True
        profile_lock = Mock()
        profile_lock.acquire.return_value = True
        expected = refresh.RoxyLoginCandidate(
            account_id=7,
            login_email=account["email"],
            old_token_fingerprint="old-fp",
            new_token_fingerprint="new-fp",
            session_rotated=True,
            access_token="new-token",
            expected_old_token=account["access_token"],
            session_info=_session_info(),
            snapshot=_record(),
        )

        with patch.object(roxy_cfg, "ROXY_OPEN_HEADLESS", True), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window"), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "_wait_for_visible_login", return_value=_session_info()
        ), patch.object(
            refresh, "_build_roxy_login_candidate", return_value=expected
        ), patch.object(refresh, "_ROXY_BROWSER_SLOTS", gate):
            candidate = refresh.run_roxy_login_candidate(
                account,
                proxy_country="US",
                profile_operation_lock=profile_lock,
            )

        self.assertIs(candidate, expected)
        client.open_profile.assert_called_once_with(
            headless=True,
            proxy_country="US",
        )
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)
        gate.release.assert_called_once_with()
        self.assertEqual(profile_lock.acquire.call_count, 2)
        self.assertEqual(profile_lock.release.call_count, 2)

    def test_hme_otp_timeout_is_classified_without_reopening_roxy(self):
        from core.icloud_hme_client import ICloudHmeError

        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened
        gate = Mock()
        gate.acquire.return_value = True
        tracer = Mock()

        with patch.object(roxy_cfg, "ROXY_OPEN_HEADLESS", True), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window"), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "RoxyChatGPTContractTracer", return_value=tracer
        ), patch.object(
            refresh,
            "_wait_for_visible_login",
            side_effect=ICloudHmeError("otp_timeout", status=503),
        ) as login, patch.object(refresh, "_ROXY_BROWSER_SLOTS", gate):
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as raised:
                refresh.run_roxy_login_candidate(account)

        self.assertEqual("session_login_otp_timeout", raised.exception.error_code)
        client.open_profile.assert_called_once_with(headless=True, proxy_country="US")
        login.assert_called_once()
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)
        gate.release.assert_called_once_with()

    def test_email_otp_timeout_can_reach_same_driver_resend(self):
        """A mailbox timeout must not fail before the one-shot resend branch."""
        from core.icloud_hme_client import ICloudHmeError

        driver = Mock()
        timeout = ICloudHmeError("otp_timeout", status=503)
        with patch(
            "core.roxy_codex_oauth._wait_for_fresh_email_otp",
            side_effect=[timeout, timeout],
        ), patch(
            "core.roxy_registration._is_email_verification_page",
            return_value=True,
        ), patch(
            "core.roxy_browser_kernel.click_resend_email_otp",
            side_effect=lambda _driver, **kwargs: (
                kwargs["before_send"](), {"status": "resent"}
            )[1],
        ) as resend, patch(
            "core.email_provider.prepare_otp_context",
        ) as prepare:
            with self.assertRaises(ICloudHmeError) as raised:
                refresh._submit_email_otp_once(
                    driver,
                    "user@example.test",
                    123.0,
                )

        self.assertEqual(raised.exception.error_code, "otp_timeout")
        resend.assert_called_once()
        self.assertGreaterEqual(prepare.call_count, 1)

    def test_login_error_keeps_failed_profile_id_only_in_memory(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-second",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease-second",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened
        gate = Mock()
        gate.acquire.return_value = True
        failure = refresh.ChatGPTSessionRefreshError(
            "session_login_interaction_required",
            "automatic deadline",
        )

        with patch.object(roxy_cfg, "ROXY_OPEN_HEADLESS", True), patch(
            "core.roxybrowser_client.RoxyBrowserClient",
            return_value=client,
        ), patch(
            "core.roxy_registration._build_driver",
            return_value=driver,
        ), patch(
            "core.roxy_registration._center_browser_window"
        ), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh,
            "RoxyChatGPTContractTracer",
            return_value=Mock(),
        ), patch.object(
            refresh,
            "_wait_for_visible_login",
            side_effect=failure,
        ), patch.object(
            refresh,
            "_ROXY_BROWSER_SLOTS",
            gate,
        ):
            with self.assertRaises(
                refresh.ChatGPTSessionRefreshError
            ) as raised:
                refresh.run_roxy_login_candidate(
                    account,
                    headless=True,
                    allow_manual_login=False,
                    excluded_profile_ids={"profile-first"},
                )

        self.assertIs(raised.exception, failure)
        self.assertEqual(
            getattr(raised.exception, "roxy_profile_id", None),
            "profile-second",
        )
        client.open_profile.assert_called_once_with(
            headless=True,
            proxy_country="US",
            excluded_profile_ids={"profile-first"},
        )
        self.assertNotIn("profile-second", str(raised.exception))
        client.cleanup_profile.assert_called_once_with(opened)


class RoxyManualSessionRefreshTests(unittest.TestCase):
    def setUp(self):
        self._low_traffic_patch = patch.object(
            roxy_cfg,
            "ROXY_REGISTRATION_LOW_TRAFFIC_MODE",
            False,
        )
        self._low_traffic_patch.start()
        self._browser_me = patch.object(
            refresh,
            "_read_browser_me_once",
            return_value=(
                200,
                {"id": "user-1", "email": "user@example.test"},
            ),
        )
        self._driver_snapshot = patch.object(
            refresh,
            "capture_driver_snapshot",
            return_value=_record(),
        )
        self._browser_me.start()
        self._driver_snapshot.start()

    def tearDown(self):
        self._driver_snapshot.stop()
        self._browser_me.stop()
        self._low_traffic_patch.stop()

    def _login_helper_patches(self):
        return (
            patch("core.email_provider.prepare_otp_context"),
            patch("core.roxy_registration._safe_get"),
            patch("core.roxy_registration._page_warmup"),
            patch("core.roxy_registration._maybe_accept"),
            patch(
                "core.roxy_registration._submit_email_and_wait_next",
                return_value="otp",
            ),
            patch("core.roxy_registration._type_email_address"),
            patch.object(refresh.time, "sleep"),
        )

    def test_configured_visible_roxy_flow_cleans_identity_saves_and_releases(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened
        events = []

        with patch.object(roxy_cfg, "ROXY_OPEN_HEADLESS", False), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window") as center, patch(
            "core.roxy_registration._reset_pooled_profile_identity",
            side_effect=lambda *_args: events.append("clean"),
        ), patch.object(
            refresh,
            "_wait_for_visible_login",
            side_effect=lambda *_args, **_kwargs: events.append("login") or _session_info(),
        ) as login, patch.object(
            refresh,
            "save_roxy_login_candidate_for_account",
            side_effect=lambda *_args, **_kwargs: events.append("save") or {"access_token": "new-token"},
        ), patch.object(
            refresh,
            "check_account_plan_in_driver",
            side_effect=lambda *_args, **_kwargs: events.append("plan") or {
                "ok": True,
                "current_plan_type": "plus",
            },
        ):
            result = refresh.run_roxy_session_refresh(account)

        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "new-token")
        self.assertTrue(result["plan_result"]["ok"])
        self.assertFalse(result["plan_result"]["session_refresh_required"])
        self.assertEqual(events, ["clean", "login", "save", "plan"])
        client.open_profile.assert_called_once_with(
            headless=False,
            proxy_country="US",
        )
        center.assert_called_once_with(driver, headless=False)
        login.assert_called_once_with(
            driver,
            account,
            account_id=7,
            allow_manual_wait=True,
        )
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)

    def test_roxy_session_refresh_runs_contract_trace_when_enabled(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened
        tracer = Mock()
        session_info = _session_info()

        with patch.object(
            roxy_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", True
        ), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window"), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "RoxyChatGPTContractTracer", return_value=tracer
        ) as tracer_cls, patch.object(
            refresh, "_wait_for_visible_login", return_value=session_info
        ), patch.object(
            refresh,
            "save_roxy_login_candidate_for_account",
            return_value={"access_token": "new-token"},
        ), patch.object(
            refresh,
            "check_account_plan_in_driver",
            return_value={"ok": True, "current_plan_type": "plus"},
        ):
            result = refresh.run_roxy_session_refresh(account, headless=True)

        self.assertTrue(result["ok"])
        tracer_cls.assert_called_once_with(
            driver,
            debugger_address="127.0.0.1:9222",
            task_kind="session_refresh",
            account_id=7,
            old_access_token=account["access_token"],
            account_unusable_callback=ANY,
            verify_credentials=False,
        )
        tracer.set_stage.assert_called_once_with("session_refresh_login")
        tracer.start.assert_called_once_with()
        tracer.observe_session_info.assert_called_once_with(
            session_info,
            source="session_refresh_result",
        )
        tracer.stop.assert_called_once_with()

    def test_roxy_session_refresh_observer_stays_active_when_trace_is_disabled(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened
        tracer = Mock()

        with patch.object(
            roxy_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", False
        ), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window"), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "RoxyChatGPTContractTracer", return_value=tracer
        ) as tracer_cls, patch.object(
            refresh, "_wait_for_visible_login", return_value=_session_info()
        ), patch.object(
            refresh,
            "save_roxy_login_candidate_for_account",
            return_value={"access_token": "new-token"},
        ), patch.object(
            refresh,
            "check_account_plan_in_driver",
            return_value={"ok": True, "current_plan_type": "plus"},
        ), patch.object(refresh.db, "mark_account_unusable", return_value=True) as mark:
            result = refresh.run_roxy_session_refresh(account, headless=True)
            callback = tracer_cls.call_args.kwargs["account_unusable_callback"]
            callback("account_deleted", {"request_id": "must-not-persist"})

        self.assertTrue(result["ok"])
        self.assertEqual(driver._turb_account_unusable_code, "account_deleted")
        mark.assert_called_once_with(
            acc_id=7,
            error_code="account_deleted",
            evidence_source="cdp_email_otp_validate",
        )
        tracer.start.assert_called_once_with()

    def test_default_roxy_flow_uses_global_headless_setting(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened

        with patch.object(roxy_cfg, "ROXY_OPEN_HEADLESS", True), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window") as center, patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "_wait_for_visible_login", return_value=_session_info()
        ) as login, patch.object(
            refresh,
            "save_roxy_login_candidate_for_account",
            return_value={"access_token": "new-token"},
        ), patch.object(
            refresh,
            "check_account_plan_in_driver",
            return_value={"ok": True, "current_plan_type": "plus"},
        ):
            result = refresh.run_roxy_session_refresh(account)

        self.assertTrue(result["ok"])
        client.open_profile.assert_called_once_with(
            headless=True,
            proxy_country="US",
        )
        center.assert_called_once_with(driver, headless=True)
        login.assert_called_once_with(
            driver,
            account,
            account_id=7,
            allow_manual_wait=False,
        )
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)

    def test_headless_bulk_flow_reuses_roxy_client_without_manual_wait(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened

        with patch("core.roxybrowser_client.RoxyBrowserClient", return_value=client), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window") as center, patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "_wait_for_visible_login", return_value=_session_info()
        ) as login, patch.object(
            refresh,
            "save_roxy_login_candidate_for_account",
            return_value={"access_token": "new-token"},
        ), patch.object(
            refresh,
            "check_account_plan_in_driver",
            return_value={"ok": True, "current_plan_type": "plus"},
        ):
            result = refresh.run_roxy_session_refresh(
                account,
                headless=True,
                allow_manual_login=False,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "new-token")
        self.assertTrue(result["plan_result"]["ok"])
        client.open_profile.assert_called_once_with(
            headless=True,
            proxy_country="US",
        )
        center.assert_called_once_with(driver, headless=True)
        login.assert_called_once_with(
            driver,
            account,
            account_id=7,
            allow_manual_wait=False,
        )
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)

    def test_driver_quit_failure_still_releases_cached_profile(self):
        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        driver.quit.side_effect = RuntimeError("quit failed")
        client = Mock()
        client.open_profile.return_value = opened

        with patch("core.roxybrowser_client.RoxyBrowserClient", return_value=client), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window"), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "_wait_for_visible_login", return_value=_session_info()
        ), patch.object(
            refresh,
            "save_roxy_login_candidate_for_account",
            return_value={"access_token": "new-token"},
        ), patch.object(
            refresh,
            "check_account_plan_in_driver",
            return_value={"ok": False, "error_code": "plan_check_edge_blocked"},
        ):
            result = refresh.run_roxy_session_refresh(account)

        self.assertTrue(result["ok"])
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)

    def test_identity_cleanup_failure_discards_pooled_profile(self):
        from core.roxy_registration import RoxyIdentityResetError

        account = _account()
        opened = SimpleNamespace(
            profile_id="profile-1",
            pooled=True,
            lease_token="lease-1",
            profile_cache_discard=False,
        )
        driver = Mock()
        client = Mock()
        client.open_profile.return_value = opened
        with patch("core.roxybrowser_client.RoxyBrowserClient", return_value=client), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch("core.roxy_registration._center_browser_window"), patch(
            "core.roxy_registration._reset_pooled_profile_identity",
            side_effect=RoxyIdentityResetError("identity_reset_failed"),
        ), patch.object(refresh, "_wait_for_visible_login") as login:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh.run_roxy_session_refresh(account)

        self.assertEqual(caught.exception.error_code, "session_identity_cleanup_failed")
        self.assertTrue(opened.profile_cache_discard)
        login.assert_not_called()
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)

    def test_registration_password_is_only_read_from_saved_registration_extra(self):
        self.assertEqual(
            refresh._registration_password(
                {"extra_json": json.dumps({"registration_password": "saved-openai-password"})}
            ),
            "saved-openai-password",
        )
        self.assertEqual(
            refresh._registration_password(
                {"registration_password": "saved-direct-password"}
            ),
            "saved-direct-password",
        )
        self.assertEqual(refresh._registration_password({"password": "mailbox-password"}), "")

    def test_saved_registration_password_is_submitted_automatically(self):
        account = {
            **_account(),
            "extra_json": json.dumps({"registration_password": "saved-password"}),
        }
        patches = self._login_helper_patches()
        with patches[0] as baseline, patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(
            refresh, "_find_session_in_windows", side_effect=[None, _session_info()]
        ), patch("core.roxy_registration._is_email_verification_page", return_value=False), patch(
            "core.roxy_registration._is_login_password_page", return_value=True
        ), patch.object(refresh, "_submit_saved_password", return_value=True) as submit_password:
            result = refresh._wait_for_visible_login(Mock(), account, account_id=7)

        self.assertEqual(result["accessToken"], _session_info()["accessToken"])
        baseline.assert_called_once_with("user@example.test")
        submit_password.assert_called_once_with(ANY, "saved-password")

    def test_saved_password_waits_for_slow_mfa_transition_before_otp_fallback(self):
        """A delayed post-password Session must not trigger passwordless login."""
        class _Clock:
            def __init__(self):
                self.now = 0.0

            def time(self):
                return self.now

            def sleep(self, seconds):
                self.now += float(seconds)

        clock = _Clock()
        account = {
            **_account(),
            "extra_json": json.dumps({"registration_password": "saved-password"}),
        }
        info = _session_info()
        session_results = iter([None] * 7 + [info])
        driver = Mock()
        patches = self._login_helper_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(
            refresh,
            "_find_session_in_windows",
            side_effect=lambda _driver: next(session_results, info),
        ), patch(
            "core.roxy_registration._is_email_verification_page",
            return_value=False,
        ), patch(
            "core.roxy_registration._is_login_password_page",
            return_value=True,
        ), patch.object(
            refresh,
            "_submit_saved_password",
            return_value=True,
        ) as submit_password, patch(
            "core.roxy_registration._click_passwordless_signup_if_present",
            return_value={"ok": False},
        ) as passwordless, patch.object(
            refresh,
            "_authenticator_mfa_page_state",
            return_value={},
        ), patch.object(
            refresh,
            "_raise_if_visible_account_unusable",
        ), patch.object(
            refresh.time,
            "time",
            side_effect=clock.time,
        ), patch.object(
            refresh.time,
            "monotonic",
            side_effect=clock.time,
        ), patch.object(
            refresh.time,
            "sleep",
            side_effect=clock.sleep,
        ):
            result = refresh._wait_for_visible_login(
                driver,
                account,
                account_id=7,
                allow_manual_wait=False,
            )

        self.assertEqual(result, info)
        submit_password.assert_called_once_with(driver, "saved-password")
        passwordless.assert_not_called()

    def test_otp_only_login_skips_saved_password_and_submits_email_otp(self):
        account = {
            **_account(),
            "extra_json": json.dumps({"registration_password": "must-not-read"}),
        }
        patches = self._login_helper_patches()
        info = _session_info()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(
            refresh,
            "_registration_password",
            side_effect=AssertionError("OTP-only path read a password"),
        ), patch.object(
            refresh,
            "_find_session_in_windows",
            side_effect=[None, None, info],
        ), patch(
            "core.roxy_registration._is_email_verification_page",
            side_effect=[False, True],
        ), patch(
            "core.roxy_registration._is_login_password_page",
            return_value=True,
        ), patch(
            "core.roxy_registration._click_passwordless_signup_if_present",
            return_value={"ok": True},
        ) as passwordless, patch.object(
            refresh,
            "_submit_saved_password",
        ) as submit_password, patch.object(
            refresh,
            "_submit_email_otp_once",
            return_value=True,
        ) as submit_otp:
            result = refresh._wait_for_visible_login(
                Mock(),
                account,
                account_id=7,
                otp_only=True,
            )

        self.assertEqual(result, info)
        passwordless.assert_called_once()
        submit_password.assert_not_called()
        submit_otp.assert_called_once()

    def test_email_otp_login_uses_existing_mailbox_without_new_lease(self):
        account = _account()
        patches = self._login_helper_patches()
        with patches[0] as baseline, patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(
            refresh, "_find_session_in_windows", side_effect=[None, _session_info()]
        ), patch("core.roxy_registration._is_email_verification_page", return_value=True), patch.object(
            refresh, "_submit_email_otp_once", return_value=True
        ) as submit_otp, patch.object(refresh.db, "mark_account_session_refresh_waiting") as waiting:
            result = refresh._wait_for_visible_login(Mock(), account, account_id=7)

        self.assertEqual(result["accessToken"], _session_info()["accessToken"])
        baseline.assert_called_once_with("user@example.test")
        submit_otp.assert_called_once()
        waiting.assert_not_called()

    def test_email_otp_submit_installs_hook_and_stops_on_terminal_account_codes(self):
        for error_code in (
            "account_deactivated",
            "account_deleted",
            "account_banned",
        ):
            with self.subTest(error_code=error_code):
                driver = Mock()
                with ExitStack() as stack:
                    stack.enter_context(
                        patch(
                            "core.roxy_codex_oauth._wait_for_fresh_email_otp",
                            return_value="123456",
                        )
                    )
                    stack.enter_context(
                        patch("core.roxy_codex_oauth._wait_for_email_otp_input")
                    )
                    install_hook = stack.enter_context(
                        patch("core.roxy_codex_oauth._install_email_otp_validate_hook")
                    )
                    stack.enter_context(
                        patch("core.roxy_registration._clear_otp_inputs")
                    )
                    stack.enter_context(patch("core.roxy_registration._type_otp"))
                    stack.enter_context(
                        patch(
                            "core.roxy_registration._ensure_email_otp_value_before_submit"
                        )
                    )
                    stack.enter_context(
                        patch("core.roxy_codex_oauth._click_if_present", return_value=True)
                    )
                    wait_after = stack.enter_context(
                        patch(
                            "core.roxy_codex_oauth._wait_after_email_otp_submit",
                            return_value=f"deactivated:{error_code}",
                        )
                    )
                    with self.assertRaises(AccountUnusableError) as caught:
                        refresh._submit_email_otp_once(
                            driver,
                            "user@example.test",
                            123.0,
                        )

                self.assertEqual(caught.exception.error_code, error_code)
                install_hook.assert_called_once_with(driver)
                wait_after.assert_called_once_with(
                    driver,
                    timeout=45,
                    accepted_predicate=refresh._is_authenticator_mfa_page,
                )

    def test_visible_terminal_account_state_requires_trusted_explicit_error_node(self):
        self.assertEqual(
            refresh._detect_visible_account_unusable_state(
                "https://auth.openai.com/log-in",
                {
                    "nodes": [{
                        "source": "role_alert",
                        "text": "Your account has been deactivated.",
                    }]
                },
            ),
            "account_deactivated",
        )
        self.assertEqual(
            refresh._detect_visible_account_unusable_state(
                "https://chatgpt.com/auth/login",
                {
                    "nodes": [{
                        "source": "page_heading",
                        "text": "Your account has been deleted.",
                    }]
                },
            ),
            "account_deleted",
        )
        # Ordinary instructions are often published through polite aria-live;
        # they are not an explicit account error and must never be classified.
        self.assertEqual(
            refresh._detect_visible_account_unusable_state(
                "https://auth.openai.com/log-in",
                {
                    "nodes": [{
                        "source": "aria_live_polite",
                        "text": "Contact support if your account has been deactivated.",
                    }]
                },
            ),
            "",
        )
        self.assertEqual(
            refresh._detect_visible_account_unusable_state(
                "https://auth.openai.com.example.test/log-in",
                {
                    "nodes": [{
                        "source": "role_alert",
                        "text": "Your account has been banned.",
                    }]
                },
            ),
            "",
        )

    def test_visible_terminal_account_state_accepts_canonical_machine_code_leaf(self):
        self.assertEqual(
            refresh._detect_visible_account_unusable_state(
                "https://auth.openai.com/log-in/password",
                {
                    "nodes": [{
                        "source": "page_heading",
                        "text": "Authentication Error",
                    }],
                    "machine_codes": ["account_deactivated"],
                },
            ),
            "account_deactivated",
        )
        self.assertEqual(
            refresh._detect_visible_account_unusable_state(
                "https://auth.openai.com/log-in/password",
                {"nodes": [], "machine_codes": ["not_a_terminal_code"]},
            ),
            "",
        )
        self.assertEqual(
            refresh._detect_visible_account_unusable_state(
                "https://auth.openai.com/log-in/password",
                {"nodes": [], "machine_codes": ["account_deactivated extra"]},
            ),
            "",
        )

    def test_headless_email_otp_waits_for_delayed_session(self):
        account = _account()
        patches = self._login_helper_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(
            refresh,
            "_find_session_in_windows",
            side_effect=[None, None, _session_info()],
        ) as find_session, patch(
            "core.roxy_registration._is_email_verification_page",
            return_value=True,
        ), patch(
            "core.roxy_registration._is_login_password_page",
            return_value=False,
        ), patch.object(
            refresh,
            "_submit_email_otp_once",
            return_value=True,
        ) as submit_otp, patch.object(
            refresh.db,
            "mark_account_session_refresh_waiting",
        ) as waiting:
            result = refresh._wait_for_visible_login(
                Mock(),
                account,
                account_id=7,
                allow_manual_wait=False,
            )

        self.assertEqual(result["accessToken"], _session_info()["accessToken"])
        self.assertEqual(find_session.call_count, 3)
        submit_otp.assert_called_once()
        waiting.assert_not_called()

    def test_missing_password_flow_enters_five_minute_manual_wait(self):
        account = _account()
        patches = self._login_helper_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(
            refresh, "_find_session_in_windows", side_effect=[None, _session_info()]
        ), patch("core.roxy_registration._is_email_verification_page", return_value=False), patch(
            "core.roxy_registration._is_login_password_page", return_value=True
        ), patch(
            "core.roxy_registration._click_passwordless_signup_if_present",
            return_value={"ok": False},
        ), patch.object(refresh.db, "mark_account_session_refresh_waiting") as waiting:
            result = refresh._wait_for_visible_login(Mock(), account, account_id=7)

        self.assertEqual(result["accessToken"], _session_info()["accessToken"])
        waiting.assert_called_once_with(7)

    def test_headless_login_fails_instead_of_waiting_for_invisible_window(self):
        account = _account()
        patches = self._login_helper_patches()
        clock = itertools.count(100.0, 60.0)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patch.object(
            refresh.time,
            "time",
            side_effect=lambda: next(clock),
        ), patch.object(refresh, "_find_session_in_windows") as find_session, patch(
            "core.roxy_registration._is_email_verification_page", return_value=False
        ), patch(
            "core.roxy_registration._is_login_password_page", return_value=False
        ), patch.object(refresh.db, "mark_account_session_refresh_waiting") as waiting:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh._wait_for_visible_login(
                    Mock(),
                    account,
                    account_id=7,
                    allow_manual_wait=False,
                )

        self.assertEqual(
            caught.exception.error_code,
            "session_login_interaction_required",
        )
        find_session.assert_not_called()
        waiting.assert_not_called()
