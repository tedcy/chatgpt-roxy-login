# -*- coding: utf-8 -*-
import itertools
import json
import sqlite3
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
class ChatGPTQuietRefreshTests(unittest.TestCase):
    def setUp(self):
        self._trace_disabled = patch.object(
            roxy_cfg,
            "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED",
            False,
        )
        self._trace_disabled.start()

    def tearDown(self):
        self._trace_disabled.stop()

    def _patch_common(self, env, session_info, *, snapshot=None):
        account = _account()
        rotated = snapshot or {**_record(), "cookies": [{
            "name": "__Secure-next-auth.session-token",
            "value": "rotated-secret",
            "domain": ".chatgpt.com",
            "path": "/",
        }]}
        return account, (
            patch.object(refresh.db, "get_account", return_value=account),
            patch.object(refresh, "get_session", return_value=_record()),
            patch.object(refresh, "record_status", return_value="ready"),
            patch.object(refresh, "hydrate_browser_session"),
            patch.object(refresh, "_read_session", return_value=(session_info, 200)),
            patch.object(refresh, "snapshot_from_http_session", return_value=rotated),
        )

    def _candidate(self):
        account = _account()
        info = _session_info()
        return refresh.SessionTokenCandidate(
            account_id=7,
            email="user@example.test",
            old_token_fingerprint=refresh._token_fingerprint(account["access_token"]),
            new_token_fingerprint=refresh._token_fingerprint(info["accessToken"]),
            session_rotated=True,
            probe_count=1,
            access_token=info["accessToken"],
            expected_old_token=account["access_token"],
            session_info=info,
            snapshot=_record(),
            route={"proxy": ""},
        )

    def test_sanitized_live_contract_selects_browser_runtime_without_secrets(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures"
            / "chatgpt_session_exchange_browser_contract.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

        self.assertEqual(
            fixture["selected_implementation"],
            refresh._SESSION_EXCHANGE_IMPLEMENTATION,
        )
        recovery = fixture["observed_sequence"][1]
        self.assertEqual(recovery["path"], "/api/auth/session")
        self.assertIn(
            "x-openai-failed-access-token-iat",
            recovery["required_header_names"],
        )
        self.assertEqual(
            recovery["access_token_relation"],
            "different_from_rejected_token",
        )
        self.assertFalse(fixture["secret_values_present"])
        raw = fixture_path.read_text(encoding="utf-8")
        self.assertNotRegex(raw, r"eyJ[A-Za-z0-9_-]{20,}")
        self.assertNotIn("@icloud.com", raw)

    def test_prepare_returns_uncommitted_changed_candidate(self):
        env = _FakeEnv()
        info = _session_info()
        account, patchers = self._patch_common(env, info)
        with ExitStack() as stack:
            for item in patchers:
                stack.enter_context(item)
            diagnostic = stack.enter_context(patch.object(refresh, "record_quiet_refresh"))
            save = stack.enter_context(patch.object(refresh, "save_snapshot"))
            replace = stack.enter_context(patch.object(refresh.db, "replace_account_access_token"))
            candidate = refresh.prepare_access_token_candidate_from_saved_session(
                account, env=env, route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}}
            )

        self.assertEqual(candidate.access_token, info["accessToken"])
        self.assertNotEqual(candidate.old_token_fingerprint, candidate.new_token_fingerprint)
        self.assertTrue(candidate.session_rotated)
        self.assertEqual(candidate.probe_count, 1)
        self.assertEqual(diagnostic.call_args.kwargs["outcome"], "session_exchange_candidate_ready")
        save.assert_not_called()
        replace.assert_not_called()
        env.session.close.assert_not_called()

    def test_incomplete_server_cookie_rotation_is_a_contract_mismatch(self):
        env = _FakeEnv()
        env.get_nextauth_headers = Mock(return_value={})
        env.session.get = Mock(return_value=SimpleNamespace(
            status_code=200,
            json=Mock(return_value=_session_info()),
        ))
        with patch.object(
            refresh,
            "apply_session_cookie_rotation",
            side_effect=refresh.ChatGPTSessionStoreError("session_cookie_rotation_failed"),
        ):
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh._read_session(env)

        self.assertEqual(caught.exception.error_code, "session_exchange_contract_mismatch")
        self.assertNotIn("session-secret", caught.exception.user_message)

    def test_same_access_token_without_cookie_rotation_is_never_a_refresh(self):
        account = _account()
        env = _FakeEnv()
        info = _session_info(token=account["access_token"])
        account, patchers = self._patch_common(env, info, snapshot=_record())
        with ExitStack() as stack:
            for item in patchers:
                stack.enter_context(item)
            diagnostic = stack.enter_context(patch.object(refresh, "record_quiet_refresh"))
            save = stack.enter_context(patch.object(refresh, "save_snapshot"))
            replace = stack.enter_context(patch.object(refresh.db, "replace_account_access_token"))
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh._prepare_access_token_candidate_from_saved_session_http(
                    account, env=env, route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}}
                )

        self.assertEqual(caught.exception.error_code, "session_probe_same_token")
        self.assertIn("仍返回旧 Token", caught.exception.user_message)
        self.assertEqual(diagnostic.call_args.kwargs["status"], "stale")
        self.assertFalse(diagnostic.call_args.kwargs["token_changed"])
        save.assert_not_called()
        replace.assert_not_called()

    def test_server_cookie_rotation_never_authorizes_a_second_session_get(self):
        account = _account()
        env = _FakeEnv()
        same = _session_info(token=account["access_token"])
        changed = _session_info()
        rotated = {**_record(), "cookies": [{
            "name": "__Secure-next-auth.session-token",
            "value": "rotated-secret",
            "domain": ".chatgpt.com",
            "path": "/",
        }]}
        with patch.object(refresh.db, "get_account", return_value=account), patch.object(
            refresh, "get_session", return_value=_record()
        ), patch.object(refresh, "record_status", return_value="ready"), patch.object(
            refresh, "hydrate_browser_session"
        ), patch.object(
            refresh, "_read_session", side_effect=[(same, 200), (changed, 200)]
        ) as read, patch.object(
            refresh, "snapshot_from_http_session", side_effect=[rotated, rotated]
        ), patch.object(refresh, "record_quiet_refresh"):
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh._prepare_access_token_candidate_from_saved_session_http(
                    account, env=env, route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}}
                )

        self.assertEqual(read.call_count, 1)
        self.assertEqual(caught.exception.error_code, "session_probe_same_token")

    def test_rotated_cookie_that_still_returns_old_token_is_rejected(self):
        account = _account()
        env = _FakeEnv()
        same = _session_info(token=account["access_token"])
        rotated = {**_record(), "cookies": [{
            "name": "__Secure-next-auth.session-token",
            "value": "rotated-secret",
            "domain": ".chatgpt.com",
            "path": "/",
        }]}
        with patch.object(refresh.db, "get_account", return_value=account), patch.object(
            refresh, "get_session", return_value=_record()
        ), patch.object(refresh, "record_status", return_value="ready"), patch.object(
            refresh, "hydrate_browser_session"
        ), patch.object(
            refresh, "_read_session", side_effect=[(same, 200), (same, 200)]
        ) as read, patch.object(
            refresh, "snapshot_from_http_session", side_effect=[rotated, rotated]
        ), patch.object(refresh, "record_quiet_refresh") as diagnostic:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh._prepare_access_token_candidate_from_saved_session_http(
                    account, env=env, route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}}
                )

        self.assertEqual(read.call_count, 1)
        self.assertEqual(caught.exception.error_code, "session_probe_same_token")
        self.assertEqual(diagnostic.call_args.kwargs["outcome"], "session_probe_same_token")
        self.assertTrue(diagnostic.call_args.kwargs["session_rotated"])

    def test_commit_saves_session_before_conditional_account_replace(self):
        candidate = self._candidate()
        events = []
        with patch.object(refresh.db, "get_account", return_value=_account()), patch.object(
            refresh, "save_snapshot", side_effect=lambda *_args, **_kwargs: events.append("session")
        ) as save, patch.object(
            refresh.db,
            "replace_account_access_token",
            side_effect=lambda **_kwargs: events.append("account") or True,
        ) as replace:
            result = refresh.commit_access_token_candidate(candidate)

        self.assertTrue(result["ok"])
        self.assertEqual(events, ["session", "account"])
        self.assertTrue(save.call_args.kwargs["refreshed"])
        self.assertEqual(replace.call_args.kwargs["expected_old_token"], candidate.expected_old_token)
        stored = save.call_args.args[0]["last_quiet_refresh"]
        self.assertEqual(stored["outcome"], "refreshed")
        self.assertTrue(stored["token_changed"])

    def test_commit_conflict_never_writes_session_or_account(self):
        candidate = self._candidate()
        changed_account = {**_account(), "access_token": "some-other-token"}
        with patch.object(refresh.db, "get_account", return_value=changed_account), patch.object(
            refresh, "save_snapshot"
        ) as save, patch.object(refresh.db, "replace_account_access_token") as replace:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh.commit_access_token_candidate(candidate)

        self.assertEqual(caught.exception.error_code, "account_token_update_conflict")
        save.assert_not_called()
        replace.assert_not_called()

    def test_commit_retries_only_token_write_after_sqlite_lock(self):
        candidate = self._candidate()
        for code, name in ((sqlite3.SQLITE_BUSY, "SQLITE_BUSY"),
                           (sqlite3.SQLITE_LOCKED, "SQLITE_LOCKED"),
                           (sqlite3.SQLITE_BUSY_SNAPSHOT, "SQLITE_BUSY_SNAPSHOT")):
            with self.subTest(code=code):
                error = sqlite3.OperationalError("must-not-log-token-or-cookie")
                error.sqlite_errorcode, error.sqlite_errorname = code, name
                with patch.object(refresh.db, "get_account", return_value=_account()), patch.object(
                    refresh, "save_snapshot"
                ) as save, patch.object(
                    refresh.db, "replace_account_access_token", side_effect=[error, error, True]
                ) as replace, patch.object(refresh.time, "sleep") as sleep, patch.object(
                    refresh.logger, "warning"
                ) as warning:
                    result = refresh.commit_access_token_candidate(candidate)
                self.assertTrue(result["ok"])
                save.assert_called_once()
                self.assertEqual(replace.call_count, 3)
                self.assertEqual(sleep.call_args_list, [call(0.5), call(1.0)])
                self.assertNotIn("must-not-log", str(warning.call_args_list))

    def test_commit_storage_failure_is_bounded_and_preserves_fixed_message(self):
        candidate = self._candidate()
        for error, attempts in ((sqlite3.OperationalError("database is locked"), 3),
                                (sqlite3.OperationalError("no such table: secret-cookie"), 1),
                                (refresh.db.AccountStoreError("secret-token"), 1)):
            with self.subTest(error_type=type(error).__name__, attempts=attempts), patch.object(
                refresh.db, "get_account", return_value=_account()
            ), patch.object(refresh, "save_snapshot") as save, patch.object(
                refresh.db, "replace_account_access_token", side_effect=error
            ) as replace, patch.object(refresh.time, "sleep") as sleep, patch.object(
                refresh.logger, "warning"
            ) as warning:
                with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                    refresh.commit_access_token_candidate(candidate)
                self.assertEqual(caught.exception.error_code, "session_refresh_storage_error")
                self.assertEqual(caught.exception.user_message, "会话结果保存失败，请重试")
                self.assertEqual(replace.call_count, attempts)
                self.assertEqual(sleep.call_count, attempts - 1)
                save.assert_called_once()
                self.assertNotIn("secret-", str(warning.call_args_list))

    def test_snapshot_write_recognizes_wrapped_sqlite_busy(self):
        busy = sqlite3.OperationalError("database is locked")
        error = refresh.ChatGPTSessionStoreError("session_record_write_failed")
        error.__cause__ = busy
        with patch.object(refresh.db, "get_account", return_value=_account()), patch.object(
            refresh, "save_snapshot", side_effect=[error, None]
        ) as save, patch.object(
            refresh.db, "replace_account_access_token", return_value=True
        ) as replace, patch.object(refresh.time, "sleep") as sleep:
            result = refresh.commit_access_token_candidate(self._candidate())
        self.assertTrue(result["ok"])
        self.assertEqual(save.call_count, 2)
        replace.assert_called_once()
        sleep.assert_called_once_with(0.5)

    def test_candidate_repr_never_contains_tokens_or_cookies(self):
        candidate = self._candidate()
        text = repr(candidate)
        self.assertNotIn(candidate.access_token, text)
        self.assertNotIn(candidate.expected_old_token, text)
        self.assertNotIn("session-secret", text)
        self.assertIn(candidate.new_token_fingerprint, text)

    def test_identity_mismatch_invalidates_saved_session(self):
        env = _FakeEnv()
        info = _session_info(
            token=_jwt(email="other@example.test", marker="new"),
            email="other@example.test",
        )
        account, patchers = self._patch_common(env, info)
        with ExitStack() as stack:
            for item in patchers:
                stack.enter_context(item)
            diagnostic = stack.enter_context(patch.object(refresh, "record_quiet_refresh"))
            save = stack.enter_context(patch.object(refresh, "save_snapshot"))
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh.prepare_access_token_candidate_from_saved_session(
                    account, env=env, route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}}
                )

        self.assertEqual(caught.exception.error_code, "session_exchange_identity_mismatch")
        self.assertEqual(diagnostic.call_args.kwargs["status"], "invalid")
        save.assert_not_called()

    def test_missing_identity_claim_required_by_existing_local_account(self):
        account = _account()
        token = _jwt(user_id="", account_id="", marker="new")
        info = {
            "accessToken": token,
            "user": {"email": account["email"]},
            "account": {},
        }
        with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
            refresh.validate_session_identity(account, info, token)
        self.assertEqual(caught.exception.error_code, "session_identity_user_mismatch")

    def test_owned_http_session_is_closed_after_candidate_is_built(self):
        env = _FakeEnv()
        info = _session_info()
        account, patchers = self._patch_common(env, info)
        with ExitStack() as stack:
            for item in patchers:
                stack.enter_context(item)
            stack.enter_context(patch.object(refresh, "BrowserSession", return_value=env))
            stack.enter_context(patch.object(refresh, "resolve_plan_check_region_route", return_value={
                "proxy": "http://fixture.invalid:8080", "plan_region": "US", "_validated_geo": {"country": "US"}
            }))
            stack.enter_context(patch.object(refresh, "record_quiet_refresh"))
            candidate = refresh.prepare_access_token_candidate_from_saved_session(account)

        self.assertEqual(candidate.access_token, info["accessToken"])
        env.session.close.assert_called_once_with()

    def test_missing_or_explicitly_rejected_session_does_not_make_network_request(self):
        account = _account()
        cases = (
            ("missing", None, "session_missing"),
            ("invalid", {**_record(), "status": "invalid", "status_reason": "session_auth_invalid"}, "session_auth_invalid"),
        )
        for status, record, expected_code in cases:
            with self.subTest(status=status), patch.object(
                refresh.db, "get_account", return_value=account
            ), patch.object(refresh, "get_session", return_value=record), patch.object(
                refresh, "record_status", return_value=status
            ), patch.object(refresh, "_read_session") as request_session:
                with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                    refresh.prepare_access_token_candidate_from_saved_session(
                        account, env=_FakeEnv(), route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}}
                    )
            self.assertEqual(caught.exception.error_code, expected_code)
            request_session.assert_not_called()

    def test_legacy_invalid_and_stale_records_are_revalidated_once(self):
        account = _account()
        for status in ("invalid", "stale"):
            with self.subTest(status=status):
                record = {**_record(), "status": status}
                env = _FakeEnv()
                info = _session_info()
                with patch.object(refresh.db, "get_account", return_value=account), patch.object(
                    refresh, "get_session", return_value=record
                ), patch.object(refresh, "record_status", return_value=status), patch.object(
                    refresh, "hydrate_browser_session"
                ) as hydrate, patch.object(
                    refresh, "_read_session", return_value=(info, 200)
                ) as request_session, patch.object(
                    refresh, "snapshot_from_http_session", return_value=_record()
                ), patch.object(refresh, "record_quiet_refresh"):
                    candidate = refresh.prepare_access_token_candidate_from_saved_session(
                        account,
                        env=env,
                        route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}},
                    )

                self.assertEqual(candidate.access_token, info["accessToken"])
                hydrate.assert_called_once_with(
                    env,
                    record,
                    allow_revalidation=True,
                    strip_transient_cookies=True,
                )
                request_session.assert_called_once()

    def test_remote_session_rejection_is_recorded_and_not_retried_as_legacy(self):
        account = _account()
        error = refresh.ChatGPTSessionRefreshError(
            "session_auth_invalid",
            "本地 ChatGPT Session 已失效，请重新登录",
        )
        with patch.object(refresh.db, "get_account", return_value=account), patch.object(
            refresh, "get_session", return_value=_record()
        ), patch.object(refresh, "record_status", return_value="ready"), patch.object(
            refresh, "hydrate_browser_session"
        ), patch.object(refresh, "_read_session", side_effect=error), patch.object(
            refresh, "mark_invalid"
        ) as invalid, patch.object(refresh, "record_quiet_refresh"):
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh.prepare_access_token_candidate_from_saved_session(
                    account,
                    env=_FakeEnv(),
                    route={"proxy": "", "plan_region": "US", "_validated_geo": {"country": "US"}},
                )

        self.assertEqual(caught.exception.error_code, "session_auth_invalid")
        invalid.assert_called_once_with("user@example.test", reason="session_auth_invalid")
        self.assertTrue(refresh.requires_interactive_login("session_probe_same_token"))

    def test_same_token_uses_verified_hidden_browser_even_when_trace_disabled(self):
        account = _account()
        expected = self._candidate()
        no_rotation = refresh.ChatGPTSessionRefreshError(
            "session_exchange_no_rotation",
            "same token",
        )
        with patch.object(
            roxy_cfg,
            "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED",
            False,
        ), patch.object(
            refresh,
            "_prepare_access_token_candidate_from_saved_session_http",
            side_effect=no_rotation,
        ) as http, patch.object(
            refresh,
            "probe_access_token_candidate_in_hidden_roxy",
            return_value=expected,
        ) as probe:
            result = refresh.prepare_access_token_candidate_from_saved_session(
                account,
                env=_FakeEnv(),
                route={"proxy": ""},
            )

        self.assertIs(result, expected)
        http.assert_called_once()
        probe.assert_called_once_with(
            account,
            route={"proxy": ""},
            timeout=30.0,
        )

    def test_hidden_browser_probe_restores_session_and_returns_uncommitted_candidate(self):
        account = _account()
        record = _record()
        changed = _session_info()
        opened = SimpleNamespace(
            profile_id="profile-1",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            profile_cache_discard=False,
        )
        client = Mock()
        client.open_profile.return_value = opened
        driver = Mock()
        tracer = Mock()
        snapshot = {**record, "cookies": [
            {
                "name": "__Secure-next-auth.session-token",
                "value": "rotated-session-secret",
                "domain": ".chatgpt.com",
                "path": "/",
            }
        ]}

        with patch.object(
            roxy_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", True
        ), patch.object(refresh.db, "get_account", return_value=account), patch.object(
            refresh, "get_session", return_value=record
        ), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ) as reset, patch.object(
            refresh, "_navigate_hidden_exchange_page", return_value="cdp_async"
        ) as navigate, patch.object(
            refresh, "_restore_saved_session_to_driver"
        ) as restore, patch.object(
            refresh, "RoxyChatGPTContractTracer", return_value=tracer
        ) as tracer_cls, patch.object(
            refresh, "_read_browser_session_once", return_value=changed
        ), patch.object(
            refresh, "capture_driver_snapshot", return_value=snapshot
        ), patch.object(
            refresh, "record_quiet_refresh"
        ) as diagnostic:
            candidate = refresh.probe_access_token_candidate_in_hidden_roxy(
                account,
                route={"proxy": ""},
                timeout=1,
            )

        self.assertEqual(candidate.access_token, changed["accessToken"])
        self.assertNotEqual(
            candidate.old_token_fingerprint,
            candidate.new_token_fingerprint,
        )
        self.assertTrue(candidate.session_rotated)
        # The browser-state fallback delegates visibility to the shared
        # ROXY_OPEN_HEADLESS setting instead of forcing an invisible window.
        client.open_profile.assert_called_once_with(
            headless=None,
            proxy_country="US",
        )
        reset.assert_called_once_with(driver)
        restore.assert_called_once_with(driver, record)
        navigate.assert_called_once()
        tracer_cls.assert_called_once_with(
            driver,
            debugger_address="127.0.0.1:9222",
            task_kind="session_exchange_probe",
            account_id=7,
            old_access_token=account["access_token"],
            token_candidate_callback=ANY,
        )
        tracer.observe_session_info.assert_called_once_with(
            changed,
            source="browser_exchange_probe",
        )
        tracer.stop.assert_called_once_with()
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)
        self.assertEqual(
            diagnostic.call_args.kwargs["outcome"],
            "session_exchange_candidate_ready",
        )

    def test_hidden_browser_probe_accepts_changed_at_observed_in_network_memory(self):
        account = _account()
        record = _record()
        old_session = _session_info(token=account["access_token"])
        changed_token = _session_info()["accessToken"]
        opened = SimpleNamespace(
            profile_id="profile-1",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            profile_cache_discard=False,
        )
        client = Mock()
        client.open_profile.return_value = opened
        driver = Mock()
        tracer = Mock()
        callback = None

        def tracer_factory(*_args, **kwargs):
            nonlocal callback
            callback = kwargs["token_candidate_callback"]
            return tracer

        def navigate(*_args, **_kwargs):
            callback(
                changed_token,
                {
                    "source": "request_authorization",
                    "host": "chatgpt.com",
                    "path": "/backend-api/me",
                },
            )

        with patch.object(
            roxy_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", True
        ), patch.object(refresh.db, "get_account", return_value=account), patch.object(
            refresh, "get_session", return_value=record
        ), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh,
            "_navigate_hidden_exchange_page",
            side_effect=lambda *_args, **_kwargs: navigate() or "cdp_async",
        ), patch.object(
            refresh, "_restore_saved_session_to_driver"
        ), patch.object(
            refresh, "RoxyChatGPTContractTracer", side_effect=tracer_factory
        ), patch.object(
            refresh, "_read_browser_session_once", return_value=old_session
        ), patch.object(
            refresh, "capture_driver_snapshot", return_value=record
        ), patch.object(
            refresh, "record_quiet_refresh"
        ):
            candidate = refresh.probe_access_token_candidate_in_hidden_roxy(
                account,
                route={"proxy": ""},
                timeout=1,
            )

        self.assertEqual(candidate.access_token, changed_token)
        self.assertEqual(candidate.session_info["accessToken"], changed_token)
        tracer.observe_session_info.assert_called_with(
            candidate.session_info,
            source="browser_network_candidate",
        )
        self.assertNotIn(changed_token, repr(candidate))

    def test_hidden_browser_exchange_without_trace_uses_session_response_candidate(self):
        account = _account()
        record = _record()
        changed = _session_info()
        opened = SimpleNamespace(
            profile_id="profile-1",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            profile_cache_discard=False,
        )
        client = Mock()
        client.open_profile.return_value = opened
        driver = Mock()
        tracer_cls = Mock()

        with patch.object(
            roxy_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", False
        ), patch.object(refresh.db, "get_account", return_value=account), patch.object(
            refresh, "get_session", return_value=record
        ), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "_navigate_hidden_exchange_page", return_value="cdp_async"
        ), patch.object(
            refresh, "_restore_saved_session_to_driver"
        ), patch.object(
            refresh, "RoxyChatGPTContractTracer", tracer_cls
        ), patch.object(
            refresh, "_read_browser_session_once", return_value=changed
        ), patch.object(
            refresh, "capture_driver_snapshot", return_value=record
        ), patch.object(
            refresh, "record_quiet_refresh"
        ):
            candidate = refresh.probe_access_token_candidate_in_hidden_roxy(
                account,
                route={"proxy": ""},
                timeout=1,
            )

        self.assertEqual(candidate.access_token, changed["accessToken"])
        tracer_cls.assert_not_called()
        driver.execute_cdp_cmd.assert_any_call("Page.stopLoading", {})

    def test_hidden_exchange_navigation_is_async_cdp_first(self):
        driver = Mock()
        driver.execute_cdp_cmd.return_value = {}
        with patch("core.roxy_registration._safe_get") as fallback:
            mode = refresh._navigate_hidden_exchange_page(driver, 30)

        self.assertEqual(mode, "cdp_async")
        self.assertEqual(
            driver.execute_cdp_cmd.call_args_list,
            [
                call("Page.enable", {}),
                call(
                    "Page.navigate", {"url": "https://chatgpt.com/"}
                ),
            ],
        )
        fallback.assert_not_called()

    def test_hidden_browser_probe_releases_slot_when_client_init_fails(self):
        slots = Mock()
        slots.acquire.return_value = True
        with patch.object(refresh, "_ROXY_BROWSER_SLOTS", slots), patch(
            "core.roxybrowser_client.RoxyBrowserClient",
            side_effect=RuntimeError("client init failed"),
        ):
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh.probe_access_token_candidate_in_hidden_roxy(
                    _account(),
                    route={"proxy": ""},
                    timeout=1,
                )

        self.assertEqual(
            caught.exception.error_code,
            "session_browser_probe_unavailable",
        )
        slots.release.assert_called_once_with()

    def test_hidden_browser_probe_never_logs_in_when_cookie_reaches_login_page(self):
        account = _account()
        record = _record()
        opened = SimpleNamespace(
            profile_id="profile-1",
            debugger_address="127.0.0.1:9222",
            pooled=True,
            profile_cache_discard=False,
        )
        client = Mock()
        client.open_profile.return_value = opened
        driver = Mock(current_url="https://auth.openai.com/log-in")
        tracer = Mock()

        with patch.object(
            roxy_cfg, "ROXY_CHATGPT_CONTRACT_TRACE_ENABLED", True
        ), patch.object(refresh.db, "get_account", return_value=account), patch.object(
            refresh, "get_session", return_value=record
        ), patch(
            "core.roxybrowser_client.RoxyBrowserClient", return_value=client
        ), patch(
            "core.roxy_registration._build_driver", return_value=driver
        ), patch(
            "core.roxy_registration._reset_pooled_profile_identity"
        ), patch.object(
            refresh, "_navigate_hidden_exchange_page", return_value="cdp_async"
        ), patch.object(
            refresh, "_restore_saved_session_to_driver"
        ), patch.object(
            refresh, "RoxyChatGPTContractTracer", return_value=tracer
        ), patch.object(
            refresh, "_read_browser_session_once", return_value=None
        ), patch.object(
            refresh, "record_quiet_refresh"
        ) as diagnostic:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh.probe_access_token_candidate_in_hidden_roxy(
                    account,
                    route={"proxy": ""},
                    timeout=1,
                )

        self.assertEqual(
            caught.exception.error_code,
            "session_browser_probe_login_required",
        )
        self.assertEqual(
            diagnostic.call_args.kwargs["outcome"],
            "session_browser_probe_login_required",
        )
        tracer.stop.assert_called_once_with()
        driver.quit.assert_called_once_with()
        client.cleanup_profile.assert_called_once_with(opened)

    def test_saved_driver_cookie_restore_is_written_and_read_back_exactly(self):
        record = _record()
        driver = Mock()

        def command(method, params):
            if method == "Network.getAllCookies":
                return {"cookies": record["cookies"]}
            return {}

        driver.execute_cdp_cmd.side_effect = command
        refresh._restore_saved_session_to_driver(driver, record)

        methods = [call.args[0] for call in driver.execute_cdp_cmd.call_args_list]
        self.assertEqual(
            methods,
            ["Network.enable", "Network.setCookies", "Network.getAllCookies"],
        )
        payload = driver.execute_cdp_cmd.call_args_list[1].args[1]
        self.assertEqual(
            payload["cookies"][0]["name"],
            "__Secure-next-auth.session-token",
        )
        self.assertEqual(payload["cookies"][0]["value"], "session-secret")

    def test_saved_driver_cookie_restore_keeps_host_cookie_host_only_and_optional_failure_is_non_blocking(self):
        record = {
            **_record(),
            "cookies": [
                {
                    "name": "__Secure-next-auth.session-token",
                    "value": "session-secret",
                    "domain": ".chatgpt.com",
                    "path": "/",
                },
                {
                    "name": "__Host-next-auth.csrf-token",
                    "value": "csrf-secret",
                    "domain": "chatgpt.com",
                    "path": "/",
                },
            ],
        }
        driver = Mock()

        def command(method, params):
            if method == "Network.setCookie":
                return {"success": False}
            if method == "Network.getAllCookies":
                return {"cookies": [record["cookies"][0]]}
            return {}

        driver.execute_cdp_cmd.side_effect = command
        refresh._restore_saved_session_to_driver(driver, record)

        calls = driver.execute_cdp_cmd.call_args_list
        batch = next(item for item in calls if item.args[0] == "Network.setCookies")
        self.assertEqual(
            [item["name"] for item in batch.args[1]["cookies"]],
            ["__Secure-next-auth.session-token"],
        )
        host_writes = [
            item.args[1]
            for item in calls
            if item.args[0] == "Network.setCookie"
        ]
        self.assertEqual(len(host_writes), 1)
        self.assertNotIn("domain", host_writes[0])
        self.assertEqual(host_writes[0]["url"], "https://chatgpt.com/")

    def test_saved_driver_cookie_restore_retries_critical_members_after_batch_failure(self):
        record = {
            **_record(),
            "cookies": [{
                "name": "__Host-next-auth.session-token",
                "value": "session-secret",
                "domain": "chatgpt.com",
                "path": "/",
            }],
        }
        driver = Mock()

        def command(method, params):
            if method == "Network.setCookies":
                raise RuntimeError("batch rejected")
            if method == "Network.getAllCookies":
                return {"cookies": record["cookies"]}
            return {}

        driver.execute_cdp_cmd.side_effect = command
        refresh._restore_saved_session_to_driver(driver, record)

        methods = [item.args[0] for item in driver.execute_cdp_cmd.call_args_list]
        self.assertEqual(
            methods,
            ["Network.enable", "Network.setCookies", "Network.setCookie", "Network.getAllCookies"],
        )
        payload = driver.execute_cdp_cmd.call_args_list[2].args[1]
        self.assertNotIn("domain", payload)
        self.assertEqual(payload["url"], "https://chatgpt.com/")

    def test_shared_roxy_session_restores_without_login_or_identity_reset(self):
        account = _account()
        info = _session_info()
        driver = Mock()
        reset = Mock()
        on_miss = Mock()
        with patch.object(
            refresh,
            "_restore_saved_session_probe",
            return_value=(info, "restored"),
        ) as probe, patch.object(refresh, "_wait_for_visible_login") as login:
            result = refresh.ensure_roxy_session_on_driver(
                driver,
                account,
                account_id=7,
                reset_identity=reset,
                on_restore_miss=on_miss,
            )

        self.assertEqual(result, info)
        probe.assert_called_once_with(
            driver,
            account,
            account_id=7,
            stop_event=None,
        )
        reset.assert_not_called()
        on_miss.assert_not_called()
        login.assert_not_called()

    def test_shared_roxy_session_reports_restore_miss_before_login_fallback(self):
        account = _account()
        info = _session_info()
        driver = Mock()
        reset = Mock()
        on_miss = Mock()
        with patch.object(
            refresh,
            "_restore_saved_session_probe",
            return_value=(None, "session_record_missing"),
        ), patch.object(
            refresh,
            "_wait_for_visible_login",
            return_value=info,
        ) as login:
            result = refresh.ensure_roxy_session_on_driver(
                driver,
                account,
                account_id=7,
                reset_identity=reset,
                on_restore_miss=on_miss,
            )

        self.assertEqual(result, info)
        on_miss.assert_called_once_with("session_record_missing")
        reset.assert_called_once_with()
        login.assert_called_once_with(
            driver,
            account,
            account_id=7,
            allow_manual_wait=True,
        )

    def test_shared_roxy_session_can_defer_mailbox_context_until_email_factor(self):
        account = _account()
        info = _session_info()
        driver = Mock()
        reset = Mock()
        with patch.object(
            refresh,
            "_wait_for_visible_login",
            return_value=info,
        ) as login:
            result = refresh.ensure_roxy_session_on_driver(
                driver,
                account,
                account_id=7,
                restore_saved_session=False,
                reset_identity=reset,
                defer_email_otp_context=True,
            )

        self.assertEqual(result, info)
        reset.assert_called_once_with()
        login.assert_called_once_with(
            driver,
            account,
            account_id=7,
            allow_manual_wait=True,
            defer_email_otp_context=True,
        )

    def test_saved_session_probe_does_not_accept_token_before_expired_modal_settles(self):
        """A cached session may publish a token before the SPA rejects it."""

        account = _account()
        info = _session_info()
        driver = Mock()
        driver.window_handles = ["window"]
        clock = [0.0]

        def monotonic():
            return clock[0]

        def sleep(seconds):
            clock[0] += float(seconds or 0.0)

        with patch.object(refresh, "get_session", return_value=_record()), patch.object(
            refresh, "_restore_saved_session_to_driver"
        ), patch.object(refresh, "_find_session_in_windows", return_value=info), patch.object(
            refresh, "validate_session_identity"
        ), patch.object(refresh, "_browser_session_expired_notice", side_effect=lambda _driver: clock[0] >= 4.0), patch.object(
            refresh.time, "monotonic", side_effect=monotonic
        ), patch.object(refresh.time, "sleep", side_effect=sleep), patch(
            "core.roxy_registration._safe_get"
        ), patch("core.roxy_registration._page_warmup"):
            result = refresh._restore_saved_session_probe(
                driver,
                account,
                account_id=7,
                timeout=12,
            )

        self.assertEqual(result, (None, "session_not_published"))
        self.assertGreaterEqual(clock[0], 4.0)

    def test_saved_session_probe_requires_short_healthy_window(self):
        account = _account()
        info = _session_info()
        driver = Mock()
        driver.window_handles = ["window"]
        clock = [0.0]

        def monotonic():
            return clock[0]

        def sleep(seconds):
            clock[0] += float(seconds or 0.0)

        with patch.object(refresh, "get_session", return_value=_record()), patch.object(
            refresh, "_restore_saved_session_to_driver"
        ), patch.object(refresh, "_find_session_in_windows", return_value=info), patch.object(
            refresh, "validate_session_identity"
        ), patch.object(refresh, "_browser_session_expired_notice", return_value=False), patch.object(
            refresh, "_browser_session_business_ready", return_value=True
        ), patch.object(
            refresh.time, "monotonic", side_effect=monotonic
        ), patch.object(refresh.time, "sleep", side_effect=sleep), patch(
            "core.roxy_registration._safe_get"
        ), patch("core.roxy_registration._page_warmup"):
            result = refresh._restore_saved_session_probe(
                driver,
                account,
                account_id=7,
                timeout=24,
            )

        self.assertEqual(result, (info, "restored"))
        self.assertGreaterEqual(clock[0], 5.0)

    def test_restore_miss_callback_failure_does_not_block_login(self):
        account = _account()
        info = _session_info()
        with patch.object(
            refresh,
            "_restore_saved_session_probe",
            return_value=(None, "session_record_missing"),
        ), patch.object(
            refresh,
            "_wait_for_visible_login",
            return_value=info,
        ) as login:
            result = refresh.ensure_roxy_session_on_driver(
                Mock(),
                account,
                account_id=7,
                on_restore_miss=Mock(side_effect=RuntimeError("state write")),
            )

        self.assertEqual(result, info)
        login.assert_called_once()


    def test_refresh_via_saved_session_commits_only_after_plan_validation(self):
        candidate = self._candidate()
        plan_result = {
            "ok": True,
            "http_status": 200,
            "current_plan_type": "plus",
        }
        events = []
        verification_env = SimpleNamespace()
        verification_context = SimpleNamespace(
            env=verification_env,
            context_mode="saved_session",
            close=Mock(),
        )
        maintenance_route = {
            "proxy": "http://us-maintenance.invalid:3010",
            "proxy_mode": "maintenance_us_sid",
            "network_route": "regional_proxy",
            "_validated_geo": {"country": "US"},
        }
        with patch(
            "core.protocol_country.protocol_route",
            return_value=maintenance_route,
        ), patch.object(
            refresh,
            "prepare_access_token_candidate_from_saved_session_http",
            side_effect=lambda *_args, **_kwargs: events.append("prepare") or candidate,
        ) as prepare, patch(
            "core.plan_check_service._new_context_for_route",
            return_value=verification_context,
        ) as make_context, patch.object(
            refresh,
            "check_account_plan",
            side_effect=lambda *_args, **_kwargs: events.append("plan") or dict(plan_result),
        ) as check, patch.object(
            refresh,
            "commit_access_token_candidate",
            side_effect=lambda *_args, **_kwargs: events.append("commit") or {"ok": True},
        ) as commit, patch.object(
            refresh, "probe_access_token_candidate_in_hidden_roxy"
        ) as hidden_roxy:
            result = refresh.refresh_access_token_via_saved_session(_account())

        self.assertEqual(events, ["prepare", "plan", "commit"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], candidate.access_token)
        self.assertEqual(result["token_refresh_method"], "http_session")
        self.assertEqual(result["plan_result"]["token_refresh_method"], "http_session")
        commit.assert_called_once_with(candidate)
        make_context.assert_called_once_with(
            region="",
            route=dict(candidate.route),
            account=_account(),
            session_record=candidate.snapshot,
        )
        self.assertIs(check.call_args.kwargs["env"], verification_env)
        self.assertEqual(
            check.call_args.kwargs["context_mode"],
            "saved_session",
        )
        self.assertEqual(
            prepare.call_args.kwargs[
                "route"
            ],
            maintenance_route,
        )
        verification_context.close.assert_called_once_with()
        hidden_roxy.assert_not_called()

    def test_refresh_via_saved_session_rejected_candidate_is_not_committed(self):
        candidate = self._candidate()
        verification_context = SimpleNamespace(
            env=SimpleNamespace(),
            context_mode="saved_session",
            close=Mock(),
        )
        rejected = {
            "ok": False,
            "http_status": 401,
            "auth_error_code": "token_invalidated",
        }
        maintenance_route = {
            "proxy": "http://us-maintenance.invalid:3010",
            "proxy_mode": "maintenance_us_sid",
            "network_route": "regional_proxy",
            "_validated_geo": {"country": "US"},
        }
        with patch(
            "core.protocol_country.protocol_route",
            return_value=maintenance_route,
        ), patch.object(
            refresh,
            "prepare_access_token_candidate_from_saved_session_http",
            return_value=candidate,
        ), patch(
            "core.plan_check_service._new_context_for_route",
            return_value=verification_context,
        ) as make_context, patch.object(
            refresh, "check_account_plan", return_value=rejected
        ) as check, patch.object(
            refresh, "record_access_token_candidate_result"
        ) as record, patch.object(
            refresh, "commit_access_token_candidate"
        ) as commit, patch.object(
            refresh, "probe_access_token_candidate_in_hidden_roxy"
        ) as hidden_roxy:
            with self.assertRaises(refresh.ChatGPTSessionRefreshError) as caught:
                refresh.refresh_access_token_via_saved_session(_account())

        make_context.assert_called_once_with(
            region="",
            route=dict(candidate.route),
            account=_account(),
            session_record=candidate.snapshot,
        )
        check.assert_called_once()
        self.assertIs(check.call_args.kwargs["env"], verification_context.env)
        self.assertEqual(check.call_args.kwargs["context_mode"], "saved_session")
        verification_context.close.assert_called_once_with()
        self.assertEqual(caught.exception.error_code, "refreshed_token_rejected")
        record.assert_called_once_with(
            candidate,
            outcome="session_exchange_token_rejected",
            http_status=401,
            status="stale",
        )
        commit.assert_not_called()
        hidden_roxy.assert_not_called()

if __name__ == "__main__":
    unittest.main()
