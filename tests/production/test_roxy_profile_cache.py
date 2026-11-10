# -*- coding: utf-8 -*-
from __future__ import annotations

import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import requests

from config import roxybrowser as roxy_cfg
from core.roxy_profile_pool import (
    PROFILE_CACHE_REMARK,
    RoxyProfileLease,
    RoxyProfilePool,
)
from core.roxy_registration import (
    RoxyIdentityResetError,
    _reset_pooled_profile_identity,
)
from core.roxybrowser_client import (
    RoxyBrowserClient,
    RoxyOpenResult,
    RoxyProfileValidationError,
    RoxyRateLimitError,
)


class _FakeClient:
    profile_id_from_row = staticmethod(RoxyBrowserClient.profile_id_from_row)
    profile_open_state = staticmethod(RoxyBrowserClient.profile_open_state)

    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.proxy_calls = 0
        self.created_payloads = []
        self.closed = []
        self.deleted = []
        self.detail_calls = []
        self.detail_states = {}

    def resolve_profile_open_state(self, row):
        state = self.profile_open_state(row)
        if state is not None:
            return state
        profile_id = self.profile_id_from_row(row)
        self.detail_calls.append(profile_id)
        return self.detail_states.get(profile_id)

    def list_profiles(self):
        return [dict(row) for row in self.rows]

    def choose_task_proxy(self):
        self.proxy_calls += 1
        return (
            {"proxyCategory": "SOCKS5", "protocol": "SOCKS5", "host": "hidden", "port": "1"},
            {"protocol": "SOCKS5", "authenticated": False},
        )

    def create_profile(self, payload=None):
        profile_id = f"new-{len(self.created_payloads) + 1}"
        self.created_payloads.append(dict(payload or {}))
        self.rows.append({
            "dirId": profile_id,
            "windowName": payload.get("windowName"),
            "windowRemark": payload.get("windowRemark"),
            "projectId": str(roxy_cfg.ROXY_PROJECT_ID),
            "openStatus": False,
            "createTime": "2026-01-01 00:00:00",
        })
        return profile_id

    def close_profile(self, profile_id):
        self.closed.append(profile_id)
        return True

    def delete_profile(self, profile_id):
        self.deleted.append(profile_id)
        self.rows = [row for row in self.rows if self.profile_id_from_row(row) != profile_id]
        return True


def _row(
    profile_id,
    *,
    owned=True,
    opened=False,
    closed_at="2026-01-01 00:00:00",
    project_id="configured",
):
    row = {
        "dirId": profile_id,
        "windowName": f"name-{profile_id}",
        "windowRemark": PROFILE_CACHE_REMARK if owned else "personal",
        "openStatus": opened,
        "closeTime": closed_at,
    }
    if project_id is not None:
        row["projectId"] = str(
            roxy_cfg.ROXY_PROJECT_ID if project_id == "configured" else project_id
        )
    return row


def _profile_configuration(
    proxy_info=None,
    *,
    country="",
    language="",
    timezone_name="",
    automatic=True,
):
    actual_proxy = dict(proxy_info or {"proxyCategory": "noproxy"})
    if country:
        actual_proxy["lastCountry"] = country
    return {
        "dirId": "profile",
        "os": "macOS",
        "proxyInfo": actual_proxy,
        "fingerInfo": {
            "isLanguageBaseIp": automatic,
            "language": language,
            "isDisplayLanguageBaseIp": automatic,
            "displayLanguage": language,
            "isTimeZone": automatic,
            "timeZone": timezone_name,
            "canvas": True,
            "webGL": False,
            "webRTC": 2,
        },
    }


class RoxyProfilePoolTests(unittest.TestCase):
    def setUp(self):
        self.pool = RoxyProfilePool()

    def test_reuses_owned_profile_and_selects_proxy_once_per_lease(self):
        client = _FakeClient([_row("owned")])

        lease = self.pool.acquire(client)

        self.assertEqual(lease.profile_id, "owned")
        self.assertFalse(lease.newly_created)
        self.assertFalse(lease.adopted)
        self.assertEqual(client.proxy_calls, 1)

    def test_lazily_creates_owned_profile_on_demand(self):
        client = _FakeClient([])

        lease = self.pool.acquire(client)

        self.assertTrue(lease.newly_created)
        self.assertEqual(len(client.created_payloads), 1)
        payload = client.created_payloads[0]
        self.assertRegex(payload["windowName"], r"^turb-gpt-cache-\d{2}$")
        self.assertEqual(payload["windowRemark"], PROFILE_CACHE_REMARK)
        self.assertEqual(payload["defaultOpenUrl"], ["about:blank"])
        self.assertEqual(payload["proxyInfo"]["host"], "hidden")
        self.assertEqual(client.proxy_calls, 1)

    def test_mru_owned_profile_is_selected(self):
        client = _FakeClient([_row("older"), _row("newer")])
        self.pool._released_at.update({"older": 10.0, "newer": 20.0})

        lease = self.pool.acquire(client)

        self.assertEqual(lease.profile_id, "newer")

    def test_restart_reserved_manual_profile_is_never_reused(self):
        client = _FakeClient([_row("idle"), _row("manual")])
        self.pool._released_at.update({"idle": 10.0, "manual": 20.0})
        self.pool.replace_external_reservations(["manual"])

        lease = self.pool.acquire(client)

        self.assertEqual(lease.profile_id, "idle")
        self.assertEqual(self.pool.status()["external_reserved"], 1)

    def test_only_restart_reserved_profile_forces_new_profile(self):
        client = _FakeClient([_row("manual")])
        self.pool.replace_external_reservations(["manual"])

        lease = self.pool.acquire(client)

        self.assertTrue(lease.newly_created)
        self.assertNotEqual(lease.profile_id, "manual")

    def test_reservation_added_during_state_check_wins_final_lease_race(self):
        pool = self.pool

        class _ReservingClient(_FakeClient):
            def resolve_profile_open_state(self, row):
                pool.reserve_external(self.profile_id_from_row(row))
                return False

        client = _ReservingClient([_row("manual")])

        lease = self.pool.acquire(client)

        self.assertTrue(lease.newly_created)
        self.assertTrue(self.pool.is_external_reserved("manual"))

    def test_per_attempt_exclusion_forces_another_cached_profile(self):
        client = _FakeClient([_row("first"), _row("second")])
        self.pool._released_at.update({"first": 20.0, "second": 10.0})

        lease = self.pool.acquire(
            client,
            excluded_profile_ids={"first"},
        )

        self.assertEqual(lease.profile_id, "second")

    def test_candidate_detail_lookup_stops_after_first_confirmed_closed(self):
        rows = [_row("older"), _row("middle"), _row("newest")]
        for row in rows:
            row.pop("openStatus")
        client = _FakeClient(rows)
        client.detail_states = {"newest": False, "middle": False, "older": False}
        self.pool._released_at.update({"older": 10.0, "middle": 20.0, "newest": 30.0})

        lease = self.pool.acquire(client)

        self.assertEqual(lease.profile_id, "newest")
        self.assertEqual(client.detail_calls, ["newest"])

    def test_foreign_profiles_do_not_count_toward_capacity_or_get_adopted(self):
        client = _FakeClient([
            _row("foreign-new", owned=False, closed_at="2026-02-01 00:00:00"),
            _row("foreign-old", owned=False, closed_at="2025-01-01 00:00:00"),
            _row("foreign-open", owned=False, opened=True),
            _row("other-project-1", owned=True, project_id="other-project"),
            _row("other-project-2", owned=True, project_id="other-project"),
        ])

        lease = self.pool.acquire(client)

        self.assertEqual(lease.profile_id, "new-1")
        self.assertFalse(lease.adopted)
        self.assertTrue(lease.newly_created)
        self.assertEqual(client.closed, [])
        self.assertEqual(client.deleted, [])
        self.assertEqual(len(client.created_payloads), 1)

    def test_concurrent_acquires_scale_to_ten_without_project_side_limit(self):
        client = _FakeClient([])
        leases = []
        errors = []

        def run():
            try:
                leases.append(self.pool.acquire(client))
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=run, daemon=True) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(1)

        self.assertEqual(errors, [])
        self.assertEqual(len({lease.profile_id for lease in leases}), 10)
        self.assertEqual(len(client.rows), 10)
        self.assertEqual(client.proxy_calls, 10)
        self.assertEqual(
            {payload["windowName"] for payload in client.created_payloads},
            {f"turb-gpt-cache-{index:02d}" for index in range(1, 11)},
        )

    def test_slow_inventory_request_does_not_hold_pool_state_lock(self):
        first_client = _FakeClient([])
        first_lease = self.pool.acquire(first_client)
        blocked_client = _FakeClient([])
        list_started = threading.Event()
        release_list = threading.Event()
        acquire_errors = []
        original_list = blocked_client.list_profiles

        def blocked_list():
            list_started.set()
            if not release_list.wait(2):
                raise AssertionError("test did not release inventory request")
            return original_list()

        blocked_client.list_profiles = blocked_list

        def acquire_next():
            try:
                self.pool.acquire(blocked_client)
            except Exception as exc:  # pragma: no cover - asserted below
                acquire_errors.append(exc)

        acquire_thread = threading.Thread(target=acquire_next, daemon=True)
        acquire_thread.start()
        self.assertTrue(list_started.wait(1))

        release_finished = threading.Event()

        def release_first():
            self.pool.release(first_lease.token, healthy=True)
            release_finished.set()

        release_thread = threading.Thread(
            target=release_first,
            daemon=True,
        )
        release_thread.start()
        self.assertTrue(
            release_finished.wait(0.2),
            "pool state updates waited for a network request",
        )
        release_list.set()
        acquire_thread.join(2)
        release_thread.join(2)

        self.assertEqual(acquire_errors, [])
        self.assertFalse(acquire_thread.is_alive())
        self.assertFalse(release_thread.is_alive())

    def test_five_leases_with_unknown_list_state_use_only_one_detail_each(self):
        rows = [_row(str(index)) for index in range(5)]
        for row in rows:
            row.pop("openStatus")
        client = _FakeClient(rows)
        client.detail_states = {str(index): False for index in range(5)}
        self.pool._released_at.update({str(index): float(index) for index in range(5)})

        leases = [self.pool.acquire(client) for _ in range(5)]

        self.assertEqual(len({lease.profile_id for lease in leases}), 5)
        self.assertEqual(len(client.detail_calls), 5)
        self.assertEqual(set(client.detail_calls), {str(index) for index in range(5)})

    def test_busy_owned_profiles_create_another_without_using_foreign_profile(self):
        client = _FakeClient(
            [_row(str(i), opened=True) for i in range(5)]
            + [_row("foreign-closed", owned=False)]
        )

        lease = self.pool.acquire(client)

        self.assertEqual(lease.profile_id, "new-1")
        self.assertTrue(lease.newly_created)
        self.assertEqual(len(client.created_payloads), 1)
        self.assertEqual(client.closed, [])
        self.assertEqual(client.deleted, [])

    def test_status_reports_demand_driven_capacity(self):
        snapshot = self.pool.status()

        self.assertIsNone(snapshot["limit"])
        self.assertEqual(snapshot["limit_mode"], "demand")

    def test_clear_deletes_only_closed_owned_profiles(self):
        client = _FakeClient([
            _row("idle"),
            _row("open", opened=True),
            _row("foreign", owned=False),
        ])

        result = self.pool.clear(client)

        self.assertEqual(result, {"ok": True, "deleted": 1, "skipped_busy": 1, "failed": 0})
        self.assertEqual(client.deleted, ["idle"])

    def test_clear_never_deletes_restart_reserved_manual_profile(self):
        client = _FakeClient([_row("idle"), _row("manual")])
        self.pool.replace_external_reservations(["manual"])

        result = self.pool.clear(client)

        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["skipped_busy"], 1)
        self.assertEqual(client.deleted, ["idle"])

    def test_external_reservation_refuses_a_normally_leased_profile(self):
        client = _FakeClient([_row("leased")])
        lease = self.pool.acquire(client)

        self.assertFalse(self.pool.reserve_external(lease.profile_id))
        self.assertFalse(self.pool.is_external_reserved(lease.profile_id))

    def test_missing_project_id_blocks_acquire_before_proxy_or_list(self):
        client = _FakeClient([_row("owned")])

        with patch.object(roxy_cfg, "ROXY_PROJECT_ID", ""):
            with self.assertRaisesRegex(RuntimeError, "ROXY_PROJECT_ID"):
                self.pool.acquire(client)

        self.assertEqual(client.proxy_calls, 0)
        self.assertEqual(client.created_payloads, [])

    def test_clear_refuses_to_run_without_project_id(self):
        client = _FakeClient([_row("idle")])

        with patch.object(roxy_cfg, "ROXY_PROJECT_ID", ""):
            result = self.pool.clear(client)

        self.assertEqual(result["error_code"], "roxy_project_id_required")
        self.assertEqual(client.closed, [])
        self.assertEqual(client.deleted, [])

    def test_discard_token_deletes_profile_and_releases_lease(self):
        client = _FakeClient([_row("broken")])
        lease = self.pool.acquire(client)

        self.pool.discard_token(client, lease.token)

        self.assertEqual(client.deleted, ["broken"])
        self.assertEqual(self.pool.status(client)["leased"], 0)

    def test_discard_refuses_legacy_adopted_or_unowned_profile(self):
        client = _FakeClient([_row("foreign", owned=False)])
        lease = RoxyProfileLease(
            token="legacy-adopted",
            profile_id="foreign",
            window_name="foreign",
            newly_created=False,
            adopted=True,
            proxy_info={"proxyCategory": "noproxy"},
            proxy_summary={"protocol": "noproxy", "authenticated": False},
        )
        self.pool._leases_by_profile[lease.profile_id] = lease
        self.pool._leases_by_token[lease.token] = lease

        with self.assertLogs("core.roxy_profile_pool", level="ERROR") as captured:
            self.pool.discard(client, lease)

        self.assertEqual(client.closed, [])
        self.assertEqual(client.deleted, [])
        self.assertEqual(self.pool.status(client)["leased"], 0)
        self.assertIn(
            "profile_ownership_not_confirmed",
            "\n".join(captured.output),
        )

    def test_transient_failure_defers_without_delete_and_closed_profile_recovers(self):
        client = _FakeClient([_row("warm")])
        lease = self.pool.acquire(client)

        self.pool.defer(lease, reason="rate_limited")

        passive = self.pool.status()
        self.assertEqual(passive["leased"], 0)
        self.assertEqual(passive["pending_recovery"], 1)
        self.assertEqual(passive["pending_cleanup"], 0)
        self.assertEqual(client.deleted, [])

        client.rows[0].pop("openStatus")
        client.detail_states = {"warm": False}
        client.detail_calls.clear()
        recovered = self.pool.acquire(client)

        self.assertEqual(recovered.profile_id, "warm")
        self.assertEqual(recovered.source, "cached")
        self.assertEqual(client.detail_calls, ["warm"])
        self.assertEqual(self.pool.status()["pending_recovery"], 0)
        self.assertEqual(client.deleted, [])

    def test_each_live_refresh_reconciles_at_most_one_pending_profile(self):
        rows = [_row("one"), _row("two")]
        client = _FakeClient(rows)
        first = self.pool.acquire(client)
        second = self.pool.acquire(client)
        self.pool.defer(first)
        self.pool.defer(second)
        for row in client.rows:
            row.pop("openStatus")
        client.detail_states = {"one": False, "two": False}
        client.detail_calls.clear()

        first_refresh = self.pool.status(client, refresh=True)
        first_refresh_detail_calls = list(client.detail_calls)
        second_refresh = self.pool.status(client, refresh=True)

        self.assertEqual(first_refresh["pending_recovery"], 1)
        self.assertEqual(second_refresh["pending_recovery"], 0)
        self.assertEqual(first_refresh_detail_calls, [first.profile_id])
        self.assertGreaterEqual(len(client.detail_calls), 2)
        self.assertEqual(client.detail_calls[1], second.profile_id)
        self.assertEqual(client.deleted, [])

    def test_pending_profile_stays_quarantined_while_open_or_unknown(self):
        for state in (True, None):
            with self.subTest(state=state):
                pool = RoxyProfilePool()
                client = _FakeClient([_row("warm")])
                lease = pool.acquire(client)
                pool.defer(lease, reason="close_state_unknown")
                client.rows[0].pop("openStatus")
                client.detail_states = {"warm": state}

                snapshot = pool.status(client, refresh=True)

                self.assertEqual(snapshot["pending_recovery"], 1)
                self.assertEqual(snapshot["leased"], 0)
                self.assertEqual(client.deleted, [])

    def test_missing_pending_profile_clears_recovery_record(self):
        client = _FakeClient([_row("gone")])
        lease = self.pool.acquire(client)
        self.pool.defer(lease, reason="close_state_unknown")
        client.rows.clear()

        snapshot = self.pool.status(client, refresh=True)

        self.assertEqual(snapshot["pending_recovery"], 0)
        self.assertEqual(snapshot["leased"], 0)
        self.assertEqual(client.deleted, [])


class RoxyCachedProfilePreparationTests(unittest.TestCase):
    def test_cached_profile_can_switch_from_proxy_to_direct_and_back(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        proxy_info = {"proxyCategory": "HTTP", "protocol": "HTTP", "host": "proxy.example", "port": "8080"}
        state = _profile_configuration(proxy_info)
        client.randomize_profile = Mock()
        client.get_profile_configuration = Mock(return_value=state)
        client.modify_profile = Mock(side_effect=lambda _pid, body: state.update(body))
        with patch("core.proxy_sid.select_default_proxy") as choose:
            direct, summary = client.choose_task_proxy("")
        choose.assert_not_called()
        self.assertEqual(summary["source"], "explicit_direct")
        for selected in (direct, proxy_info):
            with self.subTest(protocol=selected["proxyCategory"]):
                client.prepare_cached_profile(
                    "profile", proxy_info=selected,
                    proxy_summary={"protocol": selected["proxyCategory"], "authenticated": False},
                    clear_cache_once=False, window_name="turb-gpt-cache-01", window_remark=PROFILE_CACHE_REMARK,
                )
                self.assertEqual(state["proxyInfo"], selected)
                self.assertEqual(client.modify_profile.call_args.args[1]["proxyInfo"], selected)

    def test_unknown_cached_os_skips_m3_but_keeps_mandatory_image_block(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        detail = {
            "fingerInfo": {"customFingerprint": "keep"},
            "proxyInfo": {"proxyCategory": "noproxy"},
        }
        client.modify_profile = Mock()
        client.randomize_profile = Mock()
        client.get_validated_profile_configuration = Mock(return_value=detail)

        with (
            patch.object(roxy_cfg, "ROXY_BLOCK_IMAGES", False, create=True),
            patch.object(roxy_cfg, "ROXY_MAC_M3_WEBGL", True, create=True),
        ):
            client.prepare_cached_profile(
                "profile",
                proxy_info={"proxyCategory": "noproxy"},
                proxy_summary={"protocol": "noproxy", "authenticated": False},
                clear_cache_once=False,
                window_name="turb-gpt-cache-01",
                window_remark=PROFILE_CACHE_REMARK,
            )

        body = client.modify_profile.call_args_list[1].args[1]
        self.assertEqual(body["fingerInfo"]["customFingerprint"], "keep")
        self.assertIs(body["fingerInfo"]["forbidImage"], False)
        self.assertEqual(body["fingerInfo"]["forbiddenPictureSize"], 0)
        for key in ("webGLInfo", "webGLManufacturer", "webGLRender", "webGpu"):
            self.assertNotIn(key, body["fingerInfo"])

    def test_prepare_preserves_noise_and_sets_identity_cache_policy_in_order(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        events = []
        client.randomize_profile = Mock(side_effect=lambda _pid: events.append("random"))
        client.get_profile_configuration = Mock(
            side_effect=lambda _pid: events.append("detail")
            or _profile_configuration()
        )
        client.modify_profile = Mock(side_effect=lambda _pid, _body: events.append("modify"))

        with (
            patch.object(roxy_cfg, "ROXY_BLOCK_IMAGES", True),
            patch.object(roxy_cfg, "ROXY_WEBRTC_REPLACE", True),
            patch.object(roxy_cfg, "ROXY_MAC_M3_WEBGL", True),
        ):
            client.prepare_cached_profile(
                "profile",
                proxy_info={"proxyCategory": "noproxy"},
                proxy_summary={"protocol": "noproxy", "authenticated": False},
                clear_cache_once=False,
                window_name="turb-gpt-cache-01",
                window_remark=PROFILE_CACHE_REMARK,
            )

        self.assertEqual(
            events,
            ["modify", "random", "detail", "modify", "detail"],
        )
        self.assertEqual(
            client.modify_profile.call_args_list[0].args[1],
            {"proxyInfo": {"proxyCategory": "noproxy"}},
        )
        body = client.modify_profile.call_args.args[1]
        self.assertNotIn("name", body)
        finger = body["fingerInfo"]
        self.assertFalse(finger["clearCacheFile"])
        self.assertTrue(finger["clearCookie"])
        self.assertTrue(finger["clearLocalStorage"])
        self.assertFalse(finger["randomFingerprint"])
        self.assertFalse(finger["syncCookie"])
        self.assertFalse(finger["syncLocalStorage"])
        self.assertFalse(finger["forbidImage"])
        self.assertEqual(finger["webRTC"], 0)
        self.assertIs(finger["webGL"], False)
        self.assertEqual(finger["webGLManufacturer"], "Google Inc. (Apple)")

    def test_matching_validated_proxy_locale_and_timezone_pass_both_readbacks(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        selected_proxy = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "proxy.example",
            "port": "1080",
            "proxyUserName": "account-region-JP-sid-QwErTyUi-t-120",
            "proxyPassword": "secret",
        }
        selected_summary = {
            "validated": True,
            "actual_country": "JP",
            "geo": {"country": "JP", "timezone": "Asia/Tokyo"},
        }
        detail = _profile_configuration(
            selected_proxy,
            country="JP",
            language="ja-JP",
            timezone_name="GMT+09:00 Asia/Tokyo",
        )
        client.modify_profile = Mock()
        client.randomize_profile = Mock()
        client.get_profile_configuration = Mock(return_value=detail)

        client.prepare_cached_profile(
            "profile",
            proxy_info=selected_proxy,
            proxy_summary=selected_summary,
            clear_cache_once=False,
            window_name="turb-gpt-cache-01",
            window_remark=PROFILE_CACHE_REMARK,
        )

        self.assertEqual(client.get_profile_configuration.call_count, 2)
        self.assertEqual(client.modify_profile.call_count, 2)

    def test_ip_based_blank_locale_is_valid_when_proxy_country_matches(self):
        proxy_info = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "proxy.example",
            "port": "1080",
        }

        RoxyBrowserClient.validate_profile_configuration(
            _profile_configuration(proxy_info, country="JP"),
            proxy_info=proxy_info,
            proxy_summary={
                "validated": True,
                "actual_country": "JP",
                "geo": {"country": "JP", "timezone": "Asia/Tokyo"},
            },
            stage="randomized",
        )

    def test_validated_proxy_allows_missing_country_metadata(self):
        proxy_info = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "proxy.example",
            "port": "1080",
        }

        with self.assertLogs("core.roxybrowser_client", level="INFO") as captured:
            RoxyBrowserClient.validate_profile_configuration(
                _profile_configuration(
                    proxy_info,
                    language="ja-JP",
                    timezone_name="Asia/Tokyo",
                ),
                proxy_info=proxy_info,
                proxy_summary={
                    "validated": True,
                    "actual_country": "JP",
                    "geo": {"country": "JP", "timezone": "Asia/Tokyo"},
                },
                stage="randomized",
            )

        self.assertIn("country_metadata=missing", "\n".join(captured.output))

    def test_validated_proxy_allows_stale_country_metadata_when_locale_matches(self):
        proxy_info = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "proxy.example",
            "port": "1080",
        }

        with self.assertLogs("core.roxybrowser_client", level="INFO") as captured:
            RoxyBrowserClient.validate_profile_configuration(
                _profile_configuration(
                    proxy_info,
                    country="FR",
                    language="ja-JP",
                    timezone_name="Asia/Tokyo",
                ),
                proxy_info=proxy_info,
                proxy_summary={
                    "validated": True,
                    "actual_country": "JP",
                    "geo": {"country": "JP", "timezone": "Asia/Tokyo"},
                },
                stage="randomized",
            )

        self.assertIn("country_metadata=stale", "\n".join(captured.output))

    def test_japan_proxy_retries_until_locale_readback_converges(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        selected_proxy = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "proxy.example",
            "port": "1080",
            "proxyUserName": "account-region-JP-sid-QwErTyUi-t-120",
            "proxyPassword": "secret",
        }
        stale_detail = _profile_configuration(
            selected_proxy,
            country="JP",
            language="fr-FR",
            timezone_name="Europe/Paris",
        )
        converged_detail = _profile_configuration(
            selected_proxy,
            language="ja-JP",
            timezone_name="Asia/Tokyo",
        )
        client.modify_profile = Mock()
        client.randomize_profile = Mock()
        client.get_profile_configuration = Mock(
            side_effect=[stale_detail, converged_detail, converged_detail]
        )

        with patch("core.roxybrowser_client.time.sleep") as sleep_mock:
            client.prepare_cached_profile(
                "profile",
                proxy_info=selected_proxy,
                proxy_summary={
                    "validated": True,
                    "actual_country": "JP",
                    "geo": {"country": "JP", "timezone": "Asia/Tokyo"},
                },
                clear_cache_once=False,
                window_name="turb-gpt-cache-01",
                window_remark=PROFILE_CACHE_REMARK,
            )

        sleep_mock.assert_called_once_with(1.0)
        self.assertEqual(client.get_profile_configuration.call_count, 3)
        self.assertEqual(client.modify_profile.call_count, 2)

    def test_japan_proxy_rejects_persistent_french_locale_before_profile_open(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        selected_proxy = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "proxy.example",
            "port": "1080",
            "proxyUserName": "account-region-JP-sid-QwErTyUi-t-120",
            "proxyPassword": "secret",
        }
        client.modify_profile = Mock()
        client.randomize_profile = Mock()
        client.get_profile_configuration = Mock(
            return_value=_profile_configuration(
                selected_proxy,
                country="JP",
                language="fr-FR",
                timezone_name="Europe/Paris",
            )
        )

        with patch("core.roxybrowser_client.time.sleep") as sleep_mock:
            with self.assertRaises(RoxyProfileValidationError) as raised:
                client.prepare_cached_profile(
                    "profile",
                    proxy_info=selected_proxy,
                    proxy_summary={
                        "validated": True,
                        "actual_country": "JP",
                        "geo": {"country": "JP", "timezone": "Asia/Tokyo"},
                    },
                    clear_cache_once=False,
                    window_name="turb-gpt-cache-01",
                    window_remark=PROFILE_CACHE_REMARK,
                )

        self.assertEqual(
            raised.exception.reason_code,
            "roxy_profile_locale_mismatch",
        )
        self.assertEqual(raised.exception.stage, "randomized")
        self.assertIn("language_mismatch", raised.exception.issues)
        self.assertIn("timezone_mismatch", raised.exception.issues)
        self.assertEqual(client.modify_profile.call_count, 1)
        self.assertEqual(client.get_profile_configuration.call_count, 3)
        self.assertEqual(sleep_mock.call_args_list, [call(1.0), call(2.0)])

    def test_proxy_readback_mismatches_are_rejected_without_secret_diagnostics(self):
        selected_proxy = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "private-proxy.example",
            "port": "1080",
            "proxyUserName": "account-region-JP-sid-QwErTyUi-t-120",
            "proxyPassword": "top-secret",
        }
        mutations = {
            "host": "other.example",
            "port": "1081",
            "proxyUserName": "account-region-JP-sid-OtherSid-t-120",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                client = RoxyBrowserClient(
                    api_base="http://127.0.0.1:50000", token=""
                )
                actual = dict(selected_proxy)
                actual[field] = replacement
                client.modify_profile = Mock()
                client.randomize_profile = Mock()
                client.get_profile_configuration = Mock(
                    return_value=_profile_configuration(actual)
                )

                with patch("core.roxybrowser_client.time.sleep") as sleep_mock:
                    with self.assertRaises(RoxyProfileValidationError) as raised:
                        client.prepare_cached_profile(
                            "profile",
                            proxy_info=selected_proxy,
                            proxy_summary={"validated": False},
                            clear_cache_once=False,
                            window_name="turb-gpt-cache-01",
                            window_remark=PROFILE_CACHE_REMARK,
                        )

                rendered = str(raised.exception)
                self.assertEqual(
                    raised.exception.reason_code,
                    "roxy_profile_proxy_mismatch",
                )
                self.assertNotIn("private-proxy.example", rendered)
                self.assertNotIn("QwErTyUi", rendered)
                self.assertNotIn("top-secret", rendered)
                self.assertEqual(client.get_profile_configuration.call_count, 3)
                self.assertEqual(sleep_mock.call_args_list, [call(1.0), call(2.0)])

    def test_missing_full_readback_is_a_structural_failure(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        client.modify_profile = Mock()
        client.randomize_profile = Mock()
        client.get_profile_configuration = Mock(return_value={})

        with patch("core.roxybrowser_client.time.sleep") as sleep_mock:
            with self.assertRaises(RoxyProfileValidationError) as raised:
                client.prepare_cached_profile(
                    "profile",
                    proxy_info={"proxyCategory": "noproxy"},
                    proxy_summary={"protocol": "noproxy", "authenticated": False},
                    clear_cache_once=False,
                    window_name="turb-gpt-cache-01",
                    window_remark=PROFILE_CACHE_REMARK,
                )

        self.assertEqual(
            raised.exception.reason_code,
            "roxy_profile_readback_missing",
        )
        self.assertEqual(client.modify_profile.call_count, 1)
        self.assertEqual(client.get_profile_configuration.call_count, 3)
        self.assertEqual(sleep_mock.call_args_list, [call(1.0), call(2.0)])

    def test_final_proxy_mismatch_is_rejected_after_identity_configuration(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        selected_proxy = {
            "proxyCategory": "SOCKS5",
            "protocol": "SOCKS5",
            "host": "proxy.example",
            "port": "1080",
        }
        final_proxy = dict(selected_proxy)
        final_proxy["port"] = "1081"
        client.modify_profile = Mock()
        client.randomize_profile = Mock()
        client.get_profile_configuration = Mock(
            side_effect=[
                _profile_configuration(selected_proxy),
                _profile_configuration(final_proxy),
                _profile_configuration(final_proxy),
                _profile_configuration(final_proxy),
            ]
        )

        with patch("core.roxybrowser_client.time.sleep") as sleep_mock:
            with self.assertRaises(RoxyProfileValidationError) as raised:
                client.prepare_cached_profile(
                    "profile",
                    proxy_info=selected_proxy,
                    proxy_summary={"validated": False},
                    clear_cache_once=False,
                    window_name="turb-gpt-cache-01",
                    window_remark=PROFILE_CACHE_REMARK,
                )

        self.assertEqual(raised.exception.stage, "final")
        self.assertIn("proxy_port_mismatch", raised.exception.issues)
        self.assertEqual(client.modify_profile.call_count, 2)
        self.assertEqual(client.get_profile_configuration.call_count, 4)
        self.assertEqual(sleep_mock.call_args_list, [call(1.0), call(2.0)])

    def test_open_failure_discards_lease_and_preserves_original_exception(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        lease = RoxyProfileLease(
            token="lease",
            profile_id="profile",
            window_name="turb-gpt-cache-01",
            newly_created=False,
            adopted=False,
            proxy_info={"proxyCategory": "noproxy"},
            proxy_summary={"protocol": "noproxy", "authenticated": False},
        )
        pool = Mock()
        pool.acquire.return_value = lease
        client.choose_task_proxy = Mock(
            return_value=(lease.proxy_info, lease.proxy_summary)
        )
        original = ValueError("open failed")
        client.prepare_cached_profile = Mock()
        client._open_profile_by_id = Mock(side_effect=original)

        with (
            patch.object(roxy_cfg, "ROXY_PROFILE_CACHE_REUSE", True, create=True),
            patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool),
        ):
            with self.assertRaises(ValueError) as raised:
                client.open_profile()

        self.assertIs(raised.exception, original)
        pool.discard.assert_called_once_with(client, lease)

    def test_open_profile_forwards_nonempty_attempt_exclusions_to_pool(self):
        client = RoxyBrowserClient(
            api_base="http://127.0.0.1:50000",
            token="",
        )
        lease = RoxyProfileLease(
            token="lease",
            profile_id="profile-new",
            window_name="turb-gpt-cache-01",
            newly_created=False,
            adopted=False,
            proxy_info={"proxyCategory": "noproxy"},
            proxy_summary={"protocol": "noproxy", "authenticated": False},
        )
        opened = RoxyOpenResult(
            "profile-new",
            {},
            debugger_address="127.0.0.1:9222",
        )
        pool = Mock()
        pool.acquire.return_value = lease
        client.choose_task_proxy = Mock(
            return_value=(lease.proxy_info, lease.proxy_summary)
        )
        client.prepare_cached_profile = Mock()
        client._open_profile_by_id = Mock(return_value=opened)

        with (
            patch.object(roxy_cfg, "ROXY_PROFILE_CACHE_REUSE", True, create=True),
            patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool),
        ):
            result = client.open_profile(
                excluded_profile_ids={"profile-failed"},
            )

        self.assertIs(result, opened)
        self.assertEqual(
            pool.acquire.call_args.kwargs["excluded_profile_ids"],
            {"profile-failed"},
        )

    def test_readback_failure_discards_lease_without_opening_browser(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        lease = RoxyProfileLease(
            token="lease",
            profile_id="profile",
            window_name="turb-gpt-cache-01",
            newly_created=False,
            adopted=False,
            proxy_info={"proxyCategory": "noproxy"},
            proxy_summary={"protocol": "noproxy", "authenticated": False},
        )
        pool = Mock()
        pool.acquire.return_value = lease
        client.choose_task_proxy = Mock(
            return_value=(lease.proxy_info, lease.proxy_summary)
        )
        failure = RoxyProfileValidationError(
            "roxy_profile_locale_mismatch",
            stage="randomized",
            issues=["language_mismatch"],
        )
        client.prepare_cached_profile = Mock(side_effect=failure)
        client._open_profile_by_id = Mock()

        with (
            patch.object(roxy_cfg, "ROXY_PROFILE_CACHE_REUSE", True, create=True),
            patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool),
        ):
            with self.assertRaises(RoxyProfileValidationError) as raised:
                client.open_profile()

        self.assertIs(raised.exception, failure)
        pool.discard.assert_called_once_with(client, lease)
        client._open_profile_by_id.assert_not_called()

    def test_legacy_adopted_lease_is_rejected_before_profile_preparation(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        lease = RoxyProfileLease(
            token="legacy",
            profile_id="foreign",
            window_name="foreign",
            newly_created=False,
            adopted=True,
            proxy_info={"proxyCategory": "noproxy"},
            proxy_summary={"protocol": "noproxy", "authenticated": False},
        )
        pool = Mock()
        pool.acquire.return_value = lease
        client.choose_task_proxy = Mock(
            return_value=(lease.proxy_info, lease.proxy_summary)
        )
        client.prepare_cached_profile = Mock()
        client._open_profile_by_id = Mock()

        with (
            patch.object(roxy_cfg, "ROXY_PROFILE_CACHE_REUSE", True, create=True),
            patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "roxy_profile_foreign_adoption_forbidden",
            ):
                client.open_profile()

        client.prepare_cached_profile.assert_not_called()
        client._open_profile_by_id.assert_not_called()
        pool.discard.assert_called_once_with(client, lease)

    def test_transient_open_failure_defers_lease_without_deleting_profile(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        lease = RoxyProfileLease(
            token="lease",
            profile_id="profile",
            window_name="turb-gpt-cache-01",
            newly_created=False,
            adopted=False,
            proxy_info={"proxyCategory": "noproxy"},
            proxy_summary={"protocol": "noproxy", "authenticated": False},
        )
        pool = Mock()
        pool.acquire.return_value = lease
        client.choose_task_proxy = Mock(
            return_value=(lease.proxy_info, lease.proxy_summary)
        )
        original = RoxyRateLimitError("Roxy API 请求过频 POST /browser/open，请稍后再试")
        client.prepare_cached_profile = Mock()
        client._open_profile_by_id = Mock(side_effect=original)

        with (
            patch.object(roxy_cfg, "ROXY_PROFILE_CACHE_REUSE", True, create=True),
            patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool),
        ):
            with self.assertRaises(RoxyRateLimitError) as raised:
                client.open_profile()

        self.assertIs(raised.exception, original)
        pool.defer.assert_called_once_with(lease, reason="roxy_api_transient")
        pool.discard.assert_not_called()

    def test_pooled_cleanup_always_closes_and_releases_healthy_lease(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        opened = RoxyOpenResult(
            "profile",
            {},
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease",
        )
        client._close_profile_strict = Mock()
        client._profile_open_state_strict = Mock(return_value=False)
        pool = Mock()

        with (
            patch.object(roxy_cfg, "ROXY_KEEP_BROWSER_OPEN", True),
            patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool),
        ):
            client.cleanup_profile(opened)

        client._close_profile_strict.assert_called_once_with("profile")
        pool.release.assert_called_once_with("lease", healthy=True)
        pool.defer_token.assert_not_called()
        pool.discard_token.assert_not_called()

    def test_pooled_cleanup_defers_confirmed_open_profile_without_delete(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        opened = RoxyOpenResult(
            "profile",
            {},
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease",
        )
        client._close_profile_strict = Mock()
        client._profile_open_state_strict = Mock(return_value=True)
        pool = Mock()

        with patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool):
            client.cleanup_profile(opened)

        pool.defer_token.assert_called_once_with("lease", reason="close_state_open")
        pool.discard_token.assert_not_called()
        pool.release.assert_not_called()

    def test_pooled_cleanup_defers_unknown_profile_state_without_delete(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        opened = RoxyOpenResult(
            "profile",
            {},
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease",
        )
        client._close_profile_strict = Mock()
        client._profile_open_state_strict = Mock(return_value=None)
        pool = Mock()

        with patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool):
            client.cleanup_profile(opened)

        pool.defer_token.assert_called_once_with("lease", reason="close_state_unknown")
        pool.discard_token.assert_not_called()
        pool.release.assert_not_called()

    def test_all_close_api_errors_are_deferred_and_logs_are_sanitized(self):
        cases = (
            (
                RoxyRateLimitError("rate-limit-poison-profile-123"),
                "close_transient_api_error",
            ),
            (requests.Timeout("timeout-poison-profile-123"), "close_transient_api_error"),
            (
                requests.ConnectionError("connection-poison-profile-123"),
                "close_transient_api_error",
            ),
            (RuntimeError("permanent-poison-profile-123"), "close_api_error"),
        )
        for error, expected_reason in cases:
            with self.subTest(error=type(error).__name__):
                client = RoxyBrowserClient(
                    api_base="http://127.0.0.1:50000", token=""
                )
                opened = RoxyOpenResult(
                    "profile",
                    {},
                    debugger_address="127.0.0.1:9222",
                    pooled=True,
                    lease_token="lease",
                )
                client._close_profile_strict = Mock(side_effect=error)
                pool = Mock()

                with (
                    patch(
                        "core.roxy_profile_pool.get_roxy_profile_pool",
                        return_value=pool,
                    ),
                    self.assertLogs("core.roxybrowser_client", level="WARNING") as logs,
                ):
                    client.cleanup_profile(opened)

                pool.defer_token.assert_called_once_with(
                    "lease", reason=expected_reason
                )
                pool.discard_token.assert_not_called()
                pool.release.assert_not_called()
                output = "\n".join(logs.output)
                self.assertIn(f"reason={expected_reason}", output)
                self.assertIn("已延后核验并保留缓存", output)
                self.assertNotIn("poison-profile-123", output)

    def test_profile_state_api_error_after_close_is_deferred_without_delete(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        opened = RoxyOpenResult(
            "profile",
            {},
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease",
        )
        client._close_profile_strict = Mock()
        client._profile_open_state_strict = Mock(
            side_effect=RuntimeError("detail-poison-profile-123")
        )
        pool = Mock()

        with (
            patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool),
            self.assertLogs("core.roxybrowser_client", level="WARNING") as logs,
        ):
            client.cleanup_profile(opened)

        pool.defer_token.assert_called_once_with(
            "lease", reason="close_api_error"
        )
        pool.discard_token.assert_not_called()
        pool.release.assert_not_called()
        self.assertNotIn("detail-poison-profile-123", "\n".join(logs.output))

    def test_identity_reset_failure_marks_profile_for_structural_deletion(self):
        client = RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")
        opened = RoxyOpenResult(
            "profile",
            {},
            debugger_address="127.0.0.1:9222",
            pooled=True,
            lease_token="lease",
            profile_cache_discard=True,
        )
        pool = Mock()

        with patch("core.roxy_profile_pool.get_roxy_profile_pool", return_value=pool):
            client.cleanup_profile(opened)

        pool.discard_token.assert_called_once_with(client, "lease")
        pool.defer_token.assert_not_called()
        pool.release.assert_not_called()


class _SwitchTo:
    def __init__(self, driver):
        self.driver = driver

    def window(self, handle):
        self.driver.current_window_handle = handle


class _IdentityDriver:
    def __init__(self, cookies=None):
        self.window_handles = ["main", "extra"]
        self.current_window_handle = "main"
        self.switch_to = _SwitchTo(self)
        self.commands = []
        self.urls = []
        self.cookies = list(cookies or [])

    def get(self, url):
        self.urls.append(url)

    def close(self):
        self.window_handles.remove(self.current_window_handle)

    def execute_cdp_cmd(self, method, params):
        self.commands.append((method, params))
        if method == "Network.getAllCookies":
            return {"cookies": list(self.cookies)}
        return {}


class _TransientCookieDriver(_IdentityDriver):
    """Model Roxy returning the old cookie set for one CDP round-trip."""

    def __init__(self):
        super().__init__(cookies=[{"name": "stale", "domain": "chatgpt.com"}])
        self.cookie_reads = 0

    def execute_cdp_cmd(self, method, params):
        self.commands.append((method, params))
        if method == "Network.getAllCookies":
            self.cookie_reads += 1
            return {"cookies": list(self.cookies) if self.cookie_reads == 1 else []}
        return {}


class RoxyIdentityResetTests(unittest.TestCase):
    def test_identity_reset_clears_sites_but_never_http_cache(self):
        driver = _IdentityDriver()

        _reset_pooled_profile_identity(driver)

        methods = [method for method, _ in driver.commands]
        self.assertIn("Network.clearBrowserCookies", methods)
        self.assertIn("Storage.clearDataForOrigin", methods)
        self.assertNotIn("Network.clearBrowserCache", methods)
        self.assertEqual(driver.urls, ["about:blank"])
        self.assertEqual(driver.window_handles, ["main"])

    def test_remaining_cookie_is_a_hard_failure(self):
        driver = _IdentityDriver(cookies=[{"name": "stale"}])

        with self.assertRaisesRegex(RoxyIdentityResetError, "cookie_reset_incomplete"):
            _reset_pooled_profile_identity(driver)

    def test_transient_cookie_read_is_rechecked_before_discarding_profile(self):
        driver = _TransientCookieDriver()

        _reset_pooled_profile_identity(driver)

        self.assertGreaterEqual(driver.cookie_reads, 2)


if __name__ == "__main__":
    unittest.main()
