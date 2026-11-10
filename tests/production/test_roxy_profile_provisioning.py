# -*- coding: utf-8 -*-
from __future__ import annotations

import threading
import unittest
from contextlib import ExitStack, contextmanager
from unittest.mock import Mock, call, patch

import requests

from config import roxybrowser as roxy_cfg
from core.roxybrowser_client import (
    RoxyBrowserClient,
    RoxyCreateBusyError,
    reset_roxy_api_request_gate_for_tests,
)


@contextmanager
def _create_config(*, use_proxy_pool: bool = False):
    """为 create_profile 测试隔离本机的 Roxy 与指纹配置。"""
    values = {
        "ROXY_PROFILE_CREATE_PAYLOAD": {},
        "ROXY_DEFAULT_OS": "macOS",
        "ROXY_DEFAULT_OS_VERSION": "",
        "ROXY_WORKSPACE_ID": "123",
        "ROXY_PROJECT_ID": "456",
        "ROXY_CREATE_USE_PROXY_POOL": use_proxy_pool,
        "ROXY_RANDOM_OS_ON_CREATE": False,
        "ROXY_RANDOM_PROFILE_NAME_ON_CREATE": False,
        "ROXY_BLOCK_IMAGES": False,
        "ROXY_WEBRTC_REPLACE": False,
        "ROXY_MAC_M3_WEBGL": False,
        "ROXY_CREATE_METHOD": "POST",
        "ROXY_CREATE_PATH": "/browser/create",
    }
    with ExitStack() as stack:
        for name, value in values.items():
            stack.enter_context(patch.object(roxy_cfg, name, value, create=True))
        yield


@contextmanager
def _open_config(*, one_profile_per_account: bool = True):
    """为 open_profile 并发测试隔离本机 Profile 配置。"""
    values = {
        "ROXY_PROFILE_CACHE_REUSE": False,
        "ROXY_ONE_PROFILE_PER_ACCOUNT": one_profile_per_account,
        "ROXY_PROFILE_ID": "",
        "ROXY_OPEN_PATH": "/browser/open",
        "ROXY_OPEN_METHOD": "POST",
        "ROXY_OPEN_EXTRA_PARAMS": {},
        "ROXY_OPEN_HEADLESS": False,
        "ROXY_WORKSPACE_ID": "123",
        "ROXY_KEEP_BROWSER_OPEN": False,
        # Open-profile lock tests exercise provisioning only; isolate them
        # from the machine's editable default proxy configuration.
        "ROXY_CREATE_USE_PROXY_POOL": False,
    }
    with ExitStack() as stack:
        for name, value in values.items():
            stack.enter_context(patch.object(roxy_cfg, name, value, create=True))
        yield


class RoxyCreateBusyRetryTests(unittest.TestCase):
    def setUp(self):
        reset_roxy_api_request_gate_for_tests()
        self._rate_limit = patch.object(
            roxy_cfg, "ROXY_API_RATE_LIMIT_PER_MINUTE", 0, create=True
        )
        self._rate_limit.start()
        self.client = RoxyBrowserClient(
            api_base="http://127.0.0.1:50000",
            token="",
        )

    def tearDown(self):
        self._rate_limit.stop()
        reset_roxy_api_request_gate_for_tests()

    @staticmethod
    def _busy() -> RoxyCreateBusyError:
        return RoxyCreateBusyError(
            "Roxy API 返回失败 POST /browser/create: 正在创建中，请稍等！"
        )

    def test_request_classifies_structured_create_busy_response(self):
        response = Mock(status_code=200, text="busy")
        response.json.return_value = {
            "code": 1,
            "msg": "正在创建中，请稍等！",
        }
        self.client.http.request = Mock(return_value=response)

        with self.assertRaises(RoxyCreateBusyError):
            self.client.request("POST", "/browser/create", json_body={"workspaceId": 123})

        self.client.http.request.assert_called_once()

    def test_request_does_not_retry_ambiguous_create_timeout(self):
        self.client.http.request = Mock(side_effect=requests.Timeout("create timed out"))

        with patch.object(roxy_cfg, "ROXY_API_RETRIES", 9), patch(
            "core.roxybrowser_client.time.sleep"
        ) as sleep:
            with self.assertRaises(requests.Timeout):
                self.client.request(
                    "POST",
                    "/browser/create",
                    json_body={"workspaceId": 123},
                )

        self.client.http.request.assert_called_once()
        sleep.assert_not_called()

    def test_request_does_not_retry_create_connection_error(self):
        self.client.http.request = Mock(
            side_effect=requests.ConnectionError("create connection lost")
        )

        with patch.object(roxy_cfg, "ROXY_API_RETRIES", 9), patch(
            "core.roxybrowser_client.time.sleep"
        ) as sleep:
            with self.assertRaises(requests.ConnectionError):
                self.client.request(
                    "POST",
                    "/browser/create",
                    json_body={"workspaceId": 123},
                )

        self.client.http.request.assert_called_once()
        sleep.assert_not_called()

    def test_request_does_not_retry_create_http_error(self):
        response = Mock(status_code=503, text="service unavailable")
        response.json.side_effect = ValueError("not json")
        self.client.http.request = Mock(return_value=response)

        with patch.object(roxy_cfg, "ROXY_API_RETRIES", 9), patch(
            "core.roxybrowser_client.time.sleep"
        ) as sleep:
            with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
                self.client.request(
                    "POST",
                    "/browser/create",
                    json_body={"workspaceId": 123},
                )

        self.client.http.request.assert_called_once()
        sleep.assert_not_called()

    def test_busy_retries_three_times_with_two_four_second_backoff_and_same_payload(self):
        self.client.request = Mock(
            side_effect=[
                self._busy(),
                self._busy(),
                {"data": {"dirId": "901"}},
            ]
        )

        with _create_config(use_proxy_pool=True), patch(
            "config.proxy.PROXY_SID_TEMPLATE",
            "",
        ), patch(
            "config.proxy.pick_proxy",
            return_value="socks5://proxy.invalid:1080",
        ) as pick_proxy, patch(
            "core.roxybrowser_client.time.sleep"
        ) as sleep:
            profile_id = self.client.create_profile()

        self.assertEqual(profile_id, "901")
        self.assertEqual(self.client.request.call_count, 3)
        sleep.assert_has_calls([call(2.0), call(4.0)])
        self.assertEqual(sleep.call_count, 2)
        pick_proxy.assert_called_once_with()

        bodies = [item.kwargs["json_body"] for item in self.client.request.call_args_list]
        self.assertIs(bodies[0], bodies[1])
        self.assertIs(bodies[1], bodies[2])
        self.assertEqual(bodies[0]["proxyInfo"]["host"], "proxy.invalid")
        self.assertEqual(bodies[0]["proxyInfo"]["port"], "1080")

    def test_busy_exhaustion_raises_after_exactly_three_attempts(self):
        self.client.request = Mock(side_effect=[self._busy(), self._busy(), self._busy()])

        with _create_config(), patch("core.roxybrowser_client.time.sleep") as sleep:
            with self.assertRaises(RoxyCreateBusyError):
                self.client.create_profile()

        self.assertEqual(self.client.request.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(2.0), call(4.0)])

    def test_non_busy_create_error_is_not_retried(self):
        self.client.request = Mock(side_effect=RuntimeError("Roxy create rejected"))

        with _create_config(), patch("core.roxybrowser_client.time.sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "create rejected"):
                self.client.create_profile()

        self.client.request.assert_called_once()
        sleep.assert_not_called()

    def test_ambiguous_create_timeout_is_not_retried(self):
        self.client.request = Mock(side_effect=requests.Timeout("create timed out"))

        with _create_config(), patch("core.roxybrowser_client.time.sleep") as sleep:
            with self.assertRaises(requests.Timeout):
                self.client.create_profile()

        self.client.request.assert_called_once()
        sleep.assert_not_called()


class RoxyProfileProvisioningLockTests(unittest.TestCase):
    @staticmethod
    def _client() -> RoxyBrowserClient:
        return RoxyBrowserClient(api_base="http://127.0.0.1:50000", token="")

    def test_profile_create_calls_remain_serialized(self):
        first = self._client()
        second = self._client()
        first_started = threading.Event()
        second_started = threading.Event()
        release_first = threading.Event()
        errors = []

        def first_request(*_args, **_kwargs):
            first_started.set()
            if not release_first.wait(2):
                raise AssertionError("test did not release first create")
            return {"data": {"dirId": "81"}}

        def second_request(*_args, **_kwargs):
            second_started.set()
            return {"data": {"dirId": "82"}}

        first.request = Mock(side_effect=first_request)
        second.request = Mock(side_effect=second_request)

        def run(client):
            try:
                client.create_profile()
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with _create_config(), patch.object(
            roxy_cfg, "ROXY_API_RATE_LIMIT_PER_MINUTE", 0, create=True
        ):
            first_thread = threading.Thread(target=run, args=(first,), daemon=True)
            second_thread = threading.Thread(target=run, args=(second,), daemon=True)
            first_thread.start()
            self.assertTrue(first_started.wait(1))
            second_thread.start()
            self.assertFalse(second_started.wait(0.2))
            release_first.set()
            first_thread.join(2)
            second_thread.join(2)

        self.assertEqual(errors, [])
        self.assertTrue(second_started.is_set())
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())

    def test_distinct_profile_open_does_not_block_next_profile_creation(self):
        first = self._client()
        second = self._client()
        first_open_started = threading.Event()
        release_first_open = threading.Event()
        second_thread_entered = threading.Event()
        second_create_started = threading.Event()
        second_open_started = threading.Event()
        timeline: list[str] = []
        timeline_lock = threading.Lock()
        results = []
        errors = []

        def record(value: str) -> None:
            with timeline_lock:
                timeline.append(value)

        def create_first():
            record("create-1")
            return "101"

        def open_first(*args, **kwargs):
            record("open-1-start")
            first_open_started.set()
            if not release_first_open.wait(2):
                raise AssertionError("test did not release first open")
            record("open-1-end")
            return {"data": {"http": "127.0.0.1:9101"}}

        def create_second():
            record("create-2")
            second_create_started.set()
            return "102"

        def open_second(*args, **kwargs):
            record("open-2")
            second_open_started.set()
            return {"data": {"http": "127.0.0.1:9102"}}

        first.create_profile = Mock(side_effect=create_first)
        first.request = Mock(side_effect=open_first)
        second.create_profile = Mock(side_effect=create_second)
        second.request = Mock(side_effect=open_second)

        def run(client: RoxyBrowserClient, *, entered: threading.Event | None = None) -> None:
            if entered:
                entered.set()
            try:
                results.append(client.open_profile())
            except Exception as exc:  # pragma: no cover - 由主线程断言
                errors.append(exc)

        with _open_config():
            thread_1 = threading.Thread(target=run, args=(first,), daemon=True)
            thread_1.start()
            self.assertTrue(first_open_started.wait(1), "first client never reached open")

            thread_2 = threading.Thread(
                target=run,
                args=(second,),
                kwargs={"entered": second_thread_entered},
                daemon=True,
            )
            thread_2.start()
            self.assertTrue(second_thread_entered.wait(1))
            self.assertTrue(
                second_create_started.wait(1),
                "second Profile waited for the first Profile open",
            )
            self.assertTrue(
                second_open_started.wait(1),
                "second Profile open waited for the first Profile open",
            )

            release_first_open.set()
            thread_1.join(2)
            thread_2.join(2)

        self.assertFalse(thread_1.is_alive())
        self.assertFalse(thread_2.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(sorted(item.profile_id for item in results), ["101", "102"])
        self.assertLess(timeline.index("create-2"), timeline.index("open-1-end"))
        self.assertLess(timeline.index("open-2"), timeline.index("open-1-end"))

    def test_page_work_can_overlap_after_first_open_returns(self):
        first = self._client()
        second = self._client()
        first.create_profile = Mock(return_value="151")
        first.request = Mock(return_value={"data": {"http": "127.0.0.1:9151"}})
        second.create_profile = Mock(return_value="152")
        second.request = Mock(return_value={"data": {"http": "127.0.0.1:9152"}})
        first_page_started = threading.Event()
        release_first_page = threading.Event()
        second_open_finished = threading.Event()
        errors = []

        def run_first_page() -> None:
            try:
                first.open_profile()
                first_page_started.set()
                if not release_first_page.wait(2):
                    raise AssertionError("test did not release first page work")
            except Exception as exc:  # pragma: no cover - 由主线程断言
                errors.append(exc)

        def run_second_open() -> None:
            try:
                second.open_profile()
                second_open_finished.set()
            except Exception as exc:  # pragma: no cover - 由主线程断言
                errors.append(exc)

        with _open_config():
            first_thread = threading.Thread(target=run_first_page, daemon=True)
            first_thread.start()
            self.assertTrue(first_page_started.wait(1))

            second_thread = threading.Thread(target=run_second_open, daemon=True)
            second_thread.start()
            self.assertTrue(
                second_open_finished.wait(1),
                "second Profile waited for first task's page work",
            )
            self.assertTrue(first_thread.is_alive())

            release_first_page.set()
            first_thread.join(2)
            second_thread.join(2)

        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertEqual(errors, [])

    def test_fixed_profile_open_bypasses_new_profile_provisioning_lock(self):
        creator = self._client()
        fixed = self._client()
        creator_open_started = threading.Event()
        release_creator_open = threading.Event()
        fixed_open_finished = threading.Event()
        errors = []

        creator.create_profile = Mock(return_value="201")

        def creator_request(*args, **kwargs):
            creator_open_started.set()
            if not release_creator_open.wait(2):
                raise AssertionError("test did not release creator open")
            return {"data": {"http": "127.0.0.1:9201"}}

        creator.request = Mock(side_effect=creator_request)
        fixed.request = Mock(return_value={"data": {"http": "127.0.0.1:9202"}})

        def run_creator() -> None:
            try:
                creator.open_profile()
            except Exception as exc:  # pragma: no cover - 由主线程断言
                errors.append(exc)

        def run_fixed() -> None:
            try:
                fixed.open_profile("existing-profile")
                fixed_open_finished.set()
            except Exception as exc:  # pragma: no cover - 由主线程断言
                errors.append(exc)

        with _open_config(one_profile_per_account=False):
            creator_thread = threading.Thread(target=run_creator, daemon=True)
            creator_thread.start()
            self.assertTrue(creator_open_started.wait(1))

            fixed_thread = threading.Thread(target=run_fixed, daemon=True)
            fixed_thread.start()
            self.assertTrue(
                fixed_open_finished.wait(1),
                "fixed Profile incorrectly waited for the provisioning lock",
            )
            self.assertTrue(creator_thread.is_alive())

            release_creator_open.set()
            creator_thread.join(2)
            fixed_thread.join(2)

        self.assertFalse(creator_thread.is_alive())
        self.assertFalse(fixed_thread.is_alive())
        self.assertEqual(errors, [])
        creator.create_profile.assert_called_once_with()
        fixed.request.assert_called_once()

    def test_same_fixed_profile_operations_are_serialized(self):
        first = self._client()
        second = self._client()
        first_started = threading.Event()
        second_started = threading.Event()
        release_first = threading.Event()
        errors = []

        def first_request(*_args, **_kwargs):
            first_started.set()
            if not release_first.wait(2):
                raise AssertionError("test did not release first open")
            return {"data": {"http": "127.0.0.1:9251"}}

        def second_request(*_args, **_kwargs):
            second_started.set()
            return {"data": {"http": "127.0.0.1:9252"}}

        first.request = Mock(side_effect=first_request)
        second.request = Mock(side_effect=second_request)

        def run(client):
            try:
                client.open_profile("shared-profile")
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with _open_config(one_profile_per_account=False):
            first_thread = threading.Thread(target=run, args=(first,), daemon=True)
            second_thread = threading.Thread(target=run, args=(second,), daemon=True)
            first_thread.start()
            self.assertTrue(first_started.wait(1))
            second_thread.start()
            self.assertFalse(second_started.wait(0.2))
            release_first.set()
            first_thread.join(2)
            second_thread.join(2)

        self.assertEqual(errors, [])
        self.assertTrue(second_started.is_set())
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())

    def test_open_failure_closes_and_deletes_created_profile_without_masking_error(self):
        client = self._client()
        original_error = ValueError("open failed before debugger address")
        client.create_profile = Mock(return_value="301")
        client._open_profile_by_id = Mock(side_effect=original_error)
        client.close_profile = Mock(side_effect=RuntimeError("close cleanup failed"))
        client.delete_profile = Mock(side_effect=RuntimeError("delete cleanup failed"))

        with _open_config():
            with self.assertRaises(ValueError) as raised:
                client.open_profile()

        self.assertIs(raised.exception, original_error)
        client.close_profile.assert_called_once_with("301")
        client.delete_profile.assert_called_once_with("301")

    def test_missing_debugger_address_closes_and_deletes_created_profile(self):
        client = self._client()
        client.create_profile = Mock(return_value="302")
        client.request = Mock(return_value={"data": {"dirId": "302"}})
        client.close_profile = Mock()
        client.delete_profile = Mock()

        with _open_config():
            with self.assertRaisesRegex(RuntimeError, "未返回 Selenium/调试地址"):
                client.open_profile()

        client.close_profile.assert_called_once_with("302")
        client.delete_profile.assert_called_once_with("302")

    def test_keyboard_interrupt_during_open_still_cleans_created_profile(self):
        client = self._client()
        client.create_profile = Mock(return_value="303")
        client._open_profile_by_id = Mock(side_effect=KeyboardInterrupt())
        client.close_profile = Mock()
        client.delete_profile = Mock()

        with _open_config():
            with self.assertRaises(KeyboardInterrupt):
                client.open_profile()

        client.close_profile.assert_called_once_with("303")
        client.delete_profile.assert_called_once_with("303")

    def test_provisioning_lock_is_released_after_create_exception(self):
        failing = self._client()
        following = self._client()
        original_error = RuntimeError("first create failed")
        failing.create_profile = Mock(side_effect=original_error)
        following.create_profile = Mock(return_value="402")
        following.request = Mock(return_value={"data": {"http": "127.0.0.1:9402"}})
        completed = threading.Event()
        errors = []

        with _open_config():
            with self.assertRaises(RuntimeError) as raised:
                failing.open_profile()
            self.assertIs(raised.exception, original_error)

            def run_following() -> None:
                try:
                    following.open_profile()
                    completed.set()
                except Exception as exc:  # pragma: no cover - 由主线程断言
                    errors.append(exc)

            thread = threading.Thread(target=run_following, daemon=True)
            thread.start()
            self.assertTrue(completed.wait(1), "provisioning lock remained held after failure")
            thread.join(1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        following.create_profile.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
