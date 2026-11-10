import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from core.roxy_login_primitives import (
    LoginPrimitiveError,
    TotpSecretError,
    fill_totp_inputs,
    normalise_totp_secret,
    submit_login_password,
    wait_for_totp_window,
)


class _FakeDriver:
    def __init__(self, result=None, elements=None):
        self.result = result or {}
        self.elements = list(elements or [])
        self.calls = []

    def execute_script(self, script, *args):
        self.calls.append((script, args))
        return self.result

    def find_elements(self, *_args):
        return list(self.elements)


class _SequencedProbeDriver(_FakeDriver):
    def __init__(self, results):
        super().__init__()
        self.results = list(results)

    def execute_script(self, script, *args):
        self.calls.append((script, args))
        if self.results:
            return self.results.pop(0)
        return {"ok": False, "reason": "missing_password_input"}


class _Clock:
    def __init__(self, now):
        self.now = now
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)


class RoxyLoginPrimitiveTests(unittest.TestCase):
    def test_password_submission_uses_shared_control_selector(self):
        driver = _FakeDriver(
            {"ok": True, "input": "input", "button": "button"}
        )
        typed = []
        clicked = []
        delay = Mock()
        self.assertTrue(
            submit_login_password(
                driver,
                "private-password",
                human_type=lambda *args, **kwargs: typed.append((args, kwargs)),
                human_click=lambda *args, **kwargs: clicked.append((args, kwargs)),
                label="test_password",
                strategy="registration",
                delay=delay,
            )
        )
        self.assertEqual(typed[0][0][-1], "private-password")
        self.assertEqual(clicked[0][1]["label"], "test_password")
        delay.assert_called_once()
        self.assertEqual(driver.calls[0][1], ("registration",))

    def test_password_submission_waits_for_controls_to_hydrate(self):
        driver = _SequencedProbeDriver([
            {"ok": False, "reason": "missing_password_input"},
            {"ok": True, "input": "input", "button": "button"},
        ])
        typed = []
        clicked = []
        with unittest.mock.patch(
            "core.roxy_login_primitives._time.sleep",
            return_value=None,
        ):
            self.assertTrue(
                submit_login_password(
                    driver,
                    "private-password",
                    human_type=lambda *args, **kwargs: typed.append((args, kwargs)),
                    human_click=lambda *args, **kwargs: clicked.append((args, kwargs)),
                    label="test_password",
                    control_wait_timeout=0.5,
                    control_poll_interval=0.01,
                )
            )
        self.assertEqual(len(driver.calls), 2)
        self.assertEqual(len(typed), 1)
        self.assertEqual(len(clicked), 1)

    def test_password_submission_stops_after_bounded_probe_timeout(self):
        driver = _SequencedProbeDriver([])
        typed = Mock()
        clicked = Mock()
        with unittest.mock.patch(
            "core.roxy_login_primitives._time.sleep",
            return_value=None,
        ):
            self.assertFalse(
                submit_login_password(
                    driver,
                    "private-password",
                    human_type=typed,
                    human_click=clicked,
                    label="test_password",
                    control_wait_timeout=0.02,
                    control_poll_interval=0.01,
                )
            )
        self.assertGreaterEqual(len(driver.calls), 1)
        typed.assert_not_called()
        clicked.assert_not_called()

    def test_password_submission_does_not_repeat_after_action_failure(self):
        driver = _SequencedProbeDriver([
            {"ok": True, "input": "input", "button": "button"},
        ])
        typed = Mock(side_effect=RuntimeError("driver action failed"))
        clicked = Mock()
        with unittest.mock.patch(
            "core.roxy_login_primitives._time.sleep",
            return_value=None,
        ):
            self.assertFalse(
                submit_login_password(
                    driver,
                    "private-password",
                    human_type=typed,
                    human_click=clicked,
                    label="test_password",
                    control_wait_timeout=0.5,
                    control_poll_interval=0.01,
                )
            )
        typed.assert_called_once()
        clicked.assert_not_called()
        self.assertEqual(len(driver.calls), 1)

    def test_totp_secret_validation_has_fixed_codes(self):
        self.assertEqual(normalise_totp_secret(" jbsw y3dp ehpk 3pxp "), "JBSWY3DPEHPK3PXP")
        for value, code in (("", "session_login_totp_secret_missing"), ("bad!", "session_login_totp_secret_invalid")):
            with self.subTest(value=value):
                with self.assertRaises(TotpSecretError) as raised:
                    normalise_totp_secret(value)
                self.assertEqual(raised.exception.error_code, code)

    def test_totp_window_wait_is_cancelable(self):
        clock = _Clock(28.5)
        stop = threading.Event()
        stop.set()
        with self.assertRaises(LoginPrimitiveError) as raised:
            wait_for_totp_window(stop, clock=clock)
        self.assertEqual(raised.exception.error_code, "session_window_close_requested")

    def test_totp_inputs_support_single_and_six_field_forms(self):
        for count, expected in ((1, ["123456"]), (6, list("123456"))):
            with self.subTest(count=count):
                elements = [SimpleNamespace(index=index) for index in range(count)]
                driver = _FakeDriver(elements=elements)
                typed = []
                result = fill_totp_inputs(
                    driver,
                    "123456",
                    visible=lambda _element: True,
                    human_type=lambda _driver, _element, value, **_kwargs: typed.append(value),
                )
                self.assertEqual(result, elements)
                self.assertEqual(typed, expected)

    def test_totp_inputs_without_controls_use_fixed_error(self):
        with self.assertRaises(LoginPrimitiveError) as raised:
            fill_totp_inputs(
                _FakeDriver(),
                "123456",
                visible=lambda _element: True,
                human_type=Mock(),
            )
        self.assertEqual(raised.exception.error_code, "session_login_totp_failed")


if __name__ == "__main__":
    unittest.main()
