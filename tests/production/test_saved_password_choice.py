"""Regression for an OTP-first page whose password alternative renders later."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from core.headed_chrome_reference.signup_mode import select_mode


class SavedPasswordChoiceTests(unittest.TestCase):
    def worker(self, choices):
        clock = SimpleNamespace(now=0)
        state = {"host": "auth.openai.com", "path": "/email-verification", "epoch": 1, "stage": "email_otp"}
        worker = SimpleNamespace(openai_password="fixture-password", _auth_screen_hint="login_or_signup",
            _auth_page_snapshot=Mock(return_value=state),
            _select_password_auth_mode_once=Mock(side_effect=choices),
            _raise_if_stopped=Mock(), _wait_or_stop=Mock(side_effect=lambda delay: setattr(clock, "now", clock.now+delay)))
        return worker, clock

    def select(self, worker, clock):
        return select_mode(worker, object(), RuntimeError, timeout=60, clock=lambda: clock.now)

    def test_password_button_can_render_after_otp_input(self):
        worker, clock = self.worker([False, False, True])
        self.assertTrue(self.select(worker, clock))
        self.assertEqual(worker._select_password_auth_mode_once.call_count, 3)
        self.assertEqual(clock.now, .5)

    def test_visible_password_alternative_is_clicked_once(self):
        worker, clock = self.worker([True])
        self.assertTrue(self.select(worker, clock))
        worker._select_password_auth_mode_once.assert_called_once()
        worker._wait_or_stop.assert_not_called()

    def test_real_email_challenge_remains_a_bounded_miss(self):
        worker, clock = self.worker(None)
        worker._select_password_auth_mode_once.side_effect = None
        worker._select_password_auth_mode_once.return_value = False
        self.assertFalse(self.select(worker, clock))
        self.assertEqual(clock.now, 3)

    def test_document_change_returns_to_the_auth_loop(self):
        worker, clock = self.worker([False])
        first = worker._auth_page_snapshot.return_value
        worker._auth_page_snapshot.side_effect = [first, {**first, "path": "/log-in/password", "stage": "password", "epoch": 2}]
        self.assertTrue(self.select(worker, clock))
        worker._select_password_auth_mode_once.assert_called_once()

    def test_stop_request_is_not_swallowed(self):
        worker, clock = self.worker([False])
        worker._raise_if_stopped.side_effect = RuntimeError("cancelled")
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self.select(worker, clock)
        worker._select_password_auth_mode_once.assert_not_called()

    def test_account_without_password_keeps_the_original_single_probe(self):
        worker, clock = self.worker([False])
        worker.openai_password = ""
        self.assertFalse(self.select(worker, clock))
        worker._select_password_auth_mode_once.assert_called_once_with(unittest.mock.ANY)
        worker._wait_or_stop.assert_not_called()
