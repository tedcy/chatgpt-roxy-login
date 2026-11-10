"""Execute the installed auth loop against timeout/Try again page events."""
import ast
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from core.headed_chrome_reference.integrity import vendored_source_path, verify_vendored_source


def installed_method(name, clock):
    path = vendored_source_path()
    source = path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source)
    worker = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "OpenAIRegistrationWorker")
    method = next(node for node in worker.body if isinstance(node, ast.FunctionDef) and node.name == name)
    namespace = {"time": SimpleNamespace(time=lambda: clock.now), "MfaRequiredError": RuntimeError}
    exec(compile(ast.get_source_segment(source, method), str(path), "exec"), namespace)
    return namespace[name]


class RoutePages:
    def __init__(self, stages):
        self.stages = stages
        self.index = 0
        self.password_calls = self.totp_calls = self.retry_calls = 0
        self.mfa_totp_secret = "fixture-secret"
        self.account = SimpleNamespace(email="fixture@example.test")
        self.logs = []
        self.clock = SimpleNamespace(now=0)
        self.page = SimpleNamespace(url="https://auth.openai.com/log-in/password")
        self.log = self.logs.append

    @property
    def stage(self):
        return self.stages[self.index]

    def advance(self):
        if self.index < len(self.stages)-1:
            self.index += 1

    def _raise_if_stopped(self): pass
    def _install_auth_flow_observer(self, context): pass
    def _set_auth_traffic_stage(self, stage): pass
    def _reset_email_stall(self): pass
    def _create_openai_signin_url(self, context, page): return page.url
    def _recover_auth_page_if_closed(self, page, context, action): return page
    def _raise_if_page_closed(self, page, action): pass
    def _is_security_verification_page(self, page): return False
    def _is_oauth_callback_error(self, page): return False
    def _is_user_already_exists_error(self, page): return False
    def _is_email_mfa_page(self, page): return False
    def _select_password_auth_mode_if_visible(self, page): return False
    def _has_about_you_form(self, page): return False
    def _fill_email_if_visible(self, page): return False
    def _has_otp_input(self, page): return False
    def _has_chatgpt_session(self, page): return self.stage == "done"
    def _is_authenticator_mfa_page(self, page): return self.stage == "totp"
    def _has_visible_password(self, page): return self.stage == "password"
    def _detect_route_error(self, page): return "Operation timed out" if self.stage == "timeout" else ""
    def _retry_route_error(self, page):
        self.retry_calls += 1
        self.advance()
        return True
    def _fill_password_step(self, page):
        self.password_calls += 1
        self.advance()
    def _submit_authenticator_mfa_code(self, page):
        self.totp_calls += 1
        self.advance()
    def _wait_or_stop(self, delay): self.clock.now += delay
    def run(self): return installed_method("_register", self.clock)(self, self.page, object())


class RouteRetryTests(unittest.TestCase):
    def test_retry_returns_to_empty_password_form_and_submits_again(self):
        worker = RoutePages(["password", "timeout", "password", "totp", "done"])
        worker.run()
        self.assertEqual((worker.password_calls, worker.totp_calls, worker.retry_calls), (2, 1, 1))
        self.assertEqual(worker.stage, "done")

    def test_retry_returns_to_totp_form_and_submits_a_new_code(self):
        worker = RoutePages(["totp", "timeout", "totp", "done"])
        worker.run()
        self.assertEqual((worker.password_calls, worker.totp_calls, worker.retry_calls), (0, 2, 1))

    def test_repeated_timeout_still_stops_after_three_retries(self):
        worker = RoutePages(["timeout"])
        with self.assertRaisesRegex(RuntimeError, "Operation timed out"):
            worker.run()
        self.assertEqual(worker.retry_calls, 3)

    def test_normal_login_still_submits_password_and_totp_only_once(self):
        worker = RoutePages(["password", "totp", "done"])
        worker.run()
        self.assertEqual((worker.password_calls, worker.totp_calls, worker.retry_calls), (1, 1, 0))

    def test_existing_try_again_selector_clicks_visible_button(self):
        clock = SimpleNamespace(now=0)
        page = Mock()
        target = page.locator.return_value.first
        target.is_visible.return_value = True
        self.assertTrue(installed_method("_retry_route_error", clock)(object(), page))
        page.locator.assert_called_once_with('button:has-text("Try again")')
        target.click.assert_called_once_with(timeout=5000)
        page.wait_for_load_state.assert_called_once_with("domcontentloaded", timeout=15000)
        self.assertTrue(verify_vendored_source())
