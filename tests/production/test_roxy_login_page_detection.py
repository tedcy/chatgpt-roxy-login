# -*- coding: utf-8 -*-
import unittest
from unittest.mock import Mock, patch

from core import roxy_registration


class _StateDriver:
    def __init__(self, url, state=None, element=None):
        self.current_url = url
        self.state = state or {"url": url, "inputs": []}
        self.element = element
        self.script_calls = 0

    def execute_script(self, script, *_args):
        self.script_calls += 1
        if "const candidates" in script and "other_account_chooser" not in script:
            return self.element
        return self.state


class RoxyLoginPageDetectionTests(unittest.TestCase):
    def test_other_account_chooser_clicks_only_on_openai_host(self):
        element = object()
        driver = _StateDriver("https://chatgpt.com/", element=element)
        with patch.object(roxy_registration, "_human_click") as click:
            self.assertTrue(
                roxy_registration._click_other_account_chooser_if_present(driver)
            )
        click.assert_called_once_with(
            driver,
            element,
            label="other_account_chooser",
        )

        foreign = _StateDriver("https://example.test/", element=element)
        with patch.object(roxy_registration, "_human_click") as foreign_click:
            self.assertFalse(
                roxy_registration._click_other_account_chooser_if_present(foreign)
            )
        foreign_click.assert_not_called()
        self.assertEqual(foreign.script_calls, 0)

    def test_email_entry_leaves_account_chooser_before_typing(self):
        driver = Mock()
        email_input = object()
        with patch.object(
            roxy_registration,
            "_find_visible_email_input_js",
            side_effect=[None, email_input],
        ), patch.object(
            roxy_registration, "_email_input_present_js", return_value=False,
        ), patch.object(
            roxy_registration,
            "_click_other_account_chooser_if_present",
            return_value=True,
        ) as chooser, patch.object(
            roxy_registration,
            "_human_type_text",
        ) as type_text, patch.object(
            roxy_registration,
            "_assert_not_external_idp",
        ) as assert_host, patch.object(
            roxy_registration.time,
            "sleep",
        ):
            roxy_registration._type_email_address(
                driver,
                "user@example.test",
                timeout=3,
            )

        chooser.assert_called_once_with(driver)
        assert_host.assert_called_once_with(driver, "选择其他账号后")
        type_text.assert_called_once_with(
            driver,
            email_input,
            "user@example.test",
            clear=True,
        )

    def test_new_log_in_route_detects_visible_current_password(self):
        driver = _StateDriver(
            "https://auth.openai.com/log-in",
            state={
                "url": "https://auth.openai.com/log-in",
                "inputs": [{
                    "visible": True,
                    "type": "password",
                    "name": "password",
                    "id": "password",
                    "autocomplete": "current-password",
                }],
            },
        )
        self.assertTrue(roxy_registration._is_login_password_page(driver))

    def test_signup_or_new_password_field_is_not_login_password(self):
        for url in (
            "https://auth.openai.com/create-account/password",
            "https://auth.openai.com/log-in",
        ):
            with self.subTest(url=url):
                driver = _StateDriver(
                    url,
                    state={
                        "url": url,
                        "inputs": [{
                            "visible": True,
                            "type": "password",
                            "name": "password",
                            "id": "password",
                            "autocomplete": "new-password",
                        }],
                    },
                )
                self.assertFalse(
                    roxy_registration._is_login_password_page(driver)
                )

    def test_password_field_on_unrelated_page_is_not_login_password(self):
        driver = _StateDriver(
            "https://chatgpt.com/settings/security",
            state={
                "url": "https://chatgpt.com/settings/security",
                "inputs": [{
                    "visible": True,
                    "type": "password",
                    "name": "password",
                    "id": "password",
                    "autocomplete": "current-password",
                }],
            },
        )
        self.assertFalse(roxy_registration._is_login_password_page(driver))


if __name__ == "__main__":
    unittest.main()
