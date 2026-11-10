"""Feed identical offline browser events to the source checkout or shipped copy."""
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import Mock, patch

parser = argparse.ArgumentParser()
parser.add_argument("--source-root")
options = parser.parse_args()
root = Path(options.source_root).resolve() if options.source_root else Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

with ExitStack() as stack:
    if not options.source_root:
        from roxy_demo.storage import Store
        from roxy_demo.kernel_bridge import bootstrap, bound
        folder = stack.enter_context(tempfile.TemporaryDirectory())
        store = Store(Path(folder) / "data")
        bootstrap(store)
        stack.enter_context(bound(store))
    from core import roxy_registration as login
    from core import chatgpt_session_refresh as refresh
    from core.roxy_login_primitives import submit_login_password, fill_totp_inputs, wait_for_totp_window
    from tests.helpers.session_fixtures import _account, _record, _session_info

    report = {}
    class Browser:
        current_url = "https://auth.openai.com/log-in/password"
        def __init__(self, events):
            self.events, self.actions = list(events), []
        def execute_script(self, script, *args):
            self.actions.append(["script", hashlib.sha256(script.encode()).hexdigest(), list(args)])
            return self.events.pop(0) if self.events else {}

    for name, events in {
        "password_hydration": [{"ok": False, "reason": "missing_password_input"}, {"ok": True, "input": "password", "button": "continue"}],
        "password_control_timeout": [{"ok": False, "reason": "missing_password_input"}],
    }.items():
        browser = Browser(events)
        with patch("core.roxy_login_primitives._time.sleep"):
            result = submit_login_password(browser, "fixture-password",
                human_type=lambda driver, element, value, **kwargs: browser.actions.append(["type", element, "<password>", kwargs]),
                human_click=lambda driver, element, **kwargs: browser.actions.append(["click", element, kwargs]),
                label="fixture", control_wait_timeout=0 if "timeout" in name else 1)
        report[name] = {"actions": browser.actions, "result": result}

    browser = Browser(["another-account"])
    browser.current_url = "https://auth.openai.com/"
    with patch.object(login, "_human_click", side_effect=lambda driver, element, **kwargs: browser.actions.append(["click", element, kwargs])):
        result = login._click_other_account_chooser_if_present(browser)
    report["account_chooser"] = {"actions": browser.actions, "result": result}

    for count in (1, 6):
        browser = Mock()
        inputs = [f"input-{n}" for n in range(count)]
        browser.find_elements.return_value = inputs
        actions = []
        result = fill_totp_inputs(browser, "123456", visible=lambda item: True,
            human_type=lambda driver, element, value, **kwargs: actions.append(["type", element, value, kwargs]))
        report[f"totp_{count}"] = {"actions": actions, "result": result}

    stop = threading.Event()
    stop.set()
    try:
        wait_for_totp_window(stop)
    except Exception as exc:
        report["cancel"] = {"exception": type(exc).__name__, "code": getattr(exc, "error_code", str(exc))}

    record = _record()
    record["cookies"] = [{"name": "__Secure-next-auth.session-token." + str(n),
        "value": "fixture-part-" + str(n), "domain": ".chatgpt.com", "path": "/", "secure": True, "httpOnly": True} for n in range(2)]
    browser = Mock()
    browser.execute_cdp_cmd.side_effect = lambda method, params: {"cookies": record["cookies"]} if method == "Network.getAllCookies" else {}
    refresh._restore_saved_session_to_driver(browser, record)
    report["cookie_chunks"] = {"actions": [[call.args[0], call.args[1]] for call in browser.execute_cdp_cmd.call_args_list]}

    for name, url in {"apple": "https://appleid.apple.com/auth/authorize", "openai": "https://auth.openai.com/log-in"}.items():
        browser = Mock(current_url=url)
        try:
            login._assert_not_external_idp(browser, label="fixture")
            report[name] = {"result": "accepted"}
        except Exception as exc:
            report[name] = {"exception": type(exc).__name__, "message": str(exc)}

    account, info = _account(), _session_info()
    info["user"]["email"] = "wrong@example.test"
    try:
        refresh.validate_session_identity(account, info, info["accessToken"])
    except Exception as exc:
        report["identity_mismatch"] = {"exception": type(exc).__name__, "code": getattr(exc, "error_code", str(exc))}
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
