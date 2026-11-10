"""Copy the production implementation verbatim. Run only from the source repository."""
from pathlib import Path
import ast
import hashlib
import json
import shutil
import sys

PROJECT = Path(__file__).resolve().parent.parent
SOURCE = PROJECT.parent.parent
TARGET = PROJECT / "upstream"

FILES = [
    "roxy_registration", "roxy_headed_registration", "roxy_manual_window", "manual_window_browser",
    "manual_window_proxy", "roxybrowser_client", "roxy_profile_pool", "roxy_profile_utils",
    "roxy_login_primitives", "roxy_browser_kernel", "roxy_auth_runtime", "auth_factors",
    "session_candidate", "chatgpt_session_store", "headed_auth_watch", "humanize", "login_evidence",
    "password_login_choice", "registration_password_state", "plan_check_route", "operation_country",
    "email_change_identity_retry", "email_change_session_evidence", "registration_terminal_response",
    "registration_profile_diagnostic", "registration_date_segments", "otp_stop", "otp_retry_policy",
    "browser_otp_ready", "totp_confirmation", "failure_dom_artifact", "registration_password_guard",
    "plan_promo", "account_grace_period",
]
DIRECTORIES = ["roxy_domains", "roxy_auth_domains", "session_refresh_domains",
               "roxybrowser_domains", "headed_chrome_reference"]
TESTS = {
    **{f"tests/{name}": f"tests/production/{name}" for name in (
        "test_roxy_login_primitives.py", "test_roxy_login_page_detection.py",
        "test_roxy_profile_cache.py", "test_roxy_profile_provisioning.py", "test_session_candidate.py", "test_saved_password_choice.py", "test_headed_chrome_route_retry.py")},
    "tests/test_chatgpt_session_refresh.py": "tests/fixtures/source_session_refresh.py",
    "tests/test_chatgpt_session_refresh_roxy.py": "tests/fixtures/source_roxy_candidates.py",
    "tests/helpers/session_fixtures.py": "tests/helpers/session_fixtures.py",
}


def main():
    if not (SOURCE / "core/roxy_registration.py").is_file():
        raise SystemExit("Snapshot generation requires the source checkout; the standalone app does not.")
    paths = [SOURCE / "core" / (name + ".py") for name in FILES]
    paths.append(SOURCE / "core/failure_dom_capture.js")
    for name in DIRECTORIES:
        paths.extend(path for path in (SOURCE / "core" / name).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py", ".json", ".sha256", ".md"})
    manifest = {"format": 1, "files": [], "adapters": [
        "Configuration binding", "JSON account/session backend", "Disabled out-of-scope services",
        "Task lifecycle and webpage state projection", "Facade binding of unchanged production definitions"]}
    for path in sorted(set(paths)):
        if not path.exists():
            continue
        relative = path.relative_to(SOURCE)
        output = TARGET / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = path.read_bytes()
        output.write_bytes(payload)
        manifest["files"].append({"source": relative.as_posix(), "copy": "upstream/" + relative.as_posix(),
                                  "sha256": hashlib.sha256(payload).hexdigest()})
    # The original source facades are also the source of exact function/constant slices.
    for name in ("chatgpt_session_refresh", "chatgpt_plan", "openai_auth", "proxy_sid"):
        path = SOURCE / "core" / (name + ".py")
        output = TARGET / "source_facades" / path.name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(path.read_bytes())
        manifest["files"].append({"source": "core/" + path.name, "copy": output.relative_to(PROJECT).as_posix(),
                                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    for source, target in TESTS.items():
        payload = (SOURCE / source).read_bytes()
        output = PROJECT / target
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
        manifest["files"].append({"source": source, "copy": target, "sha256": hashlib.sha256(payload).hexdigest()})
    manifest["functions"] = []
    for entry in manifest["files"]:
        if not entry["copy"].endswith(".py"):
            continue
        source = (PROJECT / entry["copy"]).read_text(encoding="utf-8-sig")
        tree = ast.parse(source)
        wrapper = next((node for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(item, ast.Name) and item.id == "_SOURCE" for item in node.targets)), None)
        if wrapper:
            source = ast.literal_eval(wrapper.value.args[0])
            tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                segment = ast.get_source_segment(source, node)
                manifest["functions"].append({"source": entry["source"], "symbol": node.name,
                    "line": node.lineno, "sha256": hashlib.sha256(segment.encode()).hexdigest()})
    configuration = {}
    for name in ("roxybrowser", "humanize", "twofa", "browser"):
        values = {}
        for node in ast.parse((SOURCE / "config" / (name + ".py")).read_text(encoding="utf-8-sig")).body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            key = next((item.id for item in targets if isinstance(item, ast.Name)), "")
            if not key.isupper() or key.startswith("_"):
                continue
            if name == "browser" and key not in {"COUNTRY_LOCALE_PROFILE_MAP", "BROWSER_LOCALE_PROFILES"}:
                continue
            try:
                value = ast.literal_eval(node.value)
                json.dumps(value)
            except (ValueError, TypeError):
                if name != "browser":
                    continue
                value = eval(compile(ast.Expression(node.value), "<locale defaults>", "eval"), {"__builtins__": {}})
            values[key] = value
        if name == "roxybrowser":
            values.update(ROXY_API_BASE="http://127.0.0.1:50000", ROXY_API_TOKEN="", ROXY_WORKSPACE_ID="", ROXY_PROJECT_ID="")
        configuration[name] = values
    (TARGET / "config_defaults.json").write_text(json.dumps(configuration, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (PROJECT / "UPSTREAM_MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Verbatim upstream files:", len(manifest["files"]))


if __name__ == "__main__":
    main()
