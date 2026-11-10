"""Build a source-only distribution, excluding all local state and credentials."""
from pathlib import Path
import json
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {".py", ".json", ".md", ".txt", ".html", ".js", ".css", ".bat", ".sha256"}


def build(target):
    secrets = set()
    for name in ("accounts.json", "settings.json", "accounts.pre-upstream.json"):
        path = ROOT / "data" / name
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data.get("accounts", []) if name.startswith("accounts") else [data]
        for row in rows:
            secrets.update(str(row[key]).encode() for key in ("email", "password", "totp_secret", "proxy", "ROXY_API_TOKEN", "ROXY_WORKSPACE_ID", "ROXY_PROJECT_ID") if row.get(key))
            token = ((row.get("session") or {}).get("info") or {}).get("accessToken")
            if token:
                secrets.add(token.encode())
    payloads = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part.startswith(".") or part in {"data", "__pycache__", "node_modules"} for part in relative.parts):
            continue
        if not path.is_file() or path.suffix not in ALLOWED:
            continue
        payload = path.read_bytes()
        if any(secret in payload for secret in secrets):
            raise RuntimeError("Distribution contains local secret: " + relative.as_posix())
        payloads.append((relative.as_posix(), payload))
    temporary = target.with_suffix(".tmp")
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, payload in payloads:
                archive.writestr("roxy-login-demo/" + name, payload)
            archive.writestr("roxy-login-demo/data/.gitkeep", b"")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return len(payloads)


if __name__ == "__main__":
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT.parent / "roxy-login-demo-clean.zip"
    print("Clean distribution files:", build(target))
