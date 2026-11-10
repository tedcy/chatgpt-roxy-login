"""Verify shipped source bytes and optionally compare them with a source checkout."""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parent.parent


def verify(source_root=None):
    manifest = json.loads((ROOT / "UPSTREAM_MANIFEST.json").read_text(encoding="utf-8"))
    failures = []
    for entry in manifest["files"]:
        path = ROOT / entry["copy"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            failures.append(entry["copy"])
        if source_root is not None:
            source = Path(source_root) / entry["source"]
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != entry["sha256"]:
                failures.append("source:" + entry["source"])
    if failures:
        raise RuntimeError("Source mismatch: " + ", ".join(failures))
    return len(manifest["files"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root")
    options = parser.parse_args()
    print("Verified unchanged source files:", verify(options.source_root))
