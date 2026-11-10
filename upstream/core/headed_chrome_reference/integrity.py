"""Integrity metadata for the pinned headed-Chrome registration source."""

from __future__ import annotations

import hashlib
from pathlib import Path


REFERENCE_COMMIT = "31e59ee45a63cda259d10fefd297995e6aa84f3b"
REFERENCE_BLOB = "23a3622ef73d0bcb16788e90fd8cafb5875b6cd6"
REFERENCE_RAW_SHA256 = "a0ee9bb2a4216eb11b8ce4ef9066f1e361f32434d5d9db220d7e1174a2f6bfac"
REFERENCE_CANONICAL_SHA256 = (
    "ad2d23455adb3524e95b59e9e5209650ed4da2af91ff26665379640dfe85296b"
)
LOCAL_PATCHES = ("reset-auth-submission-state-after-route-retry",)
VENDORED_CANONICAL_SHA256 = "2db8728049daa821e46551fa6c510b7d1f1ccaabb05cd133977abdc94873cf23"


def vendored_source_path() -> Path:
    return Path(__file__).resolve().parent / "vendor" / "app.py"


def canonical_source_bytes(value: bytes) -> bytes:
    """Normalize checkout line endings and insignificant terminal blank lines."""

    normalized = value.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return normalized.rstrip(b"\n") + b"\n"


def verify_vendored_source() -> bool:
    source = vendored_source_path().read_bytes()
    digest = hashlib.sha256(canonical_source_bytes(source)).hexdigest()
    return digest == VENDORED_CANONICAL_SHA256


__all__ = [
    "REFERENCE_BLOB",
    "REFERENCE_CANONICAL_SHA256",
    "REFERENCE_COMMIT",
    "REFERENCE_RAW_SHA256",
    "LOCAL_PATCHES",
    "VENDORED_CANONICAL_SHA256",
    "canonical_source_bytes",
    "vendored_source_path",
    "verify_vendored_source",
]
