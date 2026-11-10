"""Pinned local-Chrome registration reference.

The runtime adapter is deliberately added separately so importing this package
does not import the browser runtime or the large vendored module.
"""

from .integrity import (
    REFERENCE_BLOB,
    REFERENCE_COMMIT,
    REFERENCE_RAW_SHA256,
    verify_vendored_source,
)

__all__ = [
    "REFERENCE_BLOB",
    "REFERENCE_COMMIT",
    "REFERENCE_RAW_SHA256",
    "verify_vendored_source",
]
