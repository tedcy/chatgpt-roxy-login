"""Compatibility registration facade for the shared Roxy auth runtime.

The implementation lives in :mod:`core.roxy_auth_domains.candidate`; this
module remains importable because the Session refresh facade historically
loaded candidate helpers from here.
"""
from __future__ import annotations

from core.roxy_auth_domains import candidate as _implementation


def register(namespace: dict[str, object]) -> None:
    _implementation.register(namespace)


__all__ = ["register"]
