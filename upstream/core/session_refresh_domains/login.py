"""Compatibility registration facade for the shared Roxy auth login domain.

The implementation lives in :mod:`core.roxy_auth_domains.login`; this module
keeps the historical Session-refresh import and registration seam.
"""
from __future__ import annotations

from core.roxy_auth_domains import login as _implementation


def register(namespace: dict[str, object]) -> None:
    _implementation.register(namespace)


__all__ = ["register"]
