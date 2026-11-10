"""Pure helpers for reading identifiers from Roxy profile rows."""

from __future__ import annotations


def project_id_from_row(row: dict) -> str:
    for key in ("projectId", "project_id"):
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    for key in ("project", "projectInfo", "project_info"):
        nested = row.get(key)
        if not isinstance(nested, dict):
            continue
        for nested_key in ("projectId", "project_id", "id"):
            value = nested.get(nested_key)
            if value is not None and str(value).strip():
                return str(value).strip()
    return ""


__all__ = ["project_id_from_row"]
