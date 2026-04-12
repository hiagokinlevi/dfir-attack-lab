"""Case identifier validation helpers for file-writing workflows."""
from __future__ import annotations


def validate_case_id(case_id: str) -> str:
    """Reject empty or path-like case identifiers before writing files."""
    normalized = case_id.strip()
    if not normalized:
        raise ValueError("case_id must not be empty")
    if normalized in {".", ".."} or "/" in normalized or "\\" in normalized:
        raise ValueError("case_id must be a single non-relative path segment")
    return normalized
