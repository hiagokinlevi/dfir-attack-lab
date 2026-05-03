from __future__ import annotations

from typing import Iterable, List, Optional


_SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(severity: str) -> int:
    """Return a comparable numeric rank for known severity labels."""
    if not severity:
        return 0
    return _SEVERITY_ORDER.get(str(severity).strip().lower(), 0)


def filter_events(
    events: Iterable[dict],
    min_severity: Optional[str] = None,
) -> List[dict]:
    """Filter events by severity threshold.

    When min_severity is provided, only events whose severity rank is >= threshold
    are returned. Unknown/empty severities are treated as rank 0 and excluded.
    """
    events_list = list(events)
    if not min_severity:
        return events_list

    threshold = severity_rank(min_severity)
    if threshold <= 0:
        return events_list

    return [
        event
        for event in events_list
        if severity_rank(event.get("severity", "")) >= threshold
    ]
