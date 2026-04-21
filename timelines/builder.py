from __future__ import annotations

from datetime import timedelta
from typing import Iterable

from normalizers.models import TriageEvent


def build_timeline(events: Iterable[TriageEvent], gap_threshold_minutes: int = 30) -> list[TriageEvent]:
    """Sort events chronologically and insert synthetic logging-gap events.

    Args:
        events: Iterable of normalized triage events.
        gap_threshold_minutes: Minutes between adjacent events required to flag a gap.

    Returns:
        A sorted timeline including synthetic gap events where applicable.
    """
    sorted_events = sorted(events, key=lambda e: e.ts)
    if not sorted_events:
        return []

    gap_threshold = timedelta(minutes=gap_threshold_minutes)
    output: list[TriageEvent] = [sorted_events[0]]

    for current in sorted_events[1:]:
        previous = output[-1]
        delta = current.ts - previous.ts

        if delta > gap_threshold:
            gap_event = TriageEvent(
                ts=previous.ts + gap_threshold,
                source="timeline",
                category="logging_gap",
                severity="medium",
                message=(
                    f"Potential logging gap detected: {int(delta.total_seconds() // 60)} "
                    "minutes without events"
                ),
                raw={
                    "gap_start": previous.ts.isoformat(),
                    "gap_end": current.ts.isoformat(),
                    "gap_minutes": int(delta.total_seconds() // 60),
                    "threshold_minutes": gap_threshold_minutes,
                },
            )
            output.append(gap_event)

        output.append(current)

    return output
