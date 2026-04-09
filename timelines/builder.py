"""
Incident timeline builder.

Merges TriageEvents from multiple sources into a chronological timeline.
Detects temporal gaps that may indicate log tampering or missing evidence.
"""
from __future__ import annotations
from datetime import timedelta
from normalizers.models import TriageEvent


def build_timeline(
    events: list[TriageEvent],
    gap_threshold_minutes: int = 60,
) -> list[dict]:
    """
    Sort events chronologically and annotate large temporal gaps.

    A gap is inserted into the timeline when consecutive events are separated
    by more than gap_threshold_minutes. This can indicate missing log data.

    Args:
        events:                List of TriageEvent objects from any source.
        gap_threshold_minutes: Minimum gap size (in minutes) to annotate.

    Returns:
        List of timeline entries. Each entry is either a TriageEvent dict or
        a gap marker: {"_type": "gap", "duration_minutes": N, "start": ..., "end": ...}
    """
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    timeline: list[dict] = []
    threshold = timedelta(minutes=gap_threshold_minutes)

    for i, event in enumerate(sorted_events):
        if i > 0:
            prev_time = sorted_events[i - 1].timestamp
            delta = event.timestamp - prev_time
            if delta > threshold:
                timeline.append({
                    "_type": "gap",
                    "duration_minutes": round(delta.total_seconds() / 60, 1),
                    "start": prev_time.isoformat(),
                    "end": event.timestamp.isoformat(),
                })
        timeline.append(event.model_dump(mode="json"))

    return timeline
