from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Sequence

from normalizers.models import TriageEvent


@dataclass(frozen=True)
class TimelineGap:
    start: datetime
    end: datetime
    duration_seconds: float


@dataclass(frozen=True)
class TimelineResult:
    events: List[TriageEvent]
    gaps: List[TimelineGap]


def _event_sort_key(event: TriageEvent) -> tuple:
    """Deterministic timeline ordering.

    Primary sort is timestamp. For events sharing the same timestamp, use
    stable secondary keys so repeated runs always produce the same output.
    """

    return (
        event.timestamp,
        (event.source or ""),
        (event.event_type or ""),
    )


def build_timeline(events: Sequence[TriageEvent] | Iterable[TriageEvent], gap_threshold_seconds: int = 300) -> TimelineResult:
    sorted_events = sorted(list(events), key=_event_sort_key)

    gaps: List[TimelineGap] = []
    if len(sorted_events) > 1:
        for prev, curr in zip(sorted_events, sorted_events[1:]):
            delta = (curr.timestamp - prev.timestamp).total_seconds()
            if delta > gap_threshold_seconds:
                gaps.append(
                    TimelineGap(
                        start=prev.timestamp,
                        end=curr.timestamp,
                        duration_seconds=delta,
                    )
                )

    return TimelineResult(events=sorted_events, gaps=gaps)
