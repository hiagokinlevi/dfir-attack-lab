from datetime import datetime, timezone

from normalizers.models import TriageEvent
from timelines.builder import build_timeline


def _event(source: str, event_type: str) -> TriageEvent:
    return TriageEvent(
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        source=source,
        event_type=event_type,
        category="auth",
        severity="low",
        message=f"{source}:{event_type}",
        raw={},
    )


def test_build_timeline_deterministic_sort_for_identical_timestamps():
    fixture = [
        _event("windows.security", "login_failure"),
        _event("linux.auth", "sudo"),
        _event("linux.auth", "login_success"),
        _event("windows.security", "service_install"),
    ]

    # Intentionally shuffled input order
    input_events = [fixture[3], fixture[0], fixture[2], fixture[1]]

    first = build_timeline(input_events).events
    second = build_timeline(list(reversed(input_events))).events

    first_order = [(e.source, e.event_type) for e in first]
    second_order = [(e.source, e.event_type) for e in second]

    assert first_order == second_order == [
        ("linux.auth", "login_success"),
        ("linux.auth", "sudo"),
        ("windows.security", "login_failure"),
        ("windows.security", "service_install"),
    ]
