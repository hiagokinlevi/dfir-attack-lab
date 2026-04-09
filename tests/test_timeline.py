from datetime import datetime, timezone
from timelines.builder import build_timeline
from normalizers.models import TriageEvent, EventCategory


def _make_event(dt: datetime, action: str = "test") -> TriageEvent:
    return TriageEvent(
        timestamp=dt,
        source_file="test",
        category=EventCategory.SYSTEM,
        action=action,
        raw="raw line",
    )


def test_timeline_sorted():
    e1 = _make_event(datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc))
    e2 = _make_event(datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc))
    timeline = build_timeline([e1, e2], gap_threshold_minutes=30)
    # No gap expected (out-of-order input should be sorted)
    non_gap = [e for e in timeline if e.get("_type") != "gap"]
    assert non_gap[0]["action"] == "test"


def test_gap_detected():
    e1 = _make_event(datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc))
    e2 = _make_event(datetime(2026, 1, 1, 3, 0, tzinfo=timezone.utc))  # 3h gap
    timeline = build_timeline([e1, e2], gap_threshold_minutes=60)
    gaps = [e for e in timeline if e.get("_type") == "gap"]
    assert len(gaps) == 1
    assert gaps[0]["duration_minutes"] == 180.0


def test_no_gap_below_threshold():
    e1 = _make_event(datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc))
    e2 = _make_event(datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc))  # 30m
    timeline = build_timeline([e1, e2], gap_threshold_minutes=60)
    gaps = [e for e in timeline if e.get("_type") == "gap"]
    assert len(gaps) == 0
