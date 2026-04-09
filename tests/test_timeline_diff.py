"""
Tests for analysis/timeline_diff.py

Validates:
  - diff_timelines() with identical snapshots: added=[], removed=[], unchanged=N
  - New events in current appear in diff.added
  - Events only in baseline appear in diff.removed
  - Events matching by (timestamp, source, action, actor, target) are unchanged
  - Sub-second timestamp differences do not create spurious diffs
  - total_changes = len(added) + len(removed)
  - has_new_high_severity detects HIGH events in added
  - added_by_category groups events correctly
  - category_changes.delta is correct
  - severity_changes populated
  - summary() is a non-empty string with key counts
  - TimelineDiff with empty baseline: all current events are added
  - TimelineDiff with empty current: all baseline events are removed
  - Labels are preserved in the diff
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.timeline_diff import TimelineDiff, diff_timelines
from normalizers.models import EventCategory, SeverityHint, TriageEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    action: str,
    category: EventCategory = EventCategory.AUTHENTICATION,
    severity: SeverityHint = SeverityHint.INFO,
    actor: str | None = "root",
    target: str | None = "sshd",
    ts: datetime | None = None,
    source_file: str = "auth.log",
) -> TriageEvent:
    return TriageEvent(
        timestamp=ts or datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc),
        source_file=source_file,
        category=category,
        severity=severity,
        actor=actor,
        target=target,
        action=action,
        raw=action,
    )


# ---------------------------------------------------------------------------
# Identical snapshots
# ---------------------------------------------------------------------------

class TestIdenticalSnapshots:

    def test_identical_snapshots_no_added(self):
        events = [_event("login_failure")]
        diff = diff_timelines(events, events)
        assert diff.added == []

    def test_identical_snapshots_no_removed(self):
        events = [_event("login_failure")]
        diff = diff_timelines(events, events)
        assert diff.removed == []

    def test_identical_snapshots_unchanged_count(self):
        events = [_event("login_failure"), _event("sudo_exec")]
        diff = diff_timelines(events, events)
        assert diff.unchanged_count == 2

    def test_empty_baseline_and_current(self):
        diff = diff_timelines([], [])
        assert diff.added == []
        assert diff.removed == []
        assert diff.unchanged_count == 0


# ---------------------------------------------------------------------------
# Added events
# ---------------------------------------------------------------------------

class TestAddedEvents:

    def test_new_event_in_current_is_added(self):
        baseline = [_event("login_failure")]
        new_event = _event("cron_add", ts=datetime(2026, 4, 6, 13, 0, 0, tzinfo=timezone.utc))
        current = [_event("login_failure"), new_event]
        diff = diff_timelines(baseline, current)
        assert len(diff.added) == 1
        assert diff.added[0].action == "cron_add"

    def test_empty_baseline_all_current_are_added(self):
        current = [_event("login_failure"), _event("sudo_exec")]
        diff = diff_timelines([], current)
        assert len(diff.added) == 2

    def test_added_events_correct_actions(self):
        baseline = []
        current = [_event("data_exfil")]
        diff = diff_timelines(baseline, current)
        assert diff.added[0].action == "data_exfil"


# ---------------------------------------------------------------------------
# Removed events
# ---------------------------------------------------------------------------

class TestRemovedEvents:

    def test_event_in_baseline_not_in_current_is_removed(self):
        t0 = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)
        baseline = [_event("login_failure", ts=t0)]
        current  = [_event("sudo_exec", ts=t0 + timedelta(hours=1))]
        diff = diff_timelines(baseline, current)
        assert len(diff.removed) == 1
        assert diff.removed[0].action == "login_failure"

    def test_empty_current_all_baseline_are_removed(self):
        baseline = [_event("login_failure"), _event("cron_add")]
        diff = diff_timelines(baseline, [])
        assert len(diff.removed) == 2


# ---------------------------------------------------------------------------
# Matching (unchanged)
# ---------------------------------------------------------------------------

class TestMatchedEvents:

    def test_sub_second_difference_is_unchanged(self):
        """Timestamps rounded to second — 500ms difference should not create diff."""
        t0 = datetime(2026, 4, 6, 12, 0, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 4, 6, 12, 0, 0, 500000, tzinfo=timezone.utc)  # 0.5s later
        baseline = [_event("login_failure", ts=t0)]
        current  = [_event("login_failure", ts=t1)]
        diff = diff_timelines(baseline, current)
        assert diff.unchanged_count == 1
        assert diff.added == []
        assert diff.removed == []

    def test_different_source_file_not_matched(self):
        t0 = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)
        baseline = [_event("login_failure", ts=t0, source_file="auth.log")]
        current  = [_event("login_failure", ts=t0, source_file="syslog")]
        diff = diff_timelines(baseline, current)
        assert len(diff.added) == 1
        assert len(diff.removed) == 1


# ---------------------------------------------------------------------------
# total_changes and properties
# ---------------------------------------------------------------------------

class TestDiffProperties:

    def test_total_changes_equals_added_plus_removed(self):
        baseline = [_event("login_failure")]
        current  = [_event("cron_add", ts=datetime(2026, 4, 6, 13, 0, 0, tzinfo=timezone.utc))]
        diff = diff_timelines(baseline, current)
        assert diff.total_changes == len(diff.added) + len(diff.removed)

    def test_has_new_high_severity_true_when_high_added(self):
        baseline = []
        current  = [_event("login_failure", severity=SeverityHint.HIGH)]
        diff = diff_timelines(baseline, current)
        assert diff.has_new_high_severity is True

    def test_has_new_high_severity_false_when_only_medium(self):
        baseline = []
        current  = [_event("login_failure", severity=SeverityHint.MEDIUM)]
        diff = diff_timelines(baseline, current)
        assert diff.has_new_high_severity is False

    def test_added_by_category_groups_correctly(self):
        baseline = []
        current = [
            _event("login_failure", category=EventCategory.AUTHENTICATION),
            _event("cron_add", category=EventCategory.PROCESS),
        ]
        diff = diff_timelines(baseline, current)
        assert "authentication" in diff.added_by_category
        assert "process" in diff.added_by_category

    def test_baseline_event_count_correct(self):
        baseline = [_event("a"), _event("b")]
        diff = diff_timelines(baseline, [])
        assert diff.baseline_event_count == 2

    def test_current_event_count_correct(self):
        current = [_event("a"), _event("b"), _event("c")]
        diff = diff_timelines([], current)
        assert diff.current_event_count == 3


# ---------------------------------------------------------------------------
# Category and severity changes
# ---------------------------------------------------------------------------

class TestCategoryChanges:

    def test_category_change_delta_positive_when_more_in_current(self):
        t0 = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)
        baseline = [_event("a", category=EventCategory.AUTHENTICATION, ts=t0)]
        t1 = datetime(2026, 4, 6, 13, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 4, 6, 14, 0, 0, tzinfo=timezone.utc)
        current  = [
            _event("a", category=EventCategory.AUTHENTICATION, ts=t0),  # matched
            _event("b", category=EventCategory.AUTHENTICATION, ts=t1),
            _event("c", category=EventCategory.AUTHENTICATION, ts=t2),
        ]
        diff = diff_timelines(baseline, current)
        auth_change = next(
            c for c in diff.category_changes if c.category == EventCategory.AUTHENTICATION
        )
        assert auth_change.delta == 2

    def test_severity_changes_populated(self):
        baseline = []
        current  = [_event("a", severity=SeverityHint.HIGH)]
        diff = diff_timelines(baseline, current)
        assert len(diff.severity_changes) > 0

    def test_severity_change_high_delta(self):
        baseline = []
        current  = [_event("a", severity=SeverityHint.HIGH)]
        diff = diff_timelines(baseline, current)
        high_change = next(c for c in diff.severity_changes if c.severity == SeverityHint.HIGH)
        assert high_change.delta == 1


# ---------------------------------------------------------------------------
# Labels and summary
# ---------------------------------------------------------------------------

class TestLabelsAndSummary:

    def test_labels_preserved(self):
        diff = diff_timelines([], [], baseline_label="T+0h", current_label="T+6h")
        assert diff.baseline_label == "T+0h"
        assert diff.current_label == "T+6h"

    def test_summary_is_string(self):
        diff = diff_timelines([], [])
        assert isinstance(diff.summary(), str)

    def test_summary_contains_event_counts(self):
        baseline = [_event("a")]
        current  = [_event("b", ts=datetime(2026, 4, 6, 13, 0, 0, tzinfo=timezone.utc))]
        diff = diff_timelines(baseline, current, baseline_label="T0", current_label="T1")
        summary = diff.summary()
        assert "T0" in summary
        assert "T1" in summary
