"""
Timeline Diff Engine
======================
Compares two DFIR timeline snapshots to identify new events, removed events,
and changed patterns between a baseline and a current state.

Use cases:
  - "What changed between the snapshot taken at triage and the one taken 6 hours later?"
  - "Which persistence mechanisms appeared after we thought the attacker was evicted?"
  - "Are the same authentication failures still occurring, or has the attack evolved?"

Diff algorithm:
  Events are matched by a canonical key derived from:
    (timestamp rounded to second, source_file, action, actor, target)

  Events present in current but not baseline → ADDED
  Events present in baseline but not current → REMOVED
  Unchanged events are in both snapshots with the same key.

  The diff does NOT attempt fuzzy matching — only exact key matches are
  considered unchanged. This is intentional for forensic accuracy.

Usage:
    from analysis.timeline_diff import diff_timelines, TimelineDiff

    diff = diff_timelines(baseline_events, current_events)
    print(diff.summary())
    for event in diff.added:
        print("NEW:", event.action, event.actor, event.timestamp)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from normalizers.models import EventCategory, SeverityHint, TriageEvent


# ---------------------------------------------------------------------------
# Event key for matching
# ---------------------------------------------------------------------------

def _event_key(event: TriageEvent) -> tuple:
    """
    Return a canonical match key for a TriageEvent.

    Timestamps are rounded to the nearest second to absorb sub-second
    precision differences between snapshots from the same log source.
    """
    ts = event.timestamp.replace(microsecond=0)
    return (
        ts.isoformat(),
        event.source_file,
        event.action.lower().strip(),
        (event.actor or "").lower().strip(),
        (event.target or "").lower().strip(),
    )


# ---------------------------------------------------------------------------
# Diff result types
# ---------------------------------------------------------------------------

@dataclass
class CategoryChange:
    """Change in event count for a specific EventCategory between snapshots."""
    category:        EventCategory
    baseline_count:  int
    current_count:   int

    @property
    def delta(self) -> int:
        return self.current_count - self.baseline_count

    @property
    def increased(self) -> bool:
        return self.delta > 0

    @property
    def decreased(self) -> bool:
        return self.delta < 0


@dataclass
class SeverityChange:
    """Change in event count for a specific SeverityHint between snapshots."""
    severity:        SeverityHint
    baseline_count:  int
    current_count:   int

    @property
    def delta(self) -> int:
        return self.current_count - self.baseline_count


@dataclass
class TimelineDiff:
    """
    Result of diffing two timeline snapshots.

    Attributes:
        baseline_label:   Human-readable label for the baseline snapshot.
        current_label:    Human-readable label for the current snapshot.
        added:            Events in current but not in baseline.
        removed:          Events in baseline but not in current.
        unchanged_count:  Number of events present in both snapshots.
        category_changes: Per-category count changes.
        severity_changes: Per-severity count changes.
        baseline_event_count: Total events in baseline snapshot.
        current_event_count:  Total events in current snapshot.
    """
    baseline_label:        str
    current_label:         str
    added:                 list[TriageEvent]  = field(default_factory=list)
    removed:               list[TriageEvent]  = field(default_factory=list)
    unchanged_count:       int                = 0
    category_changes:      list[CategoryChange] = field(default_factory=list)
    severity_changes:      list[SeverityChange] = field(default_factory=list)
    baseline_event_count:  int                = 0
    current_event_count:   int                = 0

    @property
    def total_changes(self) -> int:
        """Total number of changed events (added + removed)."""
        return len(self.added) + len(self.removed)

    @property
    def has_new_high_severity(self) -> bool:
        """True if any added event has HIGH or escalated severity."""
        return any(
            e.severity in (SeverityHint.HIGH,)
            for e in self.added
        )

    @property
    def added_by_category(self) -> dict[str, list[TriageEvent]]:
        """Added events grouped by EventCategory."""
        result: dict[str, list[TriageEvent]] = {}
        for e in self.added:
            result.setdefault(e.category.value, []).append(e)
        return result

    def summary(self) -> str:
        """
        Return a human-readable diff summary.

        Example::

            Timeline Diff: "triage-T+0h" vs "triage-T+6h"
            ─────────────────────────────────────────────────
            Baseline events:  142  |  Current events: 189
            Added:  47  |  Removed: 0  |  Unchanged: 142
            New HIGH severity events: 3
            ─────────────────────────────────────────────────
            Category changes (delta):
              authentication: +12
              process:        +35
        """
        lines = [
            f'Timeline Diff: "{self.baseline_label}" vs "{self.current_label}"',
            "─" * 53,
            f"Baseline events: {self.baseline_event_count:>4}  |  "
            f"Current events: {self.current_event_count}",
            f"Added: {len(self.added):>3}  |  "
            f"Removed: {len(self.removed):>3}  |  "
            f"Unchanged: {self.unchanged_count}",
        ]
        if self.has_new_high_severity:
            high_count = sum(
                1 for e in self.added if e.severity == SeverityHint.HIGH
            )
            lines.append(f"New HIGH severity events: {high_count}")

        changed_cats = [c for c in self.category_changes if c.delta != 0]
        if changed_cats:
            lines.append("─" * 53)
            lines.append("Category changes (delta):")
            for cc in sorted(changed_cats, key=lambda c: abs(c.delta), reverse=True):
                sign = "+" if cc.delta >= 0 else ""
                lines.append(f"  {cc.category.value}: {sign}{cc.delta}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core diff function
# ---------------------------------------------------------------------------

def diff_timelines(
    baseline: list[TriageEvent],
    current: list[TriageEvent],
    baseline_label: str = "baseline",
    current_label:  str = "current",
) -> TimelineDiff:
    """
    Compute the difference between two timeline snapshots.

    Args:
        baseline:        Events from the earlier snapshot.
        current:         Events from the later snapshot.
        baseline_label:  Human-readable label for the baseline (for display).
        current_label:   Human-readable label for the current snapshot.

    Returns:
        TimelineDiff with added, removed, and unchanged events plus
        per-category and per-severity change summaries.
    """
    baseline_keys: dict[tuple, TriageEvent] = {_event_key(e): e for e in baseline}
    current_keys:  dict[tuple, TriageEvent] = {_event_key(e): e for e in current}

    added   = [e for k, e in current_keys.items()  if k not in baseline_keys]
    removed = [e for k, e in baseline_keys.items() if k not in current_keys]
    unchanged_count = sum(1 for k in current_keys if k in baseline_keys)

    # Per-category changes
    category_changes: list[CategoryChange] = []
    all_categories = set(e.category for e in baseline) | set(e.category for e in current)
    for cat in sorted(all_categories, key=lambda c: c.value):
        base_count = sum(1 for e in baseline if e.category == cat)
        curr_count = sum(1 for e in current  if e.category == cat)
        category_changes.append(CategoryChange(cat, base_count, curr_count))

    # Per-severity changes
    severity_changes: list[SeverityChange] = []
    for sev in SeverityHint:
        base_count = sum(1 for e in baseline if e.severity == sev)
        curr_count = sum(1 for e in current  if e.severity == sev)
        severity_changes.append(SeverityChange(sev, base_count, curr_count))

    return TimelineDiff(
        baseline_label=baseline_label,
        current_label=current_label,
        added=added,
        removed=removed,
        unchanged_count=unchanged_count,
        category_changes=category_changes,
        severity_changes=severity_changes,
        baseline_event_count=len(baseline),
        current_event_count=len(current),
    )
