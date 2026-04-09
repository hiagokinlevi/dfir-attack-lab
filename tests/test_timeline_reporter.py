"""
Unit tests for timelines/reporter.py

Tests cover filtering (severity, category, time range, gap exclusion),
summarization, and all four export formats (jsonl, json, html, txt).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import csv
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from normalizers.models import EventCategory, SeverityHint, TriageEvent
from timelines.builder import build_timeline
from timelines.reporter import export_timeline, filter_timeline, summarize_timeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 1, 15, hour, minute, tzinfo=timezone.utc)


def _event(
    hour: int,
    severity: str = "info",
    category: str = "authentication",
    actor: str = "testuser",
    action: str = "login",
) -> TriageEvent:
    return TriageEvent(
        timestamp=_ts(hour),
        source_file="auth.log",
        category=EventCategory(category),
        severity=SeverityHint(severity),
        actor=actor,
        action=action,
        raw=f"fake log line at {hour}:00",
    )


def _make_timeline(*events: TriageEvent, gap_threshold: int = 120) -> list[dict]:
    return build_timeline(list(events), gap_threshold_minutes=gap_threshold)


# ---------------------------------------------------------------------------
# filter_timeline — severity
# ---------------------------------------------------------------------------


class TestFilterBySeverity(unittest.TestCase):

    def test_info_filter_includes_all(self):
        tl = _make_timeline(
            _event(1, severity="info"),
            _event(2, severity="low"),
            _event(3, severity="high"),
        )
        filtered = filter_timeline(tl, by_severity="info", exclude_gaps=True)
        self.assertEqual(len(filtered), 3)

    def test_high_filter_excludes_lower(self):
        tl = _make_timeline(
            _event(1, severity="info"),
            _event(2, severity="medium"),
            _event(3, severity="high"),
        )
        filtered = filter_timeline(tl, by_severity="high", exclude_gaps=True)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["severity"], "high")

    def test_medium_filter_includes_medium_and_high(self):
        tl = _make_timeline(
            _event(1, severity="info"),
            _event(2, severity="low"),
            _event(3, severity="medium"),
            _event(4, severity="high"),
        )
        filtered = filter_timeline(tl, by_severity="medium", exclude_gaps=True)
        severities = {e["severity"] for e in filtered}
        self.assertIn("medium", severities)
        self.assertIn("high", severities)
        self.assertNotIn("info", severities)
        self.assertNotIn("low", severities)

    def test_none_severity_filter_includes_all(self):
        tl = _make_timeline(_event(1), _event(2), _event(3))
        filtered = filter_timeline(tl, by_severity=None, exclude_gaps=True)
        self.assertEqual(len(filtered), 3)


# ---------------------------------------------------------------------------
# filter_timeline — category
# ---------------------------------------------------------------------------


class TestFilterByCategory(unittest.TestCase):

    def test_filter_single_category(self):
        tl = _make_timeline(
            _event(1, category="authentication"),
            _event(2, category="network"),
            _event(3, category="privilege_escalation"),
        )
        filtered = filter_timeline(tl, by_category=["authentication"], exclude_gaps=True)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["category"], "authentication")

    def test_filter_multiple_categories(self):
        tl = _make_timeline(
            _event(1, category="authentication"),
            _event(2, category="network"),
            _event(3, category="system"),
        )
        filtered = filter_timeline(
            tl,
            by_category=["authentication", "network"],
            exclude_gaps=True,
        )
        cats = {e["category"] for e in filtered}
        self.assertEqual(cats, {"authentication", "network"})

    def test_none_category_filter_includes_all(self):
        tl = _make_timeline(
            _event(1, category="authentication"),
            _event(2, category="network"),
        )
        filtered = filter_timeline(tl, by_category=None, exclude_gaps=True)
        self.assertEqual(len(filtered), 2)


# ---------------------------------------------------------------------------
# filter_timeline — time range
# ---------------------------------------------------------------------------


class TestFilterByTimeRange(unittest.TestCase):

    def test_filter_within_range(self):
        tl = _make_timeline(
            _event(8),
            _event(10),
            _event(12),
            _event(14),
        )
        start = _ts(9)
        end = _ts(13)
        filtered = filter_timeline(tl, by_time_range=(start, end), exclude_gaps=True)
        self.assertEqual(len(filtered), 2)  # 10:00 and 12:00

    def test_filter_excludes_outside_range(self):
        tl = _make_timeline(_event(1), _event(23))
        start = _ts(2)
        end = _ts(22)
        filtered = filter_timeline(tl, by_time_range=(start, end), exclude_gaps=True)
        self.assertEqual(len(filtered), 0)


# ---------------------------------------------------------------------------
# filter_timeline — gap handling
# ---------------------------------------------------------------------------


class TestFilterGaps(unittest.TestCase):

    def test_gaps_included_by_default(self):
        tl = _make_timeline(
            _event(1),
            _event(5),  # 4h gap triggers marker
            gap_threshold=120,
        )
        gaps = [e for e in tl if e.get("_type") == "gap"]
        filtered = filter_timeline(tl)
        filtered_gaps = [e for e in filtered if e.get("_type") == "gap"]
        self.assertEqual(len(filtered_gaps), len(gaps))

    def test_exclude_gaps_removes_gap_markers(self):
        tl = _make_timeline(_event(1), _event(5), gap_threshold=120)
        filtered = filter_timeline(tl, exclude_gaps=True)
        self.assertFalse(any(e.get("_type") == "gap" for e in filtered))


# ---------------------------------------------------------------------------
# summarize_timeline
# ---------------------------------------------------------------------------


class TestSummarizeTimeline(unittest.TestCase):

    def test_empty_timeline(self):
        summary = summarize_timeline([])
        self.assertEqual(summary["total_events"], 0)
        self.assertEqual(summary["gap_count"], 0)
        self.assertIsNone(summary["first_event_at"])

    def test_counts_events_and_gaps(self):
        tl = _make_timeline(_event(1), _event(5), gap_threshold=120)
        summary = summarize_timeline(tl)
        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["gap_count"], 1)
        self.assertGreater(summary["total_gap_minutes"], 0)

    def test_by_severity_counts(self):
        tl = _make_timeline(
            _event(1, severity="high"),
            _event(2, severity="high"),
            _event(3, severity="info"),
            gap_threshold=0,
        )
        summary = summarize_timeline(tl)
        self.assertEqual(summary["by_severity"].get("high", 0), 2)
        self.assertEqual(summary["by_severity"].get("info", 0), 1)

    def test_by_category_counts(self):
        tl = _make_timeline(
            _event(1, category="authentication"),
            _event(2, category="network"),
            _event(3, category="authentication"),
            gap_threshold=0,
        )
        summary = summarize_timeline(tl)
        self.assertEqual(summary["by_category"].get("authentication", 0), 2)
        self.assertEqual(summary["by_category"].get("network", 0), 1)

    def test_first_and_last_event(self):
        tl = _make_timeline(_event(6), _event(10), _event(8), gap_threshold=0)
        summary = summarize_timeline(tl)
        self.assertIn("06:00", summary["first_event_at"])
        self.assertIn("10:00", summary["last_event_at"])


# ---------------------------------------------------------------------------
# export_timeline — JSONL
# ---------------------------------------------------------------------------


class TestExportJSONL(unittest.TestCase):

    def test_jsonl_one_line_per_entry(self):
        tl = _make_timeline(_event(1), _event(2), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.jsonl"
            export_timeline(tl, path, fmt="jsonl")
            lines = path.read_text().strip().splitlines()
        self.assertEqual(len(lines), len(tl))

    def test_jsonl_each_line_is_valid_json(self):
        tl = _make_timeline(_event(1), _event(2), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.jsonl"
            export_timeline(tl, path, fmt="jsonl")
            for line in path.read_text().strip().splitlines():
                json.loads(line)  # must not raise


# ---------------------------------------------------------------------------
# export_timeline — JSON
# ---------------------------------------------------------------------------


class TestExportJSON(unittest.TestCase):

    def test_json_has_required_fields(self):
        tl = _make_timeline(_event(1), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.json"
            export_timeline(tl, path, fmt="json", case_id="TEST-JSON-001")
            doc = json.loads(path.read_text())
        self.assertEqual(doc["case_id"], "TEST-JSON-001")
        self.assertIn("summary", doc)
        self.assertIn("timeline", doc)
        self.assertIn("exported_at", doc)

    def test_json_timeline_count_matches(self):
        tl = _make_timeline(_event(1), _event(2), _event(3), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.json"
            export_timeline(tl, path, fmt="json")
            doc = json.loads(path.read_text())
        self.assertEqual(len(doc["timeline"]), len(tl))


# ---------------------------------------------------------------------------
# export_timeline — HTML
# ---------------------------------------------------------------------------


class TestExportHTML(unittest.TestCase):

    def test_html_is_valid_document(self):
        tl = _make_timeline(_event(1, severity="high"), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.html"
            export_timeline(tl, path, fmt="html", case_id="INC-2026-001")
            content = path.read_text()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("<html", content)
        self.assertIn("INC-2026-001", content)

    def test_html_contains_severity_data(self):
        tl = _make_timeline(_event(1, severity="high"), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.html"
            export_timeline(tl, path, fmt="html")
            content = path.read_text()
        self.assertIn("HIGH", content)

    def test_html_gap_marker_present(self):
        tl = _make_timeline(_event(1), _event(5), gap_threshold=120)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.html"
            export_timeline(tl, path, fmt="html")
            content = path.read_text()
        self.assertIn("GAP", content)


# ---------------------------------------------------------------------------
# export_timeline — CSV
# ---------------------------------------------------------------------------


class TestExportCSV(unittest.TestCase):

    def test_csv_contains_expected_columns(self):
        tl = _make_timeline(_event(1), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.csv"
            export_timeline(tl, path, fmt="csv")
            with path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                fieldnames = reader.fieldnames or []
        self.assertIn("entry_type", fieldnames)
        self.assertIn("timestamp", fieldnames)
        self.assertIn("severity", fieldnames)
        self.assertIn("duration_minutes", fieldnames)

    def test_csv_serializes_gap_rows(self):
        tl = _make_timeline(_event(1), _event(5), gap_threshold=120)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.csv"
            export_timeline(tl, path, fmt="csv")
            with path.open("r", encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
        gap_rows = [row for row in rows if row["entry_type"] == "gap"]
        self.assertEqual(len(gap_rows), 1)
        self.assertIn("240.0", gap_rows[0]["duration_minutes"])


# ---------------------------------------------------------------------------
# export_timeline — TXT
# ---------------------------------------------------------------------------


class TestExportTXT(unittest.TestCase):

    def test_txt_contains_header(self):
        tl = _make_timeline(_event(1), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.txt"
            export_timeline(tl, path, fmt="txt", case_id="INC-TXT-001")
            content = path.read_text()
        self.assertIn("INC-TXT-001", content)
        self.assertIn("INCIDENT TIMELINE", content)

    def test_txt_contains_event_data(self):
        tl = _make_timeline(_event(9, action="ssh_login"), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.txt"
            export_timeline(tl, path, fmt="txt")
            content = path.read_text()
        self.assertIn("ssh_login", content)


# ---------------------------------------------------------------------------
# export_timeline — unknown format
# ---------------------------------------------------------------------------


class TestExportUnknownFormat(unittest.TestCase):

    def test_raises_value_error_for_unknown_format(self):
        tl = _make_timeline(_event(1), gap_threshold=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.xyz"
            with self.assertRaises(ValueError):
                export_timeline(tl, path, fmt="xyz")


if __name__ == "__main__":
    unittest.main(verbosity=2)
