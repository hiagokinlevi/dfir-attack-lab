"""
Unit tests for the Click CLI entry point.

These tests validate the public command surface that analysts will use during
triage and reporting workflows.
"""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.main import cli
from normalizers.models import EventCategory, SeverityHint, TriageEvent
from timelines.builder import build_timeline


def _event(hour: int, severity: str = "info", category: str = "authentication") -> TriageEvent:
    return TriageEvent(
        timestamp=datetime(2026, 2, 1, hour, 0, tzinfo=timezone.utc),
        source_file="auth.log",
        category=EventCategory(category),
        severity=SeverityHint(severity),
        actor="analyst",
        action=f"{category}_{severity}",
        raw=f"raw event at {hour}:00",
    )


class TestCollectionCommands(unittest.TestCase):

    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_collect_windows_invokes_windows_collector(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            expected = Path(tmpdir) / "CASE-CLI_windows_triage.jsonl"
            with patch("cli.main.run_windows_triage", return_value=expected) as mocked:
                result = self.runner.invoke(
                    cli,
                    ["collect-windows", "--output-dir", tmpdir, "--case-id", "CASE-CLI"],
                )
        self.assertEqual(result.exit_code, 0, result.output)
        mocked.assert_called_once()
        self.assertIn("Triage complete", result.output)

    def test_collect_macos_invokes_macos_collector(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            expected = Path(tmpdir) / "CASE-CLI_macos_triage.jsonl"
            with patch("cli.main.run_macos_triage", return_value=expected) as mocked:
                result = self.runner.invoke(
                    cli,
                    ["collect-macos", "--output-dir", tmpdir, "--case-id", "CASE-CLI"],
                )
        self.assertEqual(result.exit_code, 0, result.output)
        mocked.assert_called_once()
        self.assertIn("Triage complete", result.output)

    def test_parse_macos_unified_log_writes_output(self):
        parsed_event = _event(5).model_dump(mode="json")
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "unified.log"
            log_path.write_text("placeholder", encoding="utf-8")
            output_path = Path(tmpdir) / "events.json"
            with patch("cli.main.parse_macos_unified_log", return_value=[TriageEvent(**parsed_event)]) as mocked:
                result = self.runner.invoke(
                    cli,
                    ["parse-macos-unified-log", str(log_path), "-o", str(output_path)],
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 0, result.output)
        mocked.assert_called_once()
        self.assertEqual(payload[0]["action"], parsed_event["action"])

    def test_analyze_process_tree_writes_report(self):
        processes = [
            {
                "pid": 500,
                "ppid": 100,
                "name": "cmd.exe",
                "cmdline": "cmd.exe /c whoami",
                "parent_name": "winword.exe",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "processes.json"
            output_path = Path(tmpdir) / "process-report.json"
            input_path.write_text(json.dumps({"processes": processes}), encoding="utf-8")

            result = self.runner.invoke(
                cli,
                ["analyze-process-tree", str(input_path), "-o", str(output_path)],
            )
            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(report["processes_analyzed"], 1)
        self.assertEqual(report["findings"][0]["check_id"], "PT-001")

    def test_analyze_process_tree_fail_on_threshold_exits_nonzero(self):
        processes = [
            {
                "pid": 501,
                "name": "powershell.exe",
                "cmdline": "powershell.exe -nop",
                "parent_name": "excel.exe",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "processes.json"
            input_path.write_text(json.dumps(processes), encoding="utf-8")

            result = self.runner.invoke(
                cli,
                ["analyze-process-tree", str(input_path), "--fail-on", "high"],
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("met --fail-on high", result.output)


class TestTimelineCommands(unittest.TestCase):

    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_build_timeline_command_writes_output(self):
        events = [_event(1).model_dump(mode="json"), _event(4, severity="high").model_dump(mode="json")]
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = Path(tmpdir) / "events.json"
            output_path = Path(tmpdir) / "timeline.json"
            events_path.write_text(json.dumps(events), encoding="utf-8")

            result = self.runner.invoke(
                cli,
                ["build-timeline", str(events_path), "--gap", "60", "-o", str(output_path)],
            )

            timeline = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[1]["_type"], "gap")

    def test_generate_report_csv_reads_exported_document(self):
        timeline = build_timeline([_event(1), _event(2, severity="high")], gap_threshold_minutes=120)
        with tempfile.TemporaryDirectory() as tmpdir:
            timeline_path = Path(tmpdir) / "timeline.json"
            report_path = Path(tmpdir) / "timeline.csv"
            timeline_path.write_text(
                json.dumps({"case_id": "CASE-CSV", "timeline": timeline}, indent=2),
                encoding="utf-8",
            )

            result = self.runner.invoke(
                cli,
                ["generate-report", str(timeline_path), "--format", "csv", "-o", str(report_path)],
            )

            with report_path.open("r", encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["entry_type"], "event")
        self.assertEqual(rows[1]["severity"], "high")

    def test_generate_report_filters_severity_and_excludes_gaps(self):
        timeline = build_timeline([_event(1), _event(4, severity="high")], gap_threshold_minutes=60)
        with tempfile.TemporaryDirectory() as tmpdir:
            timeline_path = Path(tmpdir) / "timeline.json"
            report_path = Path(tmpdir) / "filtered.json"
            timeline_path.write_text(json.dumps(timeline, indent=2), encoding="utf-8")

            result = self.runner.invoke(
                cli,
                [
                    "generate-report",
                    str(timeline_path),
                    "--format",
                    "json",
                    "--severity",
                    "high",
                    "--exclude-gaps",
                    "-o",
                    str(report_path),
                    "--case-id",
                    "CASE-HIGH",
                ],
            )

            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(report["case_id"], "CASE-HIGH")
        self.assertEqual(report["summary"]["total_events"], 1)
        self.assertEqual(report["summary"]["gap_count"], 0)
        self.assertEqual(report["timeline"][0]["severity"], "high")

    def test_generate_report_supports_ecs_ndjson(self):
        timeline = build_timeline([_event(1, severity="high")], gap_threshold_minutes=120)
        with tempfile.TemporaryDirectory() as tmpdir:
            timeline_path = Path(tmpdir) / "timeline.json"
            report_path = Path(tmpdir) / "timeline.ecs.ndjson"
            timeline_path.write_text(json.dumps(timeline, indent=2), encoding="utf-8")

            result = self.runner.invoke(
                cli,
                [
                    "generate-report",
                    str(timeline_path),
                    "--format",
                    "ecs",
                    "-o",
                    str(report_path),
                    "--case-id",
                    "CASE-ECS-CLI",
                ],
            )

            event = json.loads(report_path.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(event["labels"]["case_id"], "CASE-ECS-CLI")
        self.assertEqual(event["event"]["severity"], 73)

    def test_generate_report_supports_cef(self):
        timeline = build_timeline([_event(1, severity="medium")], gap_threshold_minutes=120)
        with tempfile.TemporaryDirectory() as tmpdir:
            timeline_path = Path(tmpdir) / "timeline.json"
            report_path = Path(tmpdir) / "timeline.cef"
            timeline_path.write_text(json.dumps(timeline, indent=2), encoding="utf-8")

            result = self.runner.invoke(
                cli,
                [
                    "generate-report",
                    str(timeline_path),
                    "--format",
                    "cef",
                    "-o",
                    str(report_path),
                    "--case-id",
                    "CASE-CEF-CLI",
                ],
            )

            line = report_path.read_text(encoding="utf-8").splitlines()[0]

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("deviceExternalId=CASE-CEF-CLI", line)
        self.assertIn("|authentication:authentication_medium|6|", line)

    def test_generate_report_requires_both_start_and_end(self):
        timeline = build_timeline([_event(1)], gap_threshold_minutes=60)
        with tempfile.TemporaryDirectory() as tmpdir:
            timeline_path = Path(tmpdir) / "timeline.json"
            report_path = Path(tmpdir) / "report.txt"
            timeline_path.write_text(json.dumps(timeline, indent=2), encoding="utf-8")

            result = self.runner.invoke(
                cli,
                [
                    "generate-report",
                    str(timeline_path),
                    "--start",
                    "2026-02-01T00:00:00Z",
                    "--format",
                    "txt",
                    "-o",
                    str(report_path),
                ],
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Both --start and --end", result.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
