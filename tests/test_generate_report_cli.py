from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def _write_timeline(path: Path) -> None:
    events = [
        {
            "timestamp": "2025-01-01T10:00:00Z",
            "source": "auth.log",
            "event_type": "login_failed",
            "category": "auth",
            "severity": "medium",
            "message": "failed password",
            "raw": "raw1",
            "host": "host1",
            "user": "alice",
            "ip": "10.0.0.1",
            "process": "sshd",
            "pid": 123,
            "extra": {},
        },
        {
            "timestamp": "2025-01-01T10:05:00Z",
            "source": "proc",
            "event_type": "process_start",
            "category": "process",
            "severity": "high",
            "message": "suspicious process",
            "raw": "raw2",
            "host": "host1",
            "user": "bob",
            "ip": None,
            "process": "cmd.exe",
            "pid": 456,
            "extra": {},
        },
        {
            "timestamp": "2025-01-01T10:10:00Z",
            "source": "svc",
            "event_type": "service_install",
            "category": "persistence",
            "severity": "critical",
            "message": "new service",
            "raw": "raw3",
            "host": "host1",
            "user": "SYSTEM",
            "ip": None,
            "process": "services.exe",
            "pid": 789,
            "extra": {},
        },
    ]
    path.write_text(json.dumps(events), encoding="utf-8")


def test_generate_report_category_single_and_multi(tmp_path: Path) -> None:
    runner = CliRunner()
    timeline = tmp_path / "timeline.json"
    _write_timeline(timeline)

    out_single = tmp_path / "single.json"
    result_single = runner.invoke(
        cli,
        [
            "generate-report",
            "--timeline",
            str(timeline),
            "--output",
            str(out_single),
            "--format",
            "json",
            "--category",
            "auth",
        ],
    )
    assert result_single.exit_code == 0, result_single.output
    single_events = json.loads(out_single.read_text(encoding="utf-8"))
    assert len(single_events) == 1
    assert {e["category"] for e in single_events} == {"auth"}

    out_multi = tmp_path / "multi.json"
    result_multi = runner.invoke(
        cli,
        [
            "generate-report",
            "--timeline",
            str(timeline),
            "--output",
            str(out_multi),
            "--format",
            "json",
            "--category",
            "auth",
            "--category",
            "process",
        ],
    )
    assert result_multi.exit_code == 0, result_multi.output
    multi_events = json.loads(out_multi.read_text(encoding="utf-8"))
    assert len(multi_events) == 2
    assert {e["category"] for e in multi_events} == {"auth", "process"}
