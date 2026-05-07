from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


runner = CliRunner()


def _write_events(path: Path) -> None:
    events = [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "auth.log",
            "category": "authentication",
            "severity": "high",
            "message": "failed ssh login",
        },
        {
            "timestamp": "2026-01-01T00:05:00Z",
            "source": "auth.log",
            "category": "authentication",
            "severity": "medium",
            "message": "successful ssh login",
        },
        {
            "timestamp": "2026-01-01T01:45:00Z",
            "source": "sysmon",
            "category": "process",
            "severity": "high",
            "message": "suspicious process spawn",
        },
    ]
    path.write_text(json.dumps(events), encoding="utf-8")


def test_generate_report_summary_only_with_filters(tmp_path: Path) -> None:
    in_file = tmp_path / "timeline.json"
    out_file = tmp_path / "report.json"
    _write_events(in_file)

    result = runner.invoke(
        app,
        [
            "generate-report",
            "--input",
            str(in_file),
            "--output",
            str(out_file),
            "--format",
            "json",
            "--severity",
            "high",
            "--category",
            "authentication",
            "--summary-only",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert out_file.exists()

    payload = json.loads(out_file.read_text(encoding="utf-8"))

    # Aggregate-only structure expected
    assert isinstance(payload, dict)
    assert "events" not in payload

    # Required summary keys
    assert "counts_by_severity" in payload
    assert "counts_by_category" in payload
    assert "counts_by_source" in payload
    assert "first_timestamp" in payload
    assert "last_timestamp" in payload
    assert "gap_count" in payload

    # Filter compatibility: only one matching event remains
    assert payload["counts_by_severity"] == {"high": 1}
    assert payload["counts_by_category"] == {"authentication": 1}
    assert payload["counts_by_source"] == {"auth.log": 1}
    assert payload["first_timestamp"] == "2026-01-01T00:00:00Z"
    assert payload["last_timestamp"] == "2026-01-01T00:00:00Z"
    assert isinstance(payload["gap_count"], int)
