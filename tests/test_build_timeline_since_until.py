from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


runner = CliRunner()


def _write_events(path: Path) -> None:
    events = [
        {"timestamp": "2026-01-01T00:00:00+00:00", "message": "a"},
        {"timestamp": "2026-01-01T01:00:00+00:00", "message": "b"},
        {"timestamp": "2026-01-01T02:00:00+00:00", "message": "c"},
    ]
    path.write_text(json.dumps(events), encoding="utf-8")


def test_build_timeline_filters_inclusive_window(tmp_path: Path) -> None:
    input_path = tmp_path / "events.json"
    output_path = tmp_path / "timeline.json"
    _write_events(input_path)

    result = runner.invoke(
        app,
        [
            "build-timeline",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--since",
            "2026-01-01T01:00:00+00:00",
            "--until",
            "2026-01-01T02:00:00+00:00",
        ],
    )

    assert result.exit_code == 0, result.stdout
    timeline = json.loads(output_path.read_text(encoding="utf-8"))
    timestamps = [e["timestamp"] for e in timeline.get("events", [])]
    assert timestamps == ["2026-01-01T01:00:00+00:00", "2026-01-01T02:00:00+00:00"]


def test_build_timeline_rejects_since_after_until(tmp_path: Path) -> None:
    input_path = tmp_path / "events.json"
    output_path = tmp_path / "timeline.json"
    _write_events(input_path)

    result = runner.invoke(
        app,
        [
            "build-timeline",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--since",
            "2026-01-01T03:00:00+00:00",
            "--until",
            "2026-01-01T02:00:00+00:00",
        ],
    )

    assert result.exit_code != 0
    assert "--since must be less than or equal to --until" in result.stdout


def test_build_timeline_rejects_invalid_iso8601(tmp_path: Path) -> None:
    input_path = tmp_path / "events.json"
    output_path = tmp_path / "timeline.json"
    _write_events(input_path)

    result = runner.invoke(
        app,
        [
            "build-timeline",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--since",
            "01-01-2026 00:00:00",
        ],
    )

    assert result.exit_code != 0
    assert "Invalid --since timestamp" in result.stdout
