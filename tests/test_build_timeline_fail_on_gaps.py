import json
from pathlib import Path

from click.testing import CliRunner

from dfir_attack_lab_cli.cli import cli


def _write_events(path: Path, events: list[dict]) -> None:
    path.write_text(json.dumps(events), encoding="utf-8")


def test_build_timeline_fail_on_gaps_exits_non_zero(tmp_path: Path) -> None:
    events_path = tmp_path / "events.json"
    output_path = tmp_path / "timeline.json"

    # Two events one hour apart should trigger at least one detected gap.
    _write_events(
        events_path,
        [
            {"timestamp": "2025-01-01T00:00:00Z", "event_type": "a"},
            {"timestamp": "2025-01-01T01:00:00Z", "event_type": "b"},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "build-timeline",
            "--input",
            str(events_path),
            "--output",
            str(output_path),
            "--fail-on-gaps",
        ],
    )

    assert result.exit_code != 0
    assert "gap" in result.output.lower()


def test_build_timeline_without_fail_on_gaps_stays_zero(tmp_path: Path) -> None:
    events_path = tmp_path / "events.json"
    output_path = tmp_path / "timeline.json"

    _write_events(
        events_path,
        [
            {"timestamp": "2025-01-01T00:00:00Z", "event_type": "a"},
            {"timestamp": "2025-01-01T01:00:00Z", "event_type": "b"},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "build-timeline",
            "--input",
            str(events_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
