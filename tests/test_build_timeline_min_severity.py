import json

from click.testing import CliRunner

from dfir_attack_lab_cli.main import cli


def test_build_timeline_min_severity_filters_and_accepts_choices(tmp_path):
    input_path = tmp_path / "events.json"
    output_path = tmp_path / "timeline.json"

    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "severity": "low", "message": "l"},
        {"timestamp": "2025-01-01T00:01:00Z", "severity": "medium", "message": "m"},
        {"timestamp": "2025-01-01T00:02:00Z", "severity": "high", "message": "h"},
        {"timestamp": "2025-01-01T00:03:00Z", "severity": "critical", "message": "c"},
    ]
    input_path.write_text(json.dumps(events), encoding="utf-8")

    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "build-timeline",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--min-severity",
            "HIGH",
        ],
    )
    assert result.exit_code == 0, result.output

    timeline = json.loads(output_path.read_text(encoding="utf-8"))
    rendered = json.dumps(timeline).lower()
    assert "low" not in rendered
    assert "medium" not in rendered
    assert "high" in rendered
    assert "critical" in rendered

    bad = runner.invoke(
        cli,
        [
            "build-timeline",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--min-severity",
            "urgent",
        ],
    )
    assert bad.exit_code != 0
    assert "invalid value" in bad.output.lower()
