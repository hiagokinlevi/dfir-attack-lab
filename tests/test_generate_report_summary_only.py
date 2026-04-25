import json
from pathlib import Path

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


def test_generate_report_summary_only_json(tmp_path: Path) -> None:
    runner = CliRunner()
    input_path = tmp_path / "timeline.json"
    output_path = tmp_path / "report.json"

    input_payload = {
        "events": [
            {
                "timestamp": "2026-01-01T00:00:01+00:00",
                "severity": "high",
                "category": "auth",
                "source_parser": "authlog",
                "message": "failed login",
            },
            {
                "timestamp": "2026-01-01T00:01:01+00:00",
                "severity": "medium",
                "category": "process",
                "source_parser": "windows_evtx",
                "message": "service created",
            },
        ],
        "detected_gap_count": 3,
    }
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "generate-report",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--format",
            "json",
            "--summary-only",
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert "summary" in report
    assert "events" not in report
    assert report["summary"]["total_events"] == 2
    assert report["summary"]["detected_gap_count"] == 3
    assert report["summary"]["by_severity"]["high"] == 1
    assert report["summary"]["by_category"]["auth"] == 1
    assert report["summary"]["by_source_parser"]["authlog"] == 1
