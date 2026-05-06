from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from dfir_attack_lab_cli.report import generate_report


def test_generate_report_filters_by_case_id_and_warns_on_no_match(tmp_path: Path) -> None:
    input_file = tmp_path / "events.json"
    out_file = tmp_path / "report.json"

    events = [
        {"timestamp": "2026-01-01T00:00:00Z", "case_id": "Case-123", "message": "keep"},
        {"timestamp": "2026-01-01T00:00:01Z", "case_id": "other", "message": "drop"},
    ]
    input_file.write_text(json.dumps(events), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        generate_report,
        [
            "--input",
            str(input_file),
            "--output",
            str(out_file),
            "--format",
            "json",
            "--case-id",
            "case-123",
        ],
    )

    assert result.exit_code == 0, result.output
    rendered = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(rendered) == 1
    assert rendered[0]["message"] == "keep"

    out_file_2 = tmp_path / "report_nomatch.json"
    result_no_match = runner.invoke(
        generate_report,
        [
            "--input",
            str(input_file),
            "--output",
            str(out_file_2),
            "--format",
            "json",
            "--case-id",
            "missing-case",
        ],
    )

    assert result_no_match.exit_code == 0
    assert "no events matched case_id" in result_no_match.output.lower()
    rendered_no_match = json.loads(out_file_2.read_text(encoding="utf-8"))
    assert rendered_no_match == []
