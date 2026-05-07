from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


runner = CliRunner()


def test_parse_logs_lenient_writes_even_invalid_record(monkeypatch, tmp_path: Path):
    def fake_parser(_path: Path):
        return [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "host": "host1",
                "source": "auth.log",
                "event_type": "auth_failed",
                "severity": "medium",
                "raw": "x",
            },
            {"not": "a-triage-event"},
        ]

    monkeypatch.setattr("dfir_attack_lab_cli.main.parse_auth_log", fake_parser)
    out_file = tmp_path / "out.jsonl"

    result = runner.invoke(
        app,
        [
            "parse-logs",
            "--parser",
            "authlog",
            "--input",
            str(tmp_path / "in.log"),
            "--output",
            str(out_file),
        ],
    )

    assert result.exit_code == 0
    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1]) == {"not": "a-triage-event"}


def test_parse_logs_strict_schema_fails_fast_with_index(monkeypatch, tmp_path: Path):
    def fake_parser(_path: Path):
        return [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "host": "host1",
                "source": "auth.log",
                "event_type": "auth_failed",
                "severity": "medium",
                "raw": "x",
            },
            {"not": "a-triage-event"},
            {
                "timestamp": "2024-01-01T00:00:02Z",
                "host": "host1",
                "source": "auth.log",
                "event_type": "auth_success",
                "severity": "low",
                "raw": "y",
            },
        ]

    monkeypatch.setattr("dfir_attack_lab_cli.main.parse_auth_log", fake_parser)
    out_file = tmp_path / "out.jsonl"

    result = runner.invoke(
        app,
        [
            "parse-logs",
            "--parser",
            "authlog",
            "--input",
            str(tmp_path / "in.log"),
            "--output",
            str(out_file),
            "--strict-schema",
        ],
    )

    assert result.exit_code != 0
    assert "parser 'authlog'" in result.stdout
    assert "record index 1" in result.stdout

    lines = out_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
