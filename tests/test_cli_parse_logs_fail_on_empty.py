from pathlib import Path

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


def test_parse_logs_fail_on_empty_returns_nonzero(tmp_path: Path) -> None:
    runner = CliRunner()
    empty_log = tmp_path / "empty.log"
    empty_log.write_text("", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "parse-logs",
            "--input",
            str(empty_log),
            "--format",
            "authlog",
            "--output",
            str(tmp_path / "out.jsonl"),
            "--fail-on-empty",
        ],
    )

    assert result.exit_code != 0
    assert "no matching records" in result.stdout.lower() or "zero" in result.stdout.lower()


def test_parse_logs_without_fail_on_empty_stays_success(tmp_path: Path) -> None:
    runner = CliRunner()
    empty_log = tmp_path / "empty.log"
    empty_log.write_text("", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "parse-logs",
            "--input",
            str(empty_log),
            "--format",
            "authlog",
            "--output",
            str(tmp_path / "out.jsonl"),
        ],
    )

    assert result.exit_code == 0
