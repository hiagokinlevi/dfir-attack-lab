import json

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


def test_build_timeline_without_case_id_includes_all(tmp_path):
    runner = CliRunner()
    input_file = tmp_path / "events.json"
    output_file = tmp_path / "timeline.json"

    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "case_id": "A", "message": "a1"},
        {"timestamp": "2024-01-01T00:10:00Z", "case_id": "B", "message": "b1"},
    ]
    input_file.write_text(json.dumps(events), encoding="utf-8")

    result = runner.invoke(app, ["build-timeline", str(input_file), "--output", str(output_file)])
    assert result.exit_code == 0, result.output

    timeline = json.loads(output_file.read_text(encoding="utf-8"))
    serialized = json.dumps(timeline)
    assert "a1" in serialized
    assert "b1" in serialized


def test_build_timeline_with_case_id_filters_events(tmp_path):
    runner = CliRunner()
    input_file = tmp_path / "events.jsonl"
    output_file = tmp_path / "timeline.json"

    lines = [
        {"timestamp": "2024-01-01T00:00:00Z", "case_id": "A", "message": "a1"},
        {"timestamp": "2024-01-01T00:10:00Z", "case_id": "B", "message": "b1"},
    ]
    input_file.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")

    result = runner.invoke(
        app,
        ["build-timeline", str(input_file), "--output", str(output_file), "--case-id", "A"],
    )
    assert result.exit_code == 0, result.output

    timeline = json.loads(output_file.read_text(encoding="utf-8"))
    serialized = json.dumps(timeline)
    assert "a1" in serialized
    assert "b1" not in serialized
