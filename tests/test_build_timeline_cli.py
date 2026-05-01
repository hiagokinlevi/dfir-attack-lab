import json

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


runner = CliRunner()


def test_build_timeline_default_and_desc_sort(tmp_path):
    events = [
        {
            "timestamp": "2024-01-01T10:00:00Z",
            "host": "host1",
            "source": "authlog",
            "category": "auth",
            "severity": "low",
            "message": "older",
        },
        {
            "timestamp": "2024-01-01T12:00:00Z",
            "host": "host1",
            "source": "authlog",
            "category": "auth",
            "severity": "low",
            "message": "newer",
        },
    ]

    in_file = tmp_path / "events.json"
    out_default = tmp_path / "timeline_default.json"
    out_desc = tmp_path / "timeline_desc.json"

    in_file.write_text(json.dumps(events), encoding="utf-8")

    result_default = runner.invoke(
        app,
        [
            "build-timeline",
            "--input",
            str(in_file),
            "--output",
            str(out_default),
        ],
    )
    assert result_default.exit_code == 0, result_default.output

    result_desc = runner.invoke(
        app,
        [
            "build-timeline",
            "--input",
            str(in_file),
            "--output",
            str(out_desc),
            "--sort-desc",
        ],
    )
    assert result_desc.exit_code == 0, result_desc.output

    default_timeline = json.loads(out_default.read_text(encoding="utf-8"))
    desc_timeline = json.loads(out_desc.read_text(encoding="utf-8"))

    default_events = [e for e in default_timeline if e.get("type") == "event"]
    desc_events = [e for e in desc_timeline if e.get("type") == "event"]

    assert default_events[0]["message"] == "older"
    assert default_events[-1]["message"] == "newer"

    assert desc_events[0]["message"] == "newer"
    assert desc_events[-1]["message"] == "older"
