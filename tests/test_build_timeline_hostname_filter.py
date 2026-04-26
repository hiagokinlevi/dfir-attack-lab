import json
from datetime import datetime, timedelta, timezone

from typer.testing import CliRunner

from dfir_attack_lab_cli.cli import app


def _event(ts: datetime, host: str):
    return {
        "timestamp": ts.isoformat(),
        "source": "unit-test",
        "event_type": "auth",
        "severity": "low",
        "message": f"event on {host}",
        "host": host,
        "hostname": host,
        "raw": {},
    }


def test_build_timeline_hostname_filter_and_default_behavior(tmp_path):
    runner = CliRunner()
    base = datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)

    events = [
        _event(base, "host-a"),
        _event(base + timedelta(minutes=10), "host-b"),
        _event(base + timedelta(minutes=20), "host-a"),
    ]

    input_file = tmp_path / "events.json"
    input_file.write_text(json.dumps(events), encoding="utf-8")

    out_all = tmp_path / "timeline_all.json"
    result_all = runner.invoke(app, ["build-timeline", str(input_file), str(out_all)])
    assert result_all.exit_code == 0, result_all.output
    all_data = json.loads(out_all.read_text(encoding="utf-8"))
    assert len(all_data["events"]) == 3

    out_filtered = tmp_path / "timeline_host_a.json"
    result_filtered = runner.invoke(
        app,
        ["build-timeline", str(input_file), str(out_filtered), "--hostname", "host-a"],
    )
    assert result_filtered.exit_code == 0, result_filtered.output

    filtered_data = json.loads(out_filtered.read_text(encoding="utf-8"))
    assert len(filtered_data["events"]) == 2
    assert all(
        (evt.get("host") == "host-a" or evt.get("hostname") == "host-a")
        for evt in filtered_data["events"]
    )
