from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from typer.testing import CliRunner

from dfir_attack_lab_cli.main import app


def test_build_timeline_json_output_writes_file_and_schema(tmp_path):
    runner = CliRunner()

    t0 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=1)
    t2 = t0 + timedelta(hours=2)

    events = [
        {
            "timestamp": t0.isoformat(),
            "host": "host-a",
            "source": "auth.log",
            "event_type": "ssh_login_failed",
            "severity": "medium",
            "message": "failed ssh",
            "raw": "raw1",
        },
        {
            "timestamp": t1.isoformat(),
            "host": "host-a",
            "source": "auth.log",
            "event_type": "ssh_login_success",
            "severity": "low",
            "message": "success ssh",
            "raw": "raw2",
        },
        {
            "timestamp": t2.isoformat(),
            "host": "host-a",
            "source": "auth.log",
            "event_type": "sudo_invocation",
            "severity": "high",
            "message": "sudo",
            "raw": "raw3",
        },
    ]

    input_file = tmp_path / "events.json"
    text_output = tmp_path / "timeline.txt"
    json_output = tmp_path / "timeline.json"

    input_file.write_text(json.dumps(events), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "build-timeline",
            str(input_file),
            "--output",
            str(text_output),
            "--json-output",
            str(json_output),
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert text_output.exists()
    assert json_output.exists()

    payload = json.loads(json_output.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "1.0"
    assert "timeline" in payload
    assert "events" in payload["timeline"]
    assert "gaps" in payload["timeline"]

    assert len(payload["timeline"]["events"]) == 3
    first_event = payload["timeline"]["events"][0]
    assert first_event["event_type"] == "ssh_login_failed"
    assert first_event["source"] == "auth.log"

    assert isinstance(payload["timeline"]["gaps"], list)
    if payload["timeline"]["gaps"]:
        gap = payload["timeline"]["gaps"][0]
        assert set(gap.keys()) == {"start", "end", "duration_seconds"}
