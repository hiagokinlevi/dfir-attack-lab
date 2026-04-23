from __future__ import annotations

import json
from pathlib import Path

from normalizers.models import TriageEvent
from timelines.reporter import export_jsonl_report


def test_export_jsonl_is_utf8_and_newline_terminated(tmp_path: Path) -> None:
    events = [
        TriageEvent(
            timestamp="2026-01-01T00:00:00Z",
            host="lab-host",
            source="unit-test",
            category="auth",
            event_type="login_success",
            severity="low",
            message="User logged in: café 🚀",
            raw={"detail": "naïve façade"},
        ),
        TriageEvent(
            timestamp="2026-01-01T00:01:00Z",
            host="lab-host",
            source="unit-test",
            category="process",
            event_type="process_start",
            severity="medium",
            message="Started binary",
            raw={"cmdline": "python -c 'print(\"✓\")'"},
        ),
    ]

    out_file = tmp_path / "report.jsonl"
    export_jsonl_report(events, out_file)

    data = out_file.read_bytes()

    # Output should be UTF-8 decodable and newline-terminated.
    text = data.decode("utf-8")
    assert text.endswith("\n")

    # Each event must be line-delimited JSON with no blank records.
    lines = text.splitlines()
    assert len(lines) == len(events)
    assert all(line.strip() for line in lines)

    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["message"] == "User logged in: café 🚀"
    assert parsed[0]["raw"]["detail"] == "naïve façade"
    assert parsed[1]["raw"]["cmdline"] == "python -c 'print(\"✓\")'"
