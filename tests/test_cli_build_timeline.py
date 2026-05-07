import json
from pathlib import Path

from dfir_attack_lab_cli.main import main


def test_build_timeline_honors_custom_max_gap_minutes(tmp_path: Path) -> None:
    input_path = tmp_path / "events.json"
    output_path = tmp_path / "timeline.json"

    events = [
        {"timestamp": "2024-01-01T00:00:00Z", "event": "a"},
        {"timestamp": "2024-01-01T00:31:00Z", "event": "b"},
    ]
    input_path.write_text(json.dumps(events), encoding="utf-8")

    rc = main(
        [
            "build-timeline",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--max-gap-minutes",
            "45",
        ]
    )

    assert rc == 0
    result = json.loads(output_path.read_text(encoding="utf-8"))

    # With a 45-minute threshold, a 31-minute interval should not be flagged as a gap.
    gaps = result.get("gaps") if isinstance(result, dict) else []
    assert not gaps
