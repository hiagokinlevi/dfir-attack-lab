import json
from pathlib import Path

from cli.main import main


def test_build_timeline_timezone_utc_renders(tmp_path: Path):
    src = tmp_path / "events.json"
    dst = tmp_path / "timeline.json"

    src.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2024-01-01T12:00:00+00:00",
                    "category": "auth",
                    "severity": "low",
                    "message": "ok",
                }
            ]
        ),
        encoding="utf-8",
    )

    rc = main([
        "build-timeline",
        "--input",
        str(src),
        "--output",
        str(dst),
        "--timezone",
        "UTC",
    ])

    assert rc == 0
    out = json.loads(dst.read_text(encoding="utf-8"))
    assert out[0]["timestamp"].endswith("+00:00")


def test_build_timeline_timezone_invalid_returns_error(tmp_path: Path, capsys):
    src = tmp_path / "events.json"
    dst = tmp_path / "timeline.json"

    src.write_text("[]", encoding="utf-8")

    rc = main([
        "build-timeline",
        "--input",
        str(src),
        "--output",
        str(dst),
        "--timezone",
        "Not/A_Real_Zone",
    ])

    assert rc == 2
    err = capsys.readouterr().err
    assert "Invalid timezone" in err
  