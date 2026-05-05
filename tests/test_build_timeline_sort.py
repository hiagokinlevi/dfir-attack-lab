import json

from dfir_attack_lab_cli.main import main


def _event(ts: str, msg: str):
    return {
        "timestamp": ts,
        "source": "unit",
        "category": "auth",
        "severity": "low",
        "message": msg,
        "raw": {},
    }


def test_build_timeline_sort_directions(tmp_path):
    events = [
        _event("2024-01-01T00:00:03Z", "third"),
        _event("2024-01-01T00:00:01Z", "first"),
        _event("2024-01-01T00:00:02Z", "second"),
    ]

    in_file = tmp_path / "events.json"
    in_file.write_text(json.dumps(events), encoding="utf-8")

    asc_file = tmp_path / "timeline-asc.json"
    rc = main(["build-timeline", "--input", str(in_file), "--output", str(asc_file), "--sort", "asc"])
    assert rc == 0
    asc = json.loads(asc_file.read_text(encoding="utf-8"))
    assert [e["message"] for e in asc] == ["first", "second", "third"]

    desc_file = tmp_path / "timeline-desc.json"
    rc = main(["build-timeline", "--input", str(in_file), "--output", str(desc_file), "--sort", "desc"])
    assert rc == 0
    desc = json.loads(desc_file.read_text(encoding="utf-8"))
    assert [e["message"] for e in desc] == ["third", "second", "first"]
