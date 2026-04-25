import json
from pathlib import Path

from dfir_attack_lab_cli.main import main


WINDOWS_XML = """<?xml version=\"1.0\" encoding=\"utf-8\"?>
<Events>
  <Event>
    <System>
      <EventID>4624</EventID>
      <TimeCreated SystemTime=\"2024-01-01T00:00:00.000Z\"/>
      <Computer>host1</Computer>
    </System>
    <EventData>
      <Data Name=\"TargetUserName\">alice</Data>
      <Data Name=\"IpAddress\">10.0.0.1</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>4625</EventID>
      <TimeCreated SystemTime=\"2024-01-01T00:01:00.000Z\"/>
      <Computer>host1</Computer>
    </System>
    <EventData>
      <Data Name=\"TargetUserName\">bob</Data>
      <Data Name=\"IpAddress\">10.0.0.2</Data>
    </EventData>
  </Event>
  <Event>
    <System>
      <EventID>7045</EventID>
      <TimeCreated SystemTime=\"2024-01-01T00:02:00.000Z\"/>
      <Computer>host1</Computer>
    </System>
    <EventData>
      <Data Name=\"ServiceName\">evilsvc</Data>
      <Data Name=\"ImagePath\">C:\\Temp\\evil.exe</Data>
    </EventData>
  </Event>
</Events>
"""


def _read_ids(path: Path) -> list[int]:
    ids = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        ids.append(int(obj.get("event_id")))
    return ids


def test_parse_logs_windows_event_id_filter_single_and_multiple(tmp_path: Path) -> None:
    in_file = tmp_path / "security.xml"
    in_file.write_text(WINDOWS_XML, encoding="utf-8")

    # Omitted filter -> existing behavior unchanged (all supported events emitted)
    out_all = tmp_path / "all.jsonl"
    rc = main([
        "parse-logs",
        "--source",
        "windows-security-evtx",
        "--input",
        str(in_file),
        "--output",
        str(out_all),
    ])
    assert rc == 0
    assert set(_read_ids(out_all)) == {4624, 4625, 7045}

    # Single event-id
    out_single = tmp_path / "single.jsonl"
    rc = main([
        "parse-logs",
        "--source",
        "windows-security-evtx",
        "--input",
        str(in_file),
        "--output",
        str(out_single),
        "--event-id",
        "4624",
    ])
    assert rc == 0
    assert _read_ids(out_single) == [4624]

    # Multiple event-id values
    out_multi = tmp_path / "multi.jsonl"
    rc = main([
        "parse-logs",
        "--source",
        "windows-security-evtx",
        "--input",
        str(in_file),
        "--output",
        str(out_multi),
        "--event-id",
        "4625",
        "--event-id",
        "7045",
    ])
    assert rc == 0
    assert set(_read_ids(out_multi)) == {4625, 7045}
