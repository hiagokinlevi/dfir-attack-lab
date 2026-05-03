import json
from pathlib import Path

from dfir_attack_lab_cli.main import main


class _Evt:
    def __init__(self, event_id: int):
        self.event_id = event_id

    def to_dict(self):
        return {"event_id": self.event_id}


def test_parse_logs_windows_evtx_event_id_filter(monkeypatch, tmp_path: Path):
    in_file = tmp_path / "security.xml"
    out_file = tmp_path / "out.json"
    in_file.write_text("<Events />", encoding="utf-8")

    def _fake_parse(_path):
        return [_Evt(4625), _Evt(4624), _Evt(7045)]

    monkeypatch.setattr("dfir_attack_lab_cli.main.parse_windows_evtx_xml", _fake_parse)

    rc = main(
        [
            "parse-logs",
            "--parser",
            "windows-evtx",
            "--input",
            str(in_file),
            "--output",
            str(out_file),
            "--event-id",
            "4625",
            "--event-id",
            "7045",
        ]
    )

    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert [d["event_id"] for d in data] == [4625, 7045]


def test_parse_logs_authlog_ignores_event_id(monkeypatch, tmp_path: Path):
    in_file = tmp_path / "auth.log"
    out_file = tmp_path / "out.json"
    in_file.write_text("", encoding="utf-8")

    class _A:
        def to_dict(self):
            return {"source": "authlog"}

    monkeypatch.setattr("dfir_attack_lab_cli.main.parse_auth_log", lambda _p: [_A()])

    rc = main(
        [
            "parse-logs",
            "--parser",
            "authlog",
            "--input",
            str(in_file),
            "--output",
            str(out_file),
            "--event-id",
            "4625",
        ]
    )

    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data == [{"source": "authlog"}]
