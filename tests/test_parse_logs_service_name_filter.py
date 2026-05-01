from types import SimpleNamespace

from cli.main import parse_logs_command


class _Evt:
    def __init__(self, source, event_id, service_name=None, message=None):
        self.source = source
        self.event_id = event_id
        self.service_name = service_name
        self.message = message


def test_parse_logs_windows_service_name_filter_matches_and_excludes(monkeypatch, tmp_path):
    def _fake_parse_windows_evtx(_):
        return [
            _Evt("windows_evtx", 7045, service_name="AcmeUpdaterSvc", message="Service installed"),
            _Evt("windows_evtx", 7045, service_name="BackupAgent", message="Service installed"),
            _Evt("windows_evtx", 4624, service_name="Ignored", message="Not service install"),
        ]

    monkeypatch.setattr("cli.main.parse_windows_evtx", _fake_parse_windows_evtx)

    args = SimpleNamespace(input=str(tmp_path / "x.evtx"), parser="windows-evtx", service_name="updater")
    events = parse_logs_command(args)

    assert len(events) == 1
    assert events[0].service_name == "AcmeUpdaterSvc"

    args_non_match = SimpleNamespace(input=str(tmp_path / "x.evtx"), parser="windows-evtx", service_name="does-not-exist")
    events_non_match = parse_logs_command(args_non_match)

    assert events_non_match == []
