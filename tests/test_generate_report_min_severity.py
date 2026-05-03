from dfir_attack_lab_cli.reporting import filter_events


def test_filter_events_min_severity_excludes_lower_levels():
    events = [
        {"id": "1", "severity": "low", "message": "low evt"},
        {"id": "2", "severity": "medium", "message": "medium evt"},
        {"id": "3", "severity": "high", "message": "high evt"},
        {"id": "4", "severity": "critical", "message": "critical evt"},
    ]

    filtered = filter_events(events, min_severity="high")

    assert [e["id"] for e in filtered] == ["3", "4"]
