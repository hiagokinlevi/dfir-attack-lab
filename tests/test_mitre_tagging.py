from timelines.builder import build_timeline, tag_mitre_attack


def test_event_id_based_mapping_4625_to_t1110():
    event = {"event_id": 4625, "category": "auth_failure", "timestamp": "2024-01-01T00:00:00Z"}
    tags = tag_mitre_attack(event)
    assert any(t["technique_id"] == "T1110" for t in tags)


def test_process_and_commandline_mapping_to_t1059():
    event = {
        "process_name": "powershell.exe",
        "command_line": "powershell -enc AAAA",
        "timestamp": "2024-01-01T00:01:00Z",
    }
    tags = tag_mitre_attack(event)
    assert any(t["technique_id"] == "T1059" for t in tags)


def test_build_timeline_stores_tags_with_entries():
    events = [
        {"event_id": 7045, "service_path": "C:\\Temp\\evil.exe", "timestamp": "2024-01-01T00:02:00Z"},
        {"event_id": 4624, "category": "auth_success", "timestamp": "2024-01-01T00:00:00Z"},
    ]
    timeline = build_timeline(events)

    assert len(timeline) == 2
    assert "mitre_attack" in timeline[0]
    assert isinstance(timeline[0]["mitre_attack"], list)
    all_ids = {t["technique_id"] for ev in timeline for t in ev["mitre_attack"]}
    assert "T1543.003" in all_ids
    assert "T1078" in all_ids
