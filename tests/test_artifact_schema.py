import json
import tempfile

from normalizers.artifact_schema import validate_event, write_jsonl


def test_validate_event_accepts_valid_event():
    event = {
        "timestamp": "2025-01-01T12:00:00Z",
        "host": "test-host",
        "source": "auth.log",
        "artifact_type": "authentication",
        "event_id": "ssh_login",
        "user": "alice",
        "process": "sshd",
        "raw_data": {"message": "Accepted password for alice"},
    }

    validate_event(event)


def test_validate_event_missing_required():
    bad_event = {
        "timestamp": "2025-01-01T12:00:00Z"
    }

    try:
        validate_event(bad_event)
        assert False, "Expected validation failure"
    except ValueError:
        assert True


def test_write_jsonl_creates_valid_lines():
    events = [
        {
            "timestamp": "2025-01-01T12:00:00Z",
            "host": "host1",
            "source": "auth.log",
            "artifact_type": "authentication",
            "event_id": "ssh_login",
            "user": "bob",
            "process": "sshd",
            "raw_data": {"message": "Accepted password"},
        }
    ]

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        path = tmp.name

    write_jsonl(events, path)

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    assert len(lines) == 1

    parsed = json.loads(lines[0])
    assert parsed["host"] == "host1"
    assert parsed["artifact_type"] == "authentication"
