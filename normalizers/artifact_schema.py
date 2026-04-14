import json
from typing import Dict, Iterable

# Standard JSON schema describing a normalized DFIR artifact event
ARTIFACT_SCHEMA: Dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "DFIRArtifactEvent",
    "type": "object",
    "required": [
        "timestamp",
        "host",
        "source",
        "artifact_type",
        "event_id",
        "raw_data",
    ],
    "properties": {
        "timestamp": {
            "type": "string",
            "description": "ISO8601 timestamp of the event"
        },
        "host": {
            "type": "string",
            "description": "Hostname where the artifact originated"
        },
        "source": {
            "type": "string",
            "description": "Log or telemetry source (e.g. auth.log, windows_security)"
        },
        "artifact_type": {
            "type": "string",
            "description": "Category of artifact (log, process, network, auth, etc.)"
        },
        "event_id": {
            "type": ["string", "integer"],
            "description": "Source-specific event identifier"
        },
        "user": {
            "type": ["string", "null"],
            "description": "User associated with the event"
        },
        "process": {
            "type": ["string", "null"],
            "description": "Process name or path involved in the event"
        },
        "raw_data": {
            "type": "object",
            "description": "Original parsed fields from the source log"
        }
    },
    "additionalProperties": True
}

REQUIRED_FIELDS = set(ARTIFACT_SCHEMA["required"])


def validate_event(event: Dict) -> None:
    """
    Minimal validation ensuring required fields exist.
    Full JSON Schema validation can be added later if desired.
    """
    missing = REQUIRED_FIELDS - set(event.keys())
    if missing:
        raise ValueError(f"Missing required artifact fields: {', '.join(sorted(missing))}")


def write_jsonl(events: Iterable[Dict], output_path: str) -> None:
    """
    Write normalized artifact events to a JSONL file.

    Each line is a single JSON object so downstream modules
    (timeline builder, analytics, exporters) can stream-process events.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        for event in events:
            validate_event(event)
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
