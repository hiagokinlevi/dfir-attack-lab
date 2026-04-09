# Architecture

## Pipeline Overview

```
[Target System / Log File]
         |
         v
  +-----------+
  | Collector |   collectors/linux/triage.py
  |           |   collectors/windows/triage.py (planned)
  |           |   collectors/macos/triage.py (planned)
  +-----------+
         |
         | Raw output (JSONL or log files)
         v
  +--------+
  | Parser |   parsers/authlog.py
  |        |   parsers/evtx.py (planned)
  |        |   parsers/unifiedlog.py (planned)
  +--------+
         |
         | list[TriageEvent]
         v
  +------------+
  | Normalizer |   normalizers/models.py
  |            |   Pydantic schema enforcement
  +------------+
         |
         | Validated, typed TriageEvent objects
         v
  +-----------------+
  | Timeline Builder|   timelines/builder.py
  |                 |   Sorts, deduplicates, annotates gaps
  +-----------------+
         |
         | list[dict] — chronological timeline
         v
  [JSON output / stdout / future: HTML, SIEM export]
```

---

## Component Responsibilities

### Collectors (`collectors/`)

Collectors capture raw evidence from live systems or stored artifacts. They must satisfy one invariant: **zero writes to the target system**.

On Linux, the collector uses `subprocess.run` with `check=False` and a 30-second timeout. Any command that fails (not found, permission denied, timeout) returns `None` and execution continues. The partial dataset is still written.

Output format: JSONL with a single record per collection run, containing a `case_id`, `collected_at` UTC timestamp, `platform`, and an `observations` dict.

### Parsers (`parsers/`)

Parsers consume raw log files (or collector output) and produce `list[TriageEvent]`. Each parser is responsible for one log source format.

Design principles:
- Open the file with `errors="replace"` to tolerate encoding issues in old logs.
- Use compiled regex patterns for performance on large files.
- Never modify the input file.
- Return an empty list (not raise) if the file contains no recognizable events.

### Normalizer (`normalizers/models.py`)

The `TriageEvent` Pydantic model is the single source of truth for the event schema. Every parser must produce `TriageEvent` objects. This ensures the timeline builder and any downstream consumer can operate on a uniform interface regardless of the original log source.

Key fields:

| Field | Purpose |
|---|---|
| `timestamp` | UTC-aware datetime — the authoritative event time |
| `source_file` | Path to the originating log file — preserved for chain of custody |
| `category` | Enum — authentication, network, process, filesystem, privilege_escalation, system, unknown |
| `severity` | Enum hint — high, medium, low, info — not a definitive classification |
| `actor` | Who or what caused the event (IP, username, process name) |
| `target` | What was affected (username, file path, service) |
| `action` | Normalized verb describing the event (ssh_login_failure, sudo_execution, etc.) |
| `raw` | Verbatim original log line — preserved for audit trail and re-analysis |
| `metadata` | Free-form dict for source-specific fields that do not fit the schema |

### Timeline Builder (`timelines/builder.py`)

The builder sorts events by `timestamp`, then makes a single pass to detect gaps. When the delta between consecutive events exceeds the threshold, a gap marker dict is inserted before the later event.

The gap marker is intentionally a plain dict (not a `TriageEvent`) so it can be serialized alongside events without polluting the event schema.

---

## Data Flow Example

```
/var/log/auth.log
    → parse_authlog() → [TriageEvent, TriageEvent, ...]
    → build_timeline() → [event_dict, gap_dict, event_dict, ...]
    → json.dumps() → timeline.json
```

---

## Extension Points

To add a new log source:

1. Create `parsers/<source>.py` with a function returning `list[TriageEvent]`.
2. Map source-specific fields to the `TriageEvent` schema. Use `metadata` for overflow.
3. Add tests in `tests/test_<source>_parser.py`.

To add a new platform collector:

1. Create `collectors/<platform>/triage.py` with a `run_<platform>_triage(output_dir, case_id)` function.
2. Write only to `output_dir`. Never write to any other path.
3. Add a new CLI command in `cli/main.py`.
