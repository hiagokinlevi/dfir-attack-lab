# k1n DFIR Attack Lab

A read-only Digital Forensics and Incident Response (DFIR) triage toolkit for Linux, Windows, and macOS systems. It collects non-destructive system observations during an incident, normalizes them into a common event model, and produces structured timeline reports for technical and operational review.

---

## Objective

Provide SOC analysts, incident responders, and forensics practitioners with a standardized pipeline to:

1. Capture a live system snapshot without altering any state.
2. Parse raw log sources into normalized, machine-readable events.
3. Reconstruct a chronological incident timeline with automated gap detection.
4. Export filtered reports in formats that are useful for tickets, spreadsheets, and offline review.

All operations are strictly **read-only**. No files are created, modified, or deleted on the target system.

---

## Problem Solved

During a live incident, responders often collect evidence inconsistently — running ad hoc commands, copy-pasting output, and losing context. This toolkit enforces a repeatable collection procedure and a normalized data model (`TriageEvent`) that any downstream tool can consume.

Key problems addressed:

- **Inconsistent collection**: one command surface, one output model, and read-only collectors for multiple operating systems.
- **Log source fragmentation**: Linux auth logs and Windows event log exports normalize into the same `TriageEvent` schema.
- **Hidden timeline gaps**: the builder flags periods where log activity is absent, which may indicate tampering, rotation, or collection error.
- **Weak incident reporting**: the reporter exports HTML, CSV, TXT, JSON, and JSONL artifacts with optional filtering by severity, category, and time window.

---

## Use Cases

| Role | How they use this toolkit |
|---|---|
| SOC Analyst | Quick triage during alert investigation — run `collect-linux`, `collect-windows`, or `collect-macos` on a suspicious host |
| IR Responder | Full incident timeline reconstruction from collected log artifacts |
| DFIR Analyst | Export filtered HTML/CSV reports for evidence review, ticket attachments, and leadership updates |
| Forensics Student | Hands-on practice with real log parsing and timeline analysis |
| Red Team (authorized) | Understand what blue team visibility looks like from a defender's perspective |

---

## Repository Structure

```
dfir-attack-lab/
├── collectors/
│   ├── linux/
│   │   └── triage.py          # Read-only Linux system state collector
│   ├── windows/
│   │   └── triage.py          # Read-only Windows system state collector
│   └── macos/
│       └── triage.py          # Read-only macOS system state collector
├── parsers/
│   ├── authlog.py             # Linux auth.log / secure log parser
│   ├── macos_unified_log.py   # macOS Unified Log text export parser
│   └── windows_evtx.py        # Windows Security Event Log XML parser
├── normalizers/
│   └── models.py              # Pydantic TriageEvent schema
├── timelines/
│   ├── builder.py             # Chronological timeline builder with gap detection
│   └── reporter.py            # Timeline filters and exports (HTML/CSV/TXT/JSON/JSONL)
├── cli/
│   └── main.py                # Click CLI entry point
├── case/
│   └── packager.py            # Case bundle creation with SHA-256 manifest
├── tests/                     # Pytest test suite (70% coverage gate)
├── training/                  # Step-by-step walkthrough tutorials
├── docs/                      # Architecture and learning path documentation
├── .github/workflows/ci.yml   # GitHub Actions CI pipeline
├── pyproject.toml
└── .env.example
```

---

## How to Run

### Install

```bash
git clone https://github.com/hiagokinlevi/dfir-attack-lab.git
cd dfir-attack-lab
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
k1n-dfir --help
```

### Collect a Linux triage snapshot

```bash
k1n-dfir collect-linux --case-id CASE-001 --output-dir /tmp/dfir-output
```

Output: `/tmp/dfir-output/CASE-001_linux_triage.jsonl`

### Collect Windows or macOS triage snapshots

```bash
k1n-dfir collect-windows --case-id CASE-002 --output-dir /tmp/dfir-output
k1n-dfir collect-macos --case-id CASE-003 --output-dir /tmp/dfir-output
```

### Parse an auth.log file

```bash
k1n-dfir parse-logs /var/log/auth.log -o /tmp/dfir-output/events.json
```

### Build a timeline from parsed events

```bash
k1n-dfir build-timeline /tmp/dfir-output/events.json --gap 30 -o /tmp/dfir-output/timeline.json
```

The `--gap` flag sets the minimum gap duration (in minutes) that triggers a gap marker in the timeline.

### Parse a macOS Unified Log export

Export a compact unified log snapshot on the target host and then parse it offline:

```bash
log show --style compact --last 2h > /tmp/dfir-output/unified.log
k1n-dfir parse-macos-unified-log /tmp/dfir-output/unified.log -o /tmp/dfir-output/macos-events.json
```

The parser currently extracts:

- authentication failures and successes
- `sudo` privilege escalation commands
- `launchd` / `launchctl` persistence changes involving LaunchAgents and LaunchDaemons

### Generate a filtered incident report

```bash
k1n-dfir generate-report /tmp/dfir-output/timeline.json \
  --format html \
  --severity medium \
  --exclude-gaps \
  --output /tmp/dfir-output/timeline-report.html \
  --case-id CASE-001
```

Supported report formats:

- `html` for analyst review and ticket attachments
- `csv` for spreadsheet workflows
- `txt` for chatops or incident tickets
- `json` and `jsonl` for downstream automation

### Run tests

```bash
pytest
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions must maintain the read-only, non-destructive principle.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md).

---

## License

Creative Commons Attribution 4.0 International (CC BY 4.0).
See [LICENSE](LICENSE) for full terms.

---

## Ethical Disclaimer

This toolkit is designed **exclusively for authorized incident response and forensic analysis**. Use only on systems you own or have explicit written permission to investigate. All operations are read-only and non-destructive by design. The authors accept no liability for misuse.

Unauthorized use against systems you do not own or control is illegal and unethical.
