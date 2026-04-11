# Roadmap

This roadmap tracks planned capabilities for the k1n DFIR Attack Lab toolkit. Each version extends coverage to additional platforms, log sources, and output formats.

---

## v0.1 — Linux Triage + auth.log Parser (Current)

Status: **Complete**

- Read-only Linux system state collector (`collectors/linux/triage.py`)
  - Captures: hostname, kernel info, uptime, active sessions, listening ports, running processes, cron jobs
- Linux `auth.log` / `secure` log parser (`parsers/authlog.py`)
  - Detects: SSH login failures, SSH login successes, sudo invocations
- Normalized `TriageEvent` data model (`normalizers/models.py`)
- Chronological timeline builder with gap detection (`timelines/builder.py`)
- CLI workflow for `collect-linux`, `parse-logs`, `build-timeline`, and `generate-report`
- GitHub Actions CI with 70% coverage gate

---

## v0.2 — Windows Triage + Event Log Parser (Current)

Status: **Complete**

- Windows Security Event Log XML parser (`parsers/windows_evtx.py`)
  - Supports Event IDs: 4624, 4625, 4648, 4720, 4728, 4732, 4756, 4776, 7045
  - Extracts: actor IP, target user, logon type, auth package, service paths
- Read-only Windows triage collector (`collectors/windows/triage.py`)
  - Captures: system info, active sessions, listening ports, running services, scheduled tasks, process list
  - Uses PowerShell read-only cmdlets, no system modifications
- Case packager with SHA-256 integrity manifest (`case/packager.py`)
  - Chain-of-custody documentation for all collected artifacts
  - verify_case() detects any post-collection file tampering
- CLI support for `collect-windows`

---

## v0.3 — macOS Triage Expansion

Status: **Complete**

- Read-only macOS triage collector (`collectors/macos/triage.py`)
  - Captures: host metadata, active sessions, launch agents, launch daemons, login items, recent unified security logs, open connections, and ARP cache
- macOS Unified Log parser (`parsers/macos_unified_log.py`)
  - Parses compact `log show` exports into normalized triage events
  - Covers authentication failures and successes, `sudo` elevation, and LaunchAgent/LaunchDaemon persistence changes
  - Exposed via `k1n-dfir parse-macos-unified-log`

---

## v0.4 — Timeline Visualization

Status: **Complete**

- HTML report generation from timeline JSON (`timelines/reporter.py`)
- Color-coded severity bands in self-contained HTML output
- Gap markers rendered as visual breaks in HTML and TXT reports
- Export to CSV for spreadsheet-based review and evidence packaging
- CLI report generation with filtering by severity, category, time range, and gap inclusion

---

## v0.5 — Offline Process Execution Analysis

Status: **Complete**

- Process tree analyzer for offline EDR and triage process-list exports
  - Detects suspicious Office/browser parent-to-shell execution, system process masquerading, LOLBins, unusual service-context shells, empty shell command lines, child-process fan-out, and attacker tool keywords
  - Exposed via `k1n-dfir analyze-process-tree`
  - Supports JSON output and `--fail-on` severity gating for CI or case-review automation

---

## v0.6 — SIEM Export Adapters

Status: In Progress

- Output adapters for:
  - Elastic Common Schema (ECS) NDJSON — complete via `k1n-dfir generate-report --format ecs`
    - Maps timeline events, case IDs, actor IP/user context, log source paths, severity, raw evidence, and timeline gaps into ECS-oriented documents
  - Microsoft Sentinel CEF format — complete via `k1n-dfir generate-report --format cef`
    - Emits SIEM-friendly Common Event Format lines with case IDs, actor/target context, timestamps, and gap markers
  - Splunk HEC (HTTP Event Collector)
- Planned live-upload support:
  - Configurable via environment variables in `.env`
  - Batch upload with retry logic and rate limiting

---

## Future Considerations

- Memory artifact collection (read-only via `/proc` on Linux)
- Container forensics (Docker layer inspection)
- Network PCAP metadata extraction (no payload reconstruction)
- MITRE ATT&CK tactic tagging on `TriageEvent`
- Additional SIEM adapters and scheduled export profiles
