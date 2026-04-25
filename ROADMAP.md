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
  - Captures: host metadata, active sessions, laun

## Automated Completions
- [x] Add --summary-only flag to generate-report CLI (cycle 37)
