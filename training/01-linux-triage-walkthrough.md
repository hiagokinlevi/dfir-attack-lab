# Tutorial 01: Linux Triage Walkthrough

This tutorial walks through a complete triage run on a Linux system: collecting a live snapshot, parsing an auth.log file, and producing a timeline report.

---

## Prerequisites

- Python 3.11+
- The toolkit installed: `pip install -e ".[dev]"`
- A Linux system or VM (or use the sample log provided below)

---

## Step 1: Collect a Live System Snapshot

Run the `collect-linux` command with a unique case identifier. This command executes only read-only system calls.

```bash
python -m cli.main collect-linux \
    --case-id CASE-2026-001 \
    --output-dir /tmp/dfir-output
```

Expected output:

```
Triage complete: /tmp/dfir-output/CASE-2026-001_linux_triage.jsonl
```

Open the JSONL file to inspect what was collected:

```bash
python -c "import json; data=open('/tmp/dfir-output/CASE-2026-001_linux_triage.jsonl').read(); print(json.dumps(json.loads(data), indent=2))"
```

You will see fields like `system_info`, `active_sessions`, `listening_ports`, `recent_processes`, and `cron_root` (if readable). Any command that failed due to permissions or absence is silently omitted — this is by design.

---

## Step 2: Create a Sample auth.log

For this walkthrough, create a sample auth.log that simulates a brute-force SSH attack followed by a successful login and privilege escalation.

```bash
cat > /tmp/sample_auth.log << 'EOF'
Apr  1 09:58:00 webserver sshd[4001]: Failed password for root from 203.0.113.5 port 51234 ssh2
Apr  1 09:58:12 webserver sshd[4001]: Failed password for root from 203.0.113.5 port 51235 ssh2
Apr  1 09:58:24 webserver sshd[4001]: Failed password for root from 203.0.113.5 port 51236 ssh2
Apr  1 10:02:00 webserver sshd[4050]: Accepted publickey for deploy from 10.0.1.15 port 22 ssh2
Apr  1 10:03:45 webserver sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt-get install curl
EOF
```

---

## Step 3: Parse the auth.log

Use the `parse-logs` command to extract structured events from the sample log:

```bash
python -m cli.main parse-logs /tmp/sample_auth.log \
    -o /tmp/dfir-output/events.json
```

Expected output:

```
Wrote 5 events to /tmp/dfir-output/events.json
```

Inspect the events:

```bash
python -c "import json; events=json.load(open('/tmp/dfir-output/events.json')); [print(e['action'], e['actor'], '->', e['target']) for e in events]"
```

You should see:

```
ssh_login_failure 203.0.113.5 -> root
ssh_login_failure 203.0.113.5 -> root
ssh_login_failure 203.0.113.5 -> root
ssh_login_success 10.0.1.15 -> deploy
sudo_execution deploy -> None
```

Note that `ssh_login_failure` events are classified as `severity: medium`, while `sudo_execution` is `severity: high`.

---

## Step 4: Build the Timeline

Merge the events into a chronological timeline. Use a 4-minute gap threshold — anything silent for longer than 4 minutes will be flagged.

```bash
python -m cli.main build-timeline-cmd /tmp/dfir-output/events.json \
    --gap 4 \
    -o /tmp/dfir-output/timeline.json
```

Expected output:

```
Timeline with N entries written to /tmp/dfir-output/timeline.json
```

Inspect the timeline:

```bash
python -c "
import json
timeline = json.load(open('/tmp/dfir-output/timeline.json'))
for entry in timeline:
    if entry.get('_type') == 'gap':
        print(f'  [GAP: {entry[\"duration_minutes\"]} minutes]')
    else:
        print(f'  {entry[\"timestamp\"]}  {entry[\"action\"]}  ({entry[\"severity\"]})')
"
```

You will see a gap marker between the last SSH failure (09:58:24) and the successful login (10:02:00) — a 3.6-minute silent period.

---

## Summary

In this walkthrough you:

1. Collected a live Linux system snapshot without touching any system state.
2. Parsed a simulated auth.log to extract five normalized events.
3. Built a chronological timeline that automatically flagged a temporal gap.

This three-step pipeline — collect, parse, timeline — is the foundation for all DFIR work with this toolkit.

Next: [Tutorial 02 — Timeline Analysis and Anomaly Identification](02-timeline-analysis.md)
