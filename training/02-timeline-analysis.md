# Tutorial 02: Timeline Analysis and Anomaly Identification

This tutorial explains how to read and interpret the timeline output produced by `build-timeline-cmd`, with a focus on identifying anomalies that may indicate attacker activity or evidence gaps.

---

## Understanding the Timeline Format

A timeline JSON file contains an ordered list of entries. Each entry is one of two types:

### 1. Event entry

A serialized `TriageEvent`:

```json
{
  "timestamp": "2026-04-01T09:58:00",
  "source_file": "/tmp/sample_auth.log",
  "category": "authentication",
  "severity": "medium",
  "actor": "203.0.113.5",
  "target": "root",
  "action": "ssh_login_failure",
  "raw": "Apr  1 09:58:00 webserver sshd[4001]: Failed password for root from 203.0.113.5 port 51234 ssh2",
  "metadata": {
    "ip": "203.0.113.5",
    "username": "root"
  }
}
```

### 2. Gap marker

Inserted between consecutive events separated by more than the configured threshold:

```json
{
  "_type": "gap",
  "duration_minutes": 216.0,
  "start": "2026-04-01T09:58:24",
  "end": "2026-04-01T13:34:24"
}
```

---

## Anomaly Patterns to Look For

### Pattern 1: Brute-Force Followed by Success

A cluster of `ssh_login_failure` events from the same actor IP, immediately followed by an `ssh_login_success`, is a strong indicator of a successful brute-force attack.

```
09:58:00  ssh_login_failure  203.0.113.5 -> root  (medium)
09:58:12  ssh_login_failure  203.0.113.5 -> root  (medium)
09:58:24  ssh_login_failure  203.0.113.5 -> root  (medium)
10:02:00  ssh_login_success  10.0.1.15   -> deploy (info)
```

Note that the successful login came from a different IP (`10.0.1.15`) and a different user (`deploy`). This could be coincidental or it could indicate the attacker changed their source IP after the brute-force was blocked. Investigate whether `10.0.1.15` is a known legitimate address.

### Pattern 2: Privilege Escalation After Login

A `sudo_execution` event shortly after an `ssh_login_success` from an unexpected user or IP warrants investigation.

```
10:02:00  ssh_login_success  10.0.1.15   -> deploy (info)
10:03:45  sudo_execution     deploy               (high)
```

Key questions:
- Is `deploy` expected to run `sudo`?
- What command was executed? (check `metadata.command`)
- Is this the first time this user ran `sudo` in the logs?

### Pattern 3: Large Gap in Log Activity

A gap marker covering several hours may indicate:

- Log rotation that was not captured in the artifact
- Log deletion by an attacker covering their tracks
- The system was offline during that period
- The collection window missed earlier events

```json
{
  "_type": "gap",
  "duration_minutes": 360.0,
  "start": "2026-04-01T02:00:00",
  "end": "2026-04-01T08:00:00"
}
```

A 6-hour gap overnight on a production server may be normal (low traffic). The same gap during business hours is suspicious. Context matters.

### Pattern 4: Activity Outside Business Hours

Sort the timeline by hour and look for clusters at unusual times. An `ssh_login_success` at 03:15 on a server that is only accessed during business hours is a red flag.

---

## Working with the Timeline in Python

Load and filter the timeline programmatically:

```python
import json
from pathlib import Path

timeline = json.loads(Path("/tmp/dfir-output/timeline.json").read_text())

# Get only high-severity events
high_sev = [e for e in timeline if e.get("severity") == "high"]

# Get all gaps
gaps = [e for e in timeline if e.get("_type") == "gap"]

# Get events from a specific IP
from_ip = [e for e in timeline if e.get("actor") == "203.0.113.5"]

print(f"High severity events: {len(high_sev)}")
print(f"Timeline gaps: {len(gaps)}")
print(f"Events from 203.0.113.5: {len(from_ip)}")
```

---

## Gap Detection Tuning

The `--gap` parameter controls how sensitive gap detection is:

| Threshold | Use case |
|---|---|
| `--gap 5` | High-traffic servers — flag even short silent periods |
| `--gap 60` | Default — flag anything silent for over an hour |
| `--gap 480` | Overnight analysis — only flag gaps longer than 8 hours |

Start with the default and adjust based on baseline activity for the target system.

---

## Summary

Effective timeline analysis means looking for:

1. Sequences: brute-force attempts leading to success
2. Escalation: login followed by sudo or privileged command
3. Gaps: unexplained silence in log activity
4. Timing: events at unusual hours relative to the system's baseline

All of this is only possible because every event in the timeline shares the same normalized schema. That is the core value of the `TriageEvent` model.
