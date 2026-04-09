# DFIR Basics — Beginner Learning Path

This learning path is for analysts new to Digital Forensics and Incident Response. It covers foundational concepts, hands-on exercises with this toolkit, and pointers to further study.

---

## What is DFIR?

**Digital Forensics** is the practice of collecting, preserving, and analyzing digital evidence to reconstruct past events.

**Incident Response** is the structured process of detecting, containing, eradicating, and recovering from a security incident.

DFIR combines both disciplines: you need forensic rigor (preserve evidence, maintain chain of custody, document everything) and IR speed (the attacker may still be active).

---

## The DFIR Lifecycle

```
1. Preparation   — tools, runbooks, authority to act
2. Detection     — SIEM alert, anomaly, or human observation
3. Containment   — isolate affected systems (stop the bleeding)
4. Eradication   — remove attacker persistence mechanisms
5. Recovery      — restore systems to known-good state
6. Lessons Learned — what happened and how to prevent recurrence
```

This toolkit focuses on step 2 (evidence collection for detection confirmation) and the forensic evidence gathering that informs step 3.

---

## Core Concepts

### Chain of Custody

Every artifact you collect must be traceable: who collected it, when, from which system, and how. The `case_id` and `collected_at` timestamp in every JSONL record are the starting point. You are responsible for documenting the rest.

### Non-Destructive Collection

Reading a file changes the file's `atime` (access time) on many Linux systems. This toolkit uses standard commands that minimize this footprint, but be aware that any interaction with a live system leaves traces.

For strict forensic work (legal proceedings), disk imaging with a write blocker is required. This toolkit is for **triage** — rapid, good-enough evidence for initial assessment.

### Normalization

Raw log lines from different sources (Linux syslog, Windows Event Log, macOS unified log) have completely different formats. The `TriageEvent` model normalizes them into a common schema so you can build a single timeline from many sources.

---

## Module 1: Environment Setup

1. Clone this repository and install it:
   ```bash
   pip install -e ".[dev]"
   pytest  # verify tests pass
   ```

2. Read `normalizers/models.py`. Understand each field of `TriageEvent` and why it exists.

3. Read `collectors/linux/triage.py`. Identify every system command it runs. Verify each one is read-only.

---

## Module 2: Log Sources

Study the most common Linux log sources:

| File | Contains |
|---|---|
| `/var/log/auth.log` or `/var/log/secure` | Authentication events: SSH, sudo, PAM |
| `/var/log/syslog` or `/var/log/messages` | General system events |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/cron` | Cron job execution |
| `/var/log/dpkg.log` | Package installation history |
| `/root/.bash_history` | Root shell command history (if not cleared) |

Exercise: On your own Linux system, open `/var/log/auth.log` (or `/var/log/secure`) and manually identify three login failure entries. What information does each line contain?

---

## Module 3: Running Your First Triage

Follow [Tutorial 01 — Linux Triage Walkthrough](../../training/01-linux-triage-walkthrough.md) end to end.

After completing it, answer these questions:

1. What is the `collected_at` timestamp format? Why UTC?
2. Which observation fields were `null` or missing on your system, and why?
3. What does a gap marker tell you about the evidence?

---

## Module 4: Analyzing a Timeline

Follow [Tutorial 02 — Timeline Analysis](../../training/02-timeline-analysis.md).

Practice exercise: create a synthetic auth.log with an overnight gap (e.g., last event at 23:00, next event at 06:00). Run `parse-logs` and `build-timeline-cmd` with `--gap 60`. Count the gaps detected.

---

## Module 5: Understanding Indicators of Compromise

Common IOCs visible in an auth.log timeline:

| Indicator | What to look for |
|---|---|
| Brute force | Many `ssh_login_failure` from one IP in a short window |
| Password spray | `ssh_login_failure` targeting many different usernames |
| Successful intrusion | `ssh_login_success` from an unfamiliar IP or at unusual hours |
| Lateral movement | `ssh_login_success` from an internal IP not normally used for SSH |
| Privilege escalation | `sudo_execution` for a user who should not have sudo access |
| Persistence | A new cron job entry appearing in the triage snapshot |

---

## Further Study

- NIST SP 800-61r2: Computer Security Incident Handling Guide (free PDF)
- SANS DFIR posters (free): memory forensics, log analysis cheat sheets
- Blue Team Labs Online: free DFIR challenge platform
- TryHackMe — "Incident Response and Forensics" learning path
- Autopsy (free): open-source digital forensics platform for disk images
- Volatility Framework: open-source memory forensics

---

## Next Steps in This Repository

- Read `docs/architecture.md` to understand how the pipeline is designed.
- Explore `parsers/authlog.py` in detail — study the regex patterns.
- Try writing a new parser for `/var/log/dpkg.log` as a practice exercise.
- Read `ROADMAP.md` to see where the project is headed.
