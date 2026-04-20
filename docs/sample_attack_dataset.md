# Sample DFIR Attack Simulation Dataset

This document provides a **controlled lab dataset** for validating parser, normalization, and timeline workflows.

It includes:
- Raw artifact snippets (Linux `auth.log`, Windows Security/System EVTX XML export fragments)
- Expected normalized events (JSONL-style)
- Expected timeline output ordering

Use this for parser validation and demo walkthroughs only.

---

## Scenario Overview

Host set:
- `LINUX-WEB-01` (Ubuntu) — initial access + privilege escalation + persistence
- `WIN-APP-01` (Windows Server) — lateral movement + service-based persistence

Attack story (lab-generated):
1. Repeated SSH failures from attacker IP to Linux host.
2. Successful SSH login as low-privilege user.
3. `sudo` used for privilege escalation.
4. Persistence established via cron.
5. Lateral movement to Windows using explicit credentials.
6. Malicious service installed on Windows.

Time window (UTC): `2026-02-14T10:15:00Z` to `2026-02-14T10:21:00Z`

---

## Raw Artifacts

### 1) Linux `auth.log` snippet (`raw/linux/auth.log`)

```log
Feb 14 10:15:02 LINUX-WEB-01 sshd[1183]: Failed password for invalid user admin from 10.10.50.23 port 52644 ssh2
Feb 14 10:15:08 LINUX-WEB-01 sshd[1188]: Failed password for invalid user root from 10.10.50.23 port 52688 ssh2
Feb 14 10:16:11 LINUX-WEB-01 sshd[1202]: Accepted password for analyst from 10.10.50.23 port 52990 ssh2
Feb 14 10:16:40 LINUX-WEB-01 sudo:  analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id
Feb 14 10:17:05 LINUX-WEB-01 sudo:  analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/tee /etc/cron.d/.sys-updater
```

### 2) Windows Security EVTX XML fragment (`raw/windows/security.xml`)

```xml
<Events>
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4648</EventID>
      <TimeCreated SystemTime="2026-02-14T10:19:10.000Z"/>
      <Computer>WIN-APP-01.lab.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">analyst</Data>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="TargetServerName">WIN-APP-01</Data>
      <Data Name="IpAddress">10.10.50.23</Data>
    </EventData>
  </Event>

  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-02-14T10:19:14.000Z"/>
      <Computer>WIN-APP-01.lab.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="IpAddress">10.10.50.23</Data>
      <Data Name="AuthenticationPackageName">Negotiate</Data>
    </EventData>
  </Event>
</Events>
```

### 3) Windows System EVTX XML fragment (`raw/windows/system.xml`)

```xml
<Events>
  <Event>
    <System>
      <Provider Name="Service Control Manager"/>
      <EventID>7045</EventID>
      <TimeCreated SystemTime="2026-02-14T10:20:02.000Z"/>
      <Computer>WIN-APP-01.lab.local</Computer>
    </System>
    <EventData>
      <Data Name="ServiceName">WinUpdateCheck</Data>
      <Data Name="ImagePath">C:\ProgramData\wucheck.exe</Data>
      <Data Name="StartType">auto start</Data>
      <Data Name="ServiceAccount">LocalSystem</Data>
    </EventData>
  </Event>
</Events>
```

---

## Expected Normalized Events (`expected/normalized_events.jsonl`)

```jsonl
{"timestamp":"2026-02-14T10:15:02Z","host":"LINUX-WEB-01","source":"auth.log","event_id":"ssh_failed","category":"authentication","severity":"medium","actor_ip":"10.10.50.23","target_user":"admin","summary":"SSH failed login for invalid user admin"}
{"timestamp":"2026-02-14T10:15:08Z","host":"LINUX-WEB-01","source":"auth.log","event_id":"ssh_failed","category":"authentication","severity":"medium","actor_ip":"10.10.50.23","target_user":"root","summary":"SSH failed login for invalid user root"}
{"timestamp":"2026-02-14T10:16:11Z","host":"LINUX-WEB-01","source":"auth.log","event_id":"ssh_success","category":"authentication","severity":"low","actor_ip":"10.10.50.23","target_user":"analyst","summary":"SSH successful login for analyst"}
{"timestamp":"2026-02-14T10:16:40Z","host":"LINUX-WEB-01","source":"auth.log","event_id":"sudo_command","category":"privilege_escalation","severity":"high","actor_user":"analyst","target_user":"root","command":"/usr/bin/id","summary":"Sudo command executed as root"}
{"timestamp":"2026-02-14T10:17:05Z","host":"LINUX-WEB-01","source":"auth.log","event_id":"sudo_command","category":"persistence","severity":"high","actor_user":"analyst","target_user":"root","command":"/usr/bin/tee /etc/cron.d/.sys-updater","summary":"Potential cron persistence via sudo"}
{"timestamp":"2026-02-14T10:19:10Z","host":"WIN-APP-01.lab.local","source":"security.evtx","event_id":"4648","category":"lateral_movement","severity":"high","actor_user":"analyst","target_user":"Administrator","actor_ip":"10.10.50.23","summary":"Explicit credentials used for remote access"}
{"timestamp":"2026-02-14T10:19:14Z","host":"WIN-APP-01.lab.local","source":"security.evtx","event_id":"4624","category":"authentication","severity":"medium","target_user":"Administrator","logon_type":"3","actor_ip":"10.10.50.23","summary":"Network logon success"}
{"timestamp":"2026-02-14T10:20:02Z","host":"WIN-APP-01.lab.local","source":"system.evtx","event_id":"7045","category":"persistence","severity":"critical","service_name":"WinUpdateCheck","service_path":"C:\\ProgramData\\wucheck.exe","summary":"New auto-start service installed"}
```

---

## Expected Timeline View (`expected/timeline.txt`)

```txt
2026-02-14T10:15:02Z | LINUX-WEB-01         | authentication       | medium   | SSH failed login for invalid user admin
2026-02-14T10:15:08Z | LINUX-WEB-01         | authentication       | medium   | SSH failed login for invalid user root
2026-02-14T10:16:11Z | LINUX-WEB-01         | authentication       | low      | SSH successful login for analyst
2026-02-14T10:16:40Z | LINUX-WEB-01         | privilege_escalation | high     | Sudo command executed as root
2026-02-14T10:17:05Z | LINUX-WEB-01         | persistence          | high     | Potential cron persistence via sudo
2026-02-14T10:19:10Z | WIN-APP-01.lab.local | lateral_movement     | high     | Explicit credentials used for remote access
2026-02-14T10:19:14Z | WIN-APP-01.lab.local | authentication       | medium   | Network logon success
2026-02-14T10:20:02Z | WIN-APP-01.lab.local | persistence          | critical | New auto-start service installed
```

---

## Validation Notes

- This dataset is intentionally small and deterministic for unit/integration validation.
- If parser outputs differ, compare:
  1. Timestamp parsing and timezone handling
  2. Event category mapping (`sudo` -> `privilege_escalation`/`persistence` by command context)
  3. Windows Event ID extraction and field naming
- Suggested checks:
  - Event count: `8`
  - First event timestamp: `2026-02-14T10:15:02Z`
  - Last event timestamp: `2026-02-14T10:20:02Z`
  - Contains categories: `authentication`, `privilege_escalation`, `persistence`, `lateral_movement`
