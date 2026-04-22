from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from normalizers.models import TriageEvent


SSH_FAILED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<src_ip>\S+)"
    r"(?: port (?P<src_port>\d+))?",
)

SSH_ACCEPTED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+)"
    r"(?: port (?P<src_port>\d+))?",
)

SUDO_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+sudo:\s+"
    r"(?P<actor>\S+)\s*:\s*.*COMMAND=(?P<command>.+)$",
)


def _parse_ts(ts: str, year: Optional[int] = None) -> datetime:
    if year is None:
        year = datetime.utcnow().year
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")


def parse_authlog(lines: Iterable[str], source: str = "auth.log") -> list[TriageEvent]:
    events: list[TriageEvent] = []

    for raw in lines:
        line = raw.rstrip("\n")

        m = SSH_FAILED_RE.match(line)
        if m:
            md = {
                "src_ip": m.group("src_ip"),
            }
            if m.group("src_port"):
                md["src_port"] = int(m.group("src_port"))
            events.append(
                TriageEvent(
                    timestamp=_parse_ts(m.group("ts")),
                    source=source,
                    category="authentication",
                    event_type="ssh_login_failed",
                    severity="medium",
                    actor=m.group("src_ip"),
                    target=m.group("user"),
                    raw=line,
                    metadata=md,
                )
            )
            continue

        m = SSH_ACCEPTED_RE.match(line)
        if m:
            md = {
                "src_ip": m.group("src_ip"),
            }
            if m.group("src_port"):
                md["src_port"] = int(m.group("src_port"))
            events.append(
                TriageEvent(
                    timestamp=_parse_ts(m.group("ts")),
                    source=source,
                    category="authentication",
                    event_type="ssh_login_success",
                    severity="low",
                    actor=m.group("src_ip"),
                    target=m.group("user"),
                    raw=line,
                    metadata=md,
                )
            )
            continue

        m = SUDO_RE.match(line)
        if m:
            events.append(
                TriageEvent(
                    timestamp=_parse_ts(m.group("ts")),
                    source=source,
                    category="privilege_escalation",
                    event_type="sudo_command",
                    severity="medium",
                    actor=m.group("actor"),
                    target="root",
                    raw=line,
                    metadata={"command": m.group("command").strip()},
                )
            )

    return events


def parse_authlog_file(path: str | Path) -> list[TriageEvent]:
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace") as f:
        return parse_authlog(f, source=p.name)
