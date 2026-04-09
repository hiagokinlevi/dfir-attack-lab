"""
Linux auth.log / secure log parser.

Extracts structured events from common auth.log patterns:
- SSH authentication failures and successes
- sudo invocations
- PAM events
"""
from __future__ import annotations
import re
from datetime import datetime
from pathlib import Path
from normalizers.models import EventCategory, SeverityHint, TriageEvent

# Regex patterns for common auth.log lines
_SSH_FAIL_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
_SSH_OK_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
_SUDO_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"sudo:.*(?P<user>\S+) : .*COMMAND=(?P<command>.+)"
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(month: str, day: str, time_str: str, year: int = 2026) -> datetime:
    month_num = _MONTH_MAP.get(month, 1)
    h, m, s = (int(x) for x in time_str.split(":"))
    return datetime(year, month_num, int(day), h, m, s)


def parse_authlog(log_path: Path) -> list[TriageEvent]:
    """
    Parse a Linux auth.log file and return a list of normalized TriageEvents.

    Args:
        log_path: Path to the auth.log file to parse.

    Returns:
        List of TriageEvent objects extracted from the log.
    """
    events: list[TriageEvent] = []
    source = str(log_path)

    with log_path.open(errors="replace") as fh:
        for line in fh:
            line = line.rstrip()

            m = _SSH_FAIL_RE.search(line)
            if m:
                events.append(TriageEvent(
                    timestamp=_parse_timestamp(m["month"], m["day"], m["time"]),
                    source_file=source,
                    category=EventCategory.AUTHENTICATION,
                    severity=SeverityHint.MEDIUM,
                    actor=m["ip"],
                    target=m["user"],
                    action="ssh_login_failure",
                    raw=line,
                    metadata={"ip": m["ip"], "username": m["user"]},
                ))
                continue

            m = _SSH_OK_RE.search(line)
            if m:
                events.append(TriageEvent(
                    timestamp=_parse_timestamp(m["month"], m["day"], m["time"]),
                    source_file=source,
                    category=EventCategory.AUTHENTICATION,
                    severity=SeverityHint.INFO,
                    actor=m["ip"],
                    target=m["user"],
                    action="ssh_login_success",
                    raw=line,
                    metadata={"ip": m["ip"], "username": m["user"]},
                ))
                continue

            m = _SUDO_RE.search(line)
            if m:
                events.append(TriageEvent(
                    timestamp=_parse_timestamp(m["month"], m["day"], m["time"]),
                    source_file=source,
                    category=EventCategory.PRIVILEGE_ESCALATION,
                    severity=SeverityHint.HIGH,
                    actor=m["user"],
                    target=None,
                    action="sudo_execution",
                    raw=line,
                    metadata={"user": m["user"], "command": m["command"].strip()},
                ))

    return events
