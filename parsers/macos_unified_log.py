"""
macOS Unified Log parser.

Parses text exports produced by:

    log show --style compact > unified.log

The parser extracts high-signal security events commonly reviewed during
incident response:
  - authentication failures and successes
  - sudo privilege escalation commands
  - launchd / launchctl persistence changes
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from normalizers.models import EventCategory, SeverityHint, TriageEvent

_TIMESTAMP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{4}))\s+"
    r"(?P<message>.+)$"
)

_AUTH_FAILURE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"Authentication failed for user (?P<user>\S+)(?: from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?",
        re.IGNORECASE,
    ),
    re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    ),
)

_AUTH_SUCCESS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"Authenticated user (?P<user>\S+)(?: from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?",
        re.IGNORECASE,
    ),
    re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    ),
)

_SUDO_PATTERN = re.compile(
    r"sudo\[\d+\]:\s+(?P<user>\S+)\s+:\s+.*USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<command>.+)",
    re.IGNORECASE,
)

_PERSISTENCE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?:service loaded|bootstrap succeeded|loaded)\s*:?\s*(?P<target>/(?:System/)?Library/(?:LaunchAgents|LaunchDaemons)/\S+\.plist)",
            re.IGNORECASE,
        ),
        "macos_launchd_persistence_loaded",
    ),
    (
        re.compile(
            r"(?:bootout|service unloaded|unloaded)\s*:?\s*(?P<target>/(?:System/)?Library/(?:LaunchAgents|LaunchDaemons)/\S+\.plist)",
            re.IGNORECASE,
        ),
        "macos_launchd_persistence_unloaded",
    ),
)


def _parse_timestamp(raw: str) -> datetime | None:
    """Parse macOS compact log timestamps and normalize to UTC."""
    normalized = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _build_event(
    *,
    timestamp: datetime,
    source: str,
    category: EventCategory,
    severity: SeverityHint,
    actor: str | None,
    target: str | None,
    action: str,
    raw: str,
    metadata: dict,
) -> TriageEvent:
    """Construct a normalized event with consistent defaults."""
    return TriageEvent(
        timestamp=timestamp,
        source_file=source,
        category=category,
        severity=severity,
        actor=actor,
        target=target,
        action=action,
        raw=raw,
        metadata=metadata,
    )


def parse_macos_unified_log(log_path: Path) -> list[TriageEvent]:
    """
    Parse a macOS Unified Log text export into normalized triage events.

    The parser expects compact text output from ``log show --style compact``.
    Unknown lines are ignored so analysts can safely run the parser against
    broad log exports without having to pre-filter them.
    """
    events: list[TriageEvent] = []
    source = str(log_path)

    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw = line.rstrip()
            if not raw:
                continue

            match = _TIMESTAMP_RE.match(raw)
            if not match:
                continue

            timestamp = _parse_timestamp(match["ts"])
            if timestamp is None:
                continue

            message = match["message"]

            for pattern in _AUTH_FAILURE_PATTERNS:
                auth_match = pattern.search(message)
                if auth_match:
                    user = auth_match.groupdict().get("user")
                    ip = auth_match.groupdict().get("ip")
                    events.append(
                        _build_event(
                            timestamp=timestamp,
                            source=source,
                            category=EventCategory.AUTHENTICATION,
                            severity=SeverityHint.MEDIUM,
                            actor=ip,
                            target=user,
                            action="macos_authentication_failure",
                            raw=raw,
                            metadata={"username": user, "ip": ip, "parser": "macos_unified_log"},
                        )
                    )
                    break
            else:
                for pattern in _AUTH_SUCCESS_PATTERNS:
                    auth_match = pattern.search(message)
                    if auth_match:
                        user = auth_match.groupdict().get("user")
                        ip = auth_match.groupdict().get("ip")
                        events.append(
                            _build_event(
                                timestamp=timestamp,
                                source=source,
                                category=EventCategory.AUTHENTICATION,
                                severity=SeverityHint.INFO,
                                actor=ip,
                                target=user,
                                action="macos_authentication_success",
                                raw=raw,
                                metadata={"username": user, "ip": ip, "parser": "macos_unified_log"},
                            )
                        )
                        break
                else:
                    sudo_match = _SUDO_PATTERN.search(message)
                    if sudo_match:
                        events.append(
                            _build_event(
                                timestamp=timestamp,
                                source=source,
                                category=EventCategory.PRIVILEGE_ESCALATION,
                                severity=SeverityHint.HIGH,
                                actor=sudo_match["user"],
                                target=sudo_match["target"],
                                action="macos_sudo_execution",
                                raw=raw,
                                metadata={
                                    "user": sudo_match["user"],
                                    "target_user": sudo_match["target"],
                                    "command": sudo_match["command"].strip(),
                                    "parser": "macos_unified_log",
                                },
                            )
                        )
                        continue

                    for pattern, action in _PERSISTENCE_PATTERNS:
                        persistence_match = pattern.search(message)
                        if persistence_match:
                            target = persistence_match["target"]
                            events.append(
                                _build_event(
                                    timestamp=timestamp,
                                    source=source,
                                    category=EventCategory.SYSTEM,
                                    severity=SeverityHint.HIGH,
                                    actor=None,
                                    target=target,
                                    action=action,
                                    raw=raw,
                                    metadata={"plist_path": target, "parser": "macos_unified_log"},
                                )
                            )
                            break

    return events
