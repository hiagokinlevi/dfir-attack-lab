"""
Cross-Source Log Correlation Engine
=====================================
Correlates events from heterogeneous log sources (auth.log, Windows Event
Log, container logs, honeypot feeds) by shared attributes — source IP,
username, and time proximity — to detect multi-stage attack patterns.

Correlation Patterns Detected
-------------------------------
LATERAL_MOVEMENT   — successful auth followed by access from the same IP
                     to a different host within the correlation window
PRIVILEGE_ESCALATION — auth event then sudo/privilege command from same user
BRUTE_THEN_SUCCESS — high-volume failures followed by a successful auth
SPRAY_THEN_PIVOT   — credential spray (many users, one IP) then successful auth
PERSISTENCE        — user creation or cron/startup modification following auth
RECON_THEN_EXPLOIT — network scan followed by service exploitation
ANOMALOUS_TIME     — successful auth outside the user's normal working hours
                     (configurable via ``working_hours``)

Usage::

    from analysis.log_correlator import LogCorrelator

    correlator = LogCorrelator(window_seconds=600)
    correlator.add_events(auth_events, source="auth.log")
    correlator.add_events(windows_events, source="evtx")
    report = correlator.correlate()
    for incident in report.incidents:
        print(incident.summary())
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class CorrelationPattern(str, Enum):
    LATERAL_MOVEMENT      = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION  = "PRIVILEGE_ESCALATION"
    BRUTE_THEN_SUCCESS    = "BRUTE_THEN_SUCCESS"
    SPRAY_THEN_PIVOT      = "SPRAY_THEN_PIVOT"
    PERSISTENCE           = "PERSISTENCE"
    RECON_THEN_EXPLOIT    = "RECON_THEN_EXPLOIT"
    ANOMALOUS_TIME        = "ANOMALOUS_TIME"


class CorrelationSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NormalizedEvent:
    """
    A normalised representation of a log event for correlation.

    Attributes:
        raw:        Original event dict.
        source:     Log source identifier (e.g. "auth.log", "evtx").
        event_type: Normalised type string (e.g. "auth_fail", "auth_success",
                    "sudo", "process_exec", "net_scan", "user_add").
        timestamp:  UTC datetime (None if unparseable).
        source_ip:  Remote IP address (empty if not applicable).
        username:   Account involved (empty if not applicable).
        hostname:   Target host (empty if not applicable).
        extra:      Additional k/v pairs from the original event.
    """
    raw:        dict[str, Any]
    source:     str
    event_type: str
    timestamp:  Optional[datetime]
    source_ip:  str = ""
    username:   str = ""
    hostname:   str = ""
    extra:      dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelatedIncident:
    """
    A correlated multi-event incident.

    Attributes:
        incident_id:  Unique identifier.
        pattern:      Detected CorrelationPattern.
        severity:     Incident severity.
        confidence:   0.0–1.0 confidence in the correlation.
        events:       Contributing NormalizedEvents.
        source_ip:    Primary source IP (may be empty).
        username:     Primary username (may be empty).
        description:  Human-readable description.
        start_time:   Timestamp of the earliest event.
        end_time:     Timestamp of the latest event.
        sources:      Set of log sources contributing to this incident.
    """
    incident_id: str
    pattern:     CorrelationPattern
    severity:    CorrelationSeverity
    confidence:  float
    events:      list[NormalizedEvent] = field(default_factory=list)
    source_ip:   str = ""
    username:    str = ""
    description: str = ""
    start_time:  str = ""
    end_time:    str = ""
    sources:     set[str] = field(default_factory=set)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def span_seconds(self) -> float:
        if not self.start_time or not self.end_time:
            return 0.0
        try:
            s = datetime.fromisoformat(self.start_time)
            e = datetime.fromisoformat(self.end_time)
            return max(0.0, (e - s).total_seconds())
        except ValueError:
            return 0.0

    def summary(self) -> str:
        return (
            f"[{self.severity.value}] {self.incident_id} | "
            f"pattern={self.pattern.value} confidence={self.confidence:.2f} | "
            f"{self.event_count} events from {sorted(self.sources)} | "
            f"{self.description}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "pattern":     self.pattern.value,
            "severity":    self.severity.value,
            "confidence":  round(self.confidence, 3),
            "event_count": self.event_count,
            "source_ip":   self.source_ip,
            "username":    self.username,
            "description": self.description,
            "start_time":  self.start_time,
            "end_time":    self.end_time,
            "sources":     sorted(self.sources),
            "span_seconds": self.span_seconds,
        }


@dataclass
class CorrelationReport:
    """
    Report produced by LogCorrelator.correlate().

    Attributes:
        incidents:       All detected CorrelatedIncidents.
        total_events:    Total events fed into the correlator.
        sources:         Set of log source names.
        critical_count:  Number of CRITICAL incidents.
        high_count:      Number of HIGH incidents.
    """
    incidents:      list[CorrelatedIncident] = field(default_factory=list)
    total_events:   int = 0
    sources:        set[str] = field(default_factory=set)
    critical_count: int = 0
    high_count:     int = 0

    @property
    def incident_count(self) -> int:
        return len(self.incidents)

    def summary(self) -> str:
        return (
            f"CorrelationReport: {self.incident_count} incidents | "
            f"{self.total_events} events | "
            f"sources={sorted(self.sources)} | "
            f"CRITICAL={self.critical_count} HIGH={self.high_count}"
        )

    def by_pattern(self, pattern: CorrelationPattern) -> list[CorrelatedIncident]:
        return [i for i in self.incidents if i.pattern == pattern]

    def by_ip(self, ip: str) -> list[CorrelatedIncident]:
        return [i for i in self.incidents if i.source_ip == ip]

    def by_username(self, username: str) -> list[CorrelatedIncident]:
        return [i for i in self.incidents if i.username == username]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_ts(event: dict[str, Any]) -> Optional[datetime]:
    """Extract a UTC datetime from a raw event dict."""
    for key in ("timestamp", "ts", "time", "event_time", "@timestamp", "TimeCreated"):
        raw = event.get(key)
        if not raw:
            continue
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        if isinstance(raw, str):
            try:
                dt = datetime.fromisoformat(raw.rstrip("Z"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _get_str(event: dict[str, Any], *keys: str) -> str:
    for key in keys:
        val = event.get(key)
        if val and isinstance(val, str):
            return val.strip()
    return ""


def _normalize(raw: dict[str, Any], source: str) -> NormalizedEvent:
    """
    Produce a NormalizedEvent from a raw event dict.

    Event type normalisation mapping:
      - "failed password" / "authentication failure" → auth_fail
      - "accepted password" / "session opened" / login_success → auth_success
      - "sudo" / privilege → sudo
      - "new user" / useradd → user_add
      - "cron" / "at" / "startup" → persistence
      - "nmap" / "masscan" / scan → net_scan
      - "exploit" / "payload" → exploit
    """
    event_type = _infer_event_type(raw)
    return NormalizedEvent(
        raw=raw,
        source=source,
        event_type=event_type,
        timestamp=_parse_ts(raw),
        source_ip=_get_str(raw, "source_ip", "src_ip", "ip", "remote_ip", "IpAddress"),
        username=_get_str(raw, "username", "user", "login", "SubjectUserName", "TargetUserName"),
        hostname=_get_str(raw, "hostname", "host", "computer", "Computer"),
        extra={k: v for k, v in raw.items()},
    )


_AUTH_FAIL_KEYWORDS    = ("failed password", "authentication failure", "invalid user",
                          "auth_fail", "login_failed", "failed_login")
_AUTH_SUCCESS_KEYWORDS = ("accepted password", "session opened", "login_success",
                          "auth_success", "authenticated", "accepted publickey",
                          "logon", "4624")
_SUDO_KEYWORDS         = ("sudo", "privilege", "su ", "4672", "elevated")
_USER_ADD_KEYWORDS     = ("new user", "useradd", "user created", "4720")
_PERSISTENCE_KEYWORDS  = ("cron", "crontab", "startup", "autorun", "at ", "scheduled",
                          "registry run", "4698")
_NET_SCAN_KEYWORDS     = ("nmap", "masscan", "scan", "probe", "port sweep")
_EXPLOIT_KEYWORDS      = ("exploit", "payload", "shell", "reverse", "meterpreter")


def _infer_event_type(raw: dict[str, Any]) -> str:
    """Infer a normalised event type from raw event fields."""
    # Prefer explicit type field
    explicit = _get_str(raw, "event_type", "type", "action", "EventId", "event_id")
    blob = " ".join(str(v).lower() for v in raw.values())

    def matches(keywords: tuple[str, ...]) -> bool:
        return any(kw in blob for kw in keywords)

    if explicit in ("auth_fail", "login_failed", "4625"):
        return "auth_fail"
    if explicit in ("auth_success", "login_success", "authenticated", "4624"):
        return "auth_success"
    if explicit in ("sudo", "4672"):
        return "sudo"
    if explicit in ("user_add", "4720"):
        return "user_add"
    if explicit in ("persistence", "4698"):
        return "persistence"

    # Fall back to keyword scan
    if matches(_AUTH_FAIL_KEYWORDS):
        return "auth_fail"
    if matches(_AUTH_SUCCESS_KEYWORDS):
        return "auth_success"
    if matches(_SUDO_KEYWORDS):
        return "sudo"
    if matches(_USER_ADD_KEYWORDS):
        return "user_add"
    if matches(_PERSISTENCE_KEYWORDS):
        return "persistence"
    if matches(_NET_SCAN_KEYWORDS):
        return "net_scan"
    if matches(_EXPLOIT_KEYWORDS):
        return "exploit"
    return "unknown"


# ---------------------------------------------------------------------------
# LogCorrelator
# ---------------------------------------------------------------------------

class LogCorrelator:
    """
    Correlates normalised events from multiple log sources to detect
    multi-stage attack patterns.

    Args:
        window_seconds:  Time window for correlation (default 600 s = 10 min).
        working_hours:   Tuple ``(start_hour, end_hour)`` in 24h UTC for
                         anomalous-time detection. Default ``(7, 19)``.
    """

    def __init__(
        self,
        window_seconds: float = 600.0,
        working_hours: tuple[int, int] = (7, 19),
    ) -> None:
        self._window     = window_seconds
        self._work_start = working_hours[0]
        self._work_end   = working_hours[1]
        self._events:    list[NormalizedEvent] = []
        self._raw_count: int = 0

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def add_event(self, event: dict[str, Any], source: str) -> None:
        """Normalise and add a single event."""
        self._events.append(_normalize(event, source))
        self._raw_count += 1

    def add_events(self, events: list[dict[str, Any]], source: str) -> int:
        """Normalise and add multiple events. Returns count added."""
        for event in events:
            self.add_event(event, source)
        return len(events)

    def clear(self) -> None:
        """Remove all ingested events."""
        self._events.clear()
        self._raw_count = 0

    @property
    def event_count(self) -> int:
        return len(self._events)

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate(self) -> CorrelationReport:
        """
        Run all correlation rules and return a CorrelationReport.
        """
        incidents: list[CorrelatedIncident] = []
        sources = {e.source for e in self._events}

        incidents.extend(self._detect_brute_then_success())
        incidents.extend(self._detect_spray_then_pivot())
        incidents.extend(self._detect_privilege_escalation())
        incidents.extend(self._detect_persistence())
        incidents.extend(self._detect_recon_then_exploit())
        incidents.extend(self._detect_anomalous_time())

        critical = sum(1 for i in incidents if i.severity == CorrelationSeverity.CRITICAL)
        high     = sum(1 for i in incidents if i.severity == CorrelationSeverity.HIGH)

        return CorrelationReport(
            incidents=incidents,
            total_events=len(self._events),
            sources=sources,
            critical_count=critical,
            high_count=high,
        )

    # ------------------------------------------------------------------
    # Correlation rules
    # ------------------------------------------------------------------

    def _detect_brute_then_success(self) -> list[CorrelatedIncident]:
        """
        BRUTE_THEN_SUCCESS: ≥5 auth_fail from same IP within window,
        followed by auth_success from the same IP within the window.
        """
        incidents: list[CorrelatedIncident] = []
        by_ip = self._group_by_ip()

        for ip, events in by_ip.items():
            fails    = [e for e in events if e.event_type == "auth_fail"]
            successes = [e for e in events if e.event_type == "auth_success"]
            if len(fails) < 5 or not successes:
                continue

            for success in successes:
                if success.timestamp is None:
                    continue
                # Failures that precede this success within the window
                preceding = [
                    f for f in fails
                    if f.timestamp is not None
                    and 0 <= (success.timestamp - f.timestamp).total_seconds() <= self._window
                ]
                if len(preceding) >= 5:
                    confidence = min(0.95, 0.6 + 0.01 * len(preceding))
                    inc = self._make_incident(
                        pattern=CorrelationPattern.BRUTE_THEN_SUCCESS,
                        severity=CorrelationSeverity.CRITICAL,
                        confidence=confidence,
                        events=preceding + [success],
                        source_ip=ip,
                        username=success.username,
                        description=(
                            f"{len(preceding)} auth failures from {ip} followed by "
                            f"successful login as '{success.username}'"
                        ),
                    )
                    incidents.append(inc)
                    break  # one incident per IP

        return incidents

    def _detect_spray_then_pivot(self) -> list[CorrelatedIncident]:
        """
        SPRAY_THEN_PIVOT: auth_fail events against ≥5 distinct usernames
        from same IP, then auth_success within the window.
        """
        incidents: list[CorrelatedIncident] = []
        by_ip = self._group_by_ip()

        for ip, events in by_ip.items():
            fails    = [e for e in events if e.event_type == "auth_fail"]
            successes = [e for e in events if e.event_type == "auth_success"]
            if not successes:
                continue

            usernames_tried = {e.username for e in fails if e.username}
            if len(usernames_tried) < 5:
                continue

            for success in successes:
                if success.timestamp is None:
                    continue
                preceding_fails = [
                    f for f in fails
                    if f.timestamp is not None
                    and 0 <= (success.timestamp - f.timestamp).total_seconds() <= self._window
                ]
                users_in_window = {e.username for e in preceding_fails if e.username}
                if len(users_in_window) >= 5:
                    confidence = min(0.90, 0.5 + 0.02 * len(users_in_window))
                    inc = self._make_incident(
                        pattern=CorrelationPattern.SPRAY_THEN_PIVOT,
                        severity=CorrelationSeverity.CRITICAL,
                        confidence=confidence,
                        events=preceding_fails + [success],
                        source_ip=ip,
                        username=success.username,
                        description=(
                            f"Credential spray across {len(users_in_window)} usernames "
                            f"from {ip}, then successful login as '{success.username}'"
                        ),
                    )
                    incidents.append(inc)
                    break

        return incidents

    def _detect_privilege_escalation(self) -> list[CorrelatedIncident]:
        """
        PRIVILEGE_ESCALATION: auth_success followed by sudo/privilege event
        for the same username within the window.
        """
        incidents: list[CorrelatedIncident] = []
        by_user = self._group_by_username()

        for username, events in by_user.items():
            if not username:
                continue
            auths  = [e for e in events if e.event_type == "auth_success"]
            sudos  = [e for e in events if e.event_type == "sudo"]
            if not auths or not sudos:
                continue

            for auth in auths:
                if auth.timestamp is None:
                    continue
                subsequent = [
                    s for s in sudos
                    if s.timestamp is not None
                    and 0 <= (s.timestamp - auth.timestamp).total_seconds() <= self._window
                ]
                if subsequent:
                    inc = self._make_incident(
                        pattern=CorrelationPattern.PRIVILEGE_ESCALATION,
                        severity=CorrelationSeverity.HIGH,
                        confidence=0.80,
                        events=[auth] + subsequent[:3],
                        source_ip=auth.source_ip,
                        username=username,
                        description=(
                            f"User '{username}' logged in then escalated privileges "
                            f"({len(subsequent)} sudo/privilege event(s))"
                        ),
                    )
                    incidents.append(inc)
                    break

        return incidents

    def _detect_persistence(self) -> list[CorrelatedIncident]:
        """
        PERSISTENCE: auth_success followed by user_add or persistence event
        from same username or same source IP.
        """
        incidents: list[CorrelatedIncident] = []
        auth_events = [e for e in self._events if e.event_type == "auth_success"]
        persist_events = [
            e for e in self._events if e.event_type in ("user_add", "persistence")
        ]

        for auth in auth_events:
            if auth.timestamp is None:
                continue
            related = [
                p for p in persist_events
                if p.timestamp is not None
                and 0 <= (p.timestamp - auth.timestamp).total_seconds() <= self._window
                and (
                    (p.username and p.username == auth.username)
                    or (p.source_ip and p.source_ip == auth.source_ip)
                )
            ]
            if related:
                inc = self._make_incident(
                    pattern=CorrelationPattern.PERSISTENCE,
                    severity=CorrelationSeverity.HIGH,
                    confidence=0.75,
                    events=[auth] + related[:3],
                    source_ip=auth.source_ip,
                    username=auth.username,
                    description=(
                        f"Persistence activity ({related[0].event_type}) detected "
                        f"after login by '{auth.username}' from {auth.source_ip}"
                    ),
                )
                incidents.append(inc)

        return incidents

    def _detect_recon_then_exploit(self) -> list[CorrelatedIncident]:
        """
        RECON_THEN_EXPLOIT: net_scan followed by exploit event from same IP.
        """
        incidents: list[CorrelatedIncident] = []
        scans    = [e for e in self._events if e.event_type == "net_scan"]
        exploits = [e for e in self._events if e.event_type == "exploit"]

        by_ip_scans    = {e.source_ip: e for e in scans if e.source_ip}
        by_ip_exploits: dict[str, list[NormalizedEvent]] = {}
        for e in exploits:
            if e.source_ip:
                by_ip_exploits.setdefault(e.source_ip, []).append(e)

        for ip, scan in by_ip_scans.items():
            if scan.timestamp is None:
                continue
            following_exploits = [
                ex for ex in by_ip_exploits.get(ip, [])
                if ex.timestamp is not None
                and 0 <= (ex.timestamp - scan.timestamp).total_seconds() <= self._window
            ]
            if following_exploits:
                inc = self._make_incident(
                    pattern=CorrelationPattern.RECON_THEN_EXPLOIT,
                    severity=CorrelationSeverity.CRITICAL,
                    confidence=0.85,
                    events=[scan] + following_exploits[:3],
                    source_ip=ip,
                    username="",
                    description=(
                        f"Network scan from {ip} followed by exploitation attempt "
                        f"({len(following_exploits)} exploit event(s))"
                    ),
                )
                incidents.append(inc)

        return incidents

    def _detect_anomalous_time(self) -> list[CorrelatedIncident]:
        """
        ANOMALOUS_TIME: successful auth outside configured working hours.
        """
        incidents: list[CorrelatedIncident] = []
        auth_events = [e for e in self._events if e.event_type == "auth_success"]

        for auth in auth_events:
            if auth.timestamp is None:
                continue
            hour = auth.timestamp.hour
            if not (self._work_start <= hour < self._work_end):
                inc = self._make_incident(
                    pattern=CorrelationPattern.ANOMALOUS_TIME,
                    severity=CorrelationSeverity.MEDIUM,
                    confidence=0.60,
                    events=[auth],
                    source_ip=auth.source_ip,
                    username=auth.username,
                    description=(
                        f"Successful login by '{auth.username}' from {auth.source_ip} "
                        f"at {auth.timestamp.strftime('%H:%M UTC')} "
                        f"(outside {self._work_start:02d}:00–{self._work_end:02d}:00)"
                    ),
                )
                incidents.append(inc)

        return incidents

    # ------------------------------------------------------------------
    # Group helpers
    # ------------------------------------------------------------------

    def _group_by_ip(self) -> dict[str, list[NormalizedEvent]]:
        result: dict[str, list[NormalizedEvent]] = {}
        for e in self._events:
            ip = e.source_ip or "unknown"
            result.setdefault(ip, []).append(e)
        return result

    def _group_by_username(self) -> dict[str, list[NormalizedEvent]]:
        result: dict[str, list[NormalizedEvent]] = {}
        for e in self._events:
            result.setdefault(e.username, []).append(e)
        return result

    # ------------------------------------------------------------------
    # Incident factory
    # ------------------------------------------------------------------

    _incident_counter: int = 0

    def _make_incident(
        self,
        *,
        pattern: CorrelationPattern,
        severity: CorrelationSeverity,
        confidence: float,
        events: list[NormalizedEvent],
        source_ip: str,
        username: str,
        description: str,
    ) -> CorrelatedIncident:
        LogCorrelator._incident_counter += 1
        incident_id = f"INC-CORR-{LogCorrelator._incident_counter:04d}"

        ts_list = [e.timestamp for e in events if e.timestamp is not None]
        start   = min(ts_list).isoformat() if ts_list else ""
        end     = max(ts_list).isoformat() if ts_list else ""
        sources = {e.source for e in events}

        return CorrelatedIncident(
            incident_id=incident_id,
            pattern=pattern,
            severity=severity,
            confidence=round(confidence, 3),
            events=events,
            source_ip=source_ip,
            username=username,
            description=description,
            start_time=start,
            end_time=end,
            sources=sources,
        )
