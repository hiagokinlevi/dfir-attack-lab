"""
Lateral Movement Graph Tracker
=================================
Builds a directed graph of authentication events — source IP → target host —
and detects multi-hop lateral movement patterns where an attacker pivots
from one host to another after gaining initial access.

A movement chain is a sequence of hops:
    source_ip → host_A → host_B → host_C …

where each hop is a successful authentication event and the source IP of a
later hop is consistent with the hostname of an earlier hop (or the same
IP appears across multiple target hosts within the time window).

Detection Patterns
-------------------
SEQUENTIAL_HOP    — Successful auth to host A, then from host A (or its IP)
                   to host B within the movement window.
MULTI_HOP_CHAIN   — 3+ sequential hops forming a lateral movement chain.
FAN_OUT           — Single source IP authenticating to ≥ N distinct hosts,
                   indicating systematic lateral exploration.
CREDENTIAL_REUSE  — Same username (and optionally password) appearing across
                   multiple distinct target hosts.

Usage::

    from analysis.lateral_movement import LateralMovementTracker

    tracker = LateralMovementTracker(window_seconds=3600)
    tracker.add_events(auth_events, source="auth.log")
    report = tracker.analyze()
    for chain in report.movement_chains:
        print(chain.summary())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class MovementPattern(str, Enum):
    SEQUENTIAL_HOP  = "SEQUENTIAL_HOP"
    MULTI_HOP_CHAIN = "MULTI_HOP_CHAIN"
    FAN_OUT         = "FAN_OUT"
    CREDENTIAL_REUSE = "CREDENTIAL_REUSE"


class MovementSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AuthHop:
    """
    A single successful authentication event used as a movement graph edge.

    Attributes:
        source_ip:  Originating IP address.
        target_host: Host being authenticated to.
        username:   Account used.
        password:   Credential used (empty if not available).
        timestamp:  UTC datetime.
        source:     Log source identifier.
        raw:        Original event dict.
    """
    source_ip:   str
    target_host: str
    username:    str
    timestamp:   Optional[datetime]
    password:    str = ""
    source:      str = ""
    raw:         dict[str, Any] = field(default_factory=dict)


@dataclass
class MovementChain:
    """
    A detected lateral movement chain or pattern.

    Attributes:
        chain_id:    Unique identifier.
        pattern:     Detected MovementPattern.
        severity:    Severity bucket.
        hops:        Ordered list of AuthHops.
        source_ip:   Originating IP (first hop).
        target_hosts: Ordered list of target hosts.
        usernames:   Set of usernames across the chain.
        description: Human-readable description.
        start_time:  Timestamp of first hop.
        end_time:    Timestamp of last hop.
        confidence:  0.0–1.0.
    """
    chain_id:     str
    pattern:      MovementPattern
    severity:     MovementSeverity
    hops:         list[AuthHop] = field(default_factory=list)
    source_ip:    str = ""
    target_hosts: list[str] = field(default_factory=list)
    usernames:    set[str] = field(default_factory=set)
    description:  str = ""
    start_time:   str = ""
    end_time:     str = ""
    confidence:   float = 0.0

    @property
    def hop_count(self) -> int:
        return len(self.hops)

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
        path = " → ".join(
            [self.source_ip] + self.target_hosts
        )
        return (
            f"[{self.severity.value}] {self.chain_id} | "
            f"pattern={self.pattern.value} | "
            f"path={path} | "
            f"{self.hop_count} hops | "
            f"{self.description}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id":     self.chain_id,
            "pattern":      self.pattern.value,
            "severity":     self.severity.value,
            "confidence":   round(self.confidence, 3),
            "source_ip":    self.source_ip,
            "target_hosts": self.target_hosts,
            "hop_count":    self.hop_count,
            "usernames":    sorted(self.usernames),
            "description":  self.description,
            "start_time":   self.start_time,
            "end_time":     self.end_time,
            "span_seconds": self.span_seconds,
        }


@dataclass
class LateralMovementReport:
    """
    Report produced by LateralMovementTracker.analyze().

    Attributes:
        movement_chains: All detected chains / patterns.
        total_hops:      Total auth hops ingested.
        unique_hosts:    Set of target hosts seen.
        critical_count:  Number of CRITICAL chains.
        high_count:      Number of HIGH chains.
    """
    movement_chains: list[MovementChain] = field(default_factory=list)
    total_hops:      int = 0
    unique_hosts:    set[str] = field(default_factory=set)
    critical_count:  int = 0
    high_count:      int = 0

    @property
    def chain_count(self) -> int:
        return len(self.movement_chains)

    def summary(self) -> str:
        return (
            f"LateralMovementReport: {self.chain_count} chains | "
            f"{self.total_hops} hops | "
            f"{len(self.unique_hosts)} unique hosts | "
            f"CRITICAL={self.critical_count} HIGH={self.high_count}"
        )

    def by_pattern(self, pattern: MovementPattern) -> list[MovementChain]:
        return [c for c in self.movement_chains if c.pattern == pattern]

    def by_host(self, host: str) -> list[MovementChain]:
        return [c for c in self.movement_chains if host in c.target_hosts]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_ts(event: dict[str, Any]) -> Optional[datetime]:
    for key in ("timestamp", "ts", "time", "event_time"):
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


def _is_success(event: dict[str, Any]) -> bool:
    """Return True if the event represents a successful authentication."""
    et = _get_str(event, "event_type", "type", "action")
    if et in ("auth_success", "login_success", "authenticated", "4624"):
        return True
    blob = " ".join(str(v).lower() for v in event.values())
    success_kws = ("accepted password", "session opened", "login_success", "auth_success")
    return any(kw in blob for kw in success_kws)


def _normalize_host(host: str) -> str:
    """Strip leading slash from Docker/Linux hostnames."""
    return host.lstrip("/").strip().lower()


# ---------------------------------------------------------------------------
# LateralMovementTracker
# ---------------------------------------------------------------------------

_chain_counter: int = 0


class LateralMovementTracker:
    """
    Tracks authentication events and detects lateral movement patterns.

    Args:
        window_seconds: Time window for hop correlation. Hops outside this
                        window from the previous hop are not considered part
                        of the same chain. Default 3600 (1 hour).
        fan_out_threshold: Minimum distinct target hosts to trigger FAN_OUT.
    """

    def __init__(
        self,
        window_seconds: float = 3600.0,
        fan_out_threshold: int = 3,
    ) -> None:
        self._window           = window_seconds
        self._fan_out_threshold = fan_out_threshold
        self._hops: list[AuthHop] = []

    def add_event(self, event: dict[str, Any], source: str = "") -> None:
        """Extract and add a successful auth event as an AuthHop."""
        if not _is_success(event):
            return
        source_ip   = _get_str(event, "source_ip", "src_ip", "ip", "remote_ip")
        target_host = _get_str(event, "hostname", "host", "computer", "target_host",
                               "dest_host", "dhost", "Computer")
        if not source_ip and not target_host:
            return  # Not enough info for a hop
        hop = AuthHop(
            source_ip=source_ip or "unknown",
            target_host=_normalize_host(target_host) if target_host else "unknown",
            username=_get_str(event, "username", "user", "login", "SubjectUserName"),
            password=_get_str(event, "password", "credential"),
            timestamp=_parse_ts(event),
            source=source,
            raw=event,
        )
        self._hops.append(hop)

    def add_events(self, events: list[dict[str, Any]], source: str = "") -> int:
        """Add multiple events. Returns count of hops extracted."""
        before = len(self._hops)
        for event in events:
            self.add_event(event, source)
        return len(self._hops) - before

    def clear(self) -> None:
        self._hops.clear()

    @property
    def hop_count(self) -> int:
        return len(self._hops)

    def analyze(self) -> LateralMovementReport:
        """
        Detect lateral movement patterns from ingested auth hops.
        """
        global _chain_counter
        chains: list[MovementChain] = []
        unique_hosts: set[str] = {h.target_host for h in self._hops}

        # Sort hops by timestamp
        sorted_hops = sorted(
            self._hops,
            key=lambda h: h.timestamp.timestamp() if h.timestamp else float("inf"),
        )

        chains.extend(self._detect_sequential_hops(sorted_hops))
        chains.extend(self._detect_fan_out(sorted_hops))
        chains.extend(self._detect_credential_reuse(sorted_hops))

        # Upgrade sequential hops of 3+ to MULTI_HOP_CHAIN
        for chain in chains:
            if (
                chain.pattern == MovementPattern.SEQUENTIAL_HOP
                and chain.hop_count >= 3
            ):
                chain.pattern  = MovementPattern.MULTI_HOP_CHAIN
                chain.severity = MovementSeverity.CRITICAL
                chain.confidence = min(0.95, chain.confidence + 0.10)

        critical = sum(1 for c in chains if c.severity == MovementSeverity.CRITICAL)
        high     = sum(1 for c in chains if c.severity == MovementSeverity.HIGH)

        return LateralMovementReport(
            movement_chains=chains,
            total_hops=len(self._hops),
            unique_hosts=unique_hosts,
            critical_count=critical,
            high_count=high,
        )

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _detect_sequential_hops(
        self, sorted_hops: list[AuthHop]
    ) -> list[MovementChain]:
        """
        SEQUENTIAL_HOP: a source IP authenticates to host A, then from
        host A's perspective (or same IP) authenticates to host B within
        the movement window.

        Heuristic: if the same username appears on a subsequent hop within
        the time window from a new source IP that matches the previous target
        host, it's a pivot. Also detect same IP → multiple sequential hosts.
        """
        global _chain_counter
        chains: list[MovementChain] = []

        # Group hops by source IP
        by_ip: dict[str, list[AuthHop]] = {}
        for hop in sorted_hops:
            by_ip.setdefault(hop.source_ip, []).append(hop)

        for ip, hops in by_ip.items():
            if len(hops) < 2:
                continue

            # Find sequences to different hosts within the window
            chain_hops: list[AuthHop] = [hops[0]]
            for i in range(1, len(hops)):
                prev = chain_hops[-1]
                curr = hops[i]
                if curr.target_host == prev.target_host:
                    continue  # Same host, not lateral movement
                # Check time window
                if (
                    prev.timestamp and curr.timestamp
                    and (curr.timestamp - prev.timestamp).total_seconds() > self._window
                ):
                    # Window expired — start new chain
                    if len(chain_hops) >= 2:
                        chains.append(self._make_chain(ip, chain_hops))
                    chain_hops = [curr]
                else:
                    chain_hops.append(curr)

            if len(chain_hops) >= 2:
                chains.append(self._make_chain(ip, chain_hops))

        return chains

    def _detect_fan_out(self, sorted_hops: list[AuthHop]) -> list[MovementChain]:
        """
        FAN_OUT: a single source IP successfully authenticates to ≥ N
        distinct target hosts within the movement window.
        """
        global _chain_counter
        chains: list[MovementChain] = []

        by_ip: dict[str, list[AuthHop]] = {}
        for hop in sorted_hops:
            by_ip.setdefault(hop.source_ip, []).append(hop)

        for ip, hops in by_ip.items():
            distinct_hosts = {h.target_host for h in hops}
            if len(distinct_hosts) < self._fan_out_threshold:
                continue

            # Check if enough hops fall within the window
            windowed_hops = self._hops_within_window(hops)
            windowed_hosts = {h.target_host for h in windowed_hops}
            if len(windowed_hosts) < self._fan_out_threshold:
                continue

            _chain_counter += 1
            ts_list = [h.timestamp for h in windowed_hops if h.timestamp]
            usernames = {h.username for h in windowed_hops if h.username}
            chain = MovementChain(
                chain_id=f"LM-{_chain_counter:04d}",
                pattern=MovementPattern.FAN_OUT,
                severity=MovementSeverity.HIGH,
                hops=windowed_hops,
                source_ip=ip,
                target_hosts=sorted(windowed_hosts),
                usernames=usernames,
                confidence=min(0.85, 0.40 + 0.05 * len(windowed_hosts)),
                description=(
                    f"Source IP {ip} authenticated to {len(windowed_hosts)} "
                    f"distinct hosts: {sorted(windowed_hosts)[:5]}"
                ),
                start_time=min(ts_list).isoformat() if ts_list else "",
                end_time=max(ts_list).isoformat() if ts_list else "",
            )
            chains.append(chain)

        return chains

    def _detect_credential_reuse(
        self, sorted_hops: list[AuthHop]
    ) -> list[MovementChain]:
        """
        CREDENTIAL_REUSE: same username appearing on ≥ 2 distinct target hosts.
        """
        global _chain_counter
        chains: list[MovementChain] = []

        by_username: dict[str, list[AuthHop]] = {}
        for hop in sorted_hops:
            if hop.username:
                by_username.setdefault(hop.username, []).append(hop)

        for username, hops in by_username.items():
            distinct_hosts = {h.target_host for h in hops}
            if len(distinct_hosts) < 2:
                continue

            _chain_counter += 1
            ts_list = [h.timestamp for h in hops if h.timestamp]
            chain = MovementChain(
                chain_id=f"LM-{_chain_counter:04d}",
                pattern=MovementPattern.CREDENTIAL_REUSE,
                severity=MovementSeverity.MEDIUM,
                hops=hops,
                source_ip=hops[0].source_ip,
                target_hosts=sorted(distinct_hosts),
                usernames={username},
                confidence=min(0.80, 0.50 + 0.05 * len(distinct_hosts)),
                description=(
                    f"Credential '{username}' reused across "
                    f"{len(distinct_hosts)} hosts: {sorted(distinct_hosts)[:5]}"
                ),
                start_time=min(ts_list).isoformat() if ts_list else "",
                end_time=max(ts_list).isoformat() if ts_list else "",
            )
            chains.append(chain)

        return chains

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _hops_within_window(self, hops: list[AuthHop]) -> list[AuthHop]:
        """Return hops that fall within the movement window from the first hop."""
        if not hops:
            return []
        first_ts = next((h.timestamp for h in hops if h.timestamp), None)
        if first_ts is None:
            return hops
        result = []
        for hop in hops:
            if hop.timestamp is None:
                result.append(hop)
            elif (hop.timestamp - first_ts).total_seconds() <= self._window:
                result.append(hop)
        return result

    @staticmethod
    def _make_chain(source_ip: str, hops: list[AuthHop]) -> MovementChain:
        global _chain_counter
        _chain_counter += 1
        ts_list = [h.timestamp for h in hops if h.timestamp]
        target_hosts = []
        seen: set[str] = set()
        for h in hops:
            if h.target_host not in seen:
                target_hosts.append(h.target_host)
                seen.add(h.target_host)

        severity = (
            MovementSeverity.CRITICAL if len(hops) >= 3 else MovementSeverity.HIGH
        )
        return MovementChain(
            chain_id=f"LM-{_chain_counter:04d}",
            pattern=MovementPattern.SEQUENTIAL_HOP,
            severity=severity,
            hops=hops,
            source_ip=source_ip,
            target_hosts=target_hosts,
            usernames={h.username for h in hops if h.username},
            confidence=min(0.90, 0.60 + 0.10 * (len(hops) - 2)),
            description=(
                f"Sequential lateral movement: {source_ip} → "
                + " → ".join(target_hosts[:5])
            ),
            start_time=min(ts_list).isoformat() if ts_list else "",
            end_time=max(ts_list).isoformat() if ts_list else "",
        )
