"""
Network Connection Anomaly Analyzer
======================================
Analyzes host network connection snapshots for suspicious patterns:
suspicious destination ports, unusual outbound volume, Tor/proxy indicators,
crypto-mining pool connections, and internal lateral movement signals.

Operates on structured ConnectionRecord dicts — no live network access required.
Feed it parsed netstat/ss output or equivalent.

Check IDs
----------
NC-001   Connection to known suspicious port (4444/5554/6666/7777/8888/9001/9050/31337/1337)
NC-002   Excessive outbound connections from single process (> threshold)
NC-003   High-entropy destination hostname (possible DGA/DNS tunnel)
NC-004   Connection to known crypto-mining pool port (3333/4444/5555/7777/14433/14444/45560/45700)
NC-005   Outbound connection to Tor default port (9001/9050)
NC-006   Unusually high number of LISTENING ports for process
NC-007   Internal lateral movement: connection to SMB/WinRM/RDP ports on internal private addresses

Usage::

    from analyzers.network_conn_analyzer import NetworkConnectionAnalyzer, ConnectionRecord

    records = [
        ConnectionRecord(
            pid=1234,
            process_name="nc",
            local_addr="192.168.1.10",
            local_port=45123,
            remote_addr="10.0.0.5",
            remote_port=4444,
            state="ESTABLISHED",
            protocol="TCP",
        )
    ]
    analyzer = NetworkConnectionAnalyzer()
    report = analyzer.analyze(records)
    for finding in report.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address, ip_address, ip_network
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# NC-001 — broadly suspicious ports associated with backdoors, C2 frameworks,
# and common pentesting/attack tooling.
_SUSPICIOUS_PORTS: frozenset = frozenset({
    4444,   # Metasploit default / netcat common
    5554,   # Sasser worm / various backdoors
    6666,   # IRC / various malware C2
    7777,   # Various RATs
    8888,   # Common alternative HTTP / C2 tunnels
    9001,   # Tor OR port (also overlap with NC-005)
    9050,   # Tor SOCKS proxy (also overlap with NC-005)
    31337,  # Back Orifice / "elite" hacker port
    1337,   # Common C2 / leet-speak port
})

# NC-004 — well-known crypto-mining pool ports (Stratum protocol and variants).
_MINING_PORTS: frozenset = frozenset({
    3333,   # Stratum mining default
    4444,   # Alternate Stratum / XMR
    5555,   # Nicehash / alternate Stratum
    7777,   # Various mining pools
    14433,  # SSL Stratum alternate
    14444,  # XMR Monero pool SSL
    45560,  # Various GPU mining pools
    45700,  # Various GPU mining pools
})

# NC-005 — Tor network default ports.
_TOR_PORTS: frozenset = frozenset({
    9001,   # Tor OR (onion router) default
    9050,   # Tor SOCKS proxy default
})

# NC-007 — ports associated with SMB, WinRM, and RDP used in lateral movement.
_LATERAL_MOVEMENT_PORTS: frozenset = frozenset({
    445,    # SMB over TCP
    139,    # NetBIOS / legacy SMB
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    3389,   # RDP
})

_IPV6_INTERNAL_NETWORKS = (
    ip_network("fc00::/7"),   # Unique local addresses (ULA)
    ip_network("fe80::/10"),  # Link-local addresses
)

# Risk weight per check ID.  Summed across unique fired check IDs, capped at 100.
_CHECK_WEIGHTS: Dict[str, int] = {
    "NC-001": 25,
    "NC-002": 30,
    "NC-003": 35,
    "NC-004": 35,
    "NC-005": 40,
    "NC-006": 20,
    "NC-007": 40,
}

# Shannon entropy threshold for DGA / DNS-tunnel hostname detection.
_ENTROPY_THRESHOLD: float = 3.5
_HOSTNAME_MIN_LEN: int = 20

# Default threshold for excessive outbound connections per process.
_DEFAULT_EXCESSIVE_OUTBOUND_THRESHOLD: int = 20

# Maximum LISTEN ports before NC-006 fires.
_LISTEN_PORT_THRESHOLD: int = 5


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class NetConnSeverity(str, Enum):
    """Severity levels for network connection findings."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ConnectionRecord:
    """
    Represents a single network connection entry, equivalent to one row
    of netstat/ss output after parsing.

    Attributes:
        pid:          Process ID owning the socket.
        process_name: Name of the process (e.g. ``nc``, ``python3``).
        local_addr:   Local IP address.
        local_port:   Local port number.
        remote_addr:  Remote IP address (empty string for LISTEN entries).
        remote_port:  Remote port number (0 for LISTEN entries).
        state:        Socket state string (``ESTABLISHED``, ``LISTEN``, etc.).
        protocol:     Protocol string (``TCP``, ``UDP``).
        hostname:     Optional resolved hostname for remote_addr; used for
                      NC-003 entropy checks.  Leave empty if not available.
    """
    pid:          int
    process_name: str
    local_addr:   str
    local_port:   int
    remote_addr:  str
    remote_port:  int
    state:        str = "ESTABLISHED"
    protocol:     str = "TCP"
    hostname:     str = ""


@dataclass
class NetConnFinding:
    """
    A single anomaly detected during connection analysis.

    Attributes:
        check_id:    Check identifier (e.g. ``NC-001``).
        severity:    NetConnSeverity level.
        pid:         PID of the offending process.
        process_name: Process name.
        title:       Short title for the finding.
        detail:      Human-readable detail explaining why this fired.
        evidence:    Raw connection string or supporting data.
        remediation: Suggested response action.
    """
    check_id:     str
    severity:     NetConnSeverity
    pid:          int
    process_name: str
    title:        str
    detail:       str
    evidence:     str = ""
    remediation:  str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict representation of this finding."""
        return {
            "check_id":     self.check_id,
            "severity":     self.severity.value,
            "pid":          self.pid,
            "process_name": self.process_name,
            "title":        self.title,
            "detail":       self.detail,
            "evidence":     self.evidence,
            "remediation":  self.remediation,
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        return (
            f"[{self.severity.value}] {self.check_id} | "
            f"pid={self.pid} process={self.process_name!r} | "
            f"{self.title}"
        )


@dataclass
class NetConnReport:
    """
    Aggregated result of a full connection snapshot analysis.

    Attributes:
        findings:              All NetConnFinding objects produced.
        risk_score:            0–100 composite risk score.
        connections_analyzed:  Number of ConnectionRecord objects examined.
        generated_at:          Unix timestamp (float) of report creation.
    """
    findings:             List[NetConnFinding]
    risk_score:           int
    connections_analyzed: int
    generated_at:         float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings regardless of severity."""
        return len(self.findings)

    @property
    def critical_findings(self) -> List[NetConnFinding]:
        """All CRITICAL-severity findings."""
        return [f for f in self.findings if f.severity == NetConnSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[NetConnFinding]:
        """All HIGH-severity findings."""
        return [f for f in self.findings if f.severity == NetConnSeverity.HIGH]

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def findings_by_check(self, check_id: str) -> List[NetConnFinding]:
        """Return all findings for a specific check ID (e.g. ``'NC-001'``)."""
        return [f for f in self.findings if f.check_id == check_id]

    def findings_for_process(self, process_name: str) -> List[NetConnFinding]:
        """Return all findings attributed to the given process name."""
        return [f for f in self.findings if f.process_name == process_name]

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a multi-line human-readable summary of the report."""
        lines = [
            "NetConnReport Summary",
            "=" * 40,
            f"  Connections analyzed : {self.connections_analyzed}",
            f"  Total findings       : {self.total_findings}",
            f"  Critical             : {len(self.critical_findings)}",
            f"  High                 : {len(self.high_findings)}",
            f"  Risk score           : {self.risk_score}/100",
        ]
        if self.findings:
            lines.append("")
            lines.append("  Findings:")
            for finding in self.findings:
                lines.append(f"    {finding.summary()}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict of the full report."""
        return {
            "risk_score":            self.risk_score,
            "connections_analyzed":  self.connections_analyzed,
            "total_findings":        self.total_findings,
            "generated_at":          self.generated_at,
            "findings":              [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_rfc1918(addr: str) -> bool:
    """
    Return True if *addr* falls within an RFC 1918 private address range.

    Ranges checked:
      - 10.0.0.0/8       (starts with ``10.``)
      - 172.16.0.0/12    (``172.`` with second octet 16–31)
      - 192.168.0.0/16   (starts with ``192.168.``)

    No ipaddress module is used; this is a fast prefix/octet check only.
    """
    if addr.startswith("10."):
        return True
    if addr.startswith("192.168."):
        return True
    if addr.startswith("172."):
        # Parse the second octet to check the /12 range.
        parts = addr.split(".")
        if len(parts) >= 2:
            try:
                second_octet = int(parts[1])
                if 16 <= second_octet <= 31:
                    return True
            except ValueError:
                pass
    return False


def _is_internal_address(addr: str) -> bool:
    """
    Return True when *addr* is an internal private address used for east-west traffic.

    Supported ranges:
      - IPv4 RFC1918: 10/8, 172.16/12, 192.168/16
      - IPv6 ULA:     fc00::/7
      - IPv6 link-local: fe80::/10
      - IPv4-mapped IPv6 when the embedded IPv4 address is RFC1918
    """
    if _is_rfc1918(addr):
        return True

    if not addr or ":" not in addr:
        return False

    try:
        parsed = ip_address(addr)
    except ValueError:
        return False

    if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped is not None:
        return _is_rfc1918(str(parsed.ipv4_mapped))

    return any(parsed in network for network in _IPV6_INTERNAL_NETWORKS)


def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy (bits) of string *s*.

    Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0
    length = len(s)
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _conn_evidence(rec: ConnectionRecord) -> str:
    """Format a single ConnectionRecord as a compact evidence string."""
    return (
        f"{rec.protocol} {rec.local_addr}:{rec.local_port} → "
        f"{rec.remote_addr}:{rec.remote_port} "
        f"[{rec.state}] pid={rec.pid} process={rec.process_name!r}"
    )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class NetworkConnectionAnalyzer:
    """
    Stateless analyzer that inspects a list of ConnectionRecord objects and
    produces a NetConnReport containing all detected anomalies.

    Parameters
    ----------
    excessive_outbound_threshold:
        Number of outbound ESTABLISHED TCP connections a single process may
        have before NC-002 fires.  Default: 20.
    check_lateral_movement:
        When False, NC-007 checks are skipped entirely.  Default: True.
    """

    def __init__(
        self,
        excessive_outbound_threshold: int = _DEFAULT_EXCESSIVE_OUTBOUND_THRESHOLD,
        check_lateral_movement: bool = True,
    ) -> None:
        self._excessive_outbound_threshold = excessive_outbound_threshold
        self._check_lateral_movement = check_lateral_movement

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, records: List[ConnectionRecord]) -> NetConnReport:
        """
        Analyze a list of ConnectionRecord objects and return a NetConnReport.

        All seven checks (NC-001 through NC-007) are evaluated.  NC-002 and
        NC-006 are aggregate checks that fire after per-connection iteration.

        Parameters
        ----------
        records:
            List of ConnectionRecord objects to analyze.

        Returns
        -------
        NetConnReport
            Contains all findings, a composite risk score, and metadata.
        """
        findings: List[NetConnFinding] = []

        # Accumulators for aggregate checks keyed by PID + process name so
        # separate processes that share the same executable name are not merged.
        outbound_map: Dict[tuple[int, str], List[ConnectionRecord]] = defaultdict(list)
        listen_map: Dict[tuple[int, str], List[ConnectionRecord]] = defaultdict(list)

        # ------------------------------------------------------------------
        # Per-connection checks
        # ------------------------------------------------------------------
        for rec in records:
            # NC-001: suspicious destination port
            if rec.remote_port in _SUSPICIOUS_PORTS:
                findings.append(self._make_nc001(rec))

            # NC-004: crypto-mining pool port
            if rec.remote_port in _MINING_PORTS:
                findings.append(self._make_nc004(rec))

            # NC-005: Tor default port
            if rec.remote_port in _TOR_PORTS:
                findings.append(self._make_nc005(rec))

            # NC-003: high-entropy hostname (possible DGA / DNS tunnel)
            if rec.hostname and len(rec.hostname) > _HOSTNAME_MIN_LEN:
                entropy = _shannon_entropy(rec.hostname)
                if entropy > _ENTROPY_THRESHOLD:
                    findings.append(self._make_nc003(rec, entropy))

            # NC-007: lateral movement to internal host via admin protocol
            if (
                self._check_lateral_movement
                and rec.state == "ESTABLISHED"
                and rec.remote_port in _LATERAL_MOVEMENT_PORTS
                and _is_internal_address(rec.remote_addr)
            ):
                findings.append(self._make_nc007(rec))

            # Accumulate for aggregate checks.
            if rec.state == "ESTABLISHED":
                outbound_map[(rec.pid, rec.process_name)].append(rec)
            if rec.state == "LISTEN":
                listen_map[(rec.pid, rec.process_name)].append(rec)

        # ------------------------------------------------------------------
        # NC-002: excessive outbound connections per process
        # ------------------------------------------------------------------
        for (pid, process_name), conn_list in outbound_map.items():
            if len(conn_list) > self._excessive_outbound_threshold:
                findings.append(
                    self._make_nc002(
                        process_name=process_name,
                        pid=pid,
                        count=len(conn_list),
                        threshold=self._excessive_outbound_threshold,
                    )
                )

        # ------------------------------------------------------------------
        # NC-006: unusually high number of LISTEN ports per process
        # ------------------------------------------------------------------
        for (pid, process_name), listen_list in listen_map.items():
            if len(listen_list) > _LISTEN_PORT_THRESHOLD:
                ports = sorted({r.local_port for r in listen_list})
                findings.append(
                    self._make_nc006(
                        process_name=process_name,
                        pid=pid,
                        count=len(listen_list),
                        ports=ports,
                    )
                )

        # ------------------------------------------------------------------
        # Risk score: sum weights of unique fired check IDs, cap at 100
        # ------------------------------------------------------------------
        fired_check_ids = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_check_ids)
        risk_score = min(raw_score, 100)

        return NetConnReport(
            findings=findings,
            risk_score=risk_score,
            connections_analyzed=len(records),
            generated_at=time.time(),
        )

    # ------------------------------------------------------------------
    # Finding factory methods — each encodes the check-specific text and
    # severity so that the logic in analyze() stays readable.
    # ------------------------------------------------------------------

    @staticmethod
    def _make_nc001(rec: ConnectionRecord) -> NetConnFinding:
        """NC-001 — suspicious destination port."""
        return NetConnFinding(
            check_id="NC-001",
            severity=NetConnSeverity.HIGH,
            pid=rec.pid,
            process_name=rec.process_name,
            title=f"Connection to known suspicious port {rec.remote_port}",
            detail=(
                f"Process '{rec.process_name}' (pid={rec.pid}) has an outbound "
                f"connection to {rec.remote_addr}:{rec.remote_port}, which is on "
                f"the list of ports commonly used by backdoors, RATs, and C2 "
                f"frameworks."
            ),
            evidence=_conn_evidence(rec),
            remediation=(
                "Investigate the process binary, its parent, and any loaded modules. "
                "Consider isolating the host and capturing a memory image."
            ),
        )

    @staticmethod
    def _make_nc002(
        process_name: str,
        pid: int,
        count: int,
        threshold: int,
    ) -> NetConnFinding:
        """NC-002 — excessive outbound connections from single process."""
        return NetConnFinding(
            check_id="NC-002",
            severity=NetConnSeverity.HIGH,
            pid=pid,
            process_name=process_name,
            title=f"Excessive outbound connections from '{process_name}' ({count})",
            detail=(
                f"Process '{process_name}' (pid={pid}) has {count} outbound "
                f"ESTABLISHED connections, exceeding the threshold of {threshold}. "
                f"This may indicate a scanner, worm propagation, botnet activity, "
                f"or data exfiltration."
            ),
            evidence=f"outbound_established_count={count} threshold={threshold}",
            remediation=(
                "Review the process origin and command-line arguments. "
                "Capture netflow records and correlate with DNS queries."
            ),
        )

    @staticmethod
    def _make_nc003(rec: ConnectionRecord, entropy: float) -> NetConnFinding:
        """NC-003 — high-entropy hostname suggesting DGA or DNS tunnel."""
        return NetConnFinding(
            check_id="NC-003",
            severity=NetConnSeverity.HIGH,
            pid=rec.pid,
            process_name=rec.process_name,
            title=f"High-entropy hostname detected: {rec.hostname!r}",
            detail=(
                f"Process '{rec.process_name}' (pid={rec.pid}) connected to "
                f"hostname '{rec.hostname}' (entropy={entropy:.3f} bits, "
                f"len={len(rec.hostname)}). High-entropy long hostnames are a "
                f"hallmark of Domain Generation Algorithms (DGA) and DNS tunneling."
            ),
            evidence=_conn_evidence(rec),
            remediation=(
                "Query passive DNS for the hostname. Inspect DNS query logs for "
                "high volumes of NX-domain responses. Consider blocking and "
                "reverse-engineering the sample."
            ),
        )

    @staticmethod
    def _make_nc004(rec: ConnectionRecord) -> NetConnFinding:
        """NC-004 — crypto-mining pool port."""
        return NetConnFinding(
            check_id="NC-004",
            severity=NetConnSeverity.CRITICAL,
            pid=rec.pid,
            process_name=rec.process_name,
            title=f"Connection to known crypto-mining pool port {rec.remote_port}",
            detail=(
                f"Process '{rec.process_name}' (pid={rec.pid}) connected to "
                f"{rec.remote_addr}:{rec.remote_port}, which matches a known "
                f"Stratum/mining pool port. This is a strong indicator of an "
                f"unauthorized crypto-miner (cryptojacker)."
            ),
            evidence=_conn_evidence(rec),
            remediation=(
                "Terminate the process and conduct a full triage of the host. "
                "Search for persistence mechanisms, scheduled tasks, and crontab "
                "entries that may restart the miner."
            ),
        )

    @staticmethod
    def _make_nc005(rec: ConnectionRecord) -> NetConnFinding:
        """NC-005 — connection to Tor default port."""
        return NetConnFinding(
            check_id="NC-005",
            severity=NetConnSeverity.CRITICAL,
            pid=rec.pid,
            process_name=rec.process_name,
            title=f"Outbound connection to Tor default port {rec.remote_port}",
            detail=(
                f"Process '{rec.process_name}' (pid={rec.pid}) has an outbound "
                f"connection to {rec.remote_addr}:{rec.remote_port}, which is a "
                f"default Tor port. This may indicate C2 communication routed "
                f"through the Tor anonymity network."
            ),
            evidence=_conn_evidence(rec),
            remediation=(
                "Block Tor exit/OR node IPs at the network perimeter. "
                "Investigate the process for malware and collect a memory image "
                "before terminating."
            ),
        )

    @staticmethod
    def _make_nc006(
        process_name: str,
        pid: int,
        count: int,
        ports: List[int],
    ) -> NetConnFinding:
        """NC-006 — unusually high number of LISTENING ports for a process."""
        port_str = ", ".join(str(p) for p in ports[:10])
        if len(ports) > 10:
            port_str += f", ... (+{len(ports) - 10} more)"
        return NetConnFinding(
            check_id="NC-006",
            severity=NetConnSeverity.MEDIUM,
            pid=pid,
            process_name=process_name,
            title=f"Process '{process_name}' listening on {count} ports",
            detail=(
                f"Process '{process_name}' (pid={pid}) has {count} LISTEN-state "
                f"sockets, exceeding the threshold of {_LISTEN_PORT_THRESHOLD}. "
                f"Legitimate daemons rarely open this many listeners. "
                f"Ports: {port_str}."
            ),
            evidence=f"listen_count={count} ports=[{port_str}]",
            remediation=(
                "Confirm the process is an expected service. If unexpected, "
                "investigate for bind-shell backdoors or malicious port-knocking "
                "listeners."
            ),
        )

    @staticmethod
    def _make_nc007(rec: ConnectionRecord) -> NetConnFinding:
        """NC-007 — internal lateral movement via admin protocol."""
        proto_names = {
            445: "SMB",
            139: "NetBIOS/SMB",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS",
            3389: "RDP",
        }
        proto_label = proto_names.get(rec.remote_port, str(rec.remote_port))
        return NetConnFinding(
            check_id="NC-007",
            severity=NetConnSeverity.CRITICAL,
            pid=rec.pid,
            process_name=rec.process_name,
            title=(
                f"Lateral movement: {proto_label} connection to internal host "
                f"{rec.remote_addr}"
            ),
            detail=(
                f"Process '{rec.process_name}' (pid={rec.pid}) has an ESTABLISHED "
                f"{proto_label} connection to internal private address "
                f"{rec.remote_addr}:{rec.remote_port}. This is a common indicator "
                f"of adversary lateral movement within the network."
            ),
            evidence=_conn_evidence(rec),
            remediation=(
                "Correlate with authentication logs on the destination host. "
                "Check for pass-the-hash, pass-the-ticket, or credential-stuffing "
                "activity. Isolate affected hosts pending investigation."
            ),
        )
