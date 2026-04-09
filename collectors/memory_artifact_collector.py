"""
Memory Artifact Collector
===========================
Collects and analyzes Linux process memory artifacts from /proc to detect
common process injection and living-off-the-land indicators. All collection
is read-only; no memory is written or modified.

Indicators Checked
-------------------
MA-001  Anonymous executable memory mapping
        /proc/<pid>/maps contains a region with rwx or r-x permissions that
        has no backing file path (anonymous mapping). Legitimate processes
        rarely have executable anonymous mappings — this is a hallmark of
        shellcode injection or reflective DLL loading.

MA-002  Deleted executable backing file
        A memory region is backed by a file path ending in " (deleted)".
        Attackers often delete the on-disk executable after loading it to
        hinder forensic recovery.

MA-003  Executable memory mapped from /tmp or /dev/shm
        A memory region with execute permission is backed by a file in
        /tmp, /dev/shm, /run/shm, or other world-writable directories.
        These locations are commonly used as staging areas for payloads.

MA-004  Process name / cmdline mismatch
        The process name read from /proc/<pid>/comm differs significantly
        from the executable path in /proc/<pid>/exe (e.g. a process
        named "kworker" running /tmp/implant).

MA-005  Unusual parent–child relationship
        A suspicious parent process (e.g. web server, database, document
        renderer) has spawned a shell or interpreter.

MA-006  Process with no file descriptor to its own executable
        The /proc/<pid>/exe symlink resolves to "(deleted)" or is
        unresolvable — the process is running from a deleted or replaced
        binary (living-off-the-land binary replacement).

MA-007  High entropy region in process maps
        A mapped memory region has a suspiciously high file-path entropy
        (random-looking path), consistent with randomly named malware
        droppers.

Usage::

    from collectors.memory_artifact_collector import (
        MemoryArtifactCollector,
        ArtifactReport,
    )

    collector = MemoryArtifactCollector()
    # Analyze a single PID
    report = collector.collect_pid(1234)
    print(report.summary())

    # Analyze all accessible PIDs
    reports = collector.collect_all()
    for r in reports:
        if r.has_indicators:
            print(r.summary())
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class IndicatorSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Check definitions
# ---------------------------------------------------------------------------

_CHECK_META: dict[str, tuple[IndicatorSeverity, str]] = {
    "MA-001": (IndicatorSeverity.CRITICAL, "Anonymous executable memory mapping"),
    "MA-002": (IndicatorSeverity.HIGH,     "Deleted executable backing file"),
    "MA-003": (IndicatorSeverity.HIGH,     "Executable mapping in world-writable path"),
    "MA-004": (IndicatorSeverity.HIGH,     "Process name / cmdline mismatch"),
    "MA-005": (IndicatorSeverity.MEDIUM,   "Suspicious parent-child process relationship"),
    "MA-006": (IndicatorSeverity.HIGH,     "Process running from deleted executable"),
    "MA-007": (IndicatorSeverity.MEDIUM,   "High-entropy executable path"),
}

_CHECK_WEIGHTS: dict[str, int] = {
    "MA-001": 35,
    "MA-002": 25,
    "MA-003": 25,
    "MA-004": 20,
    "MA-005": 15,
    "MA-006": 25,
    "MA-007": 10,
}

# World-writable / staging directories
_WRITEABLE_STAGING_PATHS = (
    "/tmp/", "/dev/shm/", "/run/shm/",
    "/var/tmp/", "/dev/mqueue/",
)

# Suspicious parent process names (web/db/doc renderers that should not spawn shells)
_SUSPICIOUS_PARENTS = frozenset({
    "apache2", "httpd", "nginx", "lighttpd",
    "mysqld", "postgres", "mongod",
    "java", "python", "node", "ruby",
    "php-fpm", "php",
    "libreoffice", "soffice",
    "evince", "okular",
    "chrome", "chromium", "firefox",
})

# Shell / interpreter names that should not be children of the above
_SHELL_NAMES = frozenset({
    "sh", "bash", "dash", "zsh", "fish",
    "ksh", "tcsh",
    "python", "python3", "perl", "ruby",
    "nc", "ncat", "netcat",
})

# Maps entry in /proc/<pid>/maps
_MAPS_LINE_RE = re.compile(
    r"^([0-9a-f]+-[0-9a-f]+)\s+([rwxps-]{4})\s+\S+\s+\S+\s+\S+\s*(.*)$"
)

# High-entropy path: short basename that looks random
_HIGH_ENTROPY_THRESHOLD = 3.5  # bits per char


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MemoryIndicator:
    """
    A single memory artifact indicator for a process.

    Attributes:
        check_id:    Indicator identifier (MA-001 … MA-007).
        severity:    Indicator severity.
        title:       Short description.
        detail:      Detailed explanation.
        pid:         Process ID.
        evidence:    Supporting evidence string.
    """
    check_id:  str
    severity:  IndicatorSeverity
    title:     str
    detail:    str
    pid:       int = 0
    evidence:  str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id":  self.check_id,
            "severity":  self.severity.value,
            "title":     self.title,
            "detail":    self.detail,
            "pid":       self.pid,
            "evidence":  self.evidence,
        }

    def summary(self) -> str:
        return f"[{self.severity.value}] {self.check_id} pid={self.pid}: {self.title}"


@dataclass
class ProcessSnapshot:
    """
    Snapshot of a process's observable state from /proc.

    Attributes:
        pid:       Process ID.
        comm:      Process name from /proc/<pid>/comm.
        exe:       Resolved path of /proc/<pid>/exe (empty if unresolvable).
        cmdline:   Full command line (null-separated → space-joined).
        ppid:      Parent process ID.
        parent_comm: Parent process comm name.
        maps:      List of raw lines from /proc/<pid>/maps.
        accessible: Whether /proc/<pid> was accessible without permission error.
    """
    pid:          int
    comm:         str = ""
    exe:          str = ""
    cmdline:      str = ""
    ppid:         int = 0
    parent_comm:  str = ""
    maps:         list[str] = field(default_factory=list)
    accessible:   bool = True


@dataclass
class ArtifactReport:
    """
    Memory artifact report for a single process.

    Attributes:
        snapshot:    The process snapshot that was analyzed.
        indicators:  All indicators found.
        risk_score:  Aggregate 0–100 risk score.
    """
    snapshot:    ProcessSnapshot
    indicators:  list[MemoryIndicator] = field(default_factory=list)
    risk_score:  int = 0

    @property
    def has_indicators(self) -> bool:
        return len(self.indicators) > 0

    @property
    def pid(self) -> int:
        return self.snapshot.pid

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.indicators if i.severity == IndicatorSeverity.CRITICAL)

    def indicators_by_check(self, check_id: str) -> list[MemoryIndicator]:
        return [i for i in self.indicators if i.check_id == check_id]

    def summary(self) -> str:
        return (
            f"ArtifactReport pid={self.pid} ({self.snapshot.comm!r}) | "
            f"risk={self.risk_score} | "
            f"{len(self.indicators)} indicator(s) "
            f"[CRITICAL={self.critical_count}]"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid":          self.pid,
            "comm":         self.snapshot.comm,
            "exe":          self.snapshot.exe,
            "risk_score":   self.risk_score,
            "indicators":   [i.to_dict() for i in self.indicators],
        }


# ---------------------------------------------------------------------------
# MemoryArtifactCollector
# ---------------------------------------------------------------------------

class MemoryArtifactCollector:
    """
    Read-only memory artifact collector for Linux processes.

    Reads from /proc/<pid>/ to collect process metadata and memory maps,
    then analyzes them for injection and evasion indicators.

    Args:
        proc_root:  Path to /proc (override for testing, default ``/proc``).
        dry_run:    If True, skip actual filesystem reads and return empty
                    snapshots (default False). Useful for CI environments
                    without /proc access.
    """

    def __init__(
        self,
        proc_root: str = "/proc",
        dry_run: bool = False,
    ) -> None:
        self._proc_root = Path(proc_root)
        self._dry_run   = dry_run

    def collect_pid(self, pid: int) -> ArtifactReport:
        """
        Collect and analyze memory artifacts for a single PID.

        Returns an ArtifactReport. If the PID is inaccessible or does not
        exist, the report's snapshot.accessible will be False.
        """
        snapshot = self._read_snapshot(pid)
        return self._analyze(snapshot)

    def collect_all(self) -> list[ArtifactReport]:
        """
        Enumerate all numeric directories under /proc and collect each PID.

        Returns a list of ArtifactReports (only for accessible PIDs).
        """
        if self._dry_run:
            return []
        reports: list[ArtifactReport] = []
        try:
            for entry in self._proc_root.iterdir():
                if entry.name.isdigit():
                    try:
                        report = self.collect_pid(int(entry.name))
                        if report.snapshot.accessible:
                            reports.append(report)
                    except Exception:
                        continue
        except PermissionError:
            pass
        return reports

    def analyze_snapshot(self, snapshot: ProcessSnapshot) -> ArtifactReport:
        """
        Analyze a pre-built ProcessSnapshot (useful for testing).

        Returns an ArtifactReport.
        """
        return self._analyze(snapshot)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _read_snapshot(self, pid: int) -> ProcessSnapshot:
        """Read process metadata from /proc/<pid>/."""
        snapshot = ProcessSnapshot(pid=pid)
        if self._dry_run:
            return snapshot

        proc_dir = self._proc_root / str(pid)
        if not proc_dir.exists():
            snapshot.accessible = False
            return snapshot

        try:
            comm_path = proc_dir / "comm"
            if comm_path.exists():
                snapshot.comm = comm_path.read_text().strip()
        except (PermissionError, OSError):
            pass

        try:
            exe_path = proc_dir / "exe"
            try:
                snapshot.exe = str(exe_path.resolve())
            except (PermissionError, OSError):
                snapshot.exe = ""
        except Exception:
            pass

        try:
            cmdline_path = proc_dir / "cmdline"
            if cmdline_path.exists():
                raw = cmdline_path.read_bytes()
                snapshot.cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (PermissionError, OSError):
            pass

        try:
            status_path = proc_dir / "status"
            if status_path.exists():
                for line in status_path.read_text().splitlines():
                    if line.startswith("PPid:"):
                        snapshot.ppid = int(line.split()[1])
                        break
        except (PermissionError, OSError):
            pass

        # Resolve parent comm
        if snapshot.ppid > 0:
            parent_comm_path = self._proc_root / str(snapshot.ppid) / "comm"
            try:
                if parent_comm_path.exists():
                    snapshot.parent_comm = parent_comm_path.read_text().strip()
            except (PermissionError, OSError):
                pass

        try:
            maps_path = proc_dir / "maps"
            if maps_path.exists():
                snapshot.maps = maps_path.read_text().splitlines()
        except (PermissionError, OSError):
            pass

        return snapshot

    def _analyze(self, snapshot: ProcessSnapshot) -> ArtifactReport:
        """Analyze a ProcessSnapshot and return an ArtifactReport."""
        if not snapshot.accessible:
            return ArtifactReport(snapshot=snapshot)

        indicators: list[MemoryIndicator] = []
        fired_checks: set[str] = set()

        # Analyze memory maps
        for line in snapshot.maps:
            m = _MAPS_LINE_RE.match(line)
            if not m:
                continue
            addr_range = m.group(1)
            perms      = m.group(2)
            path       = m.group(3).strip()

            is_exec    = "x" in perms
            is_write   = "w" in perms

            if not is_exec:
                continue  # only care about executable regions

            # MA-001: Anonymous executable mapping (rwx with no path)
            if not path:
                ind = self._make_indicator(
                    "MA-001", snapshot.pid,
                    detail=(
                        f"Process {snapshot.pid} ({snapshot.comm!r}) has an "
                        f"anonymous executable memory region at {addr_range} "
                        f"with permissions '{perms}'. No backing file — "
                        "shellcode injection is a likely explanation."
                    ),
                    evidence=f"addr={addr_range} perms={perms}",
                )
                indicators.append(ind)
                fired_checks.add("MA-001")

            else:
                # MA-002: Deleted executable
                if path.endswith(" (deleted)"):
                    ind = self._make_indicator(
                        "MA-002", snapshot.pid,
                        detail=(
                            f"Process {snapshot.pid} has executable mapping to "
                            f"'{path}' which has been deleted from disk. The "
                            "binary was likely removed to hinder forensic recovery."
                        ),
                        evidence=f"path='{path}'",
                    )
                    indicators.append(ind)
                    fired_checks.add("MA-002")

                # MA-003: Executable mapping from world-writable path
                clean_path = path.rstrip(" (deleted)")
                if any(clean_path.startswith(p) for p in _WRITEABLE_STAGING_PATHS):
                    ind = self._make_indicator(
                        "MA-003", snapshot.pid,
                        detail=(
                            f"Executable memory region for process {snapshot.pid} "
                            f"is backed by '{clean_path}' in a world-writable "
                            "staging directory."
                        ),
                        evidence=f"path='{clean_path}' perms={perms}",
                    )
                    indicators.append(ind)
                    fired_checks.add("MA-003")

                # MA-007: High-entropy path
                basename = os.path.basename(clean_path)
                if basename and _path_entropy(basename) >= _HIGH_ENTROPY_THRESHOLD:
                    ind = self._make_indicator(
                        "MA-007", snapshot.pid,
                        detail=(
                            f"Executable mapping basename '{basename}' has "
                            f"entropy {_path_entropy(basename):.2f} bits/char, "
                            "consistent with randomly generated malware filenames."
                        ),
                        evidence=f"basename='{basename}'",
                    )
                    indicators.append(ind)
                    fired_checks.add("MA-007")

        # MA-004: Process name / exe mismatch
        if snapshot.comm and snapshot.exe:
            exe_base = os.path.basename(snapshot.exe.rstrip(" (deleted)"))
            if exe_base and snapshot.comm not in exe_base and exe_base not in snapshot.comm:
                ind = self._make_indicator(
                    "MA-004", snapshot.pid,
                    detail=(
                        f"Process comm='{snapshot.comm}' but exe='{snapshot.exe}'. "
                        "A process masquerading under a legitimate name while "
                        "running a different binary is a common evasion technique."
                    ),
                    evidence=f"comm='{snapshot.comm}' exe_base='{exe_base}'",
                )
                indicators.append(ind)
                fired_checks.add("MA-004")

        # MA-005: Suspicious parent→child relationship
        parent_comm_lower = snapshot.parent_comm.lower()
        comm_lower        = snapshot.comm.lower()
        if parent_comm_lower in _SUSPICIOUS_PARENTS and comm_lower in _SHELL_NAMES:
            ind = self._make_indicator(
                "MA-005", snapshot.pid,
                detail=(
                    f"Process '{snapshot.comm}' (pid={snapshot.pid}) is a child "
                    f"of '{snapshot.parent_comm}' (ppid={snapshot.ppid}). "
                    "Web servers and document renderers should not spawn shells."
                ),
                evidence=f"parent='{snapshot.parent_comm}' child='{snapshot.comm}'",
            )
            indicators.append(ind)
            fired_checks.add("MA-005")

        # MA-006: Running from deleted executable
        if snapshot.exe and "(deleted)" in snapshot.exe:
            ind = self._make_indicator(
                "MA-006", snapshot.pid,
                detail=(
                    f"Process {snapshot.pid} ({snapshot.comm!r}) is running from "
                    f"a deleted executable: '{snapshot.exe}'. The binary was "
                    "removed from disk while the process was running — a common "
                    "anti-forensics technique."
                ),
                evidence=f"exe='{snapshot.exe}'",
            )
            indicators.append(ind)
            fired_checks.add("MA-006")

        risk_score = min(100, sum(
            _CHECK_WEIGHTS.get(cid, 5) for cid in fired_checks
        ))

        return ArtifactReport(
            snapshot=snapshot,
            indicators=indicators,
            risk_score=risk_score,
        )

    @staticmethod
    def _make_indicator(
        check_id: str,
        pid: int,
        detail: str,
        evidence: str = "",
    ) -> MemoryIndicator:
        severity, title = _CHECK_META[check_id]
        return MemoryIndicator(
            check_id=check_id,
            severity=severity,
            title=title,
            detail=detail,
            pid=pid,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _path_entropy(s: str) -> float:
    """Shannon entropy in bits per character of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())
