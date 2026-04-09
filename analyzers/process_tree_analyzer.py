"""
Process Tree Analyzer
=======================
Analyzes process trees (parent-child relationships) for suspicious spawning
patterns: unexpected parent processes, process masquerading, LOLBins abused
for execution, and injection-like behavior.

Operates on ProcessNode inputs — no live system access required.

Check IDs
----------
PT-001   Suspicious parent-child relationship (e.g. Word spawning cmd.exe)
PT-002   Process name masquerades as system process (svchost not from System32)
PT-003   Living-off-the-land binary (LOLBin) used for execution or download
PT-004   Unusual shell spawned from non-interactive parent
PT-005   Process with empty or suspicious command line
PT-006   High number of child processes spawned quickly (process bomb indicator)
PT-007   Known attacker tool name in process name or command line

Usage::

    from analyzers.process_tree_analyzer import ProcessTreeAnalyzer, ProcessNode

    nodes = [
        ProcessNode(pid=1234, ppid=4, name="cmd.exe", cmdline="cmd.exe /c whoami",
                    parent_name="winword.exe", path="C:\\Windows\\System32\\cmd.exe"),
    ]
    analyzer = ProcessTreeAnalyzer()
    report = analyzer.analyze(nodes)
    for finding in report.findings:
        print(finding.to_dict())
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class PTSeverity(Enum):
    """Severity levels for process tree findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Threat intelligence tables
# ---------------------------------------------------------------------------

# Maps parent process names to the set of child process names that are
# suspicious when spawned from that parent (Office / browser macro abuse).
_SUSPICIOUS_PARENT_CHILD: Dict[str, set] = {
    "winword.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "excel.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "outlook.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "powerpnt.exe": {"cmd.exe", "powershell.exe", "wscript.exe"},
    "acrobat.exe":  {"cmd.exe", "powershell.exe", "wscript.exe"},
    "acrord32.exe": {"cmd.exe", "powershell.exe", "wscript.exe"},
    "iexplore.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "chrome.exe":   {"cmd.exe", "powershell.exe"},
    "winrar.exe":   {"cmd.exe", "powershell.exe"},
}

# Processes that must only run from System32; any other path is suspicious.
_SYSTEM_PROCESS_NAMES: frozenset = frozenset({
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "smss.exe",
})

# Living-off-the-land binaries — legitimate tools commonly abused by attackers.
_LOLBINS: frozenset = frozenset({
    "certutil.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "msiexec.exe",
    "odbcconf.exe",
    "regasm.exe",
    "regsvcs.exe",
    "installutil.exe",
    "msbuild.exe",
    "cmstp.exe",
    "appsync.exe",
})

# Keywords that indicate known offensive / post-exploitation tooling.
_ATTACKER_TOOLS: frozenset = frozenset({
    "mimikatz",
    "meterpreter",
    "cobalt",
    "empire",
    "covenant",
    "bloodhound",
    "sharphound",
    "rubeus",
    "kerbrute",
    "crackmapexec",
    "impacket",
    "psexec",
    "wce.exe",
    "pwdump",
    "lazagne",
    "netcat",
    "ncat",
    "socat",
})

# Risk-score weights per check ID (capped at 100 total).
_CHECK_WEIGHTS: Dict[str, int] = {
    "PT-001": 40,
    "PT-002": 45,
    "PT-003": 35,
    "PT-004": 30,
    "PT-005": 20,
    "PT-006": 30,
    "PT-007": 45,
}

# Shell processes for PT-005 empty-cmdline check.
_SHELLS: frozenset = frozenset({"cmd.exe", "powershell.exe"})

# Service-context parents that should never directly spawn interactive shells.
_SERVICE_PARENTS: frozenset = frozenset({"services.exe", "lsass.exe", "svchost.exe"})


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ProcessNode:
    """
    Lightweight representation of a single process.

    All fields are populated from host telemetry or forensic artifacts;
    no live OS calls are made by this class.
    """
    pid: int
    ppid: int = 0
    name: str = ""
    cmdline: str = ""
    parent_name: str = ""
    path: str = ""
    user: str = ""
    child_count: int = 0

    @property
    def name_lower(self) -> str:
        """Return the process name in lower-case for case-insensitive comparisons."""
        return self.name.lower()

    @property
    def cmdline_lower(self) -> str:
        """Return the command line in lower-case for case-insensitive comparisons."""
        return self.cmdline.lower()


@dataclass
class PTFinding:
    """
    A single detection result produced by one of the PT-* checks.

    Attributes
    ----------
    check_id:      PT-NNN identifier
    severity:      PTSeverity level
    pid:           PID of the flagged process
    process_name:  Name of the flagged process
    parent_name:   Name of the parent process (may be empty)
    title:         Short human-readable title
    detail:        Longer explanation of why this was flagged
    evidence:      Raw evidence string (command line, path, etc.)
    remediation:   Suggested remediation action
    """
    check_id: str
    severity: PTSeverity
    pid: int
    process_name: str
    parent_name: str
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, object]:
        """Serialize the finding to a plain dictionary (JSON-safe types)."""
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "pid": self.pid,
            "process_name": self.process_name,
            "parent_name": self.parent_name,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        """Return a one-line summary string suitable for logging."""
        return (
            f"[{self.check_id}] [{self.severity.value}] "
            f"PID={self.pid} {self.process_name!r} — {self.title}"
        )


@dataclass
class PTReport:
    """
    Aggregated output from a single ``ProcessTreeAnalyzer.analyze()`` run.

    Attributes
    ----------
    findings:            All PTFinding objects produced during analysis
    risk_score:          Weighted risk score (0-100)
    processes_analyzed:  Number of ProcessNode objects evaluated
    generated_at:        Unix timestamp of report creation
    """
    findings: List[PTFinding] = field(default_factory=list)
    risk_score: int = 0
    processes_analyzed: int = 0
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings regardless of severity."""
        return len(self.findings)

    @property
    def critical_findings(self) -> int:
        """Number of CRITICAL-severity findings."""
        return sum(1 for f in self.findings if f.severity == PTSeverity.CRITICAL)

    @property
    def high_findings(self) -> int:
        """Number of HIGH-severity findings."""
        return sum(1 for f in self.findings if f.severity == PTSeverity.HIGH)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def findings_by_check(self) -> Dict[str, List[PTFinding]]:
        """Return findings grouped by check ID."""
        result: Dict[str, List[PTFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.check_id, []).append(finding)
        return result

    def findings_for_pid(self, pid: int) -> List[PTFinding]:
        """Return all findings that relate to a specific PID."""
        return [f for f in self.findings if f.pid == pid]

    def summary(self) -> str:
        """Return a human-readable summary of the report."""
        return (
            f"PTReport | processes_analyzed={self.processes_analyzed} "
            f"total_findings={self.total_findings} "
            f"critical={self.critical_findings} high={self.high_findings} "
            f"risk_score={self.risk_score}"
        )

    def to_dict(self) -> Dict[str, object]:
        """Serialize the full report to a plain dictionary."""
        return {
            "risk_score": self.risk_score,
            "processes_analyzed": self.processes_analyzed,
            "generated_at": self.generated_at,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class ProcessTreeAnalyzer:
    """
    Stateless process-tree analyzer.

    Parameters
    ----------
    child_count_threshold:
        Maximum number of child processes before PT-006 fires.
        Default is 20, which is suitable for most environments.
    """

    def __init__(self, child_count_threshold: int = 20) -> None:
        self.child_count_threshold = child_count_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, nodes: List[ProcessNode]) -> PTReport:
        """
        Analyze a list of ProcessNode objects and return a PTReport.

        The method is side-effect-free; calling it multiple times with the
        same input always produces equivalent output.

        Parameters
        ----------
        nodes:
            Process nodes gathered from EDR telemetry, memory acquisition,
            or any other forensic source.

        Returns
        -------
        PTReport
            Populated with all findings and a computed risk score.
        """
        findings: List[PTFinding] = []

        for node in nodes:
            findings.extend(self._check_pt001(node))
            findings.extend(self._check_pt002(node))
            findings.extend(self._check_pt003(node))
            findings.extend(self._check_pt004(node))
            findings.extend(self._check_pt005(node))
            findings.extend(self._check_pt006(node))
            findings.extend(self._check_pt007(node))

        # Risk score: sum weights for each unique check ID that fired,
        # capped at 100.
        fired_checks = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_checks)
        risk_score = min(raw_score, 100)

        return PTReport(
            findings=findings,
            risk_score=risk_score,
            processes_analyzed=len(nodes),
            generated_at=time.time(),
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_pt001(self, node: ProcessNode) -> List[PTFinding]:
        """
        PT-001: Suspicious parent-child relationship.

        Fires when a document/browser application spawns a shell or
        scripting host — a classic macro/exploit execution pattern.
        """
        parent_lower = node.parent_name.lower()
        suspicious_children = _SUSPICIOUS_PARENT_CHILD.get(parent_lower)
        if suspicious_children is None:
            return []
        if node.name_lower not in suspicious_children:
            return []

        return [PTFinding(
            check_id="PT-001",
            severity=PTSeverity.CRITICAL,
            pid=node.pid,
            process_name=node.name,
            parent_name=node.parent_name,
            title="Suspicious parent-child process relationship",
            detail=(
                f"'{node.parent_name}' spawned '{node.name}', which is a "
                "common indicator of macro-based or exploit-assisted code "
                "execution. Office/browser applications should not directly "
                "launch shell or scripting interpreters."
            ),
            evidence=(
                f"parent={node.parent_name!r} child={node.name!r} "
                f"cmdline={node.cmdline!r}"
            ),
            remediation=(
                "Investigate the parent document or browser tab that triggered "
                "this spawn. Isolate the endpoint and review EDR telemetry for "
                "follow-on activity (downloads, lateral movement)."
            ),
        )]

    def _check_pt002(self, node: ProcessNode) -> List[PTFinding]:
        """
        PT-002: Process name masquerades as a system process.

        Fires when a known system-process name is found running from a path
        that does not include 'system32', indicating a masquerading binary.
        """
        if node.name_lower not in _SYSTEM_PROCESS_NAMES:
            return []
        # Only flag if a path was provided and it does not contain system32.
        if not node.path:
            return []
        if "system32" in node.path.lower():
            return []

        return [PTFinding(
            check_id="PT-002",
            severity=PTSeverity.CRITICAL,
            pid=node.pid,
            process_name=node.name,
            parent_name=node.parent_name,
            title="System process masquerading from non-standard path",
            detail=(
                f"'{node.name}' is a protected system process that must run "
                "from '%SystemRoot%\\System32'. This instance is running from "
                f"'{node.path}', which strongly suggests process masquerading "
                "or a rootkit attempting to blend in with legitimate processes."
            ),
            evidence=f"name={node.name!r} path={node.path!r}",
            remediation=(
                "Treat this as a high-priority incident. Acquire a memory image "
                "before rebooting. Submit the binary at the non-standard path to "
                "threat intelligence / sandboxing. Consider isolating the host."
            ),
        )]

    def _check_pt003(self, node: ProcessNode) -> List[PTFinding]:
        """
        PT-003: Living-off-the-land binary (LOLBin) detected.

        Fires whenever a known LOLBin is present in the process list.
        LOLBins are legitimate Microsoft-signed tools that attackers abuse
        to proxy execution, download payloads, or bypass AppLocker.
        """
        if node.name_lower not in _LOLBINS:
            return []

        return [PTFinding(
            check_id="PT-003",
            severity=PTSeverity.HIGH,
            pid=node.pid,
            process_name=node.name,
            parent_name=node.parent_name,
            title="Living-off-the-land binary (LOLBin) execution",
            detail=(
                f"'{node.name}' is a known LOLBin — a legitimate Windows utility "
                "frequently abused by threat actors to execute code, download "
                "remote payloads, or bypass application whitelisting controls."
            ),
            evidence=(
                f"lolbin={node.name!r} cmdline={node.cmdline!r} "
                f"parent={node.parent_name!r}"
            ),
            remediation=(
                "Verify the business justification for this LOLBin invocation. "
                "Review the full command-line arguments for download cradles "
                "(e.g., certutil -urlcache, bitsadmin /transfer). "
                "Consider blocking or auditing via WDAC / AppLocker."
            ),
        )]

    def _check_pt004(self, node: ProcessNode) -> List[PTFinding]:
        """
        PT-004: Unusual shell spawned from a service-context parent.

        Fires when cmd.exe or powershell.exe is a direct child of a service
        management process (services.exe, lsass.exe, svchost.exe). These
        parents should never interactively spawn shells under normal operation.
        """
        if node.parent_name.lower() not in _SERVICE_PARENTS:
            return []
        if node.name_lower not in _SHELLS:
            return []

        return [PTFinding(
            check_id="PT-004",
            severity=PTSeverity.HIGH,
            pid=node.pid,
            process_name=node.name,
            parent_name=node.parent_name,
            title="Unexpected shell spawned from service-context parent",
            detail=(
                f"'{node.parent_name}' spawned '{node.name}'. Service-management "
                "processes do not legitimately spawn interactive shells. This "
                "pattern is consistent with service-hijacking, DLL injection, or "
                "token impersonation followed by shell access."
            ),
            evidence=(
                f"parent={node.parent_name!r} child={node.name!r} "
                f"cmdline={node.cmdline!r}"
            ),
            remediation=(
                "Verify no malicious service DLL has been loaded into the parent "
                "process. Review service registry keys "
                "(HKLM\\SYSTEM\\CurrentControlSet\\Services) for unsigned or "
                "recently modified entries. Cross-reference with scheduled task "
                "and WMI subscription logs."
            ),
        )]

    def _check_pt005(self, node: ProcessNode) -> List[PTFinding]:
        """
        PT-005: Shell process with empty or suspiciously minimal command line.

        A shell running with no arguments or only its own name may indicate
        process hollowing, where the original command line is preserved but
        the process image has been replaced.
        """
        if node.name_lower not in _SHELLS:
            return []

        # Fire if cmdline is empty or cmdline (stripped) equals just the
        # process name — neither carries meaningful arguments.
        stripped = node.cmdline.strip()
        is_empty = stripped == ""
        is_name_only = stripped.lower() == node.name_lower

        if not (is_empty or is_name_only):
            return []

        return [PTFinding(
            check_id="PT-005",
            severity=PTSeverity.MEDIUM,
            pid=node.pid,
            process_name=node.name,
            parent_name=node.parent_name,
            title="Shell process with empty or minimal command line",
            detail=(
                f"'{node.name}' was observed with an empty or name-only command "
                f"line ('{node.cmdline}'). Legitimate shells always carry argument "
                "strings. This is a common process-hollowing artifact where the "
                "attacker preserves the parent-supplied PEB command line but has "
                "already replaced the in-memory image."
            ),
            evidence=f"name={node.name!r} cmdline={node.cmdline!r}",
            remediation=(
                "Dump the process memory and compare the on-disk image hash "
                "against the in-memory PE headers. Look for PE header stomping "
                "indicators. Acquire a full memory image before remediation."
            ),
        )]

    def _check_pt006(self, node: ProcessNode) -> List[PTFinding]:
        """
        PT-006: Abnormally high child-process count (process-bomb indicator).

        A process that spawns an unusually large number of children in a short
        window may be running a fork-bomb, a crawler, or a brute-force tool.
        """
        if node.child_count <= self.child_count_threshold:
            return []

        return [PTFinding(
            check_id="PT-006",
            severity=PTSeverity.HIGH,
            pid=node.pid,
            process_name=node.name,
            parent_name=node.parent_name,
            title="Abnormally high child process count",
            detail=(
                f"'{node.name}' (PID {node.pid}) spawned {node.child_count} child "
                f"processes, exceeding the threshold of {self.child_count_threshold}. "
                "High child counts can indicate a process bomb, parallel "
                "brute-force execution, or a reconnaissance tool spawning many "
                "sub-commands."
            ),
            evidence=(
                f"name={node.name!r} pid={node.pid} "
                f"child_count={node.child_count} "
                f"threshold={self.child_count_threshold}"
            ),
            remediation=(
                "Investigate the spawned child processes for malicious activity. "
                "Correlate with network logs for port scanning or credential "
                "spraying. Consider rate-limiting child-process creation via "
                "job objects or GPO."
            ),
        )]

    def _check_pt007(self, node: ProcessNode) -> List[PTFinding]:
        """
        PT-007: Known attacker tool keyword in process name or command line.

        Matches against a curated list of offensive tool names and keywords.
        This check catches both direct execution and in-memory variants that
        surface in command-line arguments.
        """
        matched_keyword: Optional[str] = None

        for keyword in _ATTACKER_TOOLS:
            # Use re.search so keywords match anywhere in the string.
            if re.search(re.escape(keyword), node.name_lower):
                matched_keyword = keyword
                break
            if re.search(re.escape(keyword), node.cmdline_lower):
                matched_keyword = keyword
                break

        if matched_keyword is None:
            return []

        return [PTFinding(
            check_id="PT-007",
            severity=PTSeverity.CRITICAL,
            pid=node.pid,
            process_name=node.name,
            parent_name=node.parent_name,
            title="Known attacker tool detected",
            detail=(
                f"The keyword '{matched_keyword}' — associated with known "
                f"offensive tooling — was found in the process name or command "
                f"line of PID {node.pid} ('{node.name}'). Immediate investigation "
                "is required."
            ),
            evidence=(
                f"keyword={matched_keyword!r} name={node.name!r} "
                f"cmdline={node.cmdline!r}"
            ),
            remediation=(
                "Isolate the endpoint immediately. Preserve memory and disk "
                "images for forensic analysis. Revoke any credentials accessible "
                "to this process. Escalate to incident response."
            ),
        )]
