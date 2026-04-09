"""
Windows Registry Persistence Detector
=======================================
Identifies common persistence mechanisms in Windows registry exports, parsed
event logs, or structured snapshot data. Detects Run keys, startup entries,
scheduled task registrations, service installations, and IFEO hijacks.

All checks operate on structured data (dicts/lists) — no live registry access
or OS-specific APIs are required, enabling analysis in DFIR triage pipelines
on any platform.

Indicators Covered
-------------------
REG-P-001   HKCU/HKLM Run / RunOnce key entries
REG-P-002   HKCU/HKLM RunServices / RunServicesOnce entries
REG-P-003   Startup folder file entries
REG-P-004   Windows service pointing to writable / suspicious path
REG-P-005   Image File Execution Options (IFEO) debugger hijack
REG-P-006   AppInit_DLLs entry (DLL injection on every user32 load)
REG-P-007   Winlogon Userinit / Shell hijack

Usage::

    from collectors.windows.registry_persistence import (
        RegistryPersistenceDetector,
        RegistrySnapshot,
        PersistenceFinding,
    )

    snapshot = RegistrySnapshot(
        run_keys=[
            {"hive": "HKCU", "name": "EvilProg", "value": "C:\\Temp\\evil.exe"}
        ],
    )
    detector = RegistryPersistenceDetector()
    report = detector.analyze(snapshot)
    for finding in report.findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PersistenceSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ---------------------------------------------------------------------------
# RegistrySnapshot — input model
# ---------------------------------------------------------------------------

@dataclass
class RegistrySnapshot:
    """
    A structured snapshot of Windows registry persistence locations.

    Each list contains dicts with the fields relevant to that category.
    All fields are optional — omit categories that were not collected.

    Fields per category:
        run_keys:        [{"hive": str, "name": str, "value": str}]
        run_services:    [{"hive": str, "name": str, "value": str}]
        startup_files:   [{"path": str, "username": str}]
        services:        [{"name": str, "image_path": str, "start_type": str}]
        ifeo_entries:    [{"image": str, "debugger": str}]
        appinit_dlls:    [{"hive": str, "value": str}]
        winlogon_entries: [{"key": str, "value": str}]
    """
    run_keys:         List[Dict[str, str]] = field(default_factory=list)
    run_services:     List[Dict[str, str]] = field(default_factory=list)
    startup_files:    List[Dict[str, str]] = field(default_factory=list)
    services:         List[Dict[str, str]] = field(default_factory=list)
    ifeo_entries:     List[Dict[str, str]] = field(default_factory=list)
    appinit_dlls:     List[Dict[str, str]] = field(default_factory=list)
    winlogon_entries: List[Dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PersistenceFinding
# ---------------------------------------------------------------------------

@dataclass
class PersistenceFinding:
    """
    A single persistence indicator finding.

    Attributes:
        check_id:    REG-P-XXX identifier.
        severity:    Severity level.
        title:       Short description.
        detail:      Human-readable explanation.
        evidence:    The specific value or path that triggered the check.
        hive:        Registry hive (HKCU/HKLM) if applicable.
        key_name:    Registry key or entry name if applicable.
    """
    check_id:  str
    severity:  PersistenceSeverity
    title:     str
    detail:    str
    evidence:  str = ""
    hive:      str = ""
    key_name:  str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id":  self.check_id,
            "severity":  self.severity.value,
            "title":     self.title,
            "detail":    self.detail,
            "evidence":  self.evidence[:512],
            "hive":      self.hive,
            "key_name":  self.key_name,
        }

    def summary(self) -> str:
        return f"[{self.check_id}] {self.severity.value}: {self.title} — {self.evidence[:80]}"


# ---------------------------------------------------------------------------
# PersistenceReport
# ---------------------------------------------------------------------------

@dataclass
class PersistenceReport:
    """
    Aggregated persistence detection report.

    Attributes:
        findings:      All persistence findings.
        risk_score:    0–100 aggregate risk score.
        generated_at:  Unix timestamp.
    """
    findings:     List[PersistenceFinding] = field(default_factory=list)
    risk_score:   int   = 0
    generated_at: float = field(default_factory=time.time)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> List[PersistenceFinding]:
        return [f for f in self.findings if f.severity == PersistenceSeverity.CRITICAL]

    @property
    def high_findings(self) -> List[PersistenceFinding]:
        return [f for f in self.findings if f.severity == PersistenceSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> List[PersistenceFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def summary(self) -> str:
        return (
            f"Persistence Report: {self.total_findings} findings, "
            f"risk_score={self.risk_score}, "
            f"critical={len(self.critical_findings)}, "
            f"high={len(self.high_findings)}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "risk_score":     self.risk_score,
            "critical":       len(self.critical_findings),
            "high":           len(self.high_findings),
            "generated_at":   self.generated_at,
            "findings":       [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Suspicious path patterns
# ---------------------------------------------------------------------------

# Paths commonly abused for persistence (writable by non-admin users)
_SUSPICIOUS_PATH_PATTERNS = re.compile(
    r"(?:\\Temp\\|\\AppData\\|\\Public\\|\\Users\\|%temp%|%appdata%|%public%|"
    r"\\Downloads\\|\\Desktop\\|\\Startup\\|C:\\Windows\\Temp\\)",
    re.IGNORECASE,
)

# Common legitimate service paths (safe prefixes)
_LEGIT_SERVICE_PREFIXES = (
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files\\",
    r"C:\Program Files (x86)\\",
    r"%SystemRoot%\\system32",
    r"%SystemRoot%\\SysWOW64",
)

# Winlogon keys that should not be modified
_WINLOGON_SENSITIVE_KEYS = frozenset({
    "userinit",
    "shell",
    "taskman",
    "appsetup",
})

# Expected safe Winlogon values
_WINLOGON_SAFE_VALUES: Dict[str, str] = {
    "userinit": "C:\\Windows\\system32\\userinit.exe,",
    "shell":    "explorer.exe",
}

# Check weights for risk score
_CHECK_WEIGHTS: Dict[str, int] = {
    "REG-P-001": 25,
    "REG-P-002": 20,
    "REG-P-003": 15,
    "REG-P-004": 30,
    "REG-P-005": 40,  # IFEO hijack is very suspicious
    "REG-P-006": 35,
    "REG-P-007": 40,
}


# ---------------------------------------------------------------------------
# RegistryPersistenceDetector
# ---------------------------------------------------------------------------

class RegistryPersistenceDetector:
    """
    Analyzes a RegistrySnapshot for persistence indicators.

    Args:
        flag_all_run_keys:   If True, flag every Run entry regardless of path
                             (useful for forensic review). Default False —
                             only flag suspicious paths.
        flag_all_services:   If True, flag every service. Default False —
                             only flag non-standard image paths.
    """

    def __init__(
        self,
        flag_all_run_keys: bool = False,
        flag_all_services: bool = False,
    ) -> None:
        self._flag_all_run = flag_all_run_keys
        self._flag_all_svc = flag_all_services

    def analyze(self, snapshot: RegistrySnapshot) -> PersistenceReport:
        """
        Run all persistence checks against a RegistrySnapshot.

        Returns:
            PersistenceReport with all findings and risk score.
        """
        findings: List[PersistenceFinding] = []

        findings.extend(self._check_run_keys(snapshot.run_keys, "REG-P-001"))
        findings.extend(self._check_run_keys(snapshot.run_services, "REG-P-002"))
        findings.extend(self._check_startup_files(snapshot.startup_files))
        findings.extend(self._check_services(snapshot.services))
        findings.extend(self._check_ifeo(snapshot.ifeo_entries))
        findings.extend(self._check_appinit(snapshot.appinit_dlls))
        findings.extend(self._check_winlogon(snapshot.winlogon_entries))

        # Risk score: sum weights of unique fired check IDs, capped at 100
        fired_checks = {f.check_id for f in findings}
        score = min(100, sum(_CHECK_WEIGHTS.get(c, 10) for c in fired_checks))

        return PersistenceReport(findings=findings, risk_score=score)

    # ------------------------------------------------------------------
    # REG-P-001 / REG-P-002: Run / RunServices keys
    # ------------------------------------------------------------------

    def _check_run_keys(
        self,
        entries: List[Dict[str, str]],
        check_id: str,
    ) -> List[PersistenceFinding]:
        findings: List[PersistenceFinding] = []
        for entry in entries:
            value = entry.get("value", "")
            name  = entry.get("name", "")
            hive  = entry.get("hive", "")
            if self._flag_all_run or _SUSPICIOUS_PATH_PATTERNS.search(value):
                severity = (
                    PersistenceSeverity.HIGH
                    if _SUSPICIOUS_PATH_PATTERNS.search(value)
                    else PersistenceSeverity.MEDIUM
                )
                findings.append(PersistenceFinding(
                    check_id=check_id,
                    severity=severity,
                    title=f"{'Run' if check_id == 'REG-P-001' else 'RunServices'} key entry with suspicious path",
                    detail=(
                        f"Registry Run entry '{name}' in {hive} points to "
                        f"a suspicious or user-writable location: {value}"
                    ),
                    evidence=value,
                    hive=hive,
                    key_name=name,
                ))
        return findings

    # ------------------------------------------------------------------
    # REG-P-003: Startup folder files
    # ------------------------------------------------------------------

    def _check_startup_files(
        self, files: List[Dict[str, str]]
    ) -> List[PersistenceFinding]:
        findings: List[PersistenceFinding] = []
        for f in files:
            path     = f.get("path", "")
            username = f.get("username", "")
            findings.append(PersistenceFinding(
                check_id="REG-P-003",
                severity=PersistenceSeverity.MEDIUM,
                title="Startup folder entry",
                detail=(
                    f"File '{path}' exists in startup folder "
                    f"(user: {username or 'all users'}). "
                    f"Verify legitimacy."
                ),
                evidence=path,
                key_name=username,
            ))
        return findings

    # ------------------------------------------------------------------
    # REG-P-004: Services with suspicious image paths
    # ------------------------------------------------------------------

    def _check_services(
        self, services: List[Dict[str, str]]
    ) -> List[PersistenceFinding]:
        findings: List[PersistenceFinding] = []
        for svc in services:
            name       = svc.get("name", "")
            image_path = svc.get("image_path", "")
            start_type = svc.get("start_type", "")

            if self._flag_all_svc:
                findings.append(PersistenceFinding(
                    check_id="REG-P-004",
                    severity=PersistenceSeverity.LOW,
                    title="Service entry",
                    detail=f"Service '{name}' image: {image_path}",
                    evidence=image_path,
                    key_name=name,
                ))
                continue

            if _SUSPICIOUS_PATH_PATTERNS.search(image_path):
                findings.append(PersistenceFinding(
                    check_id="REG-P-004",
                    severity=PersistenceSeverity.CRITICAL,
                    title="Service with suspicious image path",
                    detail=(
                        f"Service '{name}' (start_type={start_type}) has "
                        f"image path in user-writable location: {image_path}"
                    ),
                    evidence=image_path,
                    key_name=name,
                ))
        return findings

    # ------------------------------------------------------------------
    # REG-P-005: IFEO debugger hijacks
    # ------------------------------------------------------------------

    def _check_ifeo(
        self, entries: List[Dict[str, str]]
    ) -> List[PersistenceFinding]:
        findings: List[PersistenceFinding] = []
        for entry in entries:
            image    = entry.get("image", "")
            debugger = entry.get("debugger", "")
            findings.append(PersistenceFinding(
                check_id="REG-P-005",
                severity=PersistenceSeverity.CRITICAL,
                title="IFEO debugger hijack",
                detail=(
                    f"Image File Execution Options for '{image}' sets "
                    f"Debugger to '{debugger}'. Any launch of {image} will "
                    f"execute the attacker's debugger instead."
                ),
                evidence=debugger,
                key_name=image,
            ))
        return findings

    # ------------------------------------------------------------------
    # REG-P-006: AppInit_DLLs
    # ------------------------------------------------------------------

    def _check_appinit(
        self, entries: List[Dict[str, str]]
    ) -> List[PersistenceFinding]:
        findings: List[PersistenceFinding] = []
        for entry in entries:
            hive  = entry.get("hive", "")
            value = entry.get("value", "")
            if value:
                findings.append(PersistenceFinding(
                    check_id="REG-P-006",
                    severity=PersistenceSeverity.HIGH,
                    title="AppInit_DLLs entry",
                    detail=(
                        f"AppInit_DLLs in {hive} is set to '{value}'. "
                        f"These DLLs are loaded into every process that loads "
                        f"user32.dll, enabling persistent code injection."
                    ),
                    evidence=value,
                    hive=hive,
                ))
        return findings

    # ------------------------------------------------------------------
    # REG-P-007: Winlogon Userinit / Shell hijack
    # ------------------------------------------------------------------

    def _check_winlogon(
        self, entries: List[Dict[str, str]]
    ) -> List[PersistenceFinding]:
        findings: List[PersistenceFinding] = []
        for entry in entries:
            key   = entry.get("key", "").lower()
            value = entry.get("value", "")
            if key not in _WINLOGON_SENSITIVE_KEYS:
                continue
            expected = _WINLOGON_SAFE_VALUES.get(key)
            if expected and value.lower().strip() == expected.lower().strip():
                continue  # value matches safe default
            findings.append(PersistenceFinding(
                check_id="REG-P-007",
                severity=PersistenceSeverity.CRITICAL,
                title=f"Winlogon {key} hijack",
                detail=(
                    f"Winlogon\\{key} is set to '{value}' — "
                    f"expected safe value: '{expected or 'unknown'}'. "
                    f"This can redirect logon process execution."
                ),
                evidence=value,
                key_name=key,
            ))
        return findings
