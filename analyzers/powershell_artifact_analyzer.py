"""
PowerShell Artifact Analyzer
==============================
Forensic analyzer for PowerShell artifacts collected during DFIR investigations.
Detects common offensive PowerShell techniques by examining command text or script
content.

Check IDs
----------
PSA-001  Base64-encoded command (-EncodedCommand / -enc / -e flag)
PSA-002  AMSI bypass patterns (AmsiUtils / amsiContext / AmsiScanBuffer / Bypass near AMSI)
PSA-003  Download cradle (IEX/Invoke-Expression + download keyword)
PSA-004  Execution policy bypass (-ExecutionPolicy Bypass / Set-ExecutionPolicy Bypass, etc.)
PSA-005  LOLBins abuse (certutil, mshta, rundll32, regsvr32, wscript, cscript, msiexec, installutil)
PSA-006  Obfuscation markers (tick-escape, char-array, string-concat joins)
PSA-007  Known attack framework IOCs (Mimikatz, PowerView, Empire, Cobalt Strike, etc.)

Usage::

    from analyzers.powershell_artifact_analyzer import PSArtifact, analyze, analyze_many

    artifact = PSArtifact(
        artifact_id="ev-001",
        command_text="powershell.exe -enc SQBFAFgA...",
        source="event_log",
        host="workstation-01",
    )
    result = analyze(artifact)
    print(result.summary())
    print(result.to_dict())
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Compiled regex constants (module-level, compiled once)
# ---------------------------------------------------------------------------

# PSA-001: Base64-encoded command flag
_RE_PSA001 = re.compile(
    r"(?:-EncodedCommand|-enc\b|-e\b)",
    re.IGNORECASE,
)

# PSA-002: AMSI bypass patterns (case-insensitive)
_RE_PSA002 = re.compile(
    r"(?:"
    r"System\.Management\.Automation\.AmsiUtils"
    r"|amsiContext"
    r"|AmsiScanBuffer"
    r"|Bypass(?=.*AMSI)|AMSI(?=.*Bypass)"
    r")",
    re.IGNORECASE | re.DOTALL,
)

# PSA-003a: Execution keywords
_RE_PSA003_EXEC = re.compile(
    r"\b(?:IEX|Invoke-Expression)\b",
    re.IGNORECASE,
)

# PSA-003b: Download keywords
_RE_PSA003_DL = re.compile(
    r"(?:Net\.WebClient|WebRequest|DownloadString|DownloadFile|curl|wget)",
    re.IGNORECASE,
)

# PSA-004: Execution policy bypass (case-insensitive)
_RE_PSA004 = re.compile(
    r"(?:"
    r"-ExecutionPolicy\s+Bypass"
    r"|-ep\s+Bypass"
    r"|Set-ExecutionPolicy\s+Bypass"
    r"|Set-ExecutionPolicy\s+Unrestricted"
    r")",
    re.IGNORECASE,
)

# PSA-005: LOLBins referenced in PowerShell text
_RE_PSA005 = re.compile(
    r"\b(?:certutil|mshta|rundll32|regsvr32|wscript|cscript|msiexec|installutil)\b",
    re.IGNORECASE,
)

# PSA-006a: Tick-escape (backtick mid-identifier, e.g. `I`E`X)
_RE_PSA006_TICK = re.compile(r"`[A-Za-z]")

# PSA-006b: Char-array obfuscation
_RE_PSA006_CHAR = re.compile(r"\[char\[\]\]", re.IGNORECASE)

# PSA-006c: String concatenation joins ("po"+"wer" or 'po'+'wer')
# We look for occurrences of  "+" or '+' (quote-plus-quote patterns)
_RE_PSA006_CONCAT_DQ = re.compile(r'"\s*\+\s*"')   # "..."+"..."
_RE_PSA006_CONCAT_SQ = re.compile(r"'\s*\+\s*'")   # '...'+''...'

# PSA-007: Known attack framework IOCs (case-insensitive)
_RE_PSA007 = re.compile(
    r"(?:"
    r"Mimikatz|mimi\b|sekurlsa|kerberos::"
    r"|Invoke-Mimikatz"
    r"|PowerView"
    r"|Invoke-BloodHound|SharpHound"
    r"|Empire"
    r"|Cobalt\s*Strike|CobaltStrike|cobaltstrike"
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Check metadata table
# ---------------------------------------------------------------------------

_CHECK_META: Dict[str, Dict] = {
    "PSA-001": {
        "severity": "CRITICAL",
        "description": "Base64-encoded command flag detected (-EncodedCommand/-enc/-e)",
        "weight": 45,
        "technique": "Encoded Command Execution",
    },
    "PSA-002": {
        "severity": "CRITICAL",
        "description": "AMSI bypass pattern detected",
        "weight": 45,
        "technique": "AMSI Bypass",
    },
    "PSA-003": {
        "severity": "HIGH",
        "description": "Download cradle detected (execution keyword + download keyword)",
        "weight": 30,
        "technique": "Download Cradle",
    },
    "PSA-004": {
        "severity": "HIGH",
        "description": "Execution policy bypass detected",
        "weight": 25,
        "technique": "Execution Policy Bypass",
    },
    "PSA-005": {
        "severity": "HIGH",
        "description": "LOLBin referenced in PowerShell command",
        "weight": 25,
        "technique": "LOLBins Abuse",
    },
    "PSA-006": {
        "severity": "MEDIUM",
        "description": "Script obfuscation marker detected (tick-escape, char-array, or string concat)",
        "weight": 20,
        "technique": "Script Obfuscation",
    },
    "PSA-007": {
        "severity": "CRITICAL",
        "description": "Known attack framework IOC detected",
        "weight": 45,
        "technique": "Known Attack Framework",
    },
}

# Ordered mapping of risk score thresholds to threat level labels
_THREAT_THRESHOLDS = [
    (70, "CRITICAL"),
    (40, "HIGH"),
    (20, "MEDIUM"),
    (0,  "LOW"),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PSArtifact:
    """A single PowerShell artifact to be analyzed."""

    artifact_id: str
    command_text: str           # raw PS command or script content
    source: str = ""            # e.g. "event_log", "history_file", "prefetch"
    host: str = ""
    timestamp_utc: Optional[str] = None


@dataclass
class PSACheck:
    """A single fired check result."""

    check_id: str
    severity: str               # CRITICAL / HIGH / MEDIUM
    description: str
    evidence: str               # matched substring, truncated to 200 chars
    weight: int


@dataclass
class PSAResult:
    """Aggregated analysis result for one PSArtifact."""

    artifact_id: str
    checks_fired: List[PSACheck] = field(default_factory=list)
    risk_score: int = 0
    threat_level: str = "LOW"
    suspected_techniques: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain dictionary representation suitable for serialisation."""
        return {
            "artifact_id": self.artifact_id,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "suspected_techniques": list(self.suspected_techniques),
            "checks_fired": [
                {
                    "check_id": c.check_id,
                    "severity": c.severity,
                    "description": c.description,
                    "evidence": c.evidence,
                    "weight": c.weight,
                }
                for c in self.checks_fired
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of the result."""
        techs = ", ".join(self.suspected_techniques) if self.suspected_techniques else "none"
        checks = ", ".join(c.check_id for c in self.checks_fired) if self.checks_fired else "none"
        return (
            f"[{self.threat_level}] artifact={self.artifact_id} "
            f"score={self.risk_score} checks={checks} techniques={techs}"
        )

    def by_severity(self) -> Dict[str, List[PSACheck]]:
        """Return checks grouped by severity label."""
        groups: Dict[str, List[PSACheck]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        for check in self.checks_fired:
            groups.setdefault(check.severity, []).append(check)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _first_evidence(pattern: re.Pattern, text: str) -> str:
    """Return first match text, truncated to 200 characters."""
    m = pattern.search(text)
    if m:
        return m.group(0)[:200]
    return ""


def _build_result(artifact_id: str, fired: List[PSACheck]) -> PSAResult:
    """Compute risk score, threat level and techniques from fired checks."""
    raw_score = sum(c.weight for c in fired)
    risk_score = min(100, raw_score)

    threat_level = "LOW"
    for threshold, label in _THREAT_THRESHOLDS:
        if risk_score >= threshold:
            threat_level = label
            break

    techniques = [
        _CHECK_META[c.check_id]["technique"]
        for c in fired
        if c.check_id in _CHECK_META
    ]

    return PSAResult(
        artifact_id=artifact_id,
        checks_fired=fired,
        risk_score=risk_score,
        threat_level=threat_level,
        suspected_techniques=techniques,
    )


# ---------------------------------------------------------------------------
# Core check functions (each returns Optional[PSACheck])
# ---------------------------------------------------------------------------

def _check_psa001(text: str) -> Optional[PSACheck]:
    """PSA-001: Base64-encoded command flag."""
    m = _RE_PSA001.search(text)
    if not m:
        return None
    meta = _CHECK_META["PSA-001"]
    return PSACheck(
        check_id="PSA-001",
        severity=meta["severity"],
        description=meta["description"],
        evidence=m.group(0)[:200],
        weight=meta["weight"],
    )


def _check_psa002(text: str) -> Optional[PSACheck]:
    """PSA-002: AMSI bypass pattern."""
    m = _RE_PSA002.search(text)
    if not m:
        return None
    meta = _CHECK_META["PSA-002"]
    return PSACheck(
        check_id="PSA-002",
        severity=meta["severity"],
        description=meta["description"],
        evidence=m.group(0)[:200],
        weight=meta["weight"],
    )


def _check_psa003(text: str) -> Optional[PSACheck]:
    """PSA-003: Download cradle — requires BOTH execution AND download keyword."""
    m_exec = _RE_PSA003_EXEC.search(text)
    m_dl = _RE_PSA003_DL.search(text)
    if not (m_exec and m_dl):
        return None
    meta = _CHECK_META["PSA-003"]
    # Use the first chronological match as evidence anchor
    evidence_start = min(m_exec.start(), m_dl.start())
    evidence_end = max(m_exec.end(), m_dl.end())
    evidence = text[evidence_start:evidence_end][:200]
    return PSACheck(
        check_id="PSA-003",
        severity=meta["severity"],
        description=meta["description"],
        evidence=evidence,
        weight=meta["weight"],
    )


def _check_psa004(text: str) -> Optional[PSACheck]:
    """PSA-004: Execution policy bypass."""
    m = _RE_PSA004.search(text)
    if not m:
        return None
    meta = _CHECK_META["PSA-004"]
    return PSACheck(
        check_id="PSA-004",
        severity=meta["severity"],
        description=meta["description"],
        evidence=m.group(0)[:200],
        weight=meta["weight"],
    )


def _check_psa005(text: str) -> Optional[PSACheck]:
    """PSA-005: LOLBins abuse."""
    m = _RE_PSA005.search(text)
    if not m:
        return None
    meta = _CHECK_META["PSA-005"]
    return PSACheck(
        check_id="PSA-005",
        severity=meta["severity"],
        description=meta["description"],
        evidence=m.group(0)[:200],
        weight=meta["weight"],
    )


def _check_psa006(text: str) -> Optional[PSACheck]:
    """PSA-006: Obfuscation markers.

    Fires if ANY of:
    - tick-escape backtick mid-identifier pattern
    - [char[]] array cast
    - >= 3 string-concat joins ("+"  or '+' pattern count)
    """
    # Tick escape
    m_tick = _RE_PSA006_TICK.search(text)
    if m_tick:
        meta = _CHECK_META["PSA-006"]
        return PSACheck(
            check_id="PSA-006",
            severity=meta["severity"],
            description=meta["description"],
            evidence=m_tick.group(0)[:200],
            weight=meta["weight"],
        )

    # Char-array cast
    m_char = _RE_PSA006_CHAR.search(text)
    if m_char:
        meta = _CHECK_META["PSA-006"]
        return PSACheck(
            check_id="PSA-006",
            severity=meta["severity"],
            description=meta["description"],
            evidence=m_char.group(0)[:200],
            weight=meta["weight"],
        )

    # String concat heuristic: count double-quote joins + single-quote joins
    dq_count = len(_RE_PSA006_CONCAT_DQ.findall(text))
    sq_count = len(_RE_PSA006_CONCAT_SQ.findall(text))
    if (dq_count + sq_count) >= 3:
        meta = _CHECK_META["PSA-006"]
        # Use first concat match as evidence
        m_dq = _RE_PSA006_CONCAT_DQ.search(text)
        m_sq = _RE_PSA006_CONCAT_SQ.search(text)
        # Pick the earliest
        candidates = [m for m in (m_dq, m_sq) if m is not None]
        evidence_match = min(candidates, key=lambda m: m.start())
        return PSACheck(
            check_id="PSA-006",
            severity=meta["severity"],
            description=meta["description"],
            evidence=evidence_match.group(0)[:200],
            weight=meta["weight"],
        )

    return None


def _check_psa007(text: str) -> Optional[PSACheck]:
    """PSA-007: Known attack framework IOCs."""
    m = _RE_PSA007.search(text)
    if not m:
        return None
    meta = _CHECK_META["PSA-007"]
    return PSACheck(
        check_id="PSA-007",
        severity=meta["severity"],
        description=meta["description"],
        evidence=m.group(0)[:200],
        weight=meta["weight"],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_ALL_CHECKS = [
    _check_psa001,
    _check_psa002,
    _check_psa003,
    _check_psa004,
    _check_psa005,
    _check_psa006,
    _check_psa007,
]


def analyze(artifact: PSArtifact) -> PSAResult:
    """Analyze a single PSArtifact and return a PSAResult.

    Each PSA-001–007 check is evaluated independently against the artifact's
    command_text.  Fired checks contribute their weight to the risk score
    (capped at 100).

    Args:
        artifact: The PSArtifact to examine.

    Returns:
        PSAResult populated with all fired checks, risk_score, threat_level,
        and suspected_techniques.
    """
    text = artifact.command_text
    fired: List[PSACheck] = []
    for check_fn in _ALL_CHECKS:
        result = check_fn(text)
        if result is not None:
            fired.append(result)
    return _build_result(artifact.artifact_id, fired)


def analyze_many(artifacts: List[PSArtifact]) -> List[PSAResult]:
    """Analyze a list of PSArtifacts and return a corresponding list of PSAResults.

    Args:
        artifacts: Sequence of PSArtifact objects to analyze.

    Returns:
        List of PSAResult objects in the same order as the input list.
    """
    return [analyze(a) for a in artifacts]
