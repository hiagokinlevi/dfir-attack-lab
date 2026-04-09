"""
MITRE ATT&CK Technique Auto-Mapper
=====================================
Maps normalized DFIR triage events to MITRE ATT&CK techniques based on
event category and action keywords.

Design:
  The mapper uses a two-level lookup:
    1. Primary: exact match on event.action (e.g., "login_failure" → T1110)
    2. Secondary: keyword scan of event.action and event.raw (partial match)

  Confidence levels:
    HIGH   — exact action match in the primary map
    MEDIUM — keyword match in event.action
    LOW    — keyword match in event.raw only

  The mapper returns None rather than guessing for events with insufficient
  signal. Over-mapping is worse than under-mapping in DFIR contexts because
  false ATT&CK attributions waste analyst time.

Covered tactics (partial — expand ATTACK_MAP for additional coverage):
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Credential Access
  - Lateral Movement
  - Execution
  - Discovery
  - Defense Evasion
  - Exfiltration

Usage:
    from analysis.mitre_mapper import map_event, map_all, AttackTechnique

    technique = map_event(triage_event)
    if technique:
        print(technique.technique_id, technique.name)

    report = map_all(events)
    for technique_id, count in report.technique_counts.items():
        print(technique_id, count)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from normalizers.models import EventCategory, TriageEvent


# ---------------------------------------------------------------------------
# ATT&CK technique model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackTechnique:
    """
    A single MITRE ATT&CK technique attribution.

    Attributes:
        technique_id:  ATT&CK technique ID (e.g., 'T1110.001').
        name:          Human-readable technique name.
        tactic:        Parent tactic name (e.g., 'Credential Access').
        confidence:    'high' | 'medium' | 'low' — quality of the mapping.
        description:   Brief description relevant to detection context.
    """
    technique_id: str
    name:         str
    tactic:       str
    confidence:   str    # 'high' | 'medium' | 'low'
    description:  str    = ""


# ---------------------------------------------------------------------------
# Primary action-to-technique map
# (exact match on TriageEvent.action, case-insensitive)
# ---------------------------------------------------------------------------

_PRIMARY_MAP: dict[str, AttackTechnique] = {
    # --- Credential Access ---
    "login_failure": AttackTechnique(
        "T1110", "Brute Force", "Credential Access", "high",
        "Repeated authentication failures indicate brute force or password spray.",
    ),
    "auth_failure": AttackTechnique(
        "T1110", "Brute Force", "Credential Access", "high",
        "Authentication failure consistent with credential guessing.",
    ),
    "ssh_auth_failure": AttackTechnique(
        "T1110.003", "Password Spraying", "Credential Access", "high",
        "SSH authentication failure — may indicate password spraying.",
    ),
    "kerberos_failure": AttackTechnique(
        "T1558.003", "Kerberoasting", "Credential Access", "high",
        "Kerberos pre-authentication failure associated with ticket-based attacks.",
    ),
    "credential_dump": AttackTechnique(
        "T1003", "OS Credential Dumping", "Credential Access", "high",
        "Credential material extracted from OS memory or storage.",
    ),
    "passwd_change": AttackTechnique(
        "T1098", "Account Manipulation", "Persistence", "high",
        "Password change may indicate attacker consolidating access.",
    ),

    # --- Privilege Escalation ---
    "sudo_exec": AttackTechnique(
        "T1548.003", "Sudo and Sudo Caching", "Privilege Escalation", "high",
        "Sudo execution observed — verify against expected usage.",
    ),
    "setuid_exec": AttackTechnique(
        "T1548.001", "Setuid and Setgid", "Privilege Escalation", "high",
        "Setuid binary executed; may indicate privilege escalation attempt.",
    ),
    "suid_execution": AttackTechnique(
        "T1548.001", "Setuid and Setgid", "Privilege Escalation", "high",
        "SUID file executed — check for unexpected binaries.",
    ),
    "privilege_escalation": AttackTechnique(
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "high",
        "Privilege escalation event observed.",
    ),

    # --- Persistence ---
    "cron_add": AttackTechnique(
        "T1053.003", "Cron", "Persistence", "high",
        "New cron job added — potential persistence mechanism.",
    ),
    "service_install": AttackTechnique(
        "T1543.003", "Windows Service", "Persistence", "high",
        "New service installed; may establish persistence.",
    ),
    "autorun_add": AttackTechnique(
        "T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "high",
        "Autorun entry added.",
    ),
    "startup_add": AttackTechnique(
        "T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "high",
        "Startup folder modification observed.",
    ),
    "ssh_key_add": AttackTechnique(
        "T1098.004", "SSH Authorized Keys", "Persistence", "high",
        "New SSH authorized key added — verify legitimacy.",
    ),
    "launch_agent_add": AttackTechnique(
        "T1543.001", "Launch Agent", "Persistence", "high",
        "macOS Launch Agent added — check for unauthorised persistence.",
    ),
    "launch_daemon_add": AttackTechnique(
        "T1543.004", "Launch Daemon", "Persistence", "high",
        "macOS Launch Daemon added — check for persistence.",
    ),

    # --- Lateral Movement ---
    "lateral_move": AttackTechnique(
        "T1021", "Remote Services", "Lateral Movement", "high",
        "Remote service access indicating possible lateral movement.",
    ),
    "rdp_login": AttackTechnique(
        "T1021.001", "Remote Desktop Protocol", "Lateral Movement", "high",
        "RDP login observed.",
    ),
    "ssh_login": AttackTechnique(
        "T1021.004", "SSH", "Lateral Movement", "medium",
        "SSH login — cross-correlate with expected baselines.",
    ),
    "smb_access": AttackTechnique(
        "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "high",
        "SMB share access observed.",
    ),

    # --- Execution ---
    "script_exec": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution", "high",
        "Script execution observed.",
    ),
    "powershell_exec": AttackTechnique(
        "T1059.001", "PowerShell", "Execution", "high",
        "PowerShell command execution.",
    ),
    "bash_exec": AttackTechnique(
        "T1059.004", "Unix Shell", "Execution", "high",
        "Bash or sh script execution.",
    ),
    "process_start": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution", "medium",
        "New process started — review for anomalous execution.",
    ),

    # --- Discovery ---
    "network_scan": AttackTechnique(
        "T1046", "Network Service Discovery", "Discovery", "high",
        "Network port scan detected.",
    ),
    "account_enum": AttackTechnique(
        "T1087", "Account Discovery", "Discovery", "high",
        "Account enumeration observed.",
    ),
    "dir_listing": AttackTechnique(
        "T1083", "File and Directory Discovery", "Discovery", "medium",
        "Directory listing performed.",
    ),

    # --- Defense Evasion ---
    "log_clear": AttackTechnique(
        "T1070.001", "Clear Windows Event Logs", "Defense Evasion", "high",
        "Audit log cleared — likely defense evasion.",
    ),
    "log_deleted": AttackTechnique(
        "T1070.002", "Clear Linux or Mac System Logs", "Defense Evasion", "high",
        "Log file deleted.",
    ),
    "timestamps_modified": AttackTechnique(
        "T1070.006", "Timestomp", "Defense Evasion", "high",
        "File timestamps modified.",
    ),

    # --- Exfiltration ---
    "data_exfil": AttackTechnique(
        "T1041", "Exfiltration Over C2 Channel", "Exfiltration", "high",
        "Data exfiltration pattern detected.",
    ),
    "large_upload": AttackTechnique(
        "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "high",
        "Unusually large data upload observed.",
    ),
}

# ---------------------------------------------------------------------------
# Keyword-to-technique map
# (substring match in event.action, case-insensitive)
# ---------------------------------------------------------------------------

_KEYWORD_MAP: list[tuple[str, AttackTechnique]] = [
    ("brute", AttackTechnique("T1110", "Brute Force", "Credential Access", "medium",
                              "Keyword 'brute' in action string.")),
    ("spray", AttackTechnique("T1110.003", "Password Spraying", "Credential Access", "medium",
                              "Keyword 'spray' suggests password spray.")),
    ("dump", AttackTechnique("T1003", "OS Credential Dumping", "Credential Access", "medium",
                             "Keyword 'dump' suggests credential extraction.")),
    ("escalat", AttackTechnique("T1068", "Exploitation for Privilege Escalation",
                                 "Privilege Escalation", "medium",
                                 "Keyword 'escalat' in action.")),
    ("persist", AttackTechnique("T1547", "Boot or Logon Autostart Execution",
                                 "Persistence", "medium",
                                 "Keyword 'persist' suggests persistence activity.")),
    ("lateral", AttackTechnique("T1021", "Remote Services", "Lateral Movement", "medium",
                                 "Keyword 'lateral' in action.")),
    ("exfil", AttackTechnique("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "medium",
                               "Keyword 'exfil' in action.")),
    ("scan", AttackTechnique("T1046", "Network Service Discovery", "Discovery", "medium",
                              "Keyword 'scan' suggests discovery activity.")),
    ("clearlog", AttackTechnique("T1070", "Indicator Removal", "Defense Evasion", "medium",
                                  "Log clearing keyword detected.")),
    ("mimikatz", AttackTechnique("T1003", "OS Credential Dumping", "Credential Access", "high",
                                  "Mimikatz toolname detected — credential dumping likely.")),
    ("whoami", AttackTechnique("T1033", "System Owner/User Discovery", "Discovery", "medium",
                                "whoami command — discovery activity.")),
    ("ifconfig", AttackTechnique("T1016", "System Network Configuration Discovery",
                                  "Discovery", "medium",
                                  "Network config query.")),
    ("passwd", AttackTechnique("T1003.008", "/etc/passwd and /etc/shadow",
                                "Credential Access", "medium",
                                "Access to /etc/passwd or passwd-related action.")),
    ("shadow", AttackTechnique("T1003.008", "/etc/passwd and /etc/shadow",
                                "Credential Access", "medium",
                                "Access to /etc/shadow — credential extraction risk.")),
]


# ---------------------------------------------------------------------------
# AttackMappingReport
# ---------------------------------------------------------------------------

@dataclass
class AttackMappingReport:
    """
    Summary of ATT&CK technique attribution across a set of events.

    Attributes:
        mappings:          List of (TriageEvent, AttackTechnique) tuples for
                           all events that could be attributed.
        technique_counts:  Dict of technique_id → count of matching events.
        tactic_counts:     Dict of tactic → count of matching events.
        unmapped_count:    Number of events with no technique attribution.
        total_events:      Total events processed.
    """
    mappings:          list[tuple[TriageEvent, AttackTechnique]] = field(default_factory=list)
    technique_counts:  dict[str, int]                           = field(default_factory=dict)
    tactic_counts:     dict[str, int]                           = field(default_factory=dict)
    unmapped_count:    int                                       = 0
    total_events:      int                                       = 0

    @property
    def mapped_count(self) -> int:
        return len(self.mappings)

    @property
    def coverage_pct(self) -> float:
        """Percentage of events that could be attributed to an ATT&CK technique."""
        if self.total_events == 0:
            return 0.0
        return round(100.0 * self.mapped_count / self.total_events, 1)

    def top_techniques(self, n: int = 5) -> list[tuple[str, int]]:
        """Return the top-N most frequently matched techniques as (id, count) pairs."""
        return sorted(self.technique_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def top_tactics(self, n: int = 5) -> list[tuple[str, int]]:
        """Return the top-N most frequently matched tactics as (tactic, count) pairs."""
        return sorted(self.tactic_counts.items(), key=lambda x: x[1], reverse=True)[:n]


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def map_event(event: TriageEvent) -> Optional[AttackTechnique]:
    """
    Map a single TriageEvent to a MITRE ATT&CK technique.

    Priority:
      1. Exact match in _PRIMARY_MAP on event.action (case-insensitive).
      2. Keyword match in _KEYWORD_MAP scanning event.action.
      3. Return None if no match found.

    Args:
        event: Normalized TriageEvent.

    Returns:
        AttackTechnique if a mapping was found, else None.
    """
    action_lower = event.action.lower()

    # 1. Exact match
    technique = _PRIMARY_MAP.get(action_lower)
    if technique:
        return technique

    # 2. Keyword scan of action
    for keyword, technique in _KEYWORD_MAP:
        if keyword in action_lower:
            return technique

    return None


def map_all(events: list[TriageEvent]) -> AttackMappingReport:
    """
    Map all events to ATT&CK techniques and return a summary report.

    Args:
        events: List of normalized TriageEvent objects.

    Returns:
        AttackMappingReport with mappings, counts, and coverage stats.
    """
    report = AttackMappingReport(total_events=len(events))

    for event in events:
        technique = map_event(event)
        if technique:
            report.mappings.append((event, technique))
            report.technique_counts[technique.technique_id] = (
                report.technique_counts.get(technique.technique_id, 0) + 1
            )
            report.tactic_counts[technique.tactic] = (
                report.tactic_counts.get(technique.tactic, 0) + 1
            )
        else:
            report.unmapped_count += 1

    return report
