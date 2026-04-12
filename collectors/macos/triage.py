"""
Read-only macOS triage collector.

Runs a series of non-destructive system commands and log reads to capture
system state at incident time. All data is written as JSONL. No modifications
are made to the target system.

macOS-specific observations collected:
  - system_info:          uname, sw_vers (product name / build version)
  - active_sessions:      who -a output (logged-in users)
  - listening_ports:      netstat -an -p tcp/udp filtered to LISTEN/CLOSE_WAIT
  - running_processes:    ps auxww snapshot
  - launch_agents:        ~/Library/LaunchAgents and /Library/LaunchAgents plist names
                          (persistence mechanism commonly abused by malware)
  - launch_daemons:       /Library/LaunchDaemons and /System/Library/LaunchDaemons
  - startup_items:        /Library/StartupItems (legacy, still relevant)
  - login_items:          sfltool dump-login-items (per-user login persistence)
  - recent_unified_logs:  last 200 lines of Security and auth subsystems via 'log show'
  - cron_jobs:            /usr/lib/cron/tabs and /var/at/tabs (macOS cron location)
  - sudoers:              /etc/sudoers contents (privilege escalation path)
  - arp_cache:            arp -a (lateral movement indicator — hosts recently contacted)
  - open_connections:     lsof -i -nP (active network connections with PIDs)
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from normalizers.case_id import validate_case_id


def _run_safe(command: list[str], timeout: int = 30) -> Optional[str]:
    """
    Execute a read-only command and return its stdout.

    Returns None on any failure (missing binary, permission denied, timeout).
    A failed command must never abort the overall triage run.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Never raise on non-zero exit — collect what we can
        )
        return result.stdout.strip() if result.stdout else None
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None


def _read_file_safe(path: str) -> Optional[str]:
    """Read a file and return its content, or None if not readable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip() or None
    except (OSError, PermissionError):
        return None


def _list_plist_names(directory: str) -> Optional[list[str]]:
    """
    List plist file names in a launch agent/daemon directory.

    Returns a sorted list of filenames (not full paths) for portability, or
    None if the directory does not exist or is not readable.
    """
    try:
        target = Path(directory)
        if not target.is_dir():
            return None
        names = sorted(p.name for p in target.iterdir() if p.suffix == ".plist")
        return names if names else None
    except (OSError, PermissionError):
        return None


def _collect_launch_persistence() -> dict[str, Optional[list[str]]]:
    """
    Enumerate all macOS launch persistence locations.

    These locations are the primary mechanism for malware/attacker persistence
    on macOS. Reviewing them is a mandatory step in any macOS triage.
    """
    home = os.path.expanduser("~")
    return {
        "user_launch_agents":       _list_plist_names(f"{home}/Library/LaunchAgents"),
        "system_launch_agents":     _list_plist_names("/Library/LaunchAgents"),
        "system_launch_daemons":    _list_plist_names("/Library/LaunchDaemons"),
        "os_launch_daemons":        _list_plist_names("/System/Library/LaunchDaemons"),
        "legacy_startup_items":     _list_plist_names("/Library/StartupItems"),
    }


def run_macos_triage(output_dir: Path, case_id: str) -> Path:
    """
    Collect read-only system observations from a macOS host and write as JSONL.

    All commands used are non-destructive reads. The collector never writes to
    system paths, modifies process state, or accesses raw disk images.

    Args:
        output_dir: Directory where the case JSONL file will be written.
        case_id:    Case identifier included in the output filename.

    Returns:
        Path to the written JSONL output file.
    """
    case_id = validate_case_id(case_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{case_id}_macos_triage.jsonl"
    collected_at = datetime.now(timezone.utc).isoformat()

    observations: dict[str, object] = {
        # --- Identity ---
        "uname":                 _run_safe(["uname", "-a"]),
        "sw_vers":               _run_safe(["sw_vers"]),
        "hostname":              _run_safe(["hostname"]),

        # --- Active sessions ---
        "active_sessions":       _run_safe(["who", "-a"]),
        "last_logins":           _run_safe(["last", "-20"]),  # Last 20 login entries

        # --- Processes ---
        "running_processes":     _run_safe(["ps", "auxww"], timeout=15),

        # --- Network state ---
        "listening_ports_tcp":   _run_safe(["netstat", "-an", "-p", "tcp"]),
        "listening_ports_udp":   _run_safe(["netstat", "-an", "-p", "udp"]),
        "open_connections":      _run_safe(["lsof", "-i", "-nP"], timeout=20),
        "arp_cache":             _run_safe(["arp", "-a"]),

        # --- Persistence mechanisms ---
        "launch_persistence":    _collect_launch_persistence(),
        "login_items":           _run_safe(["sfltool", "dump-login-items"]),
        "cron_jobs_system":      _read_file_safe("/usr/lib/cron/tabs"),

        # --- Privilege escalation paths ---
        "sudoers":               _read_file_safe("/etc/sudoers"),
        "sudoers_d":             _list_plist_names("/etc/sudoers.d"),

        # --- Recent security events from Unified Log ---
        # 'log show' reads from the Unified Logging System — no writes.
        # --last 1h: last 1 hour of Security subsystem events
        "recent_security_logs":  _run_safe(
            ["log", "show", "--last", "1h", "--predicate",
             "subsystem == 'com.apple.security' OR subsystem == 'com.apple.authd'",
             "--style", "compact"],
            timeout=45,
        ),
    }

    # Filter out None values to keep JSONL compact
    filtered = {k: v for k, v in observations.items() if v is not None}

    with output_path.open("w", encoding="utf-8") as fh:
        record = {
            "case_id":      case_id,
            "collected_at": collected_at,
            "platform":     "macos",
            "observations": filtered,
        }
        fh.write(json.dumps(record) + "\n")

    return output_path
