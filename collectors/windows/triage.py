"""
Read-only Windows triage collector.

Collects system state observations using PowerShell commands via subprocess.
All operations are read-only — no modifications are made to the target system.
Intended for use on Windows hosts or via WinRM remote execution.
"""
from __future__ import annotations
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from normalizers.case_id import validate_case_id


def _run_powershell(command: str, timeout: int = 30) -> Optional[str]:
    """
    Execute a read-only PowerShell command and return its stdout.

    Returns None on any failure — access denied, missing cmdlet, or timeout
    must not abort the triage run.

    Args:
        command: PowerShell command string to execute.
        timeout: Maximum execution time in seconds.

    Returns:
        Command stdout as string, or None if the command failed.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip() if result.stdout else None
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None


def run_windows_triage(output_dir: Path, case_id: str) -> Path:
    """
    Collect read-only Windows system observations and write them as JSONL.

    Data collected (all read-only):
    - system_info:      OS version, hostname, build number
    - active_sessions:  Logged-on users (query user)
    - listening_ports:  TCP listening ports (netstat equivalent)
    - running_services: Running services and their executable paths
    - scheduled_tasks:  Non-Microsoft scheduled tasks (persistence review)
    - recent_processes: Process list with parent PIDs

    Args:
        output_dir: Directory where JSONL output will be written.
        case_id:    Case identifier for the output filename.

    Returns:
        Path to the written JSONL output file.
    """
    case_id = validate_case_id(case_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{case_id}_windows_triage.jsonl"
    collected_at = datetime.now(timezone.utc).isoformat()

    observations = {
        "system_info": _run_powershell(
            "Get-ComputerInfo | Select-Object WindowsProductName,OsVersion,CsName | ConvertTo-Json"
        ),
        "active_sessions": _run_powershell(
            "query user 2>$null"
        ),
        "listening_ports": _run_powershell(
            "Get-NetTCPConnection -State Listen | Select-Object LocalPort,OwningProcess | ConvertTo-Json"
        ),
        "running_services": _run_powershell(
            "Get-WmiObject Win32_Service | Where-Object {$_.State -eq 'Running'} | "
            "Select-Object Name,PathName,StartMode | ConvertTo-Json"
        ),
        "scheduled_tasks": _run_powershell(
            "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | "
            "Select-Object TaskName,TaskPath,State | ConvertTo-Json"
        ),
        "recent_processes": _run_powershell(
            "Get-Process | Select-Object Id,ProcessName,Path,CPU | ConvertTo-Json"
        ),
    }

    with output_path.open("w") as fh:
        record = {
            "case_id": case_id,
            "collected_at": collected_at,
            "platform": "windows",
            "observations": {k: v for k, v in observations.items() if v is not None},
        }
        fh.write(json.dumps(record) + "\n")

    return output_path
