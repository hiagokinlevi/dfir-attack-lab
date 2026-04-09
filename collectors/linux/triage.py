"""
Read-only Linux triage collector.

Runs a series of non-destructive system commands to capture system state at
incident time. All data is written to a case directory as JSONL files.
No modifications are made to the target system.
"""
from __future__ import annotations
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _run_safe(command: list[str]) -> Optional[str]:
    """
    Execute a read-only command and return its stdout.

    Returns None on any failure — a missing command or permission error
    must not abort the overall triage run.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,   # Do not raise on non-zero exit — collect what we can
        )
        return result.stdout.strip() if result.stdout else None
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None


def run_linux_triage(output_dir: Path, case_id: str) -> Path:
    """
    Collect read-only system observations and write them as JSONL.

    Data collected:
    - system_info: hostname, kernel version, uptime
    - active_sessions: logged-in users (w command output)
    - listening_ports: listening sockets (ss -tlnp output)
    - recent_processes: running processes snapshot (ps auxf output)
    - cron_jobs: system cron entries (non-destructive read)

    Args:
        output_dir: Directory where the case JSONL file will be written.
        case_id:    Case identifier included in the output filename.

    Returns:
        Path to the written JSONL output file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{case_id}_linux_triage.jsonl"
    collected_at = datetime.now(timezone.utc).isoformat()

    observations = {
        "system_info": _run_safe(["uname", "-a"]),
        "hostname": _run_safe(["hostname", "-f"]),
        "uptime": _run_safe(["uptime"]),
        "active_sessions": _run_safe(["w", "-h"]),
        "listening_ports": _run_safe(["ss", "-tlnp"]),
        "recent_processes": _run_safe(["ps", "auxf"]),
        "cron_root": _run_safe(["cat", "/etc/crontab"]),
    }

    with output_path.open("w") as fh:
        record = {
            "case_id": case_id,
            "collected_at": collected_at,
            "platform": "linux",
            "observations": {k: v for k, v in observations.items() if v is not None},
        }
        fh.write(json.dumps(record) + "\n")

    return output_path
