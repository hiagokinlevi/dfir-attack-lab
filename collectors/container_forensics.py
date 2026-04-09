"""
Container Forensics Collector
==============================
Collects forensic artifacts from Docker containers for incident response.

Captures evidence from running or stopped containers WITHOUT modifying the
container's state (read-only observation). All operations default to
dry_run=True for safety.

Evidence collected:
  - Container metadata (inspect: image, env vars, labels, mounts, network)
  - Running processes (top / exec ps aux)
  - Network connections (exec ss -tunap or netstat)
  - Filesystem changes since image baseline (diff)
  - Recent log output (logs --tail N)
  - Environment variables (inspect — PII/secrets are masked)
  - Mounted volumes and bind mounts
  - Security context (capabilities, privileged flag, user, read-only rootfs)

IMPORTANT SAFETY GUIDELINES:
  - This module only reads from containers — it never modifies them.
  - Set dry_run=True (default) to preview the collection plan without execution.
  - Sensitive environment variable values are masked in the output.
  - Never delete or modify the container — preserve forensic integrity.

Usage:
    from collectors.container_forensics import collect_container_evidence

    report = collect_container_evidence(
        container_id="abc123def456",
        incident_id="INC-2026-042",
        dry_run=True,
    )
    print(report.summary())
    for artifact in report.artifacts:
        print(artifact.artifact_type, artifact.size_bytes, "bytes")
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# Env var names that likely contain secrets — values are masked
_SENSITIVE_ENV_PATTERNS = re.compile(
    r"(?i)(key|token|secret|password|passwd|pwd|auth|credential|api_key|private|cert|seed)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ContainerArtifact:
    """
    A single forensic artifact collected from a container.

    Attributes:
        artifact_type:  What was collected (e.g. "inspect", "processes", "logs").
        content:        The collected data as a string (may be JSON, plain text, etc.).
        size_bytes:     Length of content in bytes.
        collection_cmd: The Docker command that produced this artifact.
        error:          Error message if collection failed, else None.
        collected_at:   UTC timestamp of collection.
    """
    artifact_type:   str
    content:         str
    size_bytes:      int
    collection_cmd:  str
    error:           Optional[str] = None
    collected_at:    str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    @property
    def succeeded(self) -> bool:
        return self.error is None


@dataclass
class ContainerForensicsReport:
    """Aggregate forensic report for a single container."""
    container_id:   str
    container_name: str
    incident_id:    str
    image:          str
    status:         str         # "running", "stopped", "unknown"
    dry_run:        bool
    artifacts:      list[ContainerArtifact] = field(default_factory=list)
    errors:         list[str]               = field(default_factory=list)
    collected_at:   str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def total_bytes(self) -> int:
        return sum(a.size_bytes for a in self.artifacts)

    @property
    def succeeded_count(self) -> int:
        return sum(1 for a in self.artifacts if a.succeeded)

    @property
    def failed_count(self) -> int:
        return sum(1 for a in self.artifacts if not a.succeeded)

    def get_artifact(self, artifact_type: str) -> Optional[ContainerArtifact]:
        """Return the first artifact of the given type, or None."""
        return next((a for a in self.artifacts if a.artifact_type == artifact_type), None)

    def summary(self) -> str:
        status = "DRY RUN" if self.dry_run else "COLLECTED"
        return (
            f"[{status}] Container forensics: {self.container_id[:12]} "
            f"({self.container_name}) | image={self.image} | status={self.status} | "
            f"artifacts={self.succeeded_count}/{self.artifact_count} ok | "
            f"total={self.total_bytes} bytes | errors={len(self.errors)}"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _run_docker(args: list[str], timeout: int = 30) -> tuple[str, Optional[str]]:
    """
    Run a docker command and return (stdout, error).

    Returns (output, None) on success, ("", error_message) on failure.
    """
    cmd = ["docker"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout, None
        return "", result.stderr.strip() or f"docker exited with code {result.returncode}"
    except FileNotFoundError:
        return "", "docker not found — is Docker installed and in PATH?"
    except subprocess.TimeoutExpired:
        return "", f"docker command timed out after {timeout}s"
    except Exception as exc:
        return "", str(exc)


def _mask_env_vars(env_list: list[str]) -> list[str]:
    """
    Mask the values of sensitive environment variables.

    Input: ["KEY=value", "PATH=/usr/bin"]
    Output: ["KEY=****[MASKED]", "PATH=/usr/bin"]
    """
    masked = []
    for entry in env_list:
        if "=" in entry:
            name, _, value = entry.partition("=")
            if _SENSITIVE_ENV_PATTERNS.search(name):
                masked.append(f"{name}=****[MASKED]")
            else:
                masked.append(entry)
        else:
            masked.append(entry)
    return masked


def _parse_inspect(raw: str) -> dict[str, Any]:
    """Parse docker inspect JSON output, returning the first container record."""
    try:
        data = json.loads(raw)
        if isinstance(data, list) and data:
            return data[0]
    except json.JSONDecodeError:
        pass
    return {}


def _extract_security_context(inspect_data: dict[str, Any]) -> dict[str, Any]:
    """Extract security-relevant fields from docker inspect output."""
    host_config = inspect_data.get("HostConfig", {})
    config = inspect_data.get("Config", {})

    return {
        "privileged":         host_config.get("Privileged", False),
        "read_only_rootfs":   host_config.get("ReadonlyRootfs", False),
        "cap_add":            host_config.get("CapAdd") or [],
        "cap_drop":           host_config.get("CapDrop") or [],
        "security_opt":       host_config.get("SecurityOpt") or [],
        "pid_mode":           host_config.get("PidMode", ""),
        "network_mode":       host_config.get("NetworkMode", ""),
        "user":               config.get("User", ""),
        "no_new_privileges":  "no-new-privileges" in str(host_config.get("SecurityOpt") or []),
    }


# ---------------------------------------------------------------------------
# Collection functions
# ---------------------------------------------------------------------------

def _collect_inspect(
    container_id: str,
    dry_run: bool,
) -> ContainerArtifact:
    """Collect docker inspect metadata."""
    cmd = f"docker inspect {container_id}"
    if dry_run:
        return ContainerArtifact(
            artifact_type="inspect",
            content=f"[DRY RUN] Would run: {cmd}",
            size_bytes=0,
            collection_cmd=cmd,
        )
    raw, err = _run_docker(["inspect", container_id])
    if err:
        return ContainerArtifact(
            artifact_type="inspect", content="", size_bytes=0,
            collection_cmd=cmd, error=err,
        )
    # Mask sensitive env vars
    try:
        data = json.loads(raw)
        if isinstance(data, list) and data:
            env = data[0].get("Config", {}).get("Env", []) or []
            data[0]["Config"]["Env"] = _mask_env_vars(env)
            raw = json.dumps(data, indent=2)
    except Exception:
        pass
    return ContainerArtifact(
        artifact_type="inspect",
        content=raw,
        size_bytes=len(raw.encode()),
        collection_cmd=cmd,
    )


def _collect_processes(
    container_id: str,
    dry_run: bool,
    is_running: bool,
) -> ContainerArtifact:
    """Collect running processes via docker top or exec."""
    if not is_running:
        return ContainerArtifact(
            artifact_type="processes", content="Container not running — skipped",
            size_bytes=0, collection_cmd="skipped",
        )
    cmd = f"docker top {container_id} aux"
    if dry_run:
        return ContainerArtifact(
            artifact_type="processes",
            content=f"[DRY RUN] Would run: {cmd}",
            size_bytes=0, collection_cmd=cmd,
        )
    output, err = _run_docker(["top", container_id, "aux"])
    if err:
        return ContainerArtifact(
            artifact_type="processes", content="", size_bytes=0,
            collection_cmd=cmd, error=err,
        )
    return ContainerArtifact(
        artifact_type="processes",
        content=output,
        size_bytes=len(output.encode()),
        collection_cmd=cmd,
    )


def _collect_network_connections(
    container_id: str,
    dry_run: bool,
    is_running: bool,
) -> ContainerArtifact:
    """Collect network connections via docker exec ss."""
    if not is_running:
        return ContainerArtifact(
            artifact_type="network_connections",
            content="Container not running — skipped",
            size_bytes=0, collection_cmd="skipped",
        )
    cmd = f"docker exec {container_id} ss -tunap"
    if dry_run:
        return ContainerArtifact(
            artifact_type="network_connections",
            content=f"[DRY RUN] Would run: {cmd}",
            size_bytes=0, collection_cmd=cmd,
        )
    output, err = _run_docker(["exec", container_id, "ss", "-tunap"])
    if err:
        # Fall back to netstat if ss is not available
        cmd2 = f"docker exec {container_id} netstat -tunap"
        output, err2 = _run_docker(["exec", container_id, "netstat", "-tunap"])
        if err2:
            return ContainerArtifact(
                artifact_type="network_connections", content="", size_bytes=0,
                collection_cmd=cmd2, error=f"ss: {err}, netstat: {err2}",
            )
        cmd = cmd2
    return ContainerArtifact(
        artifact_type="network_connections",
        content=output,
        size_bytes=len(output.encode()),
        collection_cmd=cmd,
    )


def _collect_filesystem_diff(
    container_id: str,
    dry_run: bool,
) -> ContainerArtifact:
    """Collect filesystem changes since image baseline via docker diff."""
    cmd = f"docker diff {container_id}"
    if dry_run:
        return ContainerArtifact(
            artifact_type="filesystem_diff",
            content=f"[DRY RUN] Would run: {cmd}",
            size_bytes=0, collection_cmd=cmd,
        )
    output, err = _run_docker(["diff", container_id])
    if err:
        return ContainerArtifact(
            artifact_type="filesystem_diff", content="", size_bytes=0,
            collection_cmd=cmd, error=err,
        )
    return ContainerArtifact(
        artifact_type="filesystem_diff",
        content=output,
        size_bytes=len(output.encode()),
        collection_cmd=cmd,
    )


def _collect_logs(
    container_id: str,
    dry_run: bool,
    tail_lines: int = 500,
) -> ContainerArtifact:
    """Collect recent container log output."""
    cmd = f"docker logs --tail {tail_lines} --timestamps {container_id}"
    if dry_run:
        return ContainerArtifact(
            artifact_type="logs",
            content=f"[DRY RUN] Would run: {cmd}",
            size_bytes=0, collection_cmd=cmd,
        )
    output, err = _run_docker(["logs", "--tail", str(tail_lines), "--timestamps", container_id])
    if err:
        return ContainerArtifact(
            artifact_type="logs", content="", size_bytes=0,
            collection_cmd=cmd, error=err,
        )
    return ContainerArtifact(
        artifact_type="logs",
        content=output,
        size_bytes=len(output.encode()),
        collection_cmd=cmd,
    )


def _collect_mounts(inspect_data: dict[str, Any]) -> ContainerArtifact:
    """Extract mount information from docker inspect data."""
    mounts = inspect_data.get("Mounts", []) or []
    content = json.dumps(mounts, indent=2)
    return ContainerArtifact(
        artifact_type="mounts",
        content=content,
        size_bytes=len(content.encode()),
        collection_cmd="extracted from inspect",
    )


def _collect_security_context(inspect_data: dict[str, Any]) -> ContainerArtifact:
    """Extract security context from docker inspect data."""
    ctx = _extract_security_context(inspect_data)
    content = json.dumps(ctx, indent=2)
    return ContainerArtifact(
        artifact_type="security_context",
        content=content,
        size_bytes=len(content.encode()),
        collection_cmd="extracted from inspect",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_container_evidence(
    container_id: str,
    incident_id: str,
    tail_log_lines: int = 500,
    dry_run: bool = True,
) -> ContainerForensicsReport:
    """
    Collect forensic evidence from a Docker container.

    Performs read-only evidence collection: inspect, processes, network
    connections, filesystem diff, logs, mounts, and security context.

    Args:
        container_id:    Docker container ID or name.
        incident_id:     IR ticket reference (used for tagging only).
        tail_log_lines:  Number of recent log lines to collect (default: 500).
        dry_run:         If True (default), preview only — no commands executed.

    Returns:
        ContainerForensicsReport with all collected artifacts.
    """
    report = ContainerForensicsReport(
        container_id=container_id,
        container_name="<unknown>",
        incident_id=incident_id,
        image="<unknown>",
        status="unknown",
        dry_run=dry_run,
    )

    if dry_run:
        # Build a preview report without running any commands
        report.container_name = "<dry-run>"
        report.image = "<dry-run>"
        report.status = "unknown"

        cmds = [
            f"docker inspect {container_id}",
            f"docker top {container_id} aux",
            f"docker exec {container_id} ss -tunap",
            f"docker diff {container_id}",
            f"docker logs --tail {tail_log_lines} --timestamps {container_id}",
            "extracted from inspect (mounts)",
            "extracted from inspect (security_context)",
        ]
        types = ["inspect", "processes", "network_connections",
                 "filesystem_diff", "logs", "mounts", "security_context"]
        for t, c in zip(types, cmds):
            report.artifacts.append(ContainerArtifact(
                artifact_type=t,
                content=f"[DRY RUN] Would run: {c}",
                size_bytes=0,
                collection_cmd=c,
            ))
        return report

    # --- Live execution ---
    # Step 1: Inspect
    inspect_artifact = _collect_inspect(container_id, dry_run=False)
    report.artifacts.append(inspect_artifact)
    if inspect_artifact.error:
        report.errors.append(f"inspect: {inspect_artifact.error}")

    # Parse inspect for container metadata
    inspect_data = {}
    if inspect_artifact.succeeded:
        inspect_data = _parse_inspect(inspect_artifact.content)
        report.container_name = (
            inspect_data.get("Name", "").lstrip("/") or "<unnamed>"
        )
        report.image = (
            inspect_data.get("Config", {}).get("Image", "<unknown>")
        )
        state = inspect_data.get("State", {})
        report.status = "running" if state.get("Running") else "stopped"

    is_running = report.status == "running"

    # Step 2: Processes
    report.artifacts.append(_collect_processes(container_id, dry_run=False, is_running=is_running))

    # Step 3: Network connections
    report.artifacts.append(
        _collect_network_connections(container_id, dry_run=False, is_running=is_running)
    )

    # Step 4: Filesystem diff
    report.artifacts.append(_collect_filesystem_diff(container_id, dry_run=False))

    # Step 5: Logs
    report.artifacts.append(_collect_logs(container_id, dry_run=False, tail_lines=tail_log_lines))

    # Step 6: Mounts (from inspect data — always available if inspect succeeded)
    if inspect_data:
        report.artifacts.append(_collect_mounts(inspect_data))
        report.artifacts.append(_collect_security_context(inspect_data))
    else:
        for t in ("mounts", "security_context"):
            report.artifacts.append(ContainerArtifact(
                artifact_type=t,
                content="Skipped — inspect data unavailable",
                size_bytes=0,
                collection_cmd="skipped",
                error="inspect failed",
            ))

    # Collect errors from all artifacts
    for artifact in report.artifacts:
        if artifact.error and artifact.artifact_type != "inspect":
            report.errors.append(f"{artifact.artifact_type}: {artifact.error}")

    return report
