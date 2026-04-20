from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


class RemoteAcquisitionError(RuntimeError):
    """Raised when remote acquisition fails."""


@dataclass(frozen=True)
class SSHCredentials:
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    key_path: Optional[str] = None
    strict_host_key_checking: bool = True


@dataclass(frozen=True)
class WinRMCredentials:
    host: str
    username: str
    password: str
    transport: str = "ntlm"
    port: int = 5985
    use_ssl: bool = False


@dataclass(frozen=True)
class RemoteAcquisitionResult:
    host: str
    platform: str
    local_artifact_dir: str
    package_path: Optional[str] = None


def _env_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_ssh_credentials_from_env(prefix: str = "REMOTE_SSH_") -> SSHCredentials:
    host = os.getenv(f"{prefix}HOST")
    username = os.getenv(f"{prefix}USER")
    if not host or not username:
        raise RemoteAcquisitionError("Missing SSH credentials in environment (HOST/USER).")

    port = int(os.getenv(f"{prefix}PORT", "22"))
    password = os.getenv(f"{prefix}PASSWORD")
    key_path = os.getenv(f"{prefix}KEY_PATH")
    strict = _env_bool(os.getenv(f"{prefix}STRICT_HOST_KEY_CHECKING"), True)

    return SSHCredentials(
        host=host,
        username=username,
        port=port,
        password=password,
        key_path=key_path,
        strict_host_key_checking=strict,
    )


def load_winrm_credentials_from_env(prefix: str = "REMOTE_WINRM_") -> WinRMCredentials:
    host = os.getenv(f"{prefix}HOST")
    username = os.getenv(f"{prefix}USER")
    password = os.getenv(f"{prefix}PASSWORD")
    if not host or not username or not password:
        raise RemoteAcquisitionError("Missing WinRM credentials in environment (HOST/USER/PASSWORD).")

    transport = os.getenv(f"{prefix}TRANSPORT", "ntlm")
    port = int(os.getenv(f"{prefix}PORT", "5985"))
    use_ssl = _env_bool(os.getenv(f"{prefix}USE_SSL"), False)

    return WinRMCredentials(
        host=host,
        username=username,
        password=password,
        transport=transport,
        port=port,
        use_ssl=use_ssl,
    )


def _run(cmd: List[str], env: Optional[Dict[str, str]] = None) -> None:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    if proc.returncode != 0:
        raise RemoteAcquisitionError(f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


def _require_binary(name: str) -> None:
    if shutil.which(name) is None:
        raise RemoteAcquisitionError(f"Required executable not found: {name}")


def acquire_linux_or_macos_via_ssh(
    creds: SSHCredentials,
    remote_collector_cmd: str,
    remote_artifact_path: str,
    local_output_dir: str,
    package_case: bool = True,
) -> RemoteAcquisitionResult:
    """
    Execute a read-only remote collector over SSH and securely retrieve artifacts via SCP.

    Notes:
    - Uses key auth when key_path is provided.
    - Falls back to sshpass if password is provided and key is not.
    - Strict host key checking is enabled by default.
    """
    _require_binary("ssh")
    _require_binary("scp")

    local_dir = Path(local_output_dir)
    local_dir.mkdir(parents=True, exist_ok=True)

    ssh_opts = ["-p", str(creds.port)]
    scp_opts = ["-P", str(creds.port)]

    if creds.key_path:
        ssh_opts += ["-i", creds.key_path]
        scp_opts += ["-i", creds.key_path]

    if not creds.strict_host_key_checking:
        ssh_opts += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
        scp_opts += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]

    remote_target = f"{creds.username}@{creds.host}"

    base_ssh_cmd = ["ssh", *ssh_opts, remote_target, remote_collector_cmd]
    base_scp_cmd = ["scp", *scp_opts, "-r", f"{remote_target}:{remote_artifact_path}", str(local_dir)]

    if creds.password and not creds.key_path:
        _require_binary("sshpass")
        env = os.environ.copy()
        env["SSHPASS"] = creds.password
        _run(["sshpass", "-e", *base_ssh_cmd], env=env)
        _run(["sshpass", "-e", *base_scp_cmd], env=env)
    else:
        _run(base_ssh_cmd)
        _run(base_scp_cmd)

    package_path: Optional[str] = None
    if package_case:
        try:
            from case.packager import package_case

            package_path = str(package_case(str(local_dir)))
        except Exception as exc:  # pragma: no cover
            raise RemoteAcquisitionError(f"Artifact retrieved but packaging failed: {exc}") from exc

    return RemoteAcquisitionResult(
        host=creds.host,
        platform="linux_or_macos",
        local_artifact_dir=str(local_dir),
        package_path=package_path,
    )


def acquire_windows_via_winrm(
    creds: WinRMCredentials,
    remote_collector_ps: str,
    remote_artifact_path: str,
    local_output_dir: str,
    package_case: bool = True,
) -> RemoteAcquisitionResult:
    """
    Execute read-only Windows collection over WinRM and download artifacts.

    Requires optional dependency: pywinrm
    """
    try:
        import winrm  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RemoteAcquisitionError("pywinrm is required for WinRM acquisition.") from exc

    scheme = "https" if creds.use_ssl else "http"
    endpoint = f"{scheme}://{creds.host}:{creds.port}/wsman"

    session = winrm.Session(
        target=endpoint,
        auth=(creds.username, creds.password),
        transport=creds.transport,
        server_cert_validation="ignore" if creds.use_ssl else "validate",
    )

    run = session.run_ps(remote_collector_ps)
    if run.status_code != 0:
        stderr = run.std_err.decode(errors="ignore") if isinstance(run.std_err, (bytes, bytearray)) else str(run.std_err)
        stdout = run.std_out.decode(errors="ignore") if isinstance(run.std_out, (bytes, bytearray)) else str(run.std_out)
        raise RemoteAcquisitionError(f"Remote PowerShell collector failed ({run.status_code})\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")

    download_script = (
        "$p = Get-Item -LiteralPath " + shlex.quote(remote_artifact_path) + "; "
        "if ($p.PSIsContainer) { "
        "  $tmp = Join-Path $env:TEMP ('dfir_remote_' + [guid]::NewGuid().ToString() + '.zip'); "
        "  Compress-Archive -Path (Join-Path $p.FullName '*') -DestinationPath $tmp -Force; "
        "  [Convert]::ToBase64String([IO.File]::ReadAllBytes($tmp)); "
        "} else { "
        "  [Convert]::ToBase64String([IO.File]::ReadAllBytes($p.FullName)); "
        "}"
    )

    data = session.run_ps(download_script)
    if data.status_code != 0:
        raise RemoteAcquisitionError("Failed to retrieve remote artifact over WinRM.")

    payload = data.std_out.decode(errors="ignore") if isinstance(data.std_out, (bytes, bytearray)) else str(data.std_out)
    payload = payload.strip()
    if not payload:
        raise RemoteAcquisitionError("Remote artifact payload was empty.")

    import base64

    raw = base64.b64decode(payload)
    local_dir = Path(local_output_dir)
    local_dir.mkdir(parents=True, exist_ok=True)
    artifact_file = local_dir / f"{creds.host}_remote_artifact.bin"
    artifact_file.write_bytes(raw)

    package_path: Optional[str] = None
    if package_case:
        try:
            from case.packager import package_case

            package_path = str(package_case(str(local_dir)))
        except Exception as exc:  # pragma: no cover
            raise RemoteAcquisitionError(f"Artifact retrieved but packaging failed: {exc}") from exc

    return RemoteAcquisitionResult(
        host=creds.host,
        platform="windows",
        local_artifact_dir=str(local_dir),
        package_path=package_path,
    )
