from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(root: Path) -> Iterable[Path]:
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != "integrity_manifest.json":
            yield p


def package_case(
    source_dir: str | Path,
    destination_dir: str | Path,
    collector_command: Optional[str] = None,
) -> Path:
    source = Path(source_dir)
    destination = Path(destination_dir)

    if not source.exists() or not source.is_dir():
        raise ValueError(f"Invalid source directory: {source}")

    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)

    manifest_path = destination / "integrity_manifest.json"

    files: Dict[str, str] = {}
    for f in _iter_files(destination):
        rel = str(f.relative_to(destination)).replace("\\", "/")
        files[rel] = _sha256_file(f)

    metadata: Dict[str, str] = {
        "collected_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    if collector_command:
        metadata["collector_command"] = collector_command

    manifest = {
        "metadata": metadata,
        "files": files,
    }

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def verify_case(case_dir: str | Path) -> bool:
    root = Path(case_dir)
    manifest_path = root / "integrity_manifest.json"

    if not manifest_path.exists():
        return False

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False

    files = manifest.get("files")
    if not isinstance(files, dict):
        return False

    for rel, expected in files.items():
        p = root / rel
        if not p.exists() or not p.is_file():
            return False
        if _sha256_file(p) != expected:
            return False

    return True
