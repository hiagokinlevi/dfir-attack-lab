"""
Case packager for DFIR artifact collection.

Packages all triage artifacts, parsed event files, and timeline output into
a structured case directory with SHA-256 integrity verification. Produces a
manifest suitable for chain-of-custody documentation.
"""
from __future__ import annotations
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


def _sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def package_case(
    source_files: list[Path],
    case_id: str,
    output_dir: Path,
    analyst: str = "unknown",
    notes: str = "",
) -> Path:
    """
    Package DFIR artifacts into a structured case directory.

    Copies all source files, computes SHA-256 for each, and writes a
    case manifest JSON. The manifest provides chain-of-custody evidence
    and enables integrity verification of collected artifacts.

    Args:
        source_files: List of paths to artifact files to include.
        case_id:      Unique case identifier (e.g., "CASE-2026-001").
        output_dir:   Directory where the case package will be created.
        analyst:      Name/ID of the analyst packaging the case.
        notes:        Optional case notes to include in the manifest.

    Returns:
        Path to the written case manifest JSON file.
    """
    case_dir = output_dir / case_id
    artifacts_dir = case_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries: list[dict] = []

    for src in source_files:
        if not src.exists():
            continue
        dest = artifacts_dir / src.name
        shutil.copy2(src, dest)
        manifest_entries.append({
            "filename": src.name,
            "original_path": str(src),
            "case_path": str(dest),
            "sha256": _sha256(dest),
            "size_bytes": dest.stat().st_size,
            "collected_at": datetime.fromtimestamp(src.stat().st_mtime, tz=timezone.utc).isoformat(),
        })

    manifest = {
        "case_id": case_id,
        "packaged_at": datetime.now(timezone.utc).isoformat(),
        "analyst": analyst,
        "notes": notes,
        "artifact_count": len(manifest_entries),
        "artifacts": manifest_entries,
    }

    manifest_path = case_dir / "case_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    return manifest_path


def verify_case(manifest_path: Path) -> list[dict]:
    """
    Verify the integrity of a packaged case by re-computing SHA-256 hashes.

    Args:
        manifest_path: Path to a case_manifest.json produced by package_case().

    Returns:
        List of verification results. Each entry has keys:
        - filename: str
        - expected_sha256: str
        - actual_sha256: str
        - ok: bool — True if hashes match
    """
    manifest = json.loads(manifest_path.read_text())
    results: list[dict] = []

    for entry in manifest.get("artifacts", []):
        path = Path(entry["case_path"])
        if not path.exists():
            results.append({
                "filename": entry["filename"],
                "expected_sha256": entry["sha256"],
                "actual_sha256": "FILE_MISSING",
                "ok": False,
            })
            continue

        actual = _sha256(path)
        results.append({
            "filename": entry["filename"],
            "expected_sha256": entry["sha256"],
            "actual_sha256": actual,
            "ok": actual == entry["sha256"],
        })

    return results
