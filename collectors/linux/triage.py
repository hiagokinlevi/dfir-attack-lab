from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any


def _write_metadata(output_dir: Path, metadata: dict[str, Any]) -> Path:
    metadata_path = output_dir / "collection_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata_path


def collect_linux_triage(output_dir: Path, case_id: str | None = None) -> dict[str, Any]:
    """Collect Linux triage artifacts in a read-only manner.

    Parameters
    ----------
    output_dir:
        Destination directory for collection outputs.
    case_id:
        Optional case identifier stamped into collection metadata for correlation.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    metadata: dict[str, Any] = {
        "platform": "linux",
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    if case_id:
        metadata["case_id"] = case_id

    metadata_path = _write_metadata(output_dir, metadata)

    return {
        "status": "ok",
        "output_dir": str(output_dir),
        "metadata_path": str(metadata_path),
    }
