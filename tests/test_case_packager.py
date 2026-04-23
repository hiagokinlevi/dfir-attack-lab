import json
from pathlib import Path

from case.packager import package_case, verify_case


def test_manifest_includes_provenance_metadata(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "artifact.txt").write_text("evidence", encoding="utf-8")

    manifest_path = package_case(src, dst, collector_command="collect-linux --output case-001")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "metadata" in manifest
    assert "files" in manifest

    metadata = manifest["metadata"]
    assert metadata["collector_command"] == "collect-linux --output case-001"
    assert metadata["collected_at_utc"].endswith("+00:00")


def test_verify_case_remains_hash_based_and_backward_compatible(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "a.txt").write_text("alpha", encoding="utf-8")

    # Simulate older manifest without metadata; verification should still succeed.
    from case.packager import _sha256_file

    manifest = {
        "files": {
            "a.txt": _sha256_file(case_dir / "a.txt"),
        }
    }
    (case_dir / "integrity_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert verify_case(case_dir)

    (case_dir / "a.txt").write_text("tampered", encoding="utf-8")
    assert not verify_case(case_dir)
