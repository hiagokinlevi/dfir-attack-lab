"""Tests for the case packager."""
import json
import tempfile
from pathlib import Path
from case.packager import package_case, verify_case


def test_package_creates_manifest():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a fake artifact file
        artifact = Path(tmpdir) / "triage.jsonl"
        artifact.write_text('{"case_id": "TEST"}\n')

        output_dir = Path(tmpdir) / "cases"
        manifest_path = package_case(
            source_files=[artifact],
            case_id="CASE-001",
            output_dir=output_dir,
            analyst="analyst@example.com",
        )

        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["case_id"] == "CASE-001"
        assert manifest["artifact_count"] == 1
        assert manifest["artifacts"][0]["filename"] == "triage.jsonl"
        assert len(manifest["artifacts"][0]["sha256"]) == 64  # SHA-256 hex


def test_verify_case_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        artifact = Path(tmpdir) / "data.jsonl"
        artifact.write_text("test content\n")

        output_dir = Path(tmpdir) / "cases"
        manifest_path = package_case([artifact], "CASE-002", output_dir)

        results = verify_case(manifest_path)
        assert len(results) == 1
        assert results[0]["ok"] is True


def test_verify_detects_tampering():
    with tempfile.TemporaryDirectory() as tmpdir:
        artifact = Path(tmpdir) / "data.jsonl"
        artifact.write_text("original content\n")

        output_dir = Path(tmpdir) / "cases"
        manifest_path = package_case([artifact], "CASE-003", output_dir)

        # Tamper with the copied artifact
        manifest = json.loads(manifest_path.read_text())
        tampered_path = Path(manifest["artifacts"][0]["case_path"])
        tampered_path.write_text("tampered content\n")

        results = verify_case(manifest_path)
        assert results[0]["ok"] is False


def test_verify_rejects_case_paths_outside_artifacts_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        artifact = Path(tmpdir) / "data.jsonl"
        artifact.write_text("original content\n")
        external = Path(tmpdir) / "external.jsonl"
        external.write_text("external content\n")

        output_dir = Path(tmpdir) / "cases"
        manifest_path = package_case([artifact], "CASE-004", output_dir)

        manifest = json.loads(manifest_path.read_text())
        manifest["artifacts"][0]["case_path"] = str(external)
        manifest_path.write_text(json.dumps(manifest, indent=2))

        results = verify_case(manifest_path)
        assert results[0]["actual_sha256"] == "INVALID_CASE_PATH"
        assert results[0]["ok"] is False
