"""
Tests for collectors/container_forensics.py

All tests use dry_run=True to avoid requiring a live Docker daemon.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.container_forensics import (
    ContainerArtifact,
    ContainerForensicsReport,
    _extract_security_context,
    _mask_env_vars,
    _parse_inspect,
    collect_container_evidence,
)


# ===========================================================================
# Helper functions
# ===========================================================================

class TestMaskEnvVars:
    def test_masks_key(self):
        result = _mask_env_vars(["API_KEY=secret123"])
        assert result[0] == "API_KEY=****[MASKED]"

    def test_preserves_non_sensitive(self):
        result = _mask_env_vars(["PATH=/usr/bin"])
        assert result[0] == "PATH=/usr/bin"

    def test_masks_token(self):
        result = _mask_env_vars(["ACCESS_TOKEN=abc123"])
        assert "****[MASKED]" in result[0]

    def test_masks_password(self):
        result = _mask_env_vars(["DB_PASSWORD=secret"])
        assert "****[MASKED]" in result[0]

    def test_entry_without_equals(self):
        result = _mask_env_vars(["NO_EQUALS"])
        assert result[0] == "NO_EQUALS"

    def test_empty_list(self):
        assert _mask_env_vars([]) == []


class TestParseInspect:
    def test_parses_list(self):
        raw = json.dumps([{"Id": "abc", "Config": {}}])
        data = _parse_inspect(raw)
        assert data["Id"] == "abc"

    def test_returns_empty_on_invalid_json(self):
        data = _parse_inspect("not json")
        assert data == {}

    def test_returns_empty_on_empty_list(self):
        data = _parse_inspect("[]")
        assert data == {}


class TestExtractSecurityContext:
    def test_detects_privileged(self):
        inspect = {"HostConfig": {"Privileged": True}, "Config": {}}
        ctx = _extract_security_context(inspect)
        assert ctx["privileged"] is True

    def test_detects_read_only_rootfs(self):
        inspect = {"HostConfig": {"ReadonlyRootfs": True}, "Config": {}}
        ctx = _extract_security_context(inspect)
        assert ctx["read_only_rootfs"] is True

    def test_cap_add_extracted(self):
        inspect = {"HostConfig": {"CapAdd": ["NET_ADMIN"]}, "Config": {}}
        ctx = _extract_security_context(inspect)
        assert "NET_ADMIN" in ctx["cap_add"]

    def test_defaults_to_not_privileged(self):
        inspect = {"HostConfig": {}, "Config": {}}
        ctx = _extract_security_context(inspect)
        assert ctx["privileged"] is False


# ===========================================================================
# ContainerArtifact
# ===========================================================================

class TestContainerArtifact:
    def test_succeeded_when_no_error(self):
        a = ContainerArtifact(
            artifact_type="inspect", content="data",
            size_bytes=4, collection_cmd="docker inspect x",
        )
        assert a.succeeded

    def test_not_succeeded_when_error(self):
        a = ContainerArtifact(
            artifact_type="inspect", content="",
            size_bytes=0, collection_cmd="docker inspect x",
            error="container not found",
        )
        assert not a.succeeded


# ===========================================================================
# ContainerForensicsReport
# ===========================================================================

class TestContainerForensicsReport:
    def _make_report(self, artifact_count=3, errors=0) -> ContainerForensicsReport:
        report = ContainerForensicsReport(
            container_id="abc123def456",
            container_name="test-container",
            incident_id="INC-X",
            image="ubuntu:22.04",
            status="running",
            dry_run=True,
        )
        for i in range(artifact_count):
            report.artifacts.append(ContainerArtifact(
                artifact_type=f"type_{i}", content="data",
                size_bytes=4, collection_cmd="cmd",
            ))
        for i in range(errors):
            report.errors.append(f"error {i}")
        return report

    def test_artifact_count(self):
        assert self._make_report(3).artifact_count == 3

    def test_total_bytes(self):
        assert self._make_report(3).total_bytes == 12

    def test_succeeded_count(self):
        assert self._make_report(3).succeeded_count == 3

    def test_failed_count_with_errors(self):
        report = self._make_report(2)
        report.artifacts[1] = ContainerArtifact(
            artifact_type="x", content="", size_bytes=0,
            collection_cmd="c", error="err",
        )
        assert report.failed_count == 1

    def test_summary_contains_container_id(self):
        assert "abc123def456" in self._make_report().summary()

    def test_get_artifact_by_type(self):
        report = self._make_report(2)
        a = report.get_artifact("type_0")
        assert a is not None
        assert a.artifact_type == "type_0"

    def test_get_artifact_not_found(self):
        assert self._make_report().get_artifact("nonexistent") is None


# ===========================================================================
# collect_container_evidence — dry_run mode
# ===========================================================================

class TestCollectContainerEvidenceDryRun:
    result = collect_container_evidence(
        container_id="abc123def456",
        incident_id="INC-2026-042",
        dry_run=True,
    )

    def test_returns_report(self):
        assert isinstance(self.result, ContainerForensicsReport)

    def test_dry_run_flag_set(self):
        assert self.result.dry_run is True

    def test_artifacts_non_empty(self):
        assert len(self.result.artifacts) > 0

    def test_all_artifacts_dry_run_prefixed(self):
        for artifact in self.result.artifacts:
            assert "[DRY RUN]" in artifact.content, f"Expected DRY RUN in {artifact.artifact_type}"

    def test_artifact_types_present(self):
        types = {a.artifact_type for a in self.result.artifacts}
        for expected in ("inspect", "processes", "filesystem_diff", "logs"):
            assert expected in types

    def test_no_errors(self):
        assert self.result.errors == []

    def test_summary_contains_dry_run(self):
        assert "DRY RUN" in self.result.summary()

    def test_artifact_types_include_security_context(self):
        types = {a.artifact_type for a in self.result.artifacts}
        assert "security_context" in types

    def test_artifact_types_include_mounts(self):
        types = {a.artifact_type for a in self.result.artifacts}
        assert "mounts" in types


# ===========================================================================
# collect_container_evidence — live (docker not installed)
# ===========================================================================

class TestCollectContainerEvidenceNoDocker:
    """Test that live collection fails gracefully when Docker is unavailable."""

    def test_missing_docker_records_error(self):
        with patch("collectors.container_forensics._run_docker") as mock_run:
            mock_run.return_value = ("", "docker not found")
            result = collect_container_evidence(
                container_id="abc123",
                incident_id="INC-X",
                dry_run=False,
            )
        # Should have an error in the inspect artifact
        inspect = result.get_artifact("inspect")
        assert inspect is not None
        assert not inspect.succeeded

    def test_report_returned_even_on_failure(self):
        with patch("collectors.container_forensics._run_docker") as mock_run:
            mock_run.return_value = ("", "docker not found")
            result = collect_container_evidence(
                container_id="abc123",
                incident_id="INC-X",
                dry_run=False,
            )
        assert isinstance(result, ContainerForensicsReport)

    def test_live_successful_inspect_sets_name(self):
        """If inspect succeeds, container name is extracted."""
        sample_inspect = json.dumps([{
            "Id": "abc123",
            "Name": "/test-container",
            "Config": {"Image": "nginx:latest", "Env": []},
            "HostConfig": {"Privileged": False},
            "State": {"Running": True},
            "Mounts": [],
        }])

        def mock_run(args, timeout=30):
            cmd = args[0] if args else ""
            if cmd == "inspect":
                return sample_inspect, None
            return "", "not available"

        with patch("collectors.container_forensics._run_docker", side_effect=mock_run):
            result = collect_container_evidence(
                container_id="abc123",
                incident_id="INC-X",
                dry_run=False,
            )
        assert result.container_name == "test-container"
        assert result.image == "nginx:latest"
        assert result.status == "running"
