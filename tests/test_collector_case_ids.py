"""Regression tests for collector case ID validation."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from collectors.linux.triage import run_linux_triage
from collectors.macos.triage import run_macos_triage
from collectors.windows.triage import run_windows_triage


@pytest.mark.parametrize(
    ("collector", "case_id"),
    [
        (run_linux_triage, "../CASE-001"),
        (run_linux_triage, "nested/case"),
        (run_linux_triage, r"nested\\case"),
        (run_windows_triage, "../CASE-002"),
        (run_windows_triage, "nested/case"),
        (run_windows_triage, r"nested\\case"),
        (run_macos_triage, "../CASE-003"),
        (run_macos_triage, "nested/case"),
        (run_macos_triage, r"nested\\case"),
    ],
)
def test_collectors_reject_path_like_case_ids(collector, case_id):
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "triage" / "output"
        with pytest.raises(ValueError, match="single non-relative path segment"):
            collector(output_dir, case_id)
        assert not output_dir.exists()


@pytest.mark.parametrize("collector", [run_linux_triage, run_windows_triage, run_macos_triage])
def test_collectors_reject_blank_case_ids(collector):
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "triage" / "output"
        with pytest.raises(ValueError, match="must not be empty"):
            collector(output_dir, "   ")
        assert not output_dir.exists()
