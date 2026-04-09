"""
Unit tests for collectors/macos/triage.py

The collector runs system commands that only exist on macOS. All tests
exercise the collector in a cross-platform manner by mocking subprocess.run
so tests pass on Linux CI as well.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.macos.triage import (
    _collect_launch_persistence,
    _list_plist_names,
    _read_file_safe,
    _run_safe,
    run_macos_triage,
)


class TestRunSafe(unittest.TestCase):
    """Tests for the _run_safe() helper."""

    def test_returns_stdout_on_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="hello world", returncode=0)
            result = _run_safe(["echo", "hello world"])
        self.assertEqual(result, "hello world")

    def test_returns_none_on_file_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = _run_safe(["nonexistent_command"])
        self.assertIsNone(result)

    def test_returns_none_on_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=5)):
            result = _run_safe(["sleep", "999"])
        self.assertIsNone(result)

    def test_returns_none_on_permission_error(self):
        with patch("subprocess.run", side_effect=PermissionError):
            result = _run_safe(["restricted_cmd"])
        self.assertIsNone(result)

    def test_returns_none_when_stdout_empty(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", returncode=0)
            result = _run_safe(["true"])
        self.assertIsNone(result)

    def test_returns_stripped_output(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="  spaces around  \n", returncode=0)
            result = _run_safe(["cmd"])
        self.assertEqual(result, "spaces around")


class TestReadFileSafe(unittest.TestCase):
    """Tests for the _read_file_safe() helper."""

    def test_reads_existing_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("content here")
            path = f.name
        result = _read_file_safe(path)
        self.assertEqual(result, "content here")

    def test_returns_none_for_missing_file(self):
        result = _read_file_safe("/tmp/definitely_does_not_exist_xyz_12345.txt")
        self.assertIsNone(result)

    def test_returns_none_for_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("")
            path = f.name
        result = _read_file_safe(path)
        self.assertIsNone(result)


class TestListPlistNames(unittest.TestCase):
    """Tests for the _list_plist_names() helper."""

    def test_lists_plist_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "com.example.agent.plist").touch()
            Path(tmpdir, "com.other.agent.plist").touch()
            Path(tmpdir, "not_a_plist.txt").touch()
            names = _list_plist_names(tmpdir)
        self.assertEqual(names, ["com.example.agent.plist", "com.other.agent.plist"])

    def test_returns_none_for_missing_directory(self):
        result = _list_plist_names("/tmp/no_such_directory_xyz_99999")
        self.assertIsNone(result)

    def test_returns_none_for_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _list_plist_names(tmpdir)
        self.assertIsNone(result)

    def test_ignores_non_plist_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "something.yaml").touch()
            Path(tmpdir, "something.json").touch()
            result = _list_plist_names(tmpdir)
        self.assertIsNone(result)


class TestCollectLaunchPersistence(unittest.TestCase):
    """Tests for _collect_launch_persistence()."""

    def test_returns_dict_with_expected_keys(self):
        result = _collect_launch_persistence()
        expected_keys = {
            "user_launch_agents",
            "system_launch_agents",
            "system_launch_daemons",
            "os_launch_daemons",
            "legacy_startup_items",
        }
        self.assertEqual(set(result.keys()), expected_keys)

    def test_values_are_list_or_none(self):
        result = _collect_launch_persistence()
        for key, value in result.items():
            self.assertIsInstance(
                value, (list, type(None)),
                f"Expected list or None for key '{key}', got {type(value)}",
            )


class TestRunMacOSTriage(unittest.TestCase):
    """Integration tests for run_macos_triage()."""

    def _mock_run_safe(self, cmd, timeout=30):
        """Stub for _run_safe — returns a fake string for any command."""
        return f"mocked output for {cmd[0]}"

    def test_creates_output_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "case"
            with patch("collectors.macos.triage._run_safe", side_effect=self._mock_run_safe), \
                 patch("collectors.macos.triage._read_file_safe", return_value=None), \
                 patch("collectors.macos.triage._collect_launch_persistence", return_value={}):
                path = run_macos_triage(output_dir, case_id="TEST-001")
            self.assertTrue(path.exists())
            self.assertEqual(path.name, "TEST-001_macos_triage.jsonl")

    def test_output_is_valid_jsonl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "case"
            with patch("collectors.macos.triage._run_safe", side_effect=self._mock_run_safe), \
                 patch("collectors.macos.triage._read_file_safe", return_value=None), \
                 patch("collectors.macos.triage._collect_launch_persistence", return_value={}):
                path = run_macos_triage(output_dir, case_id="TEST-002")
            lines = path.read_text().strip().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertIn("case_id", record)
        self.assertIn("collected_at", record)
        self.assertIn("platform", record)
        self.assertIn("observations", record)

    def test_platform_is_macos(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "case"
            with patch("collectors.macos.triage._run_safe", return_value=None), \
                 patch("collectors.macos.triage._read_file_safe", return_value=None), \
                 patch("collectors.macos.triage._collect_launch_persistence", return_value={}):
                path = run_macos_triage(output_dir, case_id="TEST-003")
            record = json.loads(path.read_text())
        self.assertEqual(record["platform"], "macos")

    def test_none_observations_excluded(self):
        """Observations with None values should not appear in the output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "case"
            with patch("collectors.macos.triage._run_safe", return_value=None), \
                 patch("collectors.macos.triage._read_file_safe", return_value=None), \
                 patch("collectors.macos.triage._collect_launch_persistence", return_value={}):
                path = run_macos_triage(output_dir, case_id="TEST-004")
            record = json.loads(path.read_text())
        for key, value in record["observations"].items():
            self.assertIsNotNone(value, f"Key '{key}' should not be None in output")

    def test_case_id_in_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "case"
            with patch("collectors.macos.triage._run_safe", return_value=None), \
                 patch("collectors.macos.triage._read_file_safe", return_value=None), \
                 patch("collectors.macos.triage._collect_launch_persistence", return_value={}):
                path = run_macos_triage(output_dir, case_id="INC-2026-099")
            record = json.loads(path.read_text())
        self.assertEqual(record["case_id"], "INC-2026-099")

    def test_creates_output_directory_if_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "deep" / "case" / "dir"
            with patch("collectors.macos.triage._run_safe", return_value=None), \
                 patch("collectors.macos.triage._read_file_safe", return_value=None), \
                 patch("collectors.macos.triage._collect_launch_persistence", return_value={}):
                run_macos_triage(nested, case_id="TEST-005")
            self.assertTrue(nested.exists())
