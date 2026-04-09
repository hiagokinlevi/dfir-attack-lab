"""
Tests for collectors/memory_artifact_collector.py
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.memory_artifact_collector import (
    ArtifactReport,
    IndicatorSeverity,
    MemoryArtifactCollector,
    MemoryIndicator,
    ProcessSnapshot,
    _path_entropy,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _collector() -> MemoryArtifactCollector:
    return MemoryArtifactCollector(dry_run=True)


def _snapshot(
    pid: int = 1234,
    comm: str = "nginx",
    exe: str = "/usr/sbin/nginx",
    cmdline: str = "nginx -g daemon off;",
    ppid: int = 1,
    parent_comm: str = "systemd",
    maps: list[str] | None = None,
    accessible: bool = True,
) -> ProcessSnapshot:
    return ProcessSnapshot(
        pid=pid,
        comm=comm,
        exe=exe,
        cmdline=cmdline,
        ppid=ppid,
        parent_comm=parent_comm,
        maps=maps or [],
        accessible=accessible,
    )


def _maps_line(
    addr: str = "7f0000000000-7f0001000000",
    perms: str = "r-xp",
    offset: str = "00000000",
    dev: str = "fd:01",
    inode: str = "123456",
    path: str = "/usr/lib/libc.so.6",
) -> str:
    return f"{addr} {perms} {offset} {dev} {inode}    {path}"


def _check_ids(report: ArtifactReport) -> set[str]:
    return {i.check_id for i in report.indicators}


# ===========================================================================
# _path_entropy
# ===========================================================================

class TestPathEntropy:
    def test_single_char_zero_entropy(self):
        assert _path_entropy("aaaa") == pytest.approx(0.0, abs=0.01)

    def test_all_different_high_entropy(self):
        # "abcd" — 4 unique chars, entropy = 2.0
        assert _path_entropy("abcd") == pytest.approx(2.0, abs=0.01)

    def test_empty_string(self):
        assert _path_entropy("") == 0.0

    def test_random_looking_name_high_entropy(self):
        # Random hex looks like high entropy
        s = "a3f9b1e7c2d0"
        assert _path_entropy(s) > 3.0

    def test_nginx_name_low_entropy(self):
        # "nginx" has repeated characters and low entropy
        assert _path_entropy("nginx") < 3.5


# ===========================================================================
# ProcessSnapshot
# ===========================================================================

class TestProcessSnapshot:
    def test_defaults(self):
        s = ProcessSnapshot(pid=100)
        assert s.comm == ""
        assert s.maps == []
        assert s.accessible is True

    def test_pid_set(self):
        s = ProcessSnapshot(pid=9999)
        assert s.pid == 9999


# ===========================================================================
# MemoryIndicator
# ===========================================================================

class TestMemoryIndicator:
    def _ind(self) -> MemoryIndicator:
        return MemoryIndicator(
            check_id="MA-001",
            severity=IndicatorSeverity.CRITICAL,
            title="Anonymous executable mapping",
            detail="Detail",
            pid=1234,
            evidence="addr=...",
        )

    def test_summary_contains_check_id(self):
        assert "MA-001" in self._ind().summary()

    def test_summary_contains_pid(self):
        assert "1234" in self._ind().summary()

    def test_to_dict_keys(self):
        d = self._ind().to_dict()
        for k in ("check_id", "severity", "title", "detail", "pid", "evidence"):
            assert k in d

    def test_severity_serialized_as_string(self):
        assert self._ind().to_dict()["severity"] == "CRITICAL"


# ===========================================================================
# ArtifactReport
# ===========================================================================

class TestArtifactReport:
    def _report(self) -> ArtifactReport:
        snap = _snapshot()
        i1 = MemoryIndicator("MA-001", IndicatorSeverity.CRITICAL, "t", "d", 1234)
        i2 = MemoryIndicator("MA-002", IndicatorSeverity.HIGH,     "t", "d", 1234)
        return ArtifactReport(snapshot=snap, indicators=[i1, i2], risk_score=60)

    def test_has_indicators_true(self):
        assert self._report().has_indicators

    def test_critical_count(self):
        assert self._report().critical_count == 1

    def test_indicators_by_check(self):
        assert len(self._report().indicators_by_check("MA-001")) == 1

    def test_pid_from_snapshot(self):
        assert self._report().pid == 1234

    def test_summary_contains_pid(self):
        assert "1234" in self._report().summary()

    def test_to_dict_keys(self):
        d = self._report().to_dict()
        for k in ("pid", "comm", "exe", "risk_score", "indicators"):
            assert k in d


# ===========================================================================
# MA-001: Anonymous executable mapping
# ===========================================================================

class TestMA001:
    def test_fires_for_anon_exec_rwx(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="rwxp", path=""),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-001" in _check_ids(report)

    def test_fires_for_anon_exec_r_x(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path=""),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-001" in _check_ids(report)

    def test_not_fired_for_non_exec_anon(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="rw-p", path=""),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-001" not in _check_ids(report)

    def test_not_fired_for_named_exec(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/usr/lib/libc.so.6"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-001" not in _check_ids(report)

    def test_ma001_is_critical(self):
        col = _collector()
        snap = _snapshot(maps=[_maps_line(perms="rwxp", path="")])
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-001")
        assert i.severity == IndicatorSeverity.CRITICAL

    def test_ma001_pid_in_indicator(self):
        col = _collector()
        snap = _snapshot(pid=5678, maps=[_maps_line(perms="rwxp", path="")])
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-001")
        assert i.pid == 5678


# ===========================================================================
# MA-002: Deleted executable
# ===========================================================================

class TestMA002:
    def test_fires_for_deleted_exec(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/usr/local/bin/implant (deleted)"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-002" in _check_ids(report)

    def test_not_fired_for_non_exec_deleted(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="rw-p", path="/tmp/data (deleted)"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-002" not in _check_ids(report)

    def test_not_fired_for_normal_path(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/usr/lib/libc.so.6"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-002" not in _check_ids(report)

    def test_ma002_is_high(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/bin/evil (deleted)"),
        ])
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-002")
        assert i.severity == IndicatorSeverity.HIGH


# ===========================================================================
# MA-003: World-writable path
# ===========================================================================

class TestMA003:
    def test_fires_for_tmp_exec(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/tmp/malware.elf"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-003" in _check_ids(report)

    def test_fires_for_dev_shm_exec(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/dev/shm/payload"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-003" in _check_ids(report)

    def test_not_fired_for_usr_lib(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/usr/lib/libc.so.6"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-003" not in _check_ids(report)

    def test_ma003_is_high(self):
        col = _collector()
        snap = _snapshot(maps=[_maps_line(perms="r-xp", path="/var/tmp/stager")])
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-003")
        assert i.severity == IndicatorSeverity.HIGH


# ===========================================================================
# MA-004: Process name / exe mismatch
# ===========================================================================

class TestMA004:
    def test_fires_when_comm_differs_from_exe(self):
        col = _collector()
        snap = _snapshot(
            comm="kworker",
            exe="/tmp/implant",
        )
        report = col.analyze_snapshot(snap)
        assert "MA-004" in _check_ids(report)

    def test_not_fired_when_comm_matches(self):
        col = _collector()
        snap = _snapshot(comm="nginx", exe="/usr/sbin/nginx")
        report = col.analyze_snapshot(snap)
        assert "MA-004" not in _check_ids(report)

    def test_not_fired_when_exe_empty(self):
        col = _collector()
        snap = _snapshot(comm="nginx", exe="")
        report = col.analyze_snapshot(snap)
        assert "MA-004" not in _check_ids(report)

    def test_not_fired_when_comm_empty(self):
        col = _collector()
        snap = _snapshot(comm="", exe="/usr/sbin/nginx")
        report = col.analyze_snapshot(snap)
        assert "MA-004" not in _check_ids(report)

    def test_ma004_is_high(self):
        col = _collector()
        snap = _snapshot(comm="sshd", exe="/tmp/fakessh")
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-004")
        assert i.severity == IndicatorSeverity.HIGH


# ===========================================================================
# MA-005: Suspicious parent–child
# ===========================================================================

class TestMA005:
    def test_fires_for_nginx_spawning_bash(self):
        col = _collector()
        snap = _snapshot(comm="bash", parent_comm="nginx")
        report = col.analyze_snapshot(snap)
        assert "MA-005" in _check_ids(report)

    def test_fires_for_apache_spawning_sh(self):
        col = _collector()
        snap = _snapshot(comm="sh", parent_comm="apache2")
        report = col.analyze_snapshot(snap)
        assert "MA-005" in _check_ids(report)

    def test_not_fired_for_systemd_bash(self):
        col = _collector()
        snap = _snapshot(comm="bash", parent_comm="systemd")
        report = col.analyze_snapshot(snap)
        assert "MA-005" not in _check_ids(report)

    def test_not_fired_for_nginx_nginx_child(self):
        col = _collector()
        snap = _snapshot(comm="nginx", parent_comm="nginx")
        report = col.analyze_snapshot(snap)
        assert "MA-005" not in _check_ids(report)

    def test_ma005_is_medium(self):
        col = _collector()
        snap = _snapshot(comm="python3", parent_comm="httpd")
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-005")
        assert i.severity == IndicatorSeverity.MEDIUM


# ===========================================================================
# MA-006: Running from deleted exe
# ===========================================================================

class TestMA006:
    def test_fires_when_exe_deleted(self):
        col = _collector()
        snap = _snapshot(exe="/tmp/implant (deleted)")
        report = col.analyze_snapshot(snap)
        assert "MA-006" in _check_ids(report)

    def test_not_fired_for_normal_exe(self):
        col = _collector()
        snap = _snapshot(exe="/usr/sbin/sshd")
        report = col.analyze_snapshot(snap)
        assert "MA-006" not in _check_ids(report)

    def test_ma006_is_high(self):
        col = _collector()
        snap = _snapshot(exe="/bin/evil (deleted)")
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-006")
        assert i.severity == IndicatorSeverity.HIGH


# ===========================================================================
# MA-007: High-entropy path
# ===========================================================================

class TestMA007:
    def test_fires_for_high_entropy_basename(self):
        col = _collector()
        # Random-looking name with high entropy
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/usr/lib/a3f9b1e7c2d04852.so"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-007" in _check_ids(report)

    def test_not_fired_for_low_entropy_name(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/usr/lib/libc.so.6"),
        ])
        report = col.analyze_snapshot(snap)
        assert "MA-007" not in _check_ids(report)

    def test_ma007_is_medium(self):
        col = _collector()
        snap = _snapshot(maps=[
            _maps_line(perms="r-xp", path="/lib/a3b5c7d9e1f2.so"),
        ])
        report = col.analyze_snapshot(snap)
        i = next(i for i in report.indicators if i.check_id == "MA-007")
        assert i.severity == IndicatorSeverity.MEDIUM


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_no_indicators_zero_risk(self):
        col = _collector()
        snap = _snapshot(
            comm="nginx",
            exe="/usr/sbin/nginx",
            maps=[_maps_line(perms="r-xp", path="/usr/lib/libc.so.6")],
        )
        report = col.analyze_snapshot(snap)
        assert report.risk_score == 0

    def test_risk_capped_at_100(self):
        col = _collector()
        snap = _snapshot(
            comm="kworker",
            exe="/tmp/implant (deleted)",
            parent_comm="nginx",
            maps=[
                _maps_line(perms="rwxp", path=""),
                _maps_line(perms="r-xp", path="/tmp/evil (deleted)"),
                _maps_line(perms="r-xp", path="/dev/shm/stage"),
            ],
        )
        report = col.analyze_snapshot(snap)
        assert report.risk_score <= 100

    def test_ma001_alone_is_35(self):
        col = _collector()
        snap = _snapshot(
            comm="nginx",
            exe="/usr/sbin/nginx",
            maps=[_maps_line(perms="rwxp", path="")],
        )
        report = col.analyze_snapshot(snap)
        assert report.risk_score == 35


# ===========================================================================
# Inaccessible snapshot
# ===========================================================================

class TestInaccessibleSnapshot:
    def test_inaccessible_returns_empty_report(self):
        col = _collector()
        snap = _snapshot(accessible=False)
        report = col.analyze_snapshot(snap)
        assert not report.has_indicators
        assert report.risk_score == 0


# ===========================================================================
# dry_run mode
# ===========================================================================

class TestDryRun:
    def test_collect_all_returns_empty_in_dry_run(self):
        col = MemoryArtifactCollector(dry_run=True)
        reports = col.collect_all()
        assert reports == []

    def test_collect_pid_returns_empty_snapshot_in_dry_run(self):
        col = MemoryArtifactCollector(dry_run=True)
        report = col.collect_pid(1)
        assert not report.has_indicators
