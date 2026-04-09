"""
Tests for collectors/windows/registry_persistence.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.windows.registry_persistence import (
    PersistenceFinding,
    PersistenceReport,
    PersistenceSeverity,
    RegistryPersistenceDetector,
    RegistrySnapshot,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _detector(**kwargs) -> RegistryPersistenceDetector:
    return RegistryPersistenceDetector(**kwargs)


def _check_ids(report: PersistenceReport) -> set[str]:
    return {f.check_id for f in report.findings}


# ===========================================================================
# PersistenceFinding
# ===========================================================================

class TestPersistenceFinding:
    def _f(self) -> PersistenceFinding:
        return PersistenceFinding(
            check_id="REG-P-001",
            severity=PersistenceSeverity.HIGH,
            title="Run key",
            detail="Detail here",
            evidence="C:\\Temp\\evil.exe",
            hive="HKCU",
            key_name="EvilEntry",
        )

    def test_to_dict_has_required_keys(self):
        d = self._f().to_dict()
        for k in ("check_id", "severity", "title", "detail", "evidence", "hive", "key_name"):
            assert k in d

    def test_severity_as_string(self):
        assert self._f().to_dict()["severity"] == "HIGH"

    def test_summary_contains_check_id(self):
        assert "REG-P-001" in self._f().summary()

    def test_evidence_truncated_to_512(self):
        f = PersistenceFinding(
            check_id="REG-P-001",
            severity=PersistenceSeverity.LOW,
            title="t", detail="d",
            evidence="x" * 600,
        )
        assert len(f.to_dict()["evidence"]) == 512


# ===========================================================================
# PersistenceReport
# ===========================================================================

class TestPersistenceReport:
    def _report(self) -> PersistenceReport:
        f1 = PersistenceFinding("REG-P-001", PersistenceSeverity.HIGH, "t", "d", risk_score=0) if False else \
             PersistenceFinding("REG-P-001", PersistenceSeverity.HIGH, "t", "d")
        f2 = PersistenceFinding("REG-P-005", PersistenceSeverity.CRITICAL, "t", "d")
        return PersistenceReport(findings=[f1, f2], risk_score=65)

    def test_total_findings(self):
        assert self._report().total_findings == 2

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings(self):
        assert len(self._report().high_findings) == 1

    def test_findings_by_check(self):
        assert len(self._report().findings_by_check("REG-P-001")) == 1

    def test_summary_contains_risk_score(self):
        assert "65" in self._report().summary()

    def test_to_dict_keys(self):
        d = self._report().to_dict()
        for k in ("total_findings", "risk_score", "critical", "high",
                  "generated_at", "findings"):
            assert k in d

    def test_empty_report(self):
        r = PersistenceReport()
        assert r.total_findings == 0
        assert r.risk_score == 0


# ===========================================================================
# REG-P-001: Run keys
# ===========================================================================

class TestREGP001:
    def test_fires_for_temp_path(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKCU", "name": "Evil", "value": r"C:\Temp\evil.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-001" in _check_ids(r)

    def test_fires_for_appdata_path(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKCU", "name": "Persist", "value": r"C:\Users\bob\AppData\Local\evil.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-001" in _check_ids(r)

    def test_not_fired_for_program_files(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKLM", "name": "Legit", "value": r"C:\Program Files\MyApp\myapp.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-001" not in _check_ids(r)

    def test_flag_all_run_keys_fires_for_any(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKLM", "name": "Legit", "value": r"C:\Windows\System32\legit.exe"},
        ])
        r = _detector(flag_all_run_keys=True).analyze(snap)
        assert "REG-P-001" in _check_ids(r)

    def test_severity_high_for_suspicious_path(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKCU", "name": "E", "value": r"C:\Temp\bad.exe"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-001")
        assert f.severity == PersistenceSeverity.HIGH

    def test_hive_and_name_captured(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKCU", "name": "MyEntry", "value": r"C:\Temp\x.exe"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-001")
        assert f.hive == "HKCU"
        assert f.key_name == "MyEntry"

    def test_multiple_entries_multiple_findings(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKCU", "name": "A", "value": r"C:\Temp\a.exe"},
            {"hive": "HKCU", "name": "B", "value": r"C:\Temp\b.exe"},
        ])
        r = _detector().analyze(snap)
        assert len(r.findings_by_check("REG-P-001")) == 2


# ===========================================================================
# REG-P-002: RunServices keys
# ===========================================================================

class TestREGP002:
    def test_fires_for_appdata(self):
        snap = RegistrySnapshot(run_services=[
            {"hive": "HKCU", "name": "SvcBad", "value": r"C:\Users\bob\AppData\evil.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-002" in _check_ids(r)

    def test_not_fired_for_system32(self):
        snap = RegistrySnapshot(run_services=[
            {"hive": "HKLM", "name": "SafeSvc", "value": r"C:\Windows\System32\svchost.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-002" not in _check_ids(r)


# ===========================================================================
# REG-P-003: Startup folder files
# ===========================================================================

class TestREGP003:
    def test_fires_for_any_startup_file(self):
        snap = RegistrySnapshot(startup_files=[
            {"path": r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk",
             "username": "bob"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-003" in _check_ids(r)

    def test_severity_is_medium(self):
        snap = RegistrySnapshot(startup_files=[
            {"path": r"C:\ProgramData\startup\app.lnk", "username": ""},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-003")
        assert f.severity == PersistenceSeverity.MEDIUM

    def test_username_captured_in_key_name(self):
        snap = RegistrySnapshot(startup_files=[
            {"path": r"C:\Users\alice\startup\app.lnk", "username": "alice"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-003")
        assert f.key_name == "alice"

    def test_empty_startup_no_findings(self):
        snap = RegistrySnapshot(startup_files=[])
        r = _detector().analyze(snap)
        assert "REG-P-003" not in _check_ids(r)


# ===========================================================================
# REG-P-004: Suspicious service paths
# ===========================================================================

class TestREGP004:
    def test_fires_for_temp_image_path(self):
        snap = RegistrySnapshot(services=[
            {"name": "EvilSvc", "image_path": r"C:\Temp\malware.exe", "start_type": "auto"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-004" in _check_ids(r)

    def test_fires_for_appdata_image_path(self):
        snap = RegistrySnapshot(services=[
            {"name": "PersistSvc", "image_path": r"C:\Users\bob\AppData\Local\svc.exe", "start_type": "auto"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-004" in _check_ids(r)

    def test_not_fired_for_system32_service(self):
        snap = RegistrySnapshot(services=[
            {"name": "Spooler", "image_path": r"C:\Windows\System32\spoolsv.exe", "start_type": "auto"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-004" not in _check_ids(r)

    def test_severity_is_critical_for_suspicious_path(self):
        snap = RegistrySnapshot(services=[
            {"name": "Bad", "image_path": r"C:\Temp\bad.exe", "start_type": "auto"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-004")
        assert f.severity == PersistenceSeverity.CRITICAL

    def test_flag_all_services_fires_for_any(self):
        snap = RegistrySnapshot(services=[
            {"name": "Svc", "image_path": r"C:\Windows\System32\svc.exe", "start_type": "auto"},
        ])
        r = _detector(flag_all_services=True).analyze(snap)
        assert "REG-P-004" in _check_ids(r)


# ===========================================================================
# REG-P-005: IFEO debugger hijack
# ===========================================================================

class TestREGP005:
    def test_fires_for_any_ifeo_entry(self):
        snap = RegistrySnapshot(ifeo_entries=[
            {"image": "taskmgr.exe", "debugger": r"C:\evil\backdoor.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-005" in _check_ids(r)

    def test_severity_is_critical(self):
        snap = RegistrySnapshot(ifeo_entries=[
            {"image": "notepad.exe", "debugger": r"C:\Temp\inject.exe"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-005")
        assert f.severity == PersistenceSeverity.CRITICAL

    def test_key_name_is_target_image(self):
        snap = RegistrySnapshot(ifeo_entries=[
            {"image": "calc.exe", "debugger": r"C:\evil.exe"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-005")
        assert f.key_name == "calc.exe"

    def test_evidence_is_debugger_path(self):
        snap = RegistrySnapshot(ifeo_entries=[
            {"image": "regedit.exe", "debugger": r"C:\bad.exe"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-005")
        assert f.evidence == r"C:\bad.exe"


# ===========================================================================
# REG-P-006: AppInit_DLLs
# ===========================================================================

class TestREGP006:
    def test_fires_for_populated_appinit(self):
        snap = RegistrySnapshot(appinit_dlls=[
            {"hive": "HKLM", "value": r"C:\evil\inject.dll"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-006" in _check_ids(r)

    def test_not_fired_for_empty_value(self):
        snap = RegistrySnapshot(appinit_dlls=[
            {"hive": "HKLM", "value": ""},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-006" not in _check_ids(r)

    def test_severity_is_high(self):
        snap = RegistrySnapshot(appinit_dlls=[
            {"hive": "HKLM", "value": "bad.dll"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-006")
        assert f.severity == PersistenceSeverity.HIGH

    def test_hive_captured(self):
        snap = RegistrySnapshot(appinit_dlls=[
            {"hive": "HKLM", "value": "evil.dll"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-006")
        assert f.hive == "HKLM"


# ===========================================================================
# REG-P-007: Winlogon hijack
# ===========================================================================

class TestREGP007:
    def test_fires_for_modified_userinit(self):
        snap = RegistrySnapshot(winlogon_entries=[
            {"key": "userinit", "value": r"C:\Windows\system32\userinit.exe,C:\evil.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-007" in _check_ids(r)

    def test_fires_for_modified_shell(self):
        snap = RegistrySnapshot(winlogon_entries=[
            {"key": "shell", "value": "explorer.exe,evil.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-007" in _check_ids(r)

    def test_not_fired_for_safe_userinit(self):
        snap = RegistrySnapshot(winlogon_entries=[
            {"key": "userinit", "value": r"C:\Windows\system32\userinit.exe,"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-007" not in _check_ids(r)

    def test_not_fired_for_safe_shell(self):
        snap = RegistrySnapshot(winlogon_entries=[
            {"key": "shell", "value": "explorer.exe"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-007" not in _check_ids(r)

    def test_ignores_unknown_key(self):
        snap = RegistrySnapshot(winlogon_entries=[
            {"key": "someunknownkey", "value": "whatever"},
        ])
        r = _detector().analyze(snap)
        assert "REG-P-007" not in _check_ids(r)

    def test_severity_is_critical(self):
        snap = RegistrySnapshot(winlogon_entries=[
            {"key": "shell", "value": "evil.exe"},
        ])
        r = _detector().analyze(snap)
        f = next(f for f in r.findings if f.check_id == "REG-P-007")
        assert f.severity == PersistenceSeverity.CRITICAL


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_snapshot_zero_score(self):
        r = _detector().analyze(RegistrySnapshot())
        assert r.risk_score == 0

    def test_ifeo_alone_gives_score_40(self):
        snap = RegistrySnapshot(ifeo_entries=[
            {"image": "notepad.exe", "debugger": "evil.exe"},
        ])
        r = _detector().analyze(snap)
        assert r.risk_score == 40  # REG-P-005 weight

    def test_score_capped_at_100(self):
        snap = RegistrySnapshot(
            run_keys=[{"hive": "HKCU", "name": "A", "value": r"C:\Temp\a.exe"}],
            startup_files=[{"path": r"C:\startup\evil.lnk", "username": "bob"}],
            services=[{"name": "S", "image_path": r"C:\Temp\s.exe", "start_type": "auto"}],
            ifeo_entries=[{"image": "regedit.exe", "debugger": "evil.exe"}],
            appinit_dlls=[{"hive": "HKLM", "value": "bad.dll"}],
            winlogon_entries=[{"key": "shell", "value": "evil.exe"}],
        )
        r = _detector().analyze(snap)
        assert r.risk_score <= 100

    def test_multiple_findings_same_check_count_once_in_score(self):
        snap = RegistrySnapshot(run_keys=[
            {"hive": "HKCU", "name": "A", "value": r"C:\Temp\a.exe"},
            {"hive": "HKCU", "name": "B", "value": r"C:\Temp\b.exe"},
        ])
        r = _detector().analyze(snap)
        # Two findings, but same check_id REG-P-001 → weight counted once = 25
        assert r.risk_score == 25


# ===========================================================================
# Empty snapshot
# ===========================================================================

class TestEmptySnapshot:
    def test_empty_snapshot_no_findings(self):
        r = _detector().analyze(RegistrySnapshot())
        assert r.total_findings == 0

    def test_empty_snapshot_zero_score(self):
        r = _detector().analyze(RegistrySnapshot())
        assert r.risk_score == 0
