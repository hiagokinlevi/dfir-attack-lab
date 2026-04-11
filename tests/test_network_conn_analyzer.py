"""
Tests for analyzers.network_conn_analyzer
==========================================
Covers all seven check IDs (NC-001 through NC-007), report structure
helpers, internal utility functions, and a broad set of clean-data
(no-fire) cases.

Run with::

    pytest tests/test_network_conn_analyzer.py -v
"""
from __future__ import annotations

import math
import sys
import os

# Allow running from the repo root without an editable install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from analyzers.network_conn_analyzer import (
    ConnectionRecord,
    NetConnFinding,
    NetConnReport,
    NetConnSeverity,
    NetworkConnectionAnalyzer,
    _CHECK_WEIGHTS,
    _is_internal_address,
    _normalize_ip_literal,
    _is_rfc1918,
    _shannon_entropy,
    _conn_evidence,
    _SUSPICIOUS_PORTS,
    _MINING_PORTS,
    _TOR_PORTS,
    _LATERAL_MOVEMENT_PORTS,
)


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

def make_record(
    pid: int = 1000,
    process_name: str = "python3",
    local_addr: str = "192.168.1.50",
    local_port: int = 50000,
    remote_addr: str = "8.8.8.8",
    remote_port: int = 443,
    state: str = "ESTABLISHED",
    protocol: str = "TCP",
    hostname: str = "",
) -> ConnectionRecord:
    """Return a ConnectionRecord with sane defaults."""
    return ConnectionRecord(
        pid=pid,
        process_name=process_name,
        local_addr=local_addr,
        local_port=local_port,
        remote_addr=remote_addr,
        remote_port=remote_port,
        state=state,
        protocol=protocol,
        hostname=hostname,
    )


def analyzer() -> NetworkConnectionAnalyzer:
    """Return a default NetworkConnectionAnalyzer instance."""
    return NetworkConnectionAnalyzer()


# ---------------------------------------------------------------------------
# Section 1 — ConnectionRecord dataclass defaults
# ---------------------------------------------------------------------------

class TestConnectionRecordDefaults:
    def test_state_default(self):
        rec = ConnectionRecord(
            pid=1, process_name="x", local_addr="127.0.0.1",
            local_port=1, remote_addr="1.2.3.4", remote_port=80,
        )
        assert rec.state == "ESTABLISHED"

    def test_protocol_default(self):
        rec = ConnectionRecord(
            pid=1, process_name="x", local_addr="127.0.0.1",
            local_port=1, remote_addr="1.2.3.4", remote_port=80,
        )
        assert rec.protocol == "TCP"

    def test_hostname_default(self):
        rec = ConnectionRecord(
            pid=1, process_name="x", local_addr="127.0.0.1",
            local_port=1, remote_addr="1.2.3.4", remote_port=80,
        )
        assert rec.hostname == ""

    def test_explicit_values_preserved(self):
        rec = make_record(pid=9999, process_name="nc", remote_port=4444, state="SYN_SENT")
        assert rec.pid == 9999
        assert rec.process_name == "nc"
        assert rec.remote_port == 4444
        assert rec.state == "SYN_SENT"


# ---------------------------------------------------------------------------
# Section 2 — NetConnFinding helpers
# ---------------------------------------------------------------------------

class TestNetConnFinding:
    def _sample(self) -> NetConnFinding:
        return NetConnFinding(
            check_id="NC-001",
            severity=NetConnSeverity.HIGH,
            pid=123,
            process_name="nc",
            title="Test title",
            detail="Test detail",
            evidence="evidence string",
            remediation="do something",
        )

    def test_to_dict_keys(self):
        d = self._sample().to_dict()
        for key in ("check_id", "severity", "pid", "process_name", "title", "detail", "evidence", "remediation"):
            assert key in d

    def test_to_dict_severity_is_string(self):
        d = self._sample().to_dict()
        assert isinstance(d["severity"], str)
        assert d["severity"] == "HIGH"

    def test_summary_contains_check_id(self):
        s = self._sample().summary()
        assert "NC-001" in s

    def test_summary_contains_pid(self):
        s = self._sample().summary()
        assert "123" in s

    def test_summary_contains_process_name(self):
        s = self._sample().summary()
        assert "nc" in s

    def test_evidence_default_empty(self):
        f = NetConnFinding(
            check_id="NC-001", severity=NetConnSeverity.LOW,
            pid=0, process_name="x", title="t", detail="d",
        )
        assert f.evidence == ""

    def test_remediation_default_empty(self):
        f = NetConnFinding(
            check_id="NC-001", severity=NetConnSeverity.LOW,
            pid=0, process_name="x", title="t", detail="d",
        )
        assert f.remediation == ""


# ---------------------------------------------------------------------------
# Section 3 — _is_rfc1918 helper
# ---------------------------------------------------------------------------

class TestIsRfc1918:
    def test_10_block(self):
        assert _is_rfc1918("10.0.0.1") is True

    def test_10_block_high(self):
        assert _is_rfc1918("10.255.255.255") is True

    def test_192_168_block(self):
        assert _is_rfc1918("192.168.1.100") is True

    def test_192_168_zero(self):
        assert _is_rfc1918("192.168.0.1") is True

    def test_172_16(self):
        assert _is_rfc1918("172.16.0.1") is True

    def test_172_31(self):
        assert _is_rfc1918("172.31.255.254") is True

    def test_172_20(self):
        assert _is_rfc1918("172.20.10.5") is True

    def test_172_15_not_private(self):
        assert _is_rfc1918("172.15.0.1") is False

    def test_172_32_not_private(self):
        assert _is_rfc1918("172.32.0.1") is False

    def test_public_ip(self):
        assert _is_rfc1918("8.8.8.8") is False

    def test_loopback_not_rfc1918(self):
        assert _is_rfc1918("127.0.0.1") is False

    def test_empty_string(self):
        assert _is_rfc1918("") is False


# ---------------------------------------------------------------------------
# Section 4 — _is_internal_address helper
# ---------------------------------------------------------------------------

class TestIsInternalAddress:
    def test_rfc1918_ipv4(self):
        assert _is_internal_address("10.42.0.8") is True

    def test_ipv6_ula(self):
        assert _is_internal_address("fd12:3456:789a::5") is True

    def test_ipv6_link_local(self):
        assert _is_internal_address("fe80::1234") is True

    def test_ipv4_mapped_private_ipv6(self):
        assert _is_internal_address("::ffff:192.168.1.25") is True

    def test_public_ipv6(self):
        assert _is_internal_address("2001:4860:4860::8888") is False

    def test_ipv6_loopback_not_internal(self):
        assert _is_internal_address("::1") is False

    def test_invalid_address(self):
        assert _is_internal_address("not-an-ip") is False


# ---------------------------------------------------------------------------
# Section 4b — _normalize_ip_literal helper
# ---------------------------------------------------------------------------

class TestNormalizeIpLiteral:
    def test_strips_ipv6_brackets(self):
        assert _normalize_ip_literal("[fe80::1234%en0]") == "fe80::1234%en0"

    def test_strips_whitespace(self):
        assert _normalize_ip_literal(" 10.0.0.5 ") == "10.0.0.5"


# ---------------------------------------------------------------------------
# Section 5 — _shannon_entropy helper
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_zero(self):
        assert _shannon_entropy("aaaaaaa") == pytest.approx(0.0, abs=1e-9)

    def test_two_equal_chars_is_one_bit(self):
        assert _shannon_entropy("ab") == pytest.approx(1.0, abs=1e-9)

    def test_high_entropy_hostname(self):
        hostname = "aGVsbG8gd29ybGQ.randombase64stuff.c2.example.com"
        assert _shannon_entropy(hostname) > 3.5

    def test_low_entropy_normal_hostname(self):
        # "google.com" has low entropy — should stay below threshold.
        assert _shannon_entropy("google.com") < 3.5


# ---------------------------------------------------------------------------
# Section 5 — NC-001: suspicious port
# ---------------------------------------------------------------------------

class TestNC001:
    def test_fires_for_4444(self):
        rec = make_record(remote_port=4444)
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-001" for f in report.findings)

    def test_fires_for_31337(self):
        rec = make_record(remote_port=31337)
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-001" for f in report.findings)

    def test_fires_for_1337(self):
        rec = make_record(remote_port=1337)
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-001" for f in report.findings)

    def test_fires_for_9001(self):
        # 9001 is both suspicious and a Tor port — both NC-001 and NC-005 fire
        rec = make_record(remote_port=9001, remote_addr="5.5.5.5")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-001" for f in report.findings)

    def test_severity_is_high(self):
        rec = make_record(remote_port=6666)
        report = analyzer().analyze([rec])
        nc001 = [f for f in report.findings if f.check_id == "NC-001"]
        assert nc001[0].severity == NetConnSeverity.HIGH

    def test_does_not_fire_for_443(self):
        rec = make_record(remote_port=443)
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-001" for f in report.findings)

    def test_does_not_fire_for_80(self):
        rec = make_record(remote_port=80)
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-001" for f in report.findings)

    def test_finding_contains_port_in_title(self):
        rec = make_record(remote_port=5554)
        report = analyzer().analyze([rec])
        nc001 = [f for f in report.findings if f.check_id == "NC-001"][0]
        assert "5554" in nc001.title


# ---------------------------------------------------------------------------
# Section 6 — NC-002: excessive outbound connections
# ---------------------------------------------------------------------------

class TestNC002:
    def _make_flood(self, count: int, process_name: str = "scanner") -> list:
        return [
            make_record(
                pid=2000,
                process_name=process_name,
                remote_addr=f"1.2.3.{i % 254 + 1}",
                remote_port=80,
                state="ESTABLISHED",
            )
            for i in range(count)
        ]

    def test_fires_above_threshold(self):
        records = self._make_flood(25)
        report = analyzer().analyze(records)
        assert any(f.check_id == "NC-002" for f in report.findings)

    def test_does_not_fire_at_threshold(self):
        # Exactly at threshold (20) should NOT fire.
        records = self._make_flood(20)
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-002" for f in report.findings)

    def test_does_not_fire_below_threshold(self):
        records = self._make_flood(5)
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-002" for f in report.findings)

    def test_fires_once_per_process(self):
        records = self._make_flood(30, process_name="worm")
        report = analyzer().analyze(records)
        nc002 = [f for f in report.findings if f.check_id == "NC-002"]
        assert len(nc002) == 1

    def test_fires_separately_for_two_processes(self):
        records = self._make_flood(25, "proc_a") + self._make_flood(25, "proc_b")
        report = analyzer().analyze(records)
        nc002 = [f for f in report.findings if f.check_id == "NC-002"]
        processes = {f.process_name for f in nc002}
        assert "proc_a" in processes
        assert "proc_b" in processes

    def test_custom_threshold_respected(self):
        a = NetworkConnectionAnalyzer(excessive_outbound_threshold=5)
        records = self._make_flood(6)
        report = a.analyze(records)
        assert any(f.check_id == "NC-002" for f in report.findings)

    def test_severity_is_high(self):
        records = self._make_flood(25)
        report = analyzer().analyze(records)
        nc002 = [f for f in report.findings if f.check_id == "NC-002"][0]
        assert nc002.severity == NetConnSeverity.HIGH

    def test_same_process_name_different_pids_are_not_merged(self):
        records = [
            make_record(pid=2001, process_name="python3", remote_addr=f"1.2.3.{i + 1}")
            for i in range(11)
        ] + [
            make_record(pid=2002, process_name="python3", remote_addr=f"5.6.7.{i + 1}")
            for i in range(11)
        ]
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-002" for f in report.findings)

    def test_listen_state_not_counted_for_nc002(self):
        # LISTEN state should not count as outbound ESTABLISHED.
        records = [
            make_record(pid=3000, process_name="listener", state="LISTEN", remote_port=0)
            for _ in range(30)
        ]
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-002" for f in report.findings)


# ---------------------------------------------------------------------------
# Section 7 — NC-003: high-entropy hostname (DGA / DNS tunnel)
# ---------------------------------------------------------------------------

class TestNC003:
    # A long hostname with clearly high Shannon entropy.
    _HIGH_ENTROPY_HOST = "aGVsbG8gd29ybGQ.randombase64stuff.c2.example.com"

    def test_fires_for_high_entropy_hostname(self):
        rec = make_record(hostname=self._HIGH_ENTROPY_HOST)
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-003" for f in report.findings)

    def test_does_not_fire_for_normal_hostname(self):
        rec = make_record(hostname="www.google.com")
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-003" for f in report.findings)

    def test_does_not_fire_for_empty_hostname(self):
        rec = make_record(hostname="")
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-003" for f in report.findings)

    def test_does_not_fire_for_short_high_entropy(self):
        # High entropy but length <= 20 — should NOT fire.
        short_host = "aB3xQ7!zR2"  # only 10 chars
        rec = make_record(hostname=short_host)
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-003" for f in report.findings)

    def test_severity_is_high(self):
        rec = make_record(hostname=self._HIGH_ENTROPY_HOST)
        report = analyzer().analyze([rec])
        nc003 = [f for f in report.findings if f.check_id == "NC-003"]
        assert nc003[0].severity == NetConnSeverity.HIGH

    def test_finding_contains_entropy_in_detail(self):
        rec = make_record(hostname=self._HIGH_ENTROPY_HOST)
        report = analyzer().analyze([rec])
        nc003 = [f for f in report.findings if f.check_id == "NC-003"][0]
        assert "entropy" in nc003.detail.lower()


# ---------------------------------------------------------------------------
# Section 8 — NC-004: crypto-mining pool port
# ---------------------------------------------------------------------------

class TestNC004:
    def test_fires_for_3333(self):
        rec = make_record(remote_port=3333, remote_addr="pool.minexmr.com")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-004" for f in report.findings)

    def test_fires_for_14444(self):
        rec = make_record(remote_port=14444)
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-004" for f in report.findings)

    def test_fires_for_45700(self):
        rec = make_record(remote_port=45700)
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-004" for f in report.findings)

    def test_severity_is_critical(self):
        rec = make_record(remote_port=3333)
        report = analyzer().analyze([rec])
        nc004 = [f for f in report.findings if f.check_id == "NC-004"][0]
        assert nc004.severity == NetConnSeverity.CRITICAL

    def test_does_not_fire_for_normal_port(self):
        rec = make_record(remote_port=443)
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-004" for f in report.findings)

    def test_4444_fires_both_nc001_and_nc004(self):
        # Port 4444 is in both _SUSPICIOUS_PORTS and _MINING_PORTS.
        rec = make_record(remote_port=4444)
        report = analyzer().analyze([rec])
        check_ids = {f.check_id for f in report.findings}
        assert "NC-001" in check_ids
        assert "NC-004" in check_ids


# ---------------------------------------------------------------------------
# Section 9 — NC-005: Tor default port
# ---------------------------------------------------------------------------

class TestNC005:
    def test_fires_for_9050(self):
        rec = make_record(remote_port=9050, remote_addr="185.220.101.1")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-005" for f in report.findings)

    def test_fires_for_9001(self):
        rec = make_record(remote_port=9001, remote_addr="185.220.102.1")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-005" for f in report.findings)

    def test_severity_is_critical(self):
        rec = make_record(remote_port=9050)
        report = analyzer().analyze([rec])
        nc005 = [f for f in report.findings if f.check_id == "NC-005"][0]
        assert nc005.severity == NetConnSeverity.CRITICAL

    def test_does_not_fire_for_normal_port(self):
        rec = make_record(remote_port=8080)
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-005" for f in report.findings)

    def test_9001_fires_both_nc001_and_nc005(self):
        rec = make_record(remote_port=9001, remote_addr="5.5.5.5")
        report = analyzer().analyze([rec])
        check_ids = {f.check_id for f in report.findings}
        assert "NC-001" in check_ids
        assert "NC-005" in check_ids


# ---------------------------------------------------------------------------
# Section 10 — NC-006: high LISTEN count per process
# ---------------------------------------------------------------------------

class TestNC006:
    def _make_listeners(self, count: int, process_name: str = "backdoor") -> list:
        return [
            make_record(
                pid=4000,
                process_name=process_name,
                local_port=20000 + i,
                state="LISTEN",
                remote_addr="",
                remote_port=0,
            )
            for i in range(count)
        ]

    def test_fires_above_threshold(self):
        records = self._make_listeners(7)
        report = analyzer().analyze(records)
        assert any(f.check_id == "NC-006" for f in report.findings)

    def test_does_not_fire_at_threshold(self):
        # Exactly 5 LISTEN sockets — should NOT fire.
        records = self._make_listeners(5)
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-006" for f in report.findings)

    def test_does_not_fire_below_threshold(self):
        records = self._make_listeners(3)
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-006" for f in report.findings)

    def test_fires_once_per_process(self):
        records = self._make_listeners(10, "multi_listener")
        report = analyzer().analyze(records)
        nc006 = [f for f in report.findings if f.check_id == "NC-006"]
        assert len(nc006) == 1

    def test_severity_is_medium(self):
        records = self._make_listeners(8)
        report = analyzer().analyze(records)
        nc006 = [f for f in report.findings if f.check_id == "NC-006"][0]
        assert nc006.severity == NetConnSeverity.MEDIUM

    def test_same_process_name_different_pids_are_not_merged(self):
        records = [
            make_record(
                pid=4001,
                process_name="svc",
                local_port=20000 + i,
                state="LISTEN",
                remote_addr="",
                remote_port=0,
            )
            for i in range(3)
        ] + [
            make_record(
                pid=4002,
                process_name="svc",
                local_port=21000 + i,
                state="LISTEN",
                remote_addr="",
                remote_port=0,
            )
            for i in range(3)
        ]
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-006" for f in report.findings)

    def test_established_not_counted_for_nc006(self):
        # ESTABLISHED state should not count toward LISTEN threshold.
        records = [
            make_record(pid=5000, process_name="normalproc", state="ESTABLISHED")
            for _ in range(10)
        ]
        report = analyzer().analyze(records)
        assert not any(f.check_id == "NC-006" for f in report.findings)


# ---------------------------------------------------------------------------
# Section 11 — NC-007: lateral movement
# ---------------------------------------------------------------------------

class TestNC007:
    def test_fires_for_smb_445_internal(self):
        rec = make_record(remote_port=445, remote_addr="10.0.0.20", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_rdp_3389_internal(self):
        rec = make_record(remote_port=3389, remote_addr="192.168.10.5", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_winrm_5985_internal(self):
        rec = make_record(remote_port=5985, remote_addr="172.16.0.10", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_winrm_5986_internal(self):
        rec = make_record(remote_port=5986, remote_addr="10.1.2.3", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_netbios_139_internal(self):
        rec = make_record(remote_port=139, remote_addr="192.168.0.5", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_smb_to_ipv6_ula(self):
        rec = make_record(remote_port=445, remote_addr="fd12:3456:789a::10", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_rdp_to_ipv4_mapped_private_ipv6(self):
        rec = make_record(remote_port=3389, remote_addr="::ffff:10.10.20.30", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_rdp_to_bracketed_ipv6_link_local(self):
        rec = make_record(remote_port=3389, remote_addr="[fe80::1234%en0]", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_fires_for_winrm_to_bracketed_ipv4_mapped_private_ipv6(self):
        rec = make_record(remote_port=5985, remote_addr="[::ffff:192.168.1.25]", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert any(f.check_id == "NC-007" for f in report.findings)

    def test_does_not_fire_for_smb_to_public(self):
        # SMB to a public IP is suspicious but not NC-007 specifically.
        rec = make_record(remote_port=445, remote_addr="8.8.8.8", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-007" for f in report.findings)

    def test_does_not_fire_for_public_ipv6(self):
        rec = make_record(remote_port=445, remote_addr="2001:4860:4860::8888", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-007" for f in report.findings)

    def test_does_not_fire_when_not_established(self):
        # SYN_SENT to internal SMB should not fire NC-007 (not ESTABLISHED).
        rec = make_record(remote_port=445, remote_addr="10.0.0.1", state="SYN_SENT")
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-007" for f in report.findings)

    def test_does_not_fire_when_lateral_movement_disabled(self):
        a = NetworkConnectionAnalyzer(check_lateral_movement=False)
        rec = make_record(remote_port=445, remote_addr="10.0.0.1", state="ESTABLISHED")
        report = a.analyze([rec])
        assert not any(f.check_id == "NC-007" for f in report.findings)

    def test_severity_is_critical(self):
        rec = make_record(remote_port=445, remote_addr="10.0.0.1", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        nc007 = [f for f in report.findings if f.check_id == "NC-007"][0]
        assert nc007.severity == NetConnSeverity.CRITICAL

    def test_does_not_fire_for_normal_internal_port(self):
        # Port 443 on an internal host should not trigger NC-007.
        rec = make_record(remote_port=443, remote_addr="10.0.0.1", state="ESTABLISHED")
        report = analyzer().analyze([rec])
        assert not any(f.check_id == "NC-007" for f in report.findings)


# ---------------------------------------------------------------------------
# Section 12 — NetConnReport structure
# ---------------------------------------------------------------------------

class TestNetConnReport:
    def _report_with_findings(self) -> NetConnReport:
        """Generate a report that fires NC-001, NC-004, NC-005, NC-007."""
        records = [
            make_record(remote_port=31337),                               # NC-001
            make_record(remote_port=3333),                                # NC-004
            make_record(remote_port=9050, remote_addr="1.2.3.4"),         # NC-001 + NC-005
            make_record(remote_port=445, remote_addr="10.0.0.1"),         # NC-007
        ]
        return analyzer().analyze(records)

    def test_connections_analyzed_count(self):
        records = [make_record() for _ in range(10)]
        report = analyzer().analyze(records)
        assert report.connections_analyzed == 10

    def test_total_findings_property(self):
        report = self._report_with_findings()
        assert report.total_findings == len(report.findings)

    def test_critical_findings_property(self):
        report = self._report_with_findings()
        for f in report.critical_findings:
            assert f.severity == NetConnSeverity.CRITICAL

    def test_high_findings_property(self):
        report = self._report_with_findings()
        for f in report.high_findings:
            assert f.severity == NetConnSeverity.HIGH

    def test_findings_by_check(self):
        report = self._report_with_findings()
        nc001_list = report.findings_by_check("NC-001")
        assert all(f.check_id == "NC-001" for f in nc001_list)

    def test_findings_by_check_empty_for_unfired(self):
        # No NC-006 was fired in _report_with_findings.
        report = self._report_with_findings()
        assert report.findings_by_check("NC-006") == []

    def test_findings_for_process(self):
        report = self._report_with_findings()
        for proc_finding in report.findings_for_process("python3"):
            assert proc_finding.process_name == "python3"

    def test_risk_score_bounded_at_100(self):
        # Fire every possible check — risk score must not exceed 100.
        records = [
            make_record(remote_port=31337),                               # NC-001
            make_record(remote_port=3333),                                # NC-004
            make_record(remote_port=9050),                                # NC-005
            make_record(remote_port=445, remote_addr="10.0.0.1"),         # NC-007
            make_record(hostname="aGVsbG8gd29ybGQ.randombase64stuff.c2.example.com"),  # NC-003
        ] + [
            make_record(pid=8000, process_name="flooder",
                        remote_addr=f"4.4.4.{i % 200 + 1}", remote_port=80)
            for i in range(25)                                            # NC-002
        ] + [
            make_record(pid=9000, process_name="backdoor", local_port=30000 + i,
                        state="LISTEN", remote_addr="", remote_port=0)
            for i in range(8)                                             # NC-006
        ]
        report = analyzer().analyze(records)
        assert report.risk_score <= 100
        assert report.risk_score >= 0

    def test_risk_score_zero_on_clean_data(self):
        records = [make_record(remote_port=443), make_record(remote_port=80)]
        report = analyzer().analyze(records)
        assert report.risk_score == 0

    def test_to_dict_has_required_keys(self):
        report = analyzer().analyze([make_record()])
        d = report.to_dict()
        for key in ("risk_score", "connections_analyzed", "total_findings", "generated_at", "findings"):
            assert key in d

    def test_to_dict_findings_is_list(self):
        report = analyzer().analyze([make_record(remote_port=4444)])
        d = report.to_dict()
        assert isinstance(d["findings"], list)

    def test_summary_returns_string(self):
        report = analyzer().analyze([make_record()])
        assert isinstance(report.summary(), str)

    def test_summary_contains_risk_score(self):
        report = analyzer().analyze([make_record()])
        assert "Risk score" in report.summary() or "risk" in report.summary().lower()

    def test_generated_at_is_float(self):
        report = analyzer().analyze([])
        assert isinstance(report.generated_at, float)


# ---------------------------------------------------------------------------
# Section 13 — Empty / edge-case inputs
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_records_list(self):
        report = analyzer().analyze([])
        assert report.total_findings == 0
        assert report.risk_score == 0
        assert report.connections_analyzed == 0

    def test_single_clean_record(self):
        report = analyzer().analyze([make_record(remote_port=443)])
        assert report.total_findings == 0
        assert report.risk_score == 0

    def test_all_seven_checks_can_co_fire(self):
        """Verify every check ID can appear in a single analysis run."""
        records = [
            make_record(remote_port=5554),                                # NC-001
            make_record(remote_port=3333),                                # NC-004
            make_record(remote_port=9050),                                # NC-005
            make_record(remote_port=445, remote_addr="10.0.0.1"),         # NC-007
            make_record(hostname="aGVsbG8gd29ybGQ.randombase64stuff.c2.example.com"),  # NC-003
        ] + [
            make_record(pid=7000, process_name="spammer",
                        remote_addr=f"5.6.7.{i % 200 + 1}", remote_port=25)
            for i in range(25)                                            # NC-002
        ] + [
            make_record(pid=8000, process_name="multilistener",
                        local_port=40000 + i, state="LISTEN", remote_addr="", remote_port=0)
            for i in range(7)                                             # NC-006
        ]
        report = analyzer().analyze(records)
        fired = {f.check_id for f in report.findings}
        for check_id in ("NC-001", "NC-002", "NC-003", "NC-004", "NC-005", "NC-006", "NC-007"):
            assert check_id in fired, f"{check_id} did not fire"

    def test_check_weights_dict_has_all_seven_checks(self):
        for check_id in ("NC-001", "NC-002", "NC-003", "NC-004", "NC-005", "NC-006", "NC-007"):
            assert check_id in _CHECK_WEIGHTS

    def test_udp_record_does_not_crash(self):
        rec = make_record(protocol="UDP", state="ESTABLISHED", remote_port=53)
        report = analyzer().analyze([rec])
        assert isinstance(report, NetConnReport)

    def test_listen_record_with_zero_remote_port_does_not_crash(self):
        rec = make_record(state="LISTEN", remote_addr="", remote_port=0)
        report = analyzer().analyze([rec])
        assert isinstance(report, NetConnReport)

    def test_conn_evidence_format(self):
        rec = make_record(pid=42, process_name="evil", local_addr="10.1.1.1",
                          local_port=54321, remote_addr="8.8.8.8", remote_port=443)
        ev = _conn_evidence(rec)
        assert "10.1.1.1" in ev
        assert "8.8.8.8" in ev
        assert "evil" in ev
        assert "42" in ev
