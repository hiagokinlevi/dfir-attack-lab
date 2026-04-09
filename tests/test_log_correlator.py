"""
Tests for analysis/log_correlator.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.log_correlator import (
    CorrelatedIncident,
    CorrelationPattern,
    CorrelationReport,
    CorrelationSeverity,
    LogCorrelator,
    NormalizedEvent,
    _infer_event_type,
    _normalize,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _ts(offset_seconds: float = 0) -> str:
    base = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat()


def _auth_fail(ip: str, ts_offset: float = 0, username: str = "root") -> dict:
    return {
        "event_type": "auth_fail",
        "source_ip": ip,
        "username": username,
        "timestamp": _ts(ts_offset),
    }


def _auth_success(ip: str, ts_offset: float = 0, username: str = "root") -> dict:
    return {
        "event_type": "auth_success",
        "source_ip": ip,
        "username": username,
        "timestamp": _ts(ts_offset),
    }


def _sudo(username: str, ts_offset: float = 0) -> dict:
    return {
        "event_type": "sudo",
        "username": username,
        "timestamp": _ts(ts_offset),
    }


def _user_add(username: str, ts_offset: float = 0, source_ip: str = "") -> dict:
    e = {
        "event_type": "user_add",
        "username": username,
        "timestamp": _ts(ts_offset),
    }
    if source_ip:
        e["source_ip"] = source_ip
    return e


def _net_scan(ip: str, ts_offset: float = 0) -> dict:
    return {
        "event_type": "net_scan",
        "source_ip": ip,
        "timestamp": _ts(ts_offset),
    }


def _exploit(ip: str, ts_offset: float = 0) -> dict:
    return {
        "event_type": "exploit",
        "source_ip": ip,
        "timestamp": _ts(ts_offset),
    }


# ===========================================================================
# _infer_event_type
# ===========================================================================

class TestInferEventType:
    def test_explicit_auth_fail(self):
        assert _infer_event_type({"event_type": "auth_fail"}) == "auth_fail"

    def test_explicit_auth_success(self):
        assert _infer_event_type({"event_type": "auth_success"}) == "auth_success"

    def test_keyword_failed_password(self):
        assert _infer_event_type({"message": "Failed password for root"}) == "auth_fail"

    def test_keyword_accepted_password(self):
        assert _infer_event_type({"message": "Accepted password for admin"}) == "auth_success"

    def test_keyword_sudo(self):
        assert _infer_event_type({"message": "sudo: user used sudo"}) == "sudo"

    def test_keyword_net_scan(self):
        assert _infer_event_type({"message": "nmap scan detected"}) == "net_scan"

    def test_unknown(self):
        assert _infer_event_type({"message": "nothing special here"}) == "unknown"

    def test_windows_logon_event_id(self):
        assert _infer_event_type({"event_type": "4624"}) == "auth_success"

    def test_windows_logon_failure_event_id(self):
        assert _infer_event_type({"event_type": "4625"}) == "auth_fail"


# ===========================================================================
# _normalize
# ===========================================================================

class TestNormalize:
    def test_source_preserved(self):
        e = _normalize({"event_type": "auth_fail", "source_ip": "1.2.3.4"}, "auth.log")
        assert e.source == "auth.log"

    def test_event_type_set(self):
        e = _normalize({"event_type": "auth_success"}, "evtx")
        assert e.event_type == "auth_success"

    def test_username_extracted(self):
        e = _normalize({"event_type": "auth_fail", "username": "admin"}, "s")
        assert e.username == "admin"

    def test_source_ip_extracted(self):
        e = _normalize({"event_type": "auth_fail", "source_ip": "10.0.0.1"}, "s")
        assert e.source_ip == "10.0.0.1"


# ===========================================================================
# NormalizedEvent / CorrelatedIncident
# ===========================================================================

class TestCorrelatedIncident:
    def test_event_count(self):
        # We can't easily build NormalizedEvents without going through _normalize,
        # but we can test the property via incident with zero events
        incident = CorrelatedIncident(
            incident_id="INC-001",
            pattern=CorrelationPattern.BRUTE_THEN_SUCCESS,
            severity=CorrelationSeverity.CRITICAL,
            confidence=0.9,
        )
        assert incident.event_count == 0

    def test_to_dict_has_required_keys(self):
        incident = CorrelatedIncident(
            incident_id="INC-001",
            pattern=CorrelationPattern.BRUTE_THEN_SUCCESS,
            severity=CorrelationSeverity.HIGH,
            confidence=0.8,
            description="test",
        )
        d = incident.to_dict()
        for key in ("incident_id", "pattern", "severity", "confidence", "description"):
            assert key in d

    def test_summary_contains_pattern(self):
        incident = CorrelatedIncident(
            incident_id="INC-001",
            pattern=CorrelationPattern.PERSISTENCE,
            severity=CorrelationSeverity.HIGH,
            confidence=0.75,
        )
        assert "PERSISTENCE" in incident.summary()


# ===========================================================================
# LogCorrelator — basic
# ===========================================================================

class TestLogCorrelatorBasic:
    def test_add_event_increments_count(self):
        c = LogCorrelator()
        c.add_event(_auth_fail("1.2.3.4"), "auth.log")
        assert c.event_count == 1

    def test_add_events_batch(self):
        c = LogCorrelator()
        count = c.add_events([_auth_fail("1.2.3.4"), _auth_success("1.2.3.4")], "auth.log")
        assert count == 2

    def test_clear_resets(self):
        c = LogCorrelator()
        c.add_event(_auth_fail("1.2.3.4"), "auth.log")
        c.clear()
        assert c.event_count == 0

    def test_empty_correlate_returns_report(self):
        c = LogCorrelator()
        report = c.correlate()
        assert isinstance(report, CorrelationReport)
        assert report.incident_count == 0

    def test_report_total_events(self):
        c = LogCorrelator()
        c.add_events([_auth_fail("1.2.3.4")] * 3, "auth.log")
        report = c.correlate()
        assert report.total_events == 3


# ===========================================================================
# Brute-then-success detection
# ===========================================================================

class TestBruteThenSuccess:
    def _build(self, fail_count: int, success_offset: float = 30.0) -> LogCorrelator:
        c = LogCorrelator(window_seconds=600)
        for i in range(fail_count):
            c.add_event(_auth_fail("1.2.3.4", ts_offset=i * 5), "auth.log")
        c.add_event(_auth_success("1.2.3.4", ts_offset=success_offset + fail_count * 5), "auth.log")
        return c

    def test_detects_brute_then_success(self):
        c = self._build(fail_count=10)
        report = c.correlate()
        assert any(i.pattern == CorrelationPattern.BRUTE_THEN_SUCCESS for i in report.incidents)

    def test_not_detected_below_threshold(self):
        c = self._build(fail_count=2)
        report = c.correlate()
        bts = [i for i in report.incidents if i.pattern == CorrelationPattern.BRUTE_THEN_SUCCESS]
        assert len(bts) == 0

    def test_incident_is_critical(self):
        c = self._build(fail_count=10)
        report = c.correlate()
        inc = next(i for i in report.incidents if i.pattern == CorrelationPattern.BRUTE_THEN_SUCCESS)
        assert inc.severity == CorrelationSeverity.CRITICAL

    def test_source_ip_in_incident(self):
        c = self._build(fail_count=10)
        report = c.correlate()
        inc = next(i for i in report.incidents if i.pattern == CorrelationPattern.BRUTE_THEN_SUCCESS)
        assert inc.source_ip == "1.2.3.4"

    def test_no_detection_without_success(self):
        c = LogCorrelator()
        for i in range(10):
            c.add_event(_auth_fail("1.2.3.4", ts_offset=i * 5), "auth.log")
        report = c.correlate()
        assert not any(i.pattern == CorrelationPattern.BRUTE_THEN_SUCCESS for i in report.incidents)

    def test_different_ips_not_correlated(self):
        c = LogCorrelator(window_seconds=600)
        for i in range(10):
            c.add_event(_auth_fail("1.1.1.1", ts_offset=i * 5), "auth.log")
        c.add_event(_auth_success("2.2.2.2", ts_offset=100), "auth.log")
        report = c.correlate()
        assert not any(i.pattern == CorrelationPattern.BRUTE_THEN_SUCCESS for i in report.incidents)


# ===========================================================================
# Spray-then-pivot detection
# ===========================================================================

class TestSprayThenPivot:
    def test_detects_spray_then_pivot(self):
        c = LogCorrelator(window_seconds=600)
        for i in range(10):
            c.add_event(_auth_fail("3.3.3.3", ts_offset=i * 5, username=f"user{i}"), "auth.log")
        c.add_event(_auth_success("3.3.3.3", ts_offset=100, username="admin"), "auth.log")
        report = c.correlate()
        assert any(i.pattern == CorrelationPattern.SPRAY_THEN_PIVOT for i in report.incidents)

    def test_not_detected_few_usernames(self):
        c = LogCorrelator(window_seconds=600)
        for i in range(3):
            c.add_event(_auth_fail("3.3.3.3", ts_offset=i * 5, username=f"u{i}"), "auth.log")
        c.add_event(_auth_success("3.3.3.3", ts_offset=50), "auth.log")
        report = c.correlate()
        spray = [i for i in report.incidents if i.pattern == CorrelationPattern.SPRAY_THEN_PIVOT]
        assert len(spray) == 0


# ===========================================================================
# Privilege escalation detection
# ===========================================================================

class TestPrivilegeEscalation:
    def test_detects_escalation(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_auth_success("4.4.4.4", ts_offset=0, username="alice"), "auth.log")
        c.add_event(_sudo("alice", ts_offset=30), "auth.log")
        report = c.correlate()
        assert any(i.pattern == CorrelationPattern.PRIVILEGE_ESCALATION for i in report.incidents)

    def test_not_detected_different_users(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_auth_success("4.4.4.4", ts_offset=0, username="alice"), "auth.log")
        c.add_event(_sudo("bob", ts_offset=30), "auth.log")
        report = c.correlate()
        priv = [i for i in report.incidents if i.pattern == CorrelationPattern.PRIVILEGE_ESCALATION]
        assert len(priv) == 0


# ===========================================================================
# Persistence detection
# ===========================================================================

class TestPersistenceDetection:
    def test_detects_user_add_after_auth(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_auth_success("5.5.5.5", ts_offset=0, username="attacker"), "auth.log")
        c.add_event(_user_add("newuser", ts_offset=20, source_ip="5.5.5.5"), "auth.log")
        report = c.correlate()
        assert any(i.pattern == CorrelationPattern.PERSISTENCE for i in report.incidents)

    def test_not_detected_outside_window(self):
        c = LogCorrelator(window_seconds=60)
        c.add_event(_auth_success("5.5.5.5", ts_offset=0), "auth.log")
        c.add_event(_user_add("newuser", ts_offset=200, source_ip="5.5.5.5"), "auth.log")
        report = c.correlate()
        pers = [i for i in report.incidents if i.pattern == CorrelationPattern.PERSISTENCE]
        assert len(pers) == 0


# ===========================================================================
# Recon-then-exploit detection
# ===========================================================================

class TestReconThenExploit:
    def test_detects_scan_then_exploit(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_net_scan("6.6.6.6", ts_offset=0), "ids")
        c.add_event(_exploit("6.6.6.6", ts_offset=120), "waf")
        report = c.correlate()
        assert any(i.pattern == CorrelationPattern.RECON_THEN_EXPLOIT for i in report.incidents)

    def test_not_detected_different_ips(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_net_scan("6.6.6.6", ts_offset=0), "ids")
        c.add_event(_exploit("7.7.7.7", ts_offset=60), "waf")
        report = c.correlate()
        recon = [i for i in report.incidents if i.pattern == CorrelationPattern.RECON_THEN_EXPLOIT]
        assert len(recon) == 0

    def test_incident_severity_critical(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_net_scan("8.8.8.8", ts_offset=0), "ids")
        c.add_event(_exploit("8.8.8.8", ts_offset=30), "waf")
        report = c.correlate()
        inc = next(i for i in report.incidents if i.pattern == CorrelationPattern.RECON_THEN_EXPLOIT)
        assert inc.severity == CorrelationSeverity.CRITICAL


# ===========================================================================
# Anomalous time detection
# ===========================================================================

class TestAnomalousTime:
    def test_off_hours_login_flagged(self):
        c = LogCorrelator(working_hours=(9, 17))
        # 3 AM UTC
        ts = datetime(2026, 4, 1, 3, 0, 0, tzinfo=timezone.utc).isoformat()
        c.add_event({"event_type": "auth_success", "timestamp": ts, "username": "alice"}, "auth.log")
        report = c.correlate()
        assert any(i.pattern == CorrelationPattern.ANOMALOUS_TIME for i in report.incidents)

    def test_working_hours_not_flagged(self):
        c = LogCorrelator(working_hours=(9, 17))
        # 10 AM UTC
        ts = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc).isoformat()
        c.add_event({"event_type": "auth_success", "timestamp": ts, "username": "alice"}, "auth.log")
        report = c.correlate()
        anom = [i for i in report.incidents if i.pattern == CorrelationPattern.ANOMALOUS_TIME]
        assert len(anom) == 0

    def test_anomalous_time_medium_severity(self):
        c = LogCorrelator(working_hours=(9, 17))
        ts = datetime(2026, 4, 1, 2, 0, 0, tzinfo=timezone.utc).isoformat()
        c.add_event({"event_type": "auth_success", "timestamp": ts}, "auth.log")
        report = c.correlate()
        inc = next(i for i in report.incidents if i.pattern == CorrelationPattern.ANOMALOUS_TIME)
        assert inc.severity == CorrelationSeverity.MEDIUM


# ===========================================================================
# CorrelationReport aggregation
# ===========================================================================

class TestCorrelationReport:
    def test_by_pattern_filter(self):
        c = LogCorrelator(window_seconds=600)
        for i in range(10):
            c.add_event(_auth_fail("1.1.1.1", ts_offset=i * 5), "auth.log")
        c.add_event(_auth_success("1.1.1.1", ts_offset=100), "auth.log")
        report = c.correlate()
        bts = report.by_pattern(CorrelationPattern.BRUTE_THEN_SUCCESS)
        assert len(bts) >= 1

    def test_by_ip_filter(self):
        c = LogCorrelator(window_seconds=600)
        for i in range(10):
            c.add_event(_auth_fail("9.9.9.9", ts_offset=i * 5), "auth.log")
        c.add_event(_auth_success("9.9.9.9", ts_offset=80), "auth.log")
        report = c.correlate()
        incidents_for_ip = report.by_ip("9.9.9.9")
        assert all(i.source_ip == "9.9.9.9" for i in incidents_for_ip)

    def test_critical_count(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_net_scan("99.99.99.99", ts_offset=0), "ids")
        c.add_event(_exploit("99.99.99.99", ts_offset=10), "waf")
        report = c.correlate()
        assert report.critical_count >= 1

    def test_sources_populated(self):
        c = LogCorrelator()
        c.add_event(_auth_fail("1.2.3.4"), "auth.log")
        c.add_event(_exploit("1.2.3.4"), "waf")
        report = c.correlate()
        assert "auth.log" in report.sources
        assert "waf" in report.sources

    def test_multi_source_incident(self):
        c = LogCorrelator(window_seconds=600)
        c.add_event(_net_scan("11.11.11.11", ts_offset=0), "ids")
        c.add_event(_exploit("11.11.11.11", ts_offset=60), "waf")
        report = c.correlate()
        inc = next(
            (i for i in report.incidents if i.pattern == CorrelationPattern.RECON_THEN_EXPLOIT), None
        )
        assert inc is not None
        assert len(inc.sources) >= 1  # sources from the contributing events
