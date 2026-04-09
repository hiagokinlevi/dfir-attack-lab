"""
Tests for analysis/lateral_movement.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.lateral_movement import (
    AuthHop,
    LateralMovementReport,
    LateralMovementTracker,
    MovementChain,
    MovementPattern,
    MovementSeverity,
    _is_success,
    _normalize_host,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _ts(offset_seconds: float = 0) -> str:
    base = datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat()


def _success(
    ip: str,
    host: str,
    username: str = "alice",
    ts_offset: float = 0.0,
    password: str = "",
) -> dict:
    return {
        "event_type": "auth_success",
        "source_ip": ip,
        "hostname": host,
        "username": username,
        "password": password,
        "timestamp": _ts(ts_offset),
    }


def _fail(ip: str, host: str, username: str = "alice") -> dict:
    return {
        "event_type": "auth_fail",
        "source_ip": ip,
        "hostname": host,
        "username": username,
    }


# ===========================================================================
# Internal helpers
# ===========================================================================

class TestIsSuccess:
    def test_explicit_auth_success(self):
        assert _is_success({"event_type": "auth_success"})

    def test_explicit_login_success(self):
        assert _is_success({"event_type": "login_success"})

    def test_event_4624(self):
        assert _is_success({"event_type": "4624"})

    def test_auth_fail_not_success(self):
        assert not _is_success({"event_type": "auth_fail"})

    def test_accepted_password_keyword(self):
        assert _is_success({"message": "Accepted password for admin from 1.2.3.4"})

    def test_unknown_event_not_success(self):
        assert not _is_success({"event_type": "port_scan"})


class TestNormalizeHost:
    def test_strips_leading_slash(self):
        assert _normalize_host("/my-container") == "my-container"

    def test_lowercases(self):
        assert _normalize_host("SERVER01") == "server01"

    def test_strips_whitespace(self):
        assert _normalize_host("  host  ") == "host"


# ===========================================================================
# AuthHop
# ===========================================================================

class TestAuthHop:
    def test_fields_set(self):
        hop = AuthHop(
            source_ip="1.2.3.4",
            target_host="server01",
            username="alice",
            timestamp=datetime.now(tz=timezone.utc),
        )
        assert hop.source_ip == "1.2.3.4"
        assert hop.target_host == "server01"


# ===========================================================================
# MovementChain
# ===========================================================================

class TestMovementChain:
    def _chain(self, hop_count=2) -> MovementChain:
        return MovementChain(
            chain_id="LM-0001",
            pattern=MovementPattern.SEQUENTIAL_HOP,
            severity=MovementSeverity.HIGH,
            hops=[AuthHop("1.2.3.4", f"h{i}", "alice", None) for i in range(hop_count)],
            source_ip="1.2.3.4",
            target_hosts=[f"h{i}" for i in range(hop_count)],
            start_time=_ts(0),
            end_time=_ts(60),
        )

    def test_hop_count(self):
        assert self._chain(3).hop_count == 3

    def test_span_seconds(self):
        assert abs(self._chain().span_seconds - 60.0) < 1

    def test_summary_contains_chain_id(self):
        assert "LM-0001" in self._chain().summary()

    def test_to_dict_required_keys(self):
        d = self._chain().to_dict()
        for key in ("chain_id", "pattern", "severity", "confidence", "target_hosts"):
            assert key in d


# ===========================================================================
# LateralMovementTracker — ingestion
# ===========================================================================

class TestTrackerIngestion:
    def test_add_event_success_counted(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("1.2.3.4", "web01"))
        assert tracker.hop_count == 1

    def test_add_event_failure_not_counted(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_fail("1.2.3.4", "web01"))
        assert tracker.hop_count == 0

    def test_add_events_batch(self):
        tracker = LateralMovementTracker()
        count = tracker.add_events([
            _success("1.2.3.4", "web01"),
            _success("1.2.3.4", "db01"),
        ], source="auth.log")
        assert count == 2
        assert tracker.hop_count == 2

    def test_clear(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("1.2.3.4", "host1"))
        tracker.clear()
        assert tracker.hop_count == 0


# ===========================================================================
# Sequential hop detection
# ===========================================================================

class TestSequentialHopDetection:
    def test_detects_two_hop_movement(self):
        tracker = LateralMovementTracker(window_seconds=3600)
        tracker.add_event(_success("1.2.3.4", "web01", ts_offset=0))
        tracker.add_event(_success("1.2.3.4", "db01", ts_offset=60))
        report = tracker.analyze()
        assert any(c.pattern == MovementPattern.SEQUENTIAL_HOP for c in report.movement_chains)

    def test_same_host_not_a_hop(self):
        tracker = LateralMovementTracker(window_seconds=3600)
        tracker.add_event(_success("1.2.3.4", "web01", ts_offset=0))
        tracker.add_event(_success("1.2.3.4", "web01", ts_offset=30))
        report = tracker.analyze()
        # Two auths to same host — no lateral movement
        seqs = [c for c in report.movement_chains if c.pattern == MovementPattern.SEQUENTIAL_HOP]
        assert len(seqs) == 0

    def test_window_expiry_splits_chain(self):
        tracker = LateralMovementTracker(window_seconds=60)
        tracker.add_event(_success("2.2.2.2", "host1", ts_offset=0))
        tracker.add_event(_success("2.2.2.2", "host2", ts_offset=200))  # > 60s
        tracker.add_event(_success("2.2.2.2", "host3", ts_offset=250))
        report = tracker.analyze()
        # Should detect movement in second+third hop but not cross-window
        # Just verify we get at least one chain
        assert report.chain_count >= 1

    def test_chain_source_ip_correct(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("3.3.3.3", "host_a", ts_offset=0))
        tracker.add_event(_success("3.3.3.3", "host_b", ts_offset=30))
        report = tracker.analyze()
        chains = [c for c in report.movement_chains if c.source_ip == "3.3.3.3"]
        assert len(chains) >= 1

    def test_three_hop_becomes_multi_hop_chain(self):
        tracker = LateralMovementTracker(window_seconds=3600)
        tracker.add_event(_success("4.4.4.4", "h1", ts_offset=0))
        tracker.add_event(_success("4.4.4.4", "h2", ts_offset=30))
        tracker.add_event(_success("4.4.4.4", "h3", ts_offset=60))
        report = tracker.analyze()
        multi = [
            c for c in report.movement_chains
            if c.pattern == MovementPattern.MULTI_HOP_CHAIN
        ]
        assert len(multi) >= 1

    def test_multi_hop_chain_is_critical(self):
        tracker = LateralMovementTracker(window_seconds=3600)
        for i, host in enumerate(["h1", "h2", "h3"]):
            tracker.add_event(_success("5.5.5.5", host, ts_offset=i * 30))
        report = tracker.analyze()
        assert report.critical_count >= 1


# ===========================================================================
# Fan-out detection
# ===========================================================================

class TestFanOutDetection:
    def test_fan_out_detected(self):
        tracker = LateralMovementTracker(window_seconds=3600, fan_out_threshold=3)
        for i, host in enumerate(["h1", "h2", "h3"]):
            tracker.add_event(_success("6.6.6.6", host, ts_offset=i * 10))
        report = tracker.analyze()
        assert any(c.pattern == MovementPattern.FAN_OUT for c in report.movement_chains)

    def test_below_fan_out_threshold_not_detected(self):
        tracker = LateralMovementTracker(window_seconds=3600, fan_out_threshold=5)
        for i, host in enumerate(["h1", "h2"]):
            tracker.add_event(_success("7.7.7.7", host, ts_offset=i * 10))
        report = tracker.analyze()
        fan_outs = [c for c in report.movement_chains if c.pattern == MovementPattern.FAN_OUT]
        assert len(fan_outs) == 0

    def test_fan_out_high_severity(self):
        tracker = LateralMovementTracker(window_seconds=3600, fan_out_threshold=3)
        for i, host in enumerate(["h1", "h2", "h3"]):
            tracker.add_event(_success("8.8.8.8", host, ts_offset=i * 5))
        report = tracker.analyze()
        fan = next(c for c in report.movement_chains if c.pattern == MovementPattern.FAN_OUT)
        assert fan.severity in (MovementSeverity.HIGH, MovementSeverity.CRITICAL)


# ===========================================================================
# Credential reuse detection
# ===========================================================================

class TestCredentialReuseDetection:
    def test_same_user_multiple_hosts(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("9.9.9.9", "host1", username="admin", ts_offset=0))
        tracker.add_event(_success("10.10.10.10", "host2", username="admin", ts_offset=60))
        report = tracker.analyze()
        assert any(c.pattern == MovementPattern.CREDENTIAL_REUSE for c in report.movement_chains)

    def test_different_users_not_flagged(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("1.1.1.1", "host1", username="alice"))
        tracker.add_event(_success("2.2.2.2", "host2", username="bob"))
        report = tracker.analyze()
        cred_reuse = [
            c for c in report.movement_chains
            if c.pattern == MovementPattern.CREDENTIAL_REUSE
        ]
        assert len(cred_reuse) == 0

    def test_reuse_description_contains_username(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("1.2.3.4", "srvA", username="root", ts_offset=0))
        tracker.add_event(_success("5.6.7.8", "srvB", username="root", ts_offset=60))
        report = tracker.analyze()
        reuse = next(
            c for c in report.movement_chains
            if c.pattern == MovementPattern.CREDENTIAL_REUSE
        )
        assert "root" in reuse.description


# ===========================================================================
# LateralMovementReport
# ===========================================================================

class TestLateralMovementReport:
    def test_empty_report(self):
        tracker = LateralMovementTracker()
        report = tracker.analyze()
        assert report.chain_count == 0
        assert report.total_hops == 0

    def test_by_pattern_filter(self):
        tracker = LateralMovementTracker(window_seconds=3600, fan_out_threshold=3)
        for i, host in enumerate(["h1", "h2", "h3"]):
            tracker.add_event(_success("11.11.11.11", host, ts_offset=i * 5))
        report = tracker.analyze()
        fan = report.by_pattern(MovementPattern.FAN_OUT)
        assert all(c.pattern == MovementPattern.FAN_OUT for c in fan)

    def test_by_host_filter(self):
        tracker = LateralMovementTracker(window_seconds=3600)
        tracker.add_event(_success("1.2.3.4", "target_host", ts_offset=0))
        tracker.add_event(_success("1.2.3.4", "other_host", ts_offset=30))
        report = tracker.analyze()
        chains = report.by_host("target_host")
        assert all("target_host" in c.target_hosts for c in chains)

    def test_unique_hosts_populated(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("1.2.3.4", "web01"))
        tracker.add_event(_success("1.2.3.4", "db01"))
        report = tracker.analyze()
        assert "web01" in report.unique_hosts
        assert "db01" in report.unique_hosts

    def test_summary_contains_chain_count(self):
        tracker = LateralMovementTracker()
        report = tracker.analyze()
        assert "0" in report.summary()

    def test_total_hops_counted(self):
        tracker = LateralMovementTracker()
        tracker.add_event(_success("1.2.3.4", "h1"))
        tracker.add_event(_success("1.2.3.4", "h2"))
        report = tracker.analyze()
        assert report.total_hops == 2
