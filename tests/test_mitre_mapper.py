"""
Tests for analysis/mitre_mapper.py

Validates:
  - map_event() returns AttackTechnique for exact action matches
  - map_event() returns None for unknown actions
  - map_event() is case-insensitive
  - map_event() matches keywords when no exact match
  - Known action-to-technique mappings are correct
  - map_all() returns AttackMappingReport with correct counts
  - AttackMappingReport.technique_counts aggregates correctly
  - AttackMappingReport.tactic_counts aggregates correctly
  - AttackMappingReport.unmapped_count is accurate
  - AttackMappingReport.coverage_pct computes correctly
  - AttackMappingReport.top_techniques() returns sorted list
  - empty event list returns zero-coverage report
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.mitre_mapper import (
    AttackMappingReport,
    AttackTechnique,
    map_all,
    map_event,
)
from normalizers.models import EventCategory, SeverityHint, TriageEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    action: str,
    category: EventCategory = EventCategory.AUTHENTICATION,
    severity: SeverityHint = SeverityHint.MEDIUM,
    raw: str = "",
) -> TriageEvent:
    return TriageEvent(
        timestamp=datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc),
        source_file="auth.log",
        category=category,
        severity=severity,
        action=action,
        raw=raw or action,
    )


# ---------------------------------------------------------------------------
# map_event — exact matches
# ---------------------------------------------------------------------------

class TestMapEventExact:

    def test_login_failure_maps_to_brute_force(self):
        result = map_event(_event("login_failure"))
        assert result is not None
        assert result.technique_id == "T1110"

    def test_sudo_exec_maps_to_privilege_escalation(self):
        result = map_event(_event("sudo_exec"))
        assert result is not None
        assert "T1548" in result.technique_id

    def test_cron_add_maps_to_persistence(self):
        result = map_event(_event("cron_add"))
        assert result is not None
        assert "T1053" in result.technique_id

    def test_network_scan_maps_to_discovery(self):
        result = map_event(_event("network_scan"))
        assert result is not None
        assert result.technique_id == "T1046"

    def test_log_clear_maps_to_defense_evasion(self):
        result = map_event(_event("log_clear"))
        assert result is not None
        assert "T1070" in result.technique_id

    def test_data_exfil_maps_to_exfiltration(self):
        result = map_event(_event("data_exfil"))
        assert result is not None
        assert result.tactic == "Exfiltration"

    def test_exact_match_is_high_confidence(self):
        result = map_event(_event("login_failure"))
        assert result.confidence == "high"

    def test_ssh_auth_failure_maps_to_password_spray(self):
        result = map_event(_event("ssh_auth_failure"))
        assert result is not None
        assert "T1110" in result.technique_id

    def test_ssh_key_add_maps_to_persistence(self):
        result = map_event(_event("ssh_key_add"))
        assert result is not None
        assert result.tactic == "Persistence"

    def test_launch_agent_add_maps_to_macos_persistence(self):
        result = map_event(_event("launch_agent_add"))
        assert result is not None
        assert result.tactic == "Persistence"


# ---------------------------------------------------------------------------
# map_event — keyword matches
# ---------------------------------------------------------------------------

class TestMapEventKeyword:

    def test_keyword_brute_matches(self):
        result = map_event(_event("brute_force_attempt"))
        assert result is not None
        assert result.confidence == "medium"

    def test_keyword_spray_matches(self):
        result = map_event(_event("password_spray_detected"))
        assert result is not None
        assert "spray" in result.name.lower() or "T1110" in result.technique_id

    def test_keyword_dump_matches(self):
        result = map_event(_event("memory_dump_attempt"))
        assert result is not None

    def test_keyword_exfil_matches(self):
        result = map_event(_event("data_exfiltration_attempt"))
        assert result is not None
        assert result.tactic == "Exfiltration"

    def test_keyword_lateral_matches(self):
        result = map_event(_event("lateral_movement_detected"))
        assert result is not None
        assert result.tactic == "Lateral Movement"

    def test_keyword_scan_matches(self):
        result = map_event(_event("port_scan_detected"))
        assert result is not None


# ---------------------------------------------------------------------------
# map_event — no match
# ---------------------------------------------------------------------------

class TestMapEventNoMatch:

    def test_unknown_action_returns_none(self):
        result = map_event(_event("disk_write_completed"))
        assert result is None

    def test_generic_system_action_returns_none(self):
        result = map_event(_event("service_started"))
        assert result is None

    def test_empty_action_returns_none(self):
        result = map_event(_event("   "))
        assert result is None

    def test_case_insensitive_exact_match(self):
        result = map_event(_event("LOGIN_FAILURE"))
        assert result is not None
        assert result.technique_id == "T1110"


# ---------------------------------------------------------------------------
# AttackTechnique dataclass
# ---------------------------------------------------------------------------

class TestAttackTechnique:

    def test_is_frozen(self):
        t = AttackTechnique("T1110", "Brute Force", "Credential Access", "high")
        with pytest.raises((AttributeError, TypeError)):
            t.technique_id = "T9999"  # type: ignore

    def test_description_defaults_empty(self):
        t = AttackTechnique("T1000", "Test", "Test Tactic", "low")
        assert t.description == ""


# ---------------------------------------------------------------------------
# map_all
# ---------------------------------------------------------------------------

class TestMapAll:

    def test_returns_report(self):
        result = map_all([_event("login_failure")])
        assert isinstance(result, AttackMappingReport)

    def test_empty_events_zero_coverage(self):
        result = map_all([])
        assert result.total_events == 0
        assert result.coverage_pct == 0.0

    def test_technique_count_correct(self):
        events = [_event("login_failure"), _event("login_failure"), _event("cron_add")]
        result = map_all(events)
        assert result.technique_counts["T1110"] == 2

    def test_tactic_count_correct(self):
        events = [_event("login_failure"), _event("auth_failure")]
        result = map_all(events)
        assert result.tactic_counts["Credential Access"] == 2

    def test_unmapped_count_correct(self):
        events = [_event("login_failure"), _event("disk_write")]
        result = map_all(events)
        assert result.unmapped_count == 1

    def test_coverage_pct_correct(self):
        events = [_event("login_failure"), _event("unknown_action")]
        result = map_all(events)
        assert result.coverage_pct == 50.0

    def test_mapped_count_property(self):
        events = [_event("login_failure"), _event("cron_add"), _event("unknown")]
        result = map_all(events)
        assert result.mapped_count == 2

    def test_total_events_correct(self):
        events = [_event(a) for a in ["login_failure", "cron_add", "sudo_exec"]]
        result = map_all(events)
        assert result.total_events == 3

    def test_top_techniques_sorted(self):
        events = [_event("login_failure")] * 5 + [_event("cron_add")] * 2
        result = map_all(events)
        top = result.top_techniques(2)
        assert top[0][1] >= top[1][1]

    def test_top_tactics_sorted(self):
        events = [_event("login_failure")] * 3 + [_event("network_scan")] * 1
        result = map_all(events)
        top = result.top_tactics(2)
        assert top[0][1] >= top[1][1]

    def test_mappings_list_populated(self):
        events = [_event("login_failure"), _event("cron_add")]
        result = map_all(events)
        assert len(result.mappings) == 2
        for event, technique in result.mappings:
            assert isinstance(technique, AttackTechnique)
