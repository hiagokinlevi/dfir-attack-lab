from normalizers.models import TriageEvent, EventCategory, SeverityHint
from datetime import datetime, timezone


def test_triage_event_creation():
    e = TriageEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source_file="/var/log/auth.log",
        category=EventCategory.AUTHENTICATION,
        action="ssh_login_failure",
        raw="Jan  1 00:00:00 host sshd: Failed password for root from 1.2.3.4",
    )
    assert e.category == EventCategory.AUTHENTICATION
    assert e.severity == SeverityHint.INFO  # default


def test_event_category_values():
    assert EventCategory.AUTHENTICATION.value == "authentication"
    assert EventCategory.PRIVILEGE_ESCALATION.value == "privilege_escalation"
