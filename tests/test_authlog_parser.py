import tempfile
from pathlib import Path
from parsers.authlog import parse_authlog
from normalizers.models import EventCategory, SeverityHint


_SAMPLE_LOG = """\
Apr  1 10:00:01 host sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr  1 10:01:00 host sshd[1234]: Accepted publickey for admin from 10.0.0.5 port 22 ssh2
Apr  1 10:05:00 host sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
"""


def test_ssh_failure_parsed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(_SAMPLE_LOG)
        log_path = Path(f.name)
    events = parse_authlog(log_path)
    failures = [e for e in events if e.action == "ssh_login_failure"]
    assert len(failures) == 1
    assert failures[0].actor == "192.168.1.100"
    assert failures[0].target == "root"


def test_ssh_success_parsed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(_SAMPLE_LOG)
        log_path = Path(f.name)
    events = parse_authlog(log_path)
    successes = [e for e in events if e.action == "ssh_login_success"]
    assert len(successes) == 1
    assert successes[0].severity == SeverityHint.INFO


def test_sudo_parsed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(_SAMPLE_LOG)
        log_path = Path(f.name)
    events = parse_authlog(log_path)
    sudo_events = [e for e in events if e.action == "sudo_execution"]
    assert len(sudo_events) == 1
    assert sudo_events[0].category == EventCategory.PRIVILEGE_ESCALATION
