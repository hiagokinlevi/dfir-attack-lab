"""Tests for the macOS Unified Log parser."""
from __future__ import annotations

import tempfile
from pathlib import Path

from normalizers.models import EventCategory, SeverityHint
from parsers.macos_unified_log import parse_macos_unified_log

_MACOS_UNIFIED_LOG = """\
2026-04-09 10:12:00.100000-0300 0x111 Default 0x0 101 0 authd: Authentication failed for user analyst from 10.0.0.8
2026-04-09 10:12:05.100000-0300 0x112 Default 0x0 102 0 authd: Authenticated user analyst from 10.0.0.8
2026-04-09 10:13:00.100000-0300 0x113 Default 0x0 103 0 sudo: sudo[123]: analyst : TTY=ttys000 ; PWD=/Users/analyst ; USER=root ; COMMAND=/usr/bin/id
2026-04-09 10:14:00.100000-0300 0x114 Default 0x0 104 0 com.apple.xpc.launchd: service loaded: /Library/LaunchDaemons/com.evil.agent.plist
"""


def _write_log(content: str) -> Path:
    handle = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    handle.write(content)
    handle.close()
    return Path(handle.name)


def test_macos_unified_log_parser_extracts_auth_failure_success_sudo_and_persistence():
    path = _write_log(_MACOS_UNIFIED_LOG)
    events = parse_macos_unified_log(path)

    assert len(events) == 4

    auth_fail = events[0]
    assert auth_fail.action == "macos_authentication_failure"
    assert auth_fail.category == EventCategory.AUTHENTICATION
    assert auth_fail.severity == SeverityHint.MEDIUM
    assert auth_fail.actor == "10.0.0.8"
    assert auth_fail.target == "analyst"

    auth_success = events[1]
    assert auth_success.action == "macos_authentication_success"
    assert auth_success.severity == SeverityHint.INFO

    sudo_event = events[2]
    assert sudo_event.action == "macos_sudo_execution"
    assert sudo_event.category == EventCategory.PRIVILEGE_ESCALATION
    assert sudo_event.severity == SeverityHint.HIGH
    assert sudo_event.actor == "analyst"
    assert sudo_event.target == "root"
    assert sudo_event.metadata["command"] == "/usr/bin/id"

    persistence_event = events[3]
    assert persistence_event.action == "macos_launchd_persistence_loaded"
    assert persistence_event.category == EventCategory.SYSTEM
    assert persistence_event.severity == SeverityHint.HIGH
    assert persistence_event.target == "/Library/LaunchDaemons/com.evil.agent.plist"


def test_macos_unified_log_parser_handles_ssh_style_messages():
    path = _write_log(
        "2026-04-09 10:15:00.100000-0300 0x115 Default 0x0 105 0 sshd: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2\n"
    )
    events = parse_macos_unified_log(path)

    assert len(events) == 1
    event = events[0]
    assert event.action == "macos_authentication_failure"
    assert event.actor == "192.168.1.50"
    assert event.target == "admin"


def test_macos_unified_log_parser_ignores_invalid_lines():
    path = _write_log("this is not a compact unified log line\n")
    events = parse_macos_unified_log(path)
    assert events == []
