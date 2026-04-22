from parsers.authlog import parse_authlog


def test_parse_authlog_extracts_ssh_and_sudo_events():
    lines = [
        "Jan 12 10:22:01 labhost sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 54422 ssh2",
        "Jan 12 10:22:10 labhost sshd[1235]: Accepted password for analyst from 10.0.0.8 port 60211 ssh2",
        "Jan 12 10:23:00 labhost sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id",
    ]

    events = parse_authlog(lines)

    assert len(events) == 3

    failed = events[0]
    assert failed.event_type == "ssh_login_failed"
    assert failed.actor == "10.0.0.5"
    assert failed.target == "admin"
    assert failed.metadata["src_ip"] == "10.0.0.5"
    assert failed.metadata["src_port"] == 54422

    accepted = events[1]
    assert accepted.event_type == "ssh_login_success"
    assert accepted.actor == "10.0.0.8"
    assert accepted.target == "analyst"
    assert accepted.metadata["src_ip"] == "10.0.0.8"
    assert accepted.metadata["src_port"] == 60211

    sudo = events[2]
    assert sudo.event_type == "sudo_command"
    assert sudo.actor == "analyst"
    assert sudo.target == "root"
    assert sudo.metadata["command"] == "/usr/bin/id"
