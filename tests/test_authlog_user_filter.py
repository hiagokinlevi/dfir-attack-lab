from pathlib import Path

from parsers.authlog import parse_auth_log


def test_parse_auth_log_user_filter_matches_and_excludes(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join(
            [
                "Jan 10 12:00:00 host sshd[1001]: Accepted password for alice from 10.0.0.10 port 52525 ssh2",
                "Jan 10 12:01:00 host sshd[1002]: Accepted password for bob from 10.0.0.11 port 52526 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    all_events = parse_auth_log(str(log_file))
    assert len(all_events) == 2

    alice_events = parse_auth_log(str(log_file), user="alice")
    assert len(alice_events) == 1
    assert alice_events[0].target_user == "alice"

    no_events = parse_auth_log(str(log_file), user="charlie")
    assert no_events == []
