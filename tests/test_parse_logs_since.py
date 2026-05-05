from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest

from dfir_attack_lab_cli.main import handle_parse_logs


@pytest.fixture()
def authlog_file(tmp_path: Path) -> Path:
    p = tmp_path / "auth.log"
    p.write_text(
        """
Jan 10 10:00:00 host sshd[100]: Failed password for invalid user bad from 1.2.3.4 port 22 ssh2
Jan 10 10:05:00 host sshd[101]: Accepted password for alice from 5.6.7.8 port 22 ssh2
Jan 10 10:10:00 host sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return p


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def test_parse_logs_since_filters_events(authlog_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    args = Namespace(
        input=str(authlog_file),
        format="linux-auth",
        output=str(out),
        since="2024-01-10 10:05:00",
    )

    rc = handle_parse_logs(args)
    assert rc == 0

    events = _read_jsonl(out)
    assert len(events) == 2


def test_parse_logs_since_invalid_timestamp(authlog_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    args = Namespace(
        input=str(authlog_file),
        format="linux-auth",
        output=str(out),
        since="not-a-time",
    )

    with pytest.raises(SystemExit) as exc:
        handle_parse_logs(args)

    assert "Invalid --since timestamp" in str(exc.value)
