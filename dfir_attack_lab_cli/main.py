from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log
from parsers.windows_evtx import parse_windows_security_evtx


def _write_events(events: Iterable[TriageEvent], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event.model_dump(), ensure_ascii=False) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_logs = subparsers.add_parser("parse-logs", help="Parse raw logs into normalized TriageEvent JSONL")
    parse_logs.add_argument("--source", required=True, choices=["linux-auth", "windows-security-evtx"])
    parse_logs.add_argument("--input", required=True)
    parse_logs.add_argument("--output", required=True)
    parse_logs.add_argument(
        "--event-id",
        dest="event_ids",
        action="append",
        type=int,
        default=None,
        help="Windows Security Event ID to include (repeatable)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "parse-logs":
        input_path = Path(args.input)
        output_path = Path(args.output)

        if args.source == "linux-auth":
            events = parse_auth_log(input_path)
        elif args.source == "windows-security-evtx":
            events = parse_windows_security_evtx(input_path, allowed_event_ids=args.event_ids)
        else:
            parser.error(f"Unsupported source: {args.source}")
            return 2

        _write_events(events, output_path)
        return 0

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
