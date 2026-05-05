from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log
from parsers.windows_evtx import parse_windows_evtx


def _parse_since_timestamp(raw: str) -> datetime:
    """Parse --since timestamp in ISO-8601 or 'YYYY-MM-DD HH:MM:SS' format."""
    value = raw.strip()
    if not value:
        raise ValueError("empty timestamp")

    # Support trailing Z by converting to explicit UTC offset for fromisoformat
    iso_value = value.replace("Z", "+00:00") if value.endswith("Z") else value

    try:
        return datetime.fromisoformat(iso_value)
    except ValueError:
        pass

    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ValueError(
            "Invalid --since timestamp. Use ISO-8601 or 'YYYY-MM-DD HH:MM:SS'."
        ) from exc


def _event_dt(event: TriageEvent) -> datetime:
    ts = event.timestamp
    if ts.endswith("Z"):
        ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts)


def _apply_since_filter(events: Iterable[TriageEvent], since: datetime | None) -> list[TriageEvent]:
    if since is None:
        return list(events)

    filtered: list[TriageEvent] = []
    for event in events:
        ev_dt = _event_dt(event)
        # Normalize tz-awareness mismatch if parsers emit naive strings
        if ev_dt.tzinfo is None and since.tzinfo is not None:
            ev_dt = ev_dt.replace(tzinfo=since.tzinfo)
        elif ev_dt.tzinfo is not None and since.tzinfo is None:
            since_cmp = since.replace(tzinfo=ev_dt.tzinfo)
            if ev_dt >= since_cmp:
                filtered.append(event)
            continue

        if ev_dt >= since:
            filtered.append(event)
    return filtered


def handle_parse_logs(args: argparse.Namespace) -> int:
    src = Path(args.input)
    if not src.exists():
        raise SystemExit(f"Input path does not exist: {src}")

    if args.format == "linux-auth":
        events = parse_auth_log(src)
    elif args.format == "windows-evtx":
        events = parse_windows_evtx(src)
    else:
        raise SystemExit(f"Unsupported format: {args.format}")

    since_dt = None
    if args.since:
        try:
            since_dt = _parse_since_timestamp(args.since)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc

    events = _apply_since_filter(events, since_dt)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event.model_dump(), ensure_ascii=False) + "\n")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command")

    parse_logs = subparsers.add_parser("parse-logs", help="Parse logs into normalized JSONL events")
    parse_logs.add_argument("--input", required=True, help="Path to input log file")
    parse_logs.add_argument(
        "--format",
        required=True,
        choices=["linux-auth", "windows-evtx"],
        help="Input log format",
    )
    parse_logs.add_argument("--output", required=True, help="Path to output JSONL file")
    parse_logs.add_argument(
        "--since",
        required=False,
        help="Include only events at or after this timestamp (ISO-8601 or YYYY-MM-DD HH:MM:SS)",
    )
    parse_logs.set_defaults(func=handle_parse_logs)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
