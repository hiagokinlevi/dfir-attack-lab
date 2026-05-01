from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List

from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log
from parsers.windows_evtx import parse_windows_evtx


def _filter_by_service_name(events: Iterable[TriageEvent], service_name: str) -> List[TriageEvent]:
    needle = service_name.lower()
    filtered: List[TriageEvent] = []
    for event in events:
        if str(getattr(event, "source", "")).lower() != "windows_evtx":
            continue
        if str(getattr(event, "event_id", "")) != "7045":
            continue

        haystacks = [
            str(getattr(event, "service_name", "") or ""),
            str(getattr(event, "message", "") or ""),
        ]
        if any(needle in h.lower() for h in haystacks):
            filtered.append(event)
    return filtered


def parse_logs_command(args: argparse.Namespace) -> List[TriageEvent]:
    input_path = Path(args.input)
    parser_name = args.parser

    if parser_name == "authlog":
        events = parse_auth_log(input_path)
    elif parser_name == "windows-evtx":
        events = parse_windows_evtx(input_path)
        if getattr(args, "service_name", None):
            events = _filter_by_service_name(events, args.service_name)
    else:
        raise ValueError(f"Unsupported parser: {parser_name}")

    return events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command")

    parse_logs = subparsers.add_parser("parse-logs")
    parse_logs.add_argument("--input", required=True)
    parse_logs.add_argument("--parser", required=True, choices=["authlog", "windows-evtx"])
    parse_logs.add_argument(
        "--service-name",
        required=False,
        help="Optional case-insensitive substring filter for Windows Event ID 7045 service names (windows-evtx parser only).",
    )

    return parser
