from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Optional

from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log
from parsers.windows_evtx import parse_windows_evtx_xml


def _parse_logs(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    parser_name = args.parser

    if parser_name == "authlog":
        raw_events = parse_auth_log(input_path)
    elif parser_name == "windows-evtx":
        raw_events = parse_windows_evtx_xml(input_path)

        # Optional event-id filtering is only applicable to Windows EVTX parser path.
        event_ids: Optional[List[int]] = args.event_id
        if event_ids:
            allowed = set(event_ids)
            raw_events = [
                e
                for e in raw_events
                if int(getattr(e, "event_id", getattr(e, "id", -1))) in allowed
            ]
    else:
        raise ValueError(f"Unsupported parser: {parser_name}")

    normalized = [e.to_dict() if hasattr(e, "to_dict") else e for e in raw_events]

    if args.output:
        Path(args.output).write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    else:
        print(json.dumps(normalized, indent=2))

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_logs = subparsers.add_parser(
        "parse-logs",
        help="Parse supported log artifacts into normalized events.",
        description=(
            "Parse supported log artifacts into normalized events.\n\n"
            "Windows EVTX filtering example:\n"
            "  parse-logs --parser windows-evtx --input security.xml "
            "--event-id 4625 --event-id 7045\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parse_logs.add_argument("--parser", required=True, choices=["authlog", "windows-evtx"])
    parse_logs.add_argument("--input", required=True)
    parse_logs.add_argument("--output")
    parse_logs.add_argument(
        "--event-id",
        action="append",
        type=int,
        default=None,
        help=(
            "Repeatable Windows EVTX Event ID filter (only used with --parser windows-evtx). "
            "Example: --event-id 4625 --event-id 7045"
        ),
    )
    parse_logs.set_defaults(func=_parse_logs)

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
