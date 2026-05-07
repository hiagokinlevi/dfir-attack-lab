from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from timelines.builder import build_timeline


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _load_events(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_timeline_parser = subparsers.add_parser(
        "build-timeline",
        help="Build a chronological timeline and detect inactivity gaps",
    )
    build_timeline_parser.add_argument("--input", required=True, help="Path to normalized events JSON")
    build_timeline_parser.add_argument("--output", required=True, help="Path to output timeline JSON")
    build_timeline_parser.add_argument(
        "--max-gap-minutes",
        type=_positive_int,
        default=None,
        help="Override inactivity gap detection threshold in minutes (positive integer)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "build-timeline":
        events = _load_events(Path(args.input))
        timeline = build_timeline(events, max_gap_minutes=args.max_gap_minutes)
        _write_json(Path(args.output), timeline)
        return 0

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
