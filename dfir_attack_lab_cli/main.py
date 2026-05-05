import argparse
import json
from pathlib import Path
from typing import List

from normalizers.models import TriageEvent
from timelines.builder import build_timeline


def _load_events(path: Path) -> List[TriageEvent]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [TriageEvent(**item) for item in raw]


def _serialize_event(event: TriageEvent) -> dict:
    if hasattr(event, "model_dump"):
        return event.model_dump()
    return event.dict()


def cmd_build_timeline(args: argparse.Namespace) -> int:
    events = _load_events(Path(args.input))
    timeline = build_timeline(events)

    reverse = args.sort == "desc"
    timeline = sorted(timeline, key=lambda e: e.timestamp, reverse=reverse)

    output = [_serialize_event(e) for e in timeline]
    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    else:
        print(json.dumps(output, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    sub = parser.add_subparsers(dest="command")

    bt = sub.add_parser("build-timeline", help="Build normalized timeline from parsed events")
    bt.add_argument("--input", required=True, help="Path to parsed events JSON")
    bt.add_argument("--output", help="Optional output file path")
    bt.add_argument(
        "--sort",
        choices=["asc", "desc"],
        default="asc",
        help="Timeline sort order before output serialization (default: asc)",
    )
    bt.set_defaults(func=cmd_build_timeline)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
