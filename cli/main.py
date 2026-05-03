from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from timelines.builder import build_timeline


def _resolve_timezone(value: str):
    raw = (value or "").strip()
    lowered = raw.lower()

    if lowered == "utc":
        return ZoneInfo("UTC")
    if lowered == "local":
        return datetime.now().astimezone().tzinfo

    try:
        return ZoneInfo(raw)
    except ZoneInfoNotFoundError:
        raise ValueError(
            f"Invalid timezone '{value}'. Use 'UTC', 'local', or a valid IANA timezone like 'America/New_York'."
        )


def _format_ts(dt: datetime, tzinfo) -> str:
    if dt is None:
        return ""
    if tzinfo is None:
        return dt.isoformat()
    if dt.tzinfo is None:
        # preserve source object; only apply for rendering
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(tzinfo).isoformat()


def cmd_build_timeline(args: argparse.Namespace) -> int:
    tzinfo = None
    if getattr(args, "timezone", None):
        try:
            tzinfo = _resolve_timezone(args.timezone)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    input_path = Path(args.input)
    output_path = Path(args.output)

    events = json.loads(input_path.read_text(encoding="utf-8"))
    timeline = build_timeline(events)

    rendered = []
    for item in timeline:
        out = dict(item)
        ts = item.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                out["timestamp"] = _format_ts(dt, tzinfo)
            except ValueError:
                out["timestamp"] = ts
        rendered.append(out)

    output_path.write_text(json.dumps(rendered, indent=2), encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    sub = parser.add_subparsers(dest="command")

    p_tl = sub.add_parser("build-timeline")
    p_tl.add_argument("--input", required=True)
    p_tl.add_argument("--output", required=True)
    p_tl.add_argument(
        "--timezone",
        default="UTC",
        help="Output timezone for rendered timestamps: UTC, local, or IANA name (e.g. America/New_York).",
    )
    p_tl.set_defaults(func=cmd_build_timeline)

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
