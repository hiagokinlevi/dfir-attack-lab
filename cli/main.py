from __future__ import annotations

import argparse

from collectors.linux.triage import collect_linux_triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_linux = subparsers.add_parser("collect-linux", help="Collect Linux triage artifacts")
    collect_linux.add_argument(
        "--output-dir",
        dest="output_dir",
        default=None,
        help="Directory to write collected artifacts (defaults to existing collector behavior)",
    )

    return parser


def main(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "collect-linux":
        return collect_linux_triage(output_dir=args.output_dir)

    parser.error(f"Unknown command: {args.command}")
