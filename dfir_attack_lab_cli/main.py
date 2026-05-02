from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from analysis.process_tree import analyze_process_tree


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze-process-tree",
        help="Analyze an offline process-tree export for suspicious execution patterns.",
        description=(
            "Analyze an offline process-tree export and emit scored findings.\n\n"
            "Example:\n"
            "  dfir-attack-lab analyze-process-tree --input tree.json --min-score 70"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    analyze_parser.add_argument("--input", required=True, help="Path to process-tree JSON export")
    analyze_parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Only return findings with score >= MIN_SCORE",
    )

    return parser


def _cmd_analyze_process_tree(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    findings: list[dict[str, Any]] = analyze_process_tree(input_path)

    if args.min_score is not None:
        findings = [f for f in findings if float(f.get("score", 0)) >= args.min_score]

    print(json.dumps(findings, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze-process-tree":
        return _cmd_analyze_process_tree(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
