from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from case.packager import verify_case


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser("verify-case", help="Verify case integrity against manifest")
    verify_parser.add_argument("case_dir", help="Path to case directory")
    verify_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON summary")

    return parser


def _to_bool(result: object) -> bool:
    if isinstance(result, bool):
        return result
    if isinstance(result, dict):
        for key in ("ok", "valid", "success", "passed"):
            if key in result:
                return bool(result[key])
    return bool(result)


def _summary(result: object, case_dir: str) -> dict:
    ok = _to_bool(result)
    payload = {
        "case_dir": str(Path(case_dir)),
        "ok": ok,
    }
    if isinstance(result, dict):
        payload.update(result)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "verify-case":
        result = verify_case(args.case_dir)
        summary = _summary(result, args.case_dir)
        ok = bool(summary.get("ok", False))

        if args.as_json:
            print(json.dumps(summary, sort_keys=True))
        else:
            status = "PASS" if ok else "FAIL"
            print(f"verify-case: {status} ({summary.get('case_dir')})")

        return 0 if ok else 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
