import argparse
import json
import sys

from case.packager import verify_case


def _cmd_verify_case(args: argparse.Namespace) -> int:
    result = verify_case(args.case_dir)

    # Support either tuple-style or dict-style return from verify_case().
    valid = False
    mismatches = []

    if isinstance(result, tuple):
        if len(result) >= 1:
            valid = bool(result[0])
        if len(result) >= 2 and result[1] is not None:
            mismatches = list(result[1])
    elif isinstance(result, dict):
        valid = bool(
            result.get("valid", result.get("ok", result.get("success", False)))
        )
        mismatches = list(
            result.get("mismatches", result.get("changed_files", result.get("diff", [])))
        )
    else:
        valid = bool(result)

    if valid:
        print(f"[PASS] Case integrity verified: {args.case_dir}")
        return 0

    print(f"[FAIL] Case integrity check failed: {args.case_dir}")
    if mismatches:
        print("Files with hash mismatches:")
        for path in mismatches:
            print(f" - {path}")
    else:
        print("No specific mismatched files were reported by verifier.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser(
        "verify-case",
        help="Verify packaged case integrity against stored SHA-256 manifest",
    )
    verify_parser.add_argument("case_dir", help="Path to packaged case directory")
    verify_parser.set_defaults(func=_cmd_verify_case)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
