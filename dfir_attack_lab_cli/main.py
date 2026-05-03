from __future__ import annotations

import argparse
from pathlib import Path

from collectors.linux.triage import collect_linux_triage
from collectors.macos.triage import collect_macos_triage
from collectors.windows.triage import collect_windows_triage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfir-attack-lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    linux_parser = subparsers.add_parser("collect-linux", help="Run read-only Linux triage collection")
    linux_parser.add_argument("--target", required=False, default="/", help="Target root path (default: /)")

    windows_parser = subparsers.add_parser("collect-windows", help="Run read-only Windows triage collection")
    windows_parser.add_argument("--target", required=False, default="C:\\", help="Target root path (default: C:\\)")

    macos_parser = subparsers.add_parser("collect-macos", help="Run read-only macOS triage collection")
    macos_parser.add_argument("--target", required=False, default="/", help="Target root path (default: /)")
    macos_parser.add_argument(
        "--output-dir",
        required=False,
        default=None,
        help="Directory for collected artifacts (created if needed)",
    )

    return parser


def _resolve_output_dir(output_dir: str | None) -> Path | None:
    if output_dir is None:
        return None
    out = Path(output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not out.is_dir():
        raise ValueError(f"output directory is not a directory: {out}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "collect-linux":
        collect_linux_triage(target_root=args.target)
        return 0

    if args.command == "collect-windows":
        collect_windows_triage(target_root=args.target)
        return 0

    if args.command == "collect-macos":
        output_dir = _resolve_output_dir(args.output_dir)
        if output_dir is None:
            collect_macos_triage(target_root=args.target)
        else:
            collect_macos_triage(target_root=args.target, output_dir=str(output_dir))
        return 0

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
