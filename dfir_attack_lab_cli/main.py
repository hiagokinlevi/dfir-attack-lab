from __future__ import annotations

import json
from pathlib import Path

import click

from case.packager import verify_case
from collectors.linux.triage import collect_linux_triage
from collectors.macos.triage import collect_macos_triage
from collectors.windows.triage import collect_windows_triage
from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log
from parsers.windows_evtx import parse_windows_evtx
from timelines.builder import build_timeline


@click.group()
def cli() -> None:
    """k1n DFIR Attack Lab CLI."""


@cli.command("collect-linux")
@click.option("--output-dir", type=click.Path(path_type=Path), required=True)
def collect_linux(output_dir: Path) -> None:
    """Run Linux read-only triage collection."""
    collect_linux_triage(output_dir)
    click.echo(f"Linux triage collection complete: {output_dir}")


@cli.command("collect-windows")
@click.option("--output-dir", type=click.Path(path_type=Path), required=True)
def collect_windows(output_dir: Path) -> None:
    """Run Windows read-only triage collection."""
    collect_windows_triage(output_dir)
    click.echo(f"Windows triage collection complete: {output_dir}")


@cli.command("collect-macos")
@click.option("--output-dir", type=click.Path(path_type=Path), required=True)
def collect_macos(output_dir: Path) -> None:
    """Run macOS read-only triage collection."""
    collect_macos_triage(output_dir)
    click.echo(f"macOS triage collection complete: {output_dir}")


@cli.command("parse-logs")
@click.option("--input-path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--source-type", type=click.Choice(["authlog", "windows-evtx"]), required=True)
@click.option("--output-file", type=click.Path(path_type=Path), required=True)
def parse_logs(input_path: Path, source_type: str, output_file: Path) -> None:
    """Parse raw logs into normalized TriageEvent JSONL."""
    if source_type == "authlog":
        events = parse_auth_log(input_path)
    else:
        events = parse_windows_evtx(input_path)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(event.model_dump_json() + "\n")

    click.echo(f"Parsed {len(events)} events to {output_file}")


@cli.command("build-timeline")
@click.option("--events-file", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output-file", type=click.Path(path_type=Path), required=True)
@click.option(
    "--gap-threshold-minutes",
    type=int,
    default=30,
    show_default=True,
    help="Minutes of inactivity required before a timeline gap event is generated.",
)
def build_timeline_cmd(events_file: Path, output_file: Path, gap_threshold_minutes: int) -> None:
    """Build a chronological timeline with logging gap detection."""
    events: list[TriageEvent] = []
    with events_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(TriageEvent.model_validate_json(line))

    timeline = build_timeline(events, gap_threshold_minutes=gap_threshold_minutes)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        for event in timeline:
            f.write(event.model_dump_json() + "\n")

    click.echo(f"Built timeline with {len(timeline)} events to {output_file}")


@cli.command("verify-case")
@click.option("--case-dir", type=click.Path(exists=True, path_type=Path), required=True)
def verify_case_cmd(case_dir: Path) -> None:
    """Verify case integrity manifest hashes."""
    results = verify_case(case_dir)
    click.echo(json.dumps(results, indent=2))


if __name__ == "__main__":
    cli()
