"""
DFIR triage CLI.

Commands:
  collect-linux    - Run read-only Linux triage collection
  collect-windows  - Run read-only Windows triage collection
  collect-macos    - Run read-only macOS triage collection
  parse-logs       - Parse auth.log and produce normalized events JSON
  parse-macos-unified-log - Parse macOS log show exports into normalized events
  build-timeline   - Merge events from a JSON file into a chronological timeline
  generate-report  - Export a timeline file to HTML, CSV, TXT, JSON, or JSONL
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

# Ensure sibling top-level packages in this repository win over unrelated
# site-packages modules with generic names such as "parsers".
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) in sys.path:
    sys.path.remove(str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT))

from collectors.linux.triage import run_linux_triage
from collectors.macos.triage import run_macos_triage
from collectors.windows.triage import run_windows_triage
from parsers.authlog import parse_authlog
from parsers.macos_unified_log import parse_macos_unified_log
from timelines.builder import build_timeline
from timelines.reporter import export_timeline, filter_timeline


def _parse_iso8601(value: str) -> datetime:
    """Parse an ISO 8601 datetime string and normalize it to UTC."""
    normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_timeline_entries(path: Path) -> tuple[list[dict], str | None]:
    """
    Load timeline entries from either a raw timeline array or exported JSON doc.

    Supported shapes:
      - [ ... timeline entries ... ]
      - {"case_id": "...", "summary": {...}, "timeline": [ ... ]}
    """
    payload = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(payload, dict) and isinstance(payload.get("timeline"), list):
        return payload["timeline"], payload.get("case_id")

    if isinstance(payload, list):
        return payload, None

    raise click.ClickException(
        "Timeline input must be either a JSON array of entries or an exported JSON document with a 'timeline' field."
    )


@click.group()
def cli() -> None:
    """k1n DFIR Attack Lab — incident triage and timeline toolkit."""


@cli.command()
@click.option("--output-dir", default="/tmp/dfir-output", show_default=True, help="Directory for triage output")
@click.option("--case-id", required=True, help="Unique case identifier")
def collect_linux(output_dir: str, case_id: str) -> None:
    """Run read-only Linux system triage and write observations to JSONL."""
    path = run_linux_triage(Path(output_dir), case_id)
    click.echo(f"Triage complete: {path}")


@cli.command()
@click.option("--output-dir", default="/tmp/dfir-output", show_default=True, help="Directory for triage output")
@click.option("--case-id", required=True, help="Unique case identifier")
def collect_windows(output_dir: str, case_id: str) -> None:
    """Run read-only Windows system triage and write observations to JSONL."""
    path = run_windows_triage(Path(output_dir), case_id)
    click.echo(f"Triage complete: {path}")


@cli.command()
@click.option("--output-dir", default="/tmp/dfir-output", show_default=True, help="Directory for triage output")
@click.option("--case-id", required=True, help="Unique case identifier")
def collect_macos(output_dir: str, case_id: str) -> None:
    """Run read-only macOS system triage and write observations to JSONL."""
    path = run_macos_triage(Path(output_dir), case_id)
    click.echo(f"Triage complete: {path}")


@cli.command()
@click.argument("log_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="-", help="Output file path (default: stdout)")
def parse_logs(log_path: str, output: str) -> None:
    """Parse an auth.log file and output normalized events as JSON."""
    events = parse_authlog(Path(log_path))
    data = json.dumps([e.model_dump(mode="json") for e in events], indent=2)
    if output == "-":
        click.echo(data)
    else:
        Path(output).write_text(data, encoding="utf-8")
        click.echo(f"Wrote {len(events)} events to {output}")


@cli.command(name="parse-macos-unified-log")
@click.argument("log_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="-", help="Output file path (default: stdout)")
def parse_macos_unified_log_cmd(log_path: str, output: str) -> None:
    """Parse a macOS Unified Log text export and output normalized events as JSON."""
    events = parse_macos_unified_log(Path(log_path))
    data = json.dumps([e.model_dump(mode="json") for e in events], indent=2)
    if output == "-":
        click.echo(data)
    else:
        Path(output).write_text(data, encoding="utf-8")
        click.echo(f"Wrote {len(events)} events to {output}")


def _build_timeline_impl(events_file: str, gap: int, output: str) -> None:
    """Shared implementation for timeline-building commands."""
    raw = json.loads(Path(events_file).read_text(encoding="utf-8"))
    from normalizers.models import TriageEvent

    events = [TriageEvent(**entry) for entry in raw]
    timeline = build_timeline(events, gap_threshold_minutes=gap)
    data = json.dumps(timeline, indent=2)
    if output == "-":
        click.echo(data)
    else:
        Path(output).write_text(data, encoding="utf-8")
        click.echo(f"Timeline with {len(timeline)} entries written to {output}")


@cli.command(name="build-timeline")
@click.argument("events_file", type=click.Path(exists=True))
@click.option("--gap", default=60, show_default=True, help="Gap threshold in minutes")
@click.option("--output", "-o", default="-", help="Output file path (default: stdout)")
def build_timeline_cmd(events_file: str, gap: int, output: str) -> None:
    """Build a chronological timeline from a normalized events JSON file."""
    _build_timeline_impl(events_file, gap, output)


@cli.command(name="build-timeline-cmd", hidden=True)
@click.argument("events_file", type=click.Path(exists=True))
@click.option("--gap", default=60, show_default=True, help="Gap threshold in minutes")
@click.option("--output", "-o", default="-", help="Output file path (default: stdout)")
def build_timeline_cmd_legacy(events_file: str, gap: int, output: str) -> None:
    """Legacy command alias maintained for backward compatibility."""
    _build_timeline_impl(events_file, gap, output)


@cli.command(name="generate-report")
@click.argument("timeline_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["html", "csv", "txt", "json", "jsonl"], case_sensitive=False),
    default="html",
    show_default=True,
    help="Report export format.",
)
@click.option("--output", "-o", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--severity",
    type=click.Choice(["info", "low", "medium", "high"], case_sensitive=False),
    help="Only include events at or above this severity.",
)
@click.option(
    "--category",
    "categories",
    multiple=True,
    help="Include only matching event categories. Repeat the flag for multiple values.",
)
@click.option("--start", help="UTC start timestamp in ISO 8601 format.")
@click.option("--end", help="UTC end timestamp in ISO 8601 format.")
@click.option("--exclude-gaps", is_flag=True, help="Exclude gap markers from the exported report.")
@click.option("--case-id", help="Override the case identifier embedded in JSON and HTML exports.")
def generate_report(
    timeline_file: Path,
    report_format: str,
    output: Path,
    severity: str | None,
    categories: tuple[str, ...],
    start: str | None,
    end: str | None,
    exclude_gaps: bool,
    case_id: str | None,
) -> None:
    """Filter and export a previously built timeline to a report file."""
    if bool(start) ^ bool(end):
        raise click.ClickException("Both --start and --end must be provided together.")

    time_range: tuple[datetime, datetime] | None = None
    if start and end:
        try:
            start_dt = _parse_iso8601(start)
            end_dt = _parse_iso8601(end)
        except ValueError as exc:
            raise click.ClickException(f"Invalid ISO 8601 datetime: {exc}") from exc
        if end_dt < start_dt:
            raise click.ClickException("--end must be greater than or equal to --start.")
        time_range = (start_dt, end_dt)

    timeline, embedded_case_id = _load_timeline_entries(timeline_file)
    filtered = filter_timeline(
        timeline,
        by_severity=severity.lower() if severity else None,
        by_category=list(categories) or None,
        by_time_range=time_range,
        exclude_gaps=exclude_gaps,
    )
    export_case_id = case_id or embedded_case_id or "unknown"
    export_timeline(filtered, output, fmt=report_format.lower(), case_id=export_case_id)
    click.echo(f"Wrote {len(filtered)} timeline entries to {output}")


if __name__ == "__main__":
    cli()
