from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from timelines.builder import build_timeline


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _load_events(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "events" in data and isinstance(data["events"], list):
        return data["events"]
    raise click.ClickException("Unsupported normalized event input format")


def _filter_by_min_severity(events: list[dict[str, Any]], min_severity: str | None) -> list[dict[str, Any]]:
    if not min_severity:
        return events
    threshold = SEVERITY_ORDER[min_severity]
    return [
        ev
        for ev in events
        if SEVERITY_ORDER.get(str(ev.get("severity", "low")).lower(), 1) >= threshold
    ]


@click.group()
def cli() -> None:
    pass


@cli.command("build-timeline")
@click.option("--input", "input_path", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Only include events at or above this severity before timeline generation.",
)
def build_timeline_cmd(input_path: Path, output_path: Path, min_severity: str | None) -> None:
    events = _load_events(input_path)
    filtered_events = _filter_by_min_severity(events, min_severity.lower() if min_severity else None)
    timeline = build_timeline(filtered_events)
    output_path.write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    click.echo(f"Wrote timeline: {output_path}")


if __name__ == "__main__":
    cli()
