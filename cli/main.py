from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import click

from normalizers.models import TriageEvent
from timelines.writer import write_report


def _load_events(path: Path) -> list[TriageEvent]:
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return [TriageEvent(**item) for item in raw]


def _filter_by_category(events: Iterable[TriageEvent], categories: tuple[str, ...]) -> list[TriageEvent]:
    if not categories:
        return list(events)
    wanted = {c.strip().lower() for c in categories if c and c.strip()}
    if not wanted:
        return list(events)
    return [e for e in events if (getattr(e, "category", "") or "").lower() in wanted]


@click.group()
def cli() -> None:
    pass


@cli.command("generate-report")
@click.option("--timeline", "timeline_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True)
@click.option("--format", "fmt", type=click.Choice(["html", "csv", "txt", "json", "jsonl", "ecs", "cef"]), required=True)
@click.option("--severity", multiple=True, help="Filter by severity (repeatable).")
@click.option("--category", "categories", multiple=True, help="Filter by event category (repeatable).")
def generate_report(timeline_path: Path, output_path: Path, fmt: str, severity: tuple[str, ...], categories: tuple[str, ...]) -> None:
    events = _load_events(timeline_path)

    if severity:
        sev = {s.strip().lower() for s in severity if s and s.strip()}
        events = [e for e in events if (getattr(e, "severity", "") or "").lower() in sev]

    events = _filter_by_category(events, categories)

    write_report(events=events, output_path=output_path, fmt=fmt)


if __name__ == "__main__":
    cli()
