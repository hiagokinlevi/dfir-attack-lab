from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from normalizers.models import TriageEvent
from timelines.builder import build_timeline

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


def _load_events(input_path: Path) -> list[TriageEvent]:
    with input_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "events" in data:
        data = data["events"]

    return [TriageEvent.model_validate(item) for item in data]


@app.command("build-timeline")
def build_timeline_cmd(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="Normalized events JSON file"),
    output_file: Path = typer.Argument(..., help="Output timeline JSON file"),
    gap_minutes: int = typer.Option(30, "--gap-minutes", min=1, help="Gap threshold in minutes"),
    hostname: Optional[str] = typer.Option(
        None,
        "--hostname",
        help="Only include events matching this normalized host/hostname value",
    ),
) -> None:
    events = _load_events(input_file)

    if hostname:
        needle = hostname.strip().lower()
        events = [
            e
            for e in events
            if (
                (e.host and e.host.strip().lower() == needle)
                or (e.hostname and e.hostname.strip().lower() == needle)
            )
        ]

    timeline = build_timeline(events, gap_minutes=gap_minutes)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2, default=str)

    typer.echo(f"Timeline written to {output_file}")


if __name__ == "__main__":
    app()
