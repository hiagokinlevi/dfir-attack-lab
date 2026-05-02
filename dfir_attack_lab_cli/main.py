from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from timelines.builder import build_timeline

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


@app.command("build-timeline")
def build_timeline_command(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="Path to normalized JSON/JSONL events"),
    output_file: Path = typer.Option(..., "--output", "-o", help="Path to write timeline JSON"),
    gap_minutes: int = typer.Option(30, "--gap-minutes", min=1, help="Gap threshold in minutes"),
    case_id: str | None = typer.Option(
        None,
        "--case-id",
        help="Only include normalized events matching this case_id before timeline generation",
    ),
) -> None:
    events: list[dict[str, Any]] = []

    if input_file.suffix.lower() == ".jsonl":
        with input_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
    else:
        with input_file.open("r", encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, list):
            events = loaded
        else:
            raise typer.BadParameter("Input JSON must be an array of normalized events")

    if case_id is not None:
        events = [e for e in events if e.get("case_id") == case_id]

    timeline = build_timeline(events, gap_minutes=gap_minutes)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2)

    typer.echo(f"Timeline written: {output_file}")


if __name__ == "__main__":
    app()
