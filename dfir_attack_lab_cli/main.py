from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from normalizers.models import TriageEvent
from timelines.builder import build_timeline

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


@app.command("build-timeline")
def build_timeline_command(
    input_file: Path = typer.Argument(..., exists=True, readable=True, help="Path to normalized events JSON file"),
    output_file: Path = typer.Option(
        Path("timeline.txt"),
        "--output",
        "-o",
        help="Path to timeline text output",
    ),
    json_output: Path | None = typer.Option(
        None,
        "--json-output",
        help="Optional path to write timeline and gap metadata as JSON",
    ),
) -> None:
    """Build a chronological timeline from normalized events with gap detection."""
    raw = json.loads(input_file.read_text(encoding="utf-8"))

    events: list[TriageEvent] = []
    for item in raw:
        if isinstance(item, dict):
            events.append(TriageEvent(**item))

    timeline = build_timeline(events)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(timeline.lines), encoding="utf-8")

    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "timeline": {
                "events": [
                    {
                        "timestamp": e.timestamp.isoformat() if hasattr(e.timestamp, "isoformat") else str(e.timestamp),
                        "host": getattr(e, "host", None),
                        "source": getattr(e, "source", None),
                        "event_type": getattr(e, "event_type", None),
                        "severity": getattr(e, "severity", None),
                        "message": getattr(e, "message", None),
                        "raw": getattr(e, "raw", None),
                    }
                    for e in timeline.events
                ],
                "gaps": [
                    {
                        "start": g.start.isoformat() if hasattr(g.start, "isoformat") else str(g.start),
                        "end": g.end.isoformat() if hasattr(g.end, "isoformat") else str(g.end),
                        "duration_seconds": g.duration_seconds,
                    }
                    for g in timeline.gaps
                ],
            },
        }
        json_output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    typer.echo(f"Timeline written to: {output_file}")
    if json_output is not None:
        typer.echo(f"Timeline JSON written to: {json_output}")
