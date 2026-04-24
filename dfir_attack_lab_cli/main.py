from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import typer

from timelines.builder import build_timeline

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


def _parse_iso8601(value: str, flag_name: str) -> datetime:
    """Parse ISO-8601 timestamp strictly and raise a user-friendly CLI error."""
    try:
        normalized = value.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception as exc:  # pragma: no cover - defensive
        raise typer.BadParameter(
            f"Invalid {flag_name} timestamp '{value}'. Expected strict ISO-8601 format (e.g. 2026-01-31T14:30:00+00:00)."
        ) from exc


@app.command("build-timeline")
def build_timeline_cmd(
    input_path: Path = typer.Option(..., "--input", exists=True, readable=True, resolve_path=True),
    output_path: Path = typer.Option(..., "--output", resolve_path=True),
    gap_minutes: int = typer.Option(30, "--gap-minutes", min=1),
    since: str | None = typer.Option(None, "--since", help="Inclusive lower time bound (ISO-8601)."),
    until: str | None = typer.Option(None, "--until", help="Inclusive upper time bound (ISO-8601)."),
) -> None:
    events: list[dict[str, Any]] = json.loads(input_path.read_text(encoding="utf-8"))

    since_dt = _parse_iso8601(since, "--since") if since else None
    until_dt = _parse_iso8601(until, "--until") if until else None

    if since_dt and until_dt and since_dt > until_dt:
        raise typer.BadParameter("Invalid time window: --since must be less than or equal to --until.")

    if since_dt or until_dt:
        filtered: list[dict[str, Any]] = []
        for event in events:
            ts_raw = event.get("timestamp")
            if not isinstance(ts_raw, str):
                continue
            event_dt = _parse_iso8601(ts_raw, "event timestamp")
            if since_dt and event_dt < since_dt:
                continue
            if until_dt and event_dt > until_dt:
                continue
            filtered.append(event)
        events = filtered

    timeline = build_timeline(events, gap_minutes=gap_minutes)
    output_path.write_text(json.dumps(timeline, indent=2), encoding="utf-8")


if __name__ == "__main__":
    app()
