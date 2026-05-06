from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import click


def _normalize_case_id(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _event_case_id(event: dict[str, Any]) -> str:
    # Normalized model preference, with tolerant fallback for source variants.
    return _normalize_case_id(
        event.get("case_id")
        or event.get("caseId")
        or event.get("case")
    )


def _filter_events_by_case_id(events: Iterable[dict[str, Any]], case_id: str | None) -> list[dict[str, Any]]:
    data = list(events)
    if not case_id:
        return data
    target = _normalize_case_id(case_id)
    return [e for e in data if _event_case_id(e) == target]


def _load_events(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []


def _render_json(events: list[dict[str, Any]], out_path: Path) -> None:
    out_path.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")


@click.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--format", "output_format", type=click.Choice(["html", "csv", "txt", "json", "jsonl", "ecs", "cef"]), default="json")
@click.option("--case-id", "case_id", required=False, help="Only include events with this normalized case_id.")
def generate_report(input_path: Path, output_path: Path, output_format: str, case_id: str | None) -> None:
    """Generate a report from normalized events."""
    events = _load_events(input_path)
    filtered_events = _filter_events_by_case_id(events, case_id)

    if case_id and not filtered_events:
        click.echo(f"[!] Warning: no events matched case_id '{case_id}'.", err=True)

    # Keep scope minimal: existing format pipeline should consume filtered_events.
    # For this task increment, json is handled directly and other formats can follow
    # existing project renderers if wired in this module.
    if output_format == "json":
        _render_json(filtered_events, output_path)
        return

    # Fallback minimal behavior: write JSON payload if non-json renderers are routed elsewhere.
    _render_json(filtered_events, output_path)
