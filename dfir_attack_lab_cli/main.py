from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional

import typer

from collectors.linux.triage import collect_linux_triage
from collectors.macos.triage import collect_macos_triage
from collectors.windows.triage import collect_windows_triage
from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_logs
from parsers.windows_evtx import parse_windows_security_xml
from timelines.builder import build_timeline

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


def _load_paths_from_file(path: Path) -> List[Path]:
    """Load newline-delimited artifact paths from a UTF-8 text file.

    Ignores blank lines and lines beginning with '#'.
    """
    raw = path.read_text(encoding="utf-8")
    items: List[Path] = []
    for line in raw.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        items.append(Path(candidate))
    return items


def _validate_readable_files(paths: Iterable[Path]) -> List[Path]:
    valid: List[Path] = []
    for p in paths:
        if not p.exists():
            typer.secho(f"[parse-logs] Skipping missing path: {p}", fg=typer.colors.YELLOW, err=True)
            continue
        if not p.is_file():
            typer.secho(f"[parse-logs] Skipping non-file path: {p}", fg=typer.colors.YELLOW, err=True)
            continue
        try:
            with p.open("rb"):
                pass
        except OSError as exc:
            typer.secho(
                f"[parse-logs] Skipping unreadable path: {p} ({exc})",
                fg=typer.colors.YELLOW,
                err=True,
            )
            continue
        valid.append(p)
    return valid


@app.command("collect-linux")
def collect_linux(output: Path = typer.Option(..., "--output", "-o", help="Output JSON file")) -> None:
    data = collect_linux_triage()
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"Linux triage written to {output}")


@app.command("collect-windows")
def collect_windows(output: Path = typer.Option(..., "--output", "-o", help="Output JSON file")) -> None:
    data = collect_windows_triage()
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"Windows triage written to {output}")


@app.command("collect-macos")
def collect_macos(output: Path = typer.Option(..., "--output", "-o", help="Output JSON file")) -> None:
    data = collect_macos_triage()
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"macOS triage written to {output}")


@app.command("parse-logs")
def parse_logs(
    inputs: List[Path] = typer.Argument(..., help="Input log files (auth.log/secure or Windows Security XML)"),
    output: Path = typer.Option(..., "--output", "-o", help="Output normalized events JSONL"),
    from_file: Optional[Path] = typer.Option(
        None,
        "--from-file",
        help="UTF-8 file containing additional input paths (one path per line; blank lines and # comments ignored)",
    ),
) -> None:
    all_inputs: List[Path] = list(inputs)

    if from_file is not None:
        if not from_file.exists() or not from_file.is_file():
            raise typer.BadParameter(f"--from-file path is not a readable file: {from_file}")
        try:
            additional = _load_paths_from_file(from_file)
        except OSError as exc:
            raise typer.BadParameter(f"Unable to read --from-file: {exc}") from exc
        all_inputs.extend(additional)

    valid_inputs = _validate_readable_files(all_inputs)
    if not valid_inputs:
        raise typer.BadParameter("No valid readable input files were provided.")

    events: List[TriageEvent] = []
    for path in valid_inputs:
        lower_name = path.name.lower()
        if lower_name.endswith(".xml"):
            events.extend(parse_windows_security_xml(path))
        else:
            events.extend(parse_auth_logs(path))

    with output.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(event.model_dump_json())
            fh.write("\n")

    typer.echo(f"Parsed {len(events)} events from {len(valid_inputs)} files into {output}")


@app.command("build-timeline")
def build_timeline_cmd(
    events_jsonl: Path = typer.Option(..., "--events", help="Normalized events JSONL"),
    output: Path = typer.Option(..., "--output", "-o", help="Output timeline JSON"),
    gap_minutes: int = typer.Option(60, "--gap-minutes", help="Gap threshold in minutes"),
) -> None:
    events: List[TriageEvent] = []
    with events_jsonl.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            events.append(TriageEvent.model_validate_json(line))

    timeline = build_timeline(events, gap_threshold_minutes=gap_minutes)
    output.write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    typer.echo(f"Timeline written to {output}")


if __name__ == "__main__":
    app()
