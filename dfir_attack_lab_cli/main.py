from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from case.packager import package_case, verify_case
from collectors.linux.triage import collect_linux_triage
from collectors.macos.triage import collect_macos_triage
from collectors.windows.triage import collect_windows_triage
from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log
from parsers.windows_evtx import parse_windows_security_evtx
from timelines.builder import build_timeline

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


def _load_events(input_path: Path) -> list[TriageEvent]:
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    return [TriageEvent(**event) if not isinstance(event, TriageEvent) else event for event in raw]


@app.command("collect-linux")
def collect_linux(output: Path = typer.Option(..., "--output", "-o", help="Output JSON file path")) -> None:
    data = collect_linux_triage()
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"Linux triage written to {output}")


@app.command("collect-windows")
def collect_windows(output: Path = typer.Option(..., "--output", "-o", help="Output JSON file path")) -> None:
    data = collect_windows_triage()
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"Windows triage written to {output}")


@app.command("collect-macos")
def collect_macos(output: Path = typer.Option(..., "--output", "-o", help="Output JSON file path")) -> None:
    data = collect_macos_triage()
    output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"macOS triage written to {output}")


@app.command("parse-logs")
def parse_logs(
    source: str = typer.Option(..., "--source", help="Log source type: authlog|windows-evtx"),
    input_path: Path = typer.Option(..., "--input", "-i", help="Input log file"),
    output: Path = typer.Option(..., "--output", "-o", help="Output JSON events file"),
) -> None:
    if source == "authlog":
        events = parse_auth_log(input_path)
    elif source == "windows-evtx":
        events = parse_windows_security_evtx(input_path)
    else:
        raise typer.BadParameter("Unsupported source. Use authlog or windows-evtx.")

    output.write_text(json.dumps([e.model_dump() for e in events], indent=2), encoding="utf-8")
    typer.echo(f"Parsed {len(events)} events to {output}")


@app.command("build-timeline")
def build_timeline_command(
    input_path: Path = typer.Option(..., "--input", "-i", help="Input normalized events JSON"),
    output: Path = typer.Option(..., "--output", "-o", help="Output timeline JSON"),
    gap_minutes: int = typer.Option(30, "--gap-minutes", help="Gap threshold in minutes"),
    sort_desc: bool = typer.Option(False, "--sort-desc", help="Sort newest first"),
) -> None:
    events = _load_events(input_path)
    timeline = build_timeline(events, gap_minutes=gap_minutes, reverse=sort_desc)
    output.write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    typer.echo(f"Timeline written to {output}")


@app.command("package-case")
def package_case_command(
    input_dir: Path = typer.Option(..., "--input-dir", help="Directory containing collected artifacts"),
    output_case: Path = typer.Option(..., "--output", "-o", help="Output case archive path"),
) -> None:
    package_case(input_dir, output_case)
    typer.echo(f"Case package written to {output_case}")


@app.command("verify-case")
def verify_case_command(
    case_path: Path = typer.Option(..., "--input", "-i", help="Input case archive path"),
) -> None:
    result: dict[str, Any] = verify_case(case_path)
    typer.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
