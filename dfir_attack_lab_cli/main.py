from __future__ import annotations

import json
from pathlib import Path

import typer

from collectors.linux.triage import collect_linux_triage

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


@app.command("collect-linux")
def collect_linux(
    output_dir: Path = typer.Option(..., "--output-dir", help="Output directory for collected artifacts"),
    case_id: str | None = typer.Option(
        None,
        "--case-id",
        help="Optional case identifier to embed in collection metadata/manifests",
    ),
) -> None:
    """Run read-only Linux triage collection."""
    output_dir.mkdir(parents=True, exist_ok=True)
    result = collect_linux_triage(output_dir=output_dir, case_id=case_id)
    typer.echo(json.dumps(result, indent=2))
