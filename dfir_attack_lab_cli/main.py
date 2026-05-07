from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log
from parsers.windows_evtx import parse_windows_evtx

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


@app.command("parse-logs")
def parse_logs(
    parser: str = typer.Option(..., "--parser", help="Parser to use: authlog|windows-evtx"),
    input_path: Path = typer.Option(..., "--input", exists=True, readable=True, help="Input log file"),
    output_path: Path = typer.Option(..., "--output", help="Output JSONL file"),
    strict_schema: bool = typer.Option(
        False,
        "--strict-schema",
        help="Validate each normalized TriageEvent and fail fast on first invalid record.",
    ),
) -> None:
    parser_name = parser.strip().lower()

    if parser_name == "authlog":
        records = parse_auth_log(input_path)
    elif parser_name in {"windows-evtx", "windows_evtx", "evtx"}:
        records = parse_windows_evtx(input_path)
    else:
        raise typer.BadParameter(f"Unsupported parser: {parser}")

    with output_path.open("w", encoding="utf-8") as f:
        for idx, record in enumerate(records):
            payload: dict[str, Any]
            if isinstance(record, TriageEvent):
                if strict_schema:
                    try:
                        # Re-validate model explicitly to ensure strict mode catches malformed objects.
                        TriageEvent.model_validate(record.model_dump())
                    except Exception as exc:  # pragma: no cover - defensive
                        typer.echo(
                            f"Schema validation failed for parser '{parser_name}' at record index {idx}: {exc}",
                            err=True,
                        )
                        raise typer.Exit(code=1)
                payload = record.model_dump(mode="json")
            else:
                if strict_schema:
                    try:
                        validated = TriageEvent.model_validate(record)
                    except Exception as exc:
                        typer.echo(
                            f"Schema validation failed for parser '{parser_name}' at record index {idx}: {exc}",
                            err=True,
                        )
                        raise typer.Exit(code=1)
                    payload = validated.model_dump(mode="json")
                else:
                    payload = record if isinstance(record, dict) else {"raw": str(record)}

            f.write(json.dumps(payload, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    app()
