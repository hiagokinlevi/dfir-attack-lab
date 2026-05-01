from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from normalizers.models import TriageEvent
from parsers.authlog import parse_auth_log

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


@app.command("parse-logs")
def parse_logs(
    source: Path = typer.Argument(..., exists=True, readable=True, help="Path to raw log file"),
    output: Path = typer.Option(..., "--output", "-o", help="Path to output JSONL file"),
    user: Optional[str] = typer.Option(
        None,
        "--user",
        help="Filter Linux auth events by target/account username",
    ),
) -> None:
    """Parse raw logs into normalized TriageEvent JSONL."""

    # Current roadmap scope: Linux auth.log / secure parser path
    events = parse_auth_log(str(source), user=user)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for event in events:
            if isinstance(event, TriageEvent):
                fh.write(json.dumps(event.model_dump(mode="json"), ensure_ascii=False) + "\n")
            else:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    app()
