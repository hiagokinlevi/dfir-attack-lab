import json
from pathlib import Path

import click

from timelines.builder import build_timeline


@click.group()
def cli() -> None:
    pass


@cli.command("build-timeline")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--fail-on-gaps",
    is_flag=True,
    default=False,
    help="Exit with non-zero status when one or more timeline gaps are detected.",
)
def build_timeline_cmd(input_path: Path, output_path: Path, fail_on_gaps: bool) -> None:
    """Build a chronological timeline from normalized events."""
    with input_path.open("r", encoding="utf-8") as f:
        events = json.load(f)

    result = build_timeline(events)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    meta = result.get("metadata", {}) if isinstance(result, dict) else {}
    gap_count = meta.get("gap_count")
    if gap_count is None:
        gaps = result.get("gaps", []) if isinstance(result, dict) else []
        gap_count = len(gaps) if isinstance(gaps, list) else 0

    if fail_on_gaps and gap_count > 0:
        raise click.ClickException(f"Timeline gap detection found {gap_count} gap(s); failing due to --fail-on-gaps.")


if __name__ == "__main__":
    cli()
