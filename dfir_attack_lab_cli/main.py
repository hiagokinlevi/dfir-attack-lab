from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import typer

app = typer.Typer(help="k1n DFIR Attack Lab CLI")


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def _build_summary(events: list[dict[str, Any]], detected_gap_count: int | None = None) -> dict[str, Any]:
    severity = Counter()
    category = Counter()
    source_parser = Counter()
    timestamps: list[datetime] = []

    for ev in events:
        severity[str(ev.get("severity", "unknown"))] += 1
        category[str(ev.get("category", "unknown"))] += 1
        source_parser[str(ev.get("source_parser", ev.get("parser", "unknown")))] += 1
        ts = _parse_ts(ev.get("timestamp"))
        if ts is not None:
            timestamps.append(ts)

    first_ts = min(timestamps).isoformat() if timestamps else None
    last_ts = max(timestamps).isoformat() if timestamps else None

    return {
        "total_events": len(events),
        "by_severity": dict(severity),
        "by_category": dict(category),
        "by_source_parser": dict(source_parser),
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "detected_gap_count": int(detected_gap_count or 0),
    }


def _emit_report(
    events: list[dict[str, Any]],
    out_file: Path,
    fmt: str,
    summary_only: bool = False,
    detected_gap_count: int | None = None,
) -> None:
    summary = _build_summary(events, detected_gap_count=detected_gap_count)

    if fmt == "json":
        payload: dict[str, Any] = {"summary": summary}
        if not summary_only:
            payload["events"] = events
        out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return

    if fmt == "jsonl":
        lines: list[str] = [json.dumps({"type": "summary", "data": summary})]
        if not summary_only:
            lines.extend(json.dumps({"type": "event", "data": ev}) for ev in events)
        out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    if fmt == "csv":
        with out_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["section", "key", "value"])
            writer.writerow(["summary", "total_events", summary["total_events"]])
            writer.writerow(["summary", "first_timestamp", summary["first_timestamp"] or ""])
            writer.writerow(["summary", "last_timestamp", summary["last_timestamp"] or ""])
            writer.writerow(["summary", "detected_gap_count", summary["detected_gap_count"]])
            for k, v in summary["by_severity"].items():
                writer.writerow(["by_severity", k, v])
            for k, v in summary["by_category"].items():
                writer.writerow(["by_category", k, v])
            for k, v in summary["by_source_parser"].items():
                writer.writerow(["by_source_parser", k, v])

            if not summary_only:
                writer.writerow([])
                event_keys = sorted({k for ev in events for k in ev.keys()})
                writer.writerow(["events", *event_keys])
                for ev in events:
                    writer.writerow(["event", *[ev.get(k, "") for k in event_keys]])
        return

    if fmt == "txt":
        lines = [
            "=== Incident Summary ===",
            f"Total events: {summary['total_events']}",
            f"First timestamp: {summary['first_timestamp']}",
            f"Last timestamp: {summary['last_timestamp']}",
            f"Detected gap count: {summary['detected_gap_count']}",
            "",
            "By severity:",
        ]
        lines.extend([f"- {k}: {v}" for k, v in summary["by_severity"].items()])
        lines.append("By category:")
        lines.extend([f"- {k}: {v}" for k, v in summary["by_category"].items()])
        lines.append("By source parser:")
        lines.extend([f"- {k}: {v}" for k, v in summary["by_source_parser"].items()])

        if not summary_only:
            lines.append("")
            lines.append("=== Events ===")
            lines.extend([json.dumps(ev, ensure_ascii=False) for ev in events])

        out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    if fmt == "html":
        html = [
            "<html><head><meta charset='utf-8'><title>DFIR Report</title></head><body>",
            "<h1>Incident Summary</h1>",
            f"<p><strong>Total events:</strong> {summary['total_events']}</p>",
            f"<p><strong>First timestamp:</strong> {summary['first_timestamp'] or ''}</p>",
            f"<p><strong>Last timestamp:</strong> {summary['last_timestamp'] or ''}</p>",
            f"<p><strong>Detected gap count:</strong> {summary['detected_gap_count']}</p>",
            "<h2>By Severity</h2><ul>",
        ]
        html.extend([f"<li>{k}: {v}</li>" for k, v in summary["by_severity"].items()])
        html.append("</ul><h2>By Category</h2><ul>")
        html.extend([f"<li>{k}: {v}</li>" for k, v in summary["by_category"].items()])
        html.append("</ul><h2>By Source Parser</h2><ul>")
        html.extend([f"<li>{k}: {v}</li>" for k, v in summary["by_source_parser"].items()])
        html.append("</ul>")

        if not summary_only:
            html.append("<h2>Events</h2><table border='1'><thead><tr>")
            event_keys = sorted({k for ev in events for k in ev.keys()})
            html.extend([f"<th>{k}</th>" for k in event_keys])
            html.append("</tr></thead><tbody>")
            for ev in events:
                html.append("<tr>")
                html.extend([f"<td>{ev.get(k, '')}</td>" for k in event_keys])
                html.append("</tr>")
            html.append("</tbody></table>")

        html.append("</body></html>")
        out_file.write_text("".join(html), encoding="utf-8")
        return

    raise typer.BadParameter(f"Unsupported format: {fmt}")


@app.command("generate-report")
def generate_report(
    input_file: Path = typer.Option(..., "--input", exists=True, readable=True),
    output_file: Path = typer.Option(..., "--output"),
    fmt: str = typer.Option("json", "--format"),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        help="Emit only aggregated incident summary (no per-event rows).",
    ),
) -> None:
    data = json.loads(input_file.read_text(encoding="utf-8"))
    events = data.get("events", data if isinstance(data, list) else [])
    detected_gap_count = data.get("detected_gap_count", data.get("gap_count", 0)) if isinstance(data, dict) else 0
    _emit_report(events=events, out_file=output_file, fmt=fmt.lower(), summary_only=summary_only, detected_gap_count=detected_gap_count)


if __name__ == "__main__":
    app()
