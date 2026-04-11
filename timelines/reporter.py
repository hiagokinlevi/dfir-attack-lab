"""
Incident Timeline Reporter
===========================
Filters, summarizes, and exports an incident timeline to multiple formats.

Supported export formats:
  - JSONL: one JSON object per line (machine-readable, for SIEM ingestion)
  - ECS:   Elastic Common Schema NDJSON for SIEM import
  - CEF:   Common Event Format lines for Microsoft Sentinel or ArcSight ingestion
  - JSON:  full timeline array in a single JSON document
  - HTML:  self-contained HTML report for human review (no external dependencies)
  - CSV:   flattened rows suitable for spreadsheets and ticket attachments
  - TXT:   plain-text table for terminal/paste into incident tickets

Filtering options:
  - by_severity:   Include only events at or above a given SeverityHint level
  - by_category:   Include only events from specified EventCategory values
  - by_time_range: Include only events within a UTC datetime range
  - exclude_gaps:  Strip gap markers from the output (default: False)

Usage:
    from timelines.builder import build_timeline
    from timelines.reporter import filter_timeline, export_timeline

    timeline = build_timeline(events)

    # Filter to high-severity authentication events only
    filtered = filter_timeline(
        timeline,
        by_severity="high",
        by_category=["authentication", "privilege_escalation"],
    )

    # Export as self-contained HTML report
    export_timeline(filtered, output_path=Path("report.html"), fmt="html")
"""
from __future__ import annotations

import csv
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from normalizers.models import SeverityHint, EventCategory


# Severity order for filtering (higher index = higher severity)
_SEVERITY_ORDER: dict[str, int] = {
    SeverityHint.INFO.value:   0,
    SeverityHint.LOW.value:    1,
    SeverityHint.MEDIUM.value: 2,
    SeverityHint.HIGH.value:   3,
}


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def filter_timeline(
    timeline: list[dict],
    by_severity: Optional[str] = None,
    by_category: Optional[list[str]] = None,
    by_time_range: Optional[tuple[datetime, datetime]] = None,
    exclude_gaps: bool = False,
) -> list[dict]:
    """
    Filter a timeline produced by build_timeline().

    Args:
        timeline:       Output of build_timeline().
        by_severity:    Minimum severity level to include: "info", "low",
                        "medium", or "high". Events below this threshold
                        are excluded. Gap markers are unaffected.
        by_category:    List of EventCategory string values to include
                        (e.g. ["authentication", "privilege_escalation"]).
                        If None, all categories are included.
        by_time_range:  Tuple of (start, end) UTC datetime objects.
                        Only events whose timestamp falls within [start, end]
                        are included.
        exclude_gaps:   If True, gap markers are removed from the output.

    Returns:
        Filtered list of timeline entries.
    """
    result: list[dict] = []
    min_severity = _SEVERITY_ORDER.get(by_severity or "info", 0)

    for entry in timeline:
        # --- Gap markers ---
        if entry.get("_type") == "gap":
            if not exclude_gaps:
                result.append(entry)
            continue

        # --- Severity filter ---
        entry_severity = _SEVERITY_ORDER.get(entry.get("severity", "info"), 0)
        if entry_severity < min_severity:
            continue

        # --- Category filter ---
        if by_category is not None:
            if entry.get("category") not in by_category:
                continue

        # --- Time range filter ---
        if by_time_range is not None:
            start_dt, end_dt = by_time_range
            ts_str = entry.get("timestamp")
            if ts_str:
                try:
                    # Python 3.9 fromisoformat does not accept the 'Z' suffix.
                    # Normalize it to '+00:00' for cross-version compatibility.
                    ts_normalized = ts_str.replace("Z", "+00:00") if ts_str.endswith("Z") else ts_str
                    ts = datetime.fromisoformat(ts_normalized)
                    # Normalize to UTC if naive
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if not (start_dt <= ts <= end_dt):
                        continue
                except (ValueError, TypeError):
                    pass  # Cannot parse timestamp — include the entry

        result.append(entry)

    return result


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def summarize_timeline(timeline: list[dict]) -> dict:
    """
    Compute a summary of a (possibly filtered) timeline.

    Returns:
        dict with keys: total_events, gap_count, by_severity, by_category,
        first_event_at, last_event_at, total_gap_minutes.
    """
    events = [e for e in timeline if e.get("_type") != "gap"]
    gaps   = [e for e in timeline if e.get("_type") == "gap"]

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    timestamps: list[str] = []

    for entry in events:
        sev = entry.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        cat = entry.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

        if entry.get("timestamp"):
            timestamps.append(entry["timestamp"])

    timestamps.sort()
    total_gap_minutes = sum(g.get("duration_minutes", 0) for g in gaps)

    return {
        "total_events":      len(events),
        "gap_count":         len(gaps),
        "by_severity":       by_severity,
        "by_category":       by_category,
        "first_event_at":    timestamps[0] if timestamps else None,
        "last_event_at":     timestamps[-1] if timestamps else None,
        "total_gap_minutes": round(total_gap_minutes, 1),
    }


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_timeline(
    timeline: list[dict],
    output_path: Path,
    fmt: str = "jsonl",
    case_id: str = "unknown",
) -> Path:
    """
    Export a timeline to the specified format.

    Args:
        timeline:     Timeline entries (output of build_timeline or filter_timeline).
        output_path:  Destination file path.
        fmt:          Export format: "jsonl", "ecs", "cef", "json", "html", "csv", or "txt".
        case_id:      Case identifier for report headers.

    Returns:
        The output_path that was written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "jsonl":
        _export_jsonl(timeline, output_path)
    elif fmt == "ecs":
        _export_ecs_ndjson(timeline, output_path, case_id)
    elif fmt == "cef":
        _export_cef(timeline, output_path, case_id)
    elif fmt == "json":
        _export_json(timeline, output_path, case_id)
    elif fmt == "html":
        _export_html(timeline, output_path, case_id)
    elif fmt == "csv":
        _export_csv(timeline, output_path)
    elif fmt == "txt":
        _export_txt(timeline, output_path, case_id)
    else:
        raise ValueError(f"Unknown export format: '{fmt}'. Use: jsonl, ecs, cef, json, html, csv, txt")

    return output_path


def _export_jsonl(timeline: list[dict], path: Path) -> None:
    """Write one JSON object per line."""
    with path.open("w", encoding="utf-8") as fh:
        for entry in timeline:
            fh.write(json.dumps(entry) + "\n")


def _ecs_severity(severity: str) -> int:
    """Map the toolkit's severity hints to ECS-compatible numeric severity."""
    return {
        "info": 1,
        "low": 21,
        "medium": 47,
        "high": 73,
    }.get(severity, 1)


def _ecs_category(category: str) -> list[str]:
    """Map normalized DFIR categories into broad ECS event.category values."""
    return {
        "authentication": ["authentication"],
        "network": ["network"],
        "process": ["process"],
        "filesystem": ["file"],
        "privilege_escalation": ["iam"],
        "system": ["configuration"],
        "unknown": ["intrusion_detection"],
    }.get(category, ["intrusion_detection"])


def _actor_fields(actor: str | None) -> dict:
    """Represent an actor as source.ip when it parses as an IP, else user.name."""
    if not actor:
        return {}
    try:
        ipaddress.ip_address(actor)
    except ValueError:
        return {"user": {"name": actor}}
    return {"source": {"ip": actor}, "related": {"ip": [actor]}}


def _timeline_entry_to_ecs(entry: dict, case_id: str) -> dict:
    """Convert one timeline entry into an ECS-oriented event document."""
    if entry.get("_type") == "gap":
        return {
            "@timestamp": entry.get("end"),
            "ecs": {"version": "8.11.0"},
            "event": {
                "kind": "state",
                "category": ["configuration"],
                "type": ["info"],
                "action": "timeline_gap",
                "reason": "No timeline events were observed between adjacent evidence entries.",
                "duration": int(float(entry.get("duration_minutes", 0)) * 60_000_000_000),
            },
            "labels": {"case_id": case_id},
            "dfir": {
                "gap_start": entry.get("start"),
                "gap_end": entry.get("end"),
                "gap_minutes": entry.get("duration_minutes"),
            },
            "observer": {"product": "k1n-dfir-attack-lab"},
        }

    severity = entry.get("severity", "info")
    category = entry.get("category", "unknown")
    doc = {
        "@timestamp": entry.get("timestamp"),
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "event",
            "category": _ecs_category(category),
            "type": ["info"],
            "action": entry.get("action"),
            "severity": _ecs_severity(severity),
            "risk_score": _ecs_severity(severity),
            "original": entry.get("raw"),
        },
        "message": entry.get("raw"),
        "log": {"file": {"path": entry.get("source_file")}},
        "labels": {"case_id": case_id, "dfir_category": category},
        "observer": {"product": "k1n-dfir-attack-lab"},
        "dfir": {"target": entry.get("target"), "metadata": entry.get("metadata", {})},
    }
    doc.update(_actor_fields(entry.get("actor")))
    if entry.get("target"):
        doc["related"] = {**doc.get("related", {}), "hosts": [entry["target"]]}
    return doc


def _export_ecs_ndjson(timeline: list[dict], path: Path, case_id: str) -> None:
    """Write Elastic Common Schema-oriented NDJSON for SIEM import."""
    with path.open("w", encoding="utf-8") as fh:
        for entry in timeline:
            fh.write(json.dumps(_timeline_entry_to_ecs(entry, case_id), sort_keys=True) + "\n")


def _cef_severity(severity: str) -> int:
    """Map the toolkit's severity hints to CEF-compatible numeric severity."""
    return {
        "info": 1,
        "low": 3,
        "medium": 6,
        "high": 8,
    }.get(severity, 1)


def _escape_cef_header(value: object) -> str:
    """Escape CEF header values."""
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _escape_cef_extension(value: object) -> str:
    """Escape CEF extension values."""
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _cef_timestamp_millis(value: str | None) -> int | None:
    """Convert an ISO 8601 timestamp string into epoch milliseconds."""
    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
        timestamp = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)
    return int(timestamp.timestamp() * 1000)


def _build_cef_line(
    signature_id: str,
    name: str,
    severity: str,
    extension_fields: list[tuple[str, object]],
) -> str:
    """Build a single Common Event Format line."""
    header = [
        "CEF:0",
        _escape_cef_header("k1n"),
        _escape_cef_header("dfir-attack-lab"),
        _escape_cef_header("0.1.0"),
        _escape_cef_header(signature_id),
        _escape_cef_header(name),
        str(_cef_severity(severity)),
    ]
    extension = " ".join(
        f"{key}={_escape_cef_extension(value)}"
        for key, value in extension_fields
        if value not in (None, "")
    )
    return "|".join(header) + f"|{extension}"


def _timeline_entry_to_cef(entry: dict, case_id: str) -> str:
    """Convert one timeline entry into a CEF log line."""
    if entry.get("_type") == "gap":
        extension_fields: list[tuple[str, object]] = [
            ("deviceExternalId", case_id),
            ("cat", "timeline_gap"),
            ("act", "timeline_gap"),
            ("msg", "No timeline events were observed between adjacent evidence entries."),
            ("cn1Label", "gapMinutes"),
            ("cn1", entry.get("duration_minutes")),
            ("cs1Label", "gapStart"),
            ("cs1", entry.get("start")),
            ("cs2Label", "gapEnd"),
            ("cs2", entry.get("end")),
        ]
        if (timestamp_ms := _cef_timestamp_millis(entry.get("end"))) is not None:
            extension_fields.insert(1, ("rt", timestamp_ms))
        return _build_cef_line("timeline_gap", "Timeline Gap", "low", extension_fields)

    severity = entry.get("severity", "info")
    category = entry.get("category", "unknown")
    action = entry.get("action") or "timeline_event"
    extension_fields = [
        ("deviceExternalId", case_id),
        ("cat", category),
        ("act", action),
        ("fname", entry.get("source_file")),
        ("msg", entry.get("raw")),
    ]
    if (timestamp_ms := _cef_timestamp_millis(entry.get("timestamp"))) is not None:
        extension_fields.append(("rt", timestamp_ms))

    actor = entry.get("actor")
    if actor:
        try:
            ipaddress.ip_address(actor)
        except ValueError:
            extension_fields.append(("suser", actor))
        else:
            extension_fields.append(("src", actor))

    if entry.get("target"):
        extension_fields.append(("dhost", entry["target"]))
    if entry.get("metadata"):
        extension_fields.extend(
            [
                ("cs1Label", "dfirMetadata"),
                ("cs1", json.dumps(entry["metadata"], sort_keys=True)),
            ]
        )

    return _build_cef_line(action, f"{category}:{action}", severity, extension_fields)


def _export_cef(timeline: list[dict], path: Path, case_id: str) -> None:
    """Write Common Event Format lines for SIEM connectors such as Sentinel."""
    with path.open("w", encoding="utf-8") as fh:
        for entry in timeline:
            fh.write(_timeline_entry_to_cef(entry, case_id) + "\n")


def _export_json(timeline: list[dict], path: Path, case_id: str) -> None:
    """Write full timeline as a single JSON document with a summary header."""
    summary = summarize_timeline(timeline)
    doc = {
        "case_id":   case_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "summary":   summary,
        "timeline":  timeline,
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def _severity_badge_color(severity: str) -> str:
    """Return a CSS color class for the severity badge."""
    return {
        "high":   "#c0392b",
        "medium": "#e67e22",
        "low":    "#2980b9",
        "info":   "#7f8c8d",
    }.get(severity, "#7f8c8d")


def _export_html(timeline: list[dict], path: Path, case_id: str) -> None:
    """
    Generate a self-contained HTML incident timeline report.

    No external CSS or JS dependencies — the file is portable and can be
    attached to incident tickets or opened offline.
    """
    summary = summarize_timeline(timeline)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rows: list[str] = []
    for entry in timeline:
        if entry.get("_type") == "gap":
            rows.append(
                f'<tr class="gap"><td colspan="6">'
                f'⚠ GAP: {entry["duration_minutes"]} min missing '
                f'({entry["start"]} → {entry["end"]})</td></tr>'
            )
            continue

        severity = entry.get("severity", "info")
        color = _severity_badge_color(severity)
        badge = (
            f'<span style="background:{color};color:#fff;padding:2px 6px;'
            f'border-radius:3px;font-size:0.8em;">{severity.upper()}</span>'
        )
        raw_escaped = (entry.get("raw", "") or "")[:120].replace("<", "&lt;").replace(">", "&gt;")
        rows.append(
            f"<tr>"
            f"<td>{entry.get('timestamp', '')}</td>"
            f"<td>{badge}</td>"
            f"<td>{entry.get('category', '')}</td>"
            f"<td>{entry.get('actor') or ''}</td>"
            f"<td>{entry.get('action', '')}</td>"
            f"<td><code>{raw_escaped}</code></td>"
            f"</tr>"
        )

    rows_html = "\n".join(rows)
    sev_summary = " | ".join(
        f"{k}: {v}" for k, v in sorted(summary["by_severity"].items())
    )
    cat_summary = " | ".join(
        f"{k}: {v}" for k, v in sorted(summary["by_category"].items())
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Incident Timeline — {case_id}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2rem; background: #f5f6fa; color: #2c3e50; }}
  h1 {{ color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 0.5rem; }}
  .meta {{ background: #ecf0f1; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.9em; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 6px; overflow: hidden;
           box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
  th {{ background: #2c3e50; color: #fff; padding: 0.6rem 1rem; text-align: left; }}
  td {{ padding: 0.5rem 1rem; border-bottom: 1px solid #ecf0f1; vertical-align: top; font-size: 0.9em; }}
  tr.gap td {{ background: #fff3cd; color: #856404; font-style: italic; text-align: center; }}
  tr:hover:not(.gap) {{ background: #f8f9fa; }}
  code {{ font-family: 'Courier New', monospace; font-size: 0.85em; color: #555; }}
  .footer {{ margin-top: 1.5rem; font-size: 0.8em; color: #7f8c8d; text-align: center; }}
</style>
</head>
<body>
<h1>Incident Timeline — <code>{case_id}</code></h1>
<div class="meta">
  <strong>Generated:</strong> {generated_at} &nbsp;|&nbsp;
  <strong>Events:</strong> {summary['total_events']} &nbsp;|&nbsp;
  <strong>Gaps:</strong> {summary['gap_count']} ({summary['total_gap_minutes']} min total)<br>
  <strong>Severity:</strong> {sev_summary or 'n/a'}<br>
  <strong>Category:</strong> {cat_summary or 'n/a'}
</div>
<table>
  <thead>
    <tr>
      <th>Timestamp</th>
      <th>Severity</th>
      <th>Category</th>
      <th>Actor</th>
      <th>Action</th>
      <th>Raw (truncated)</th>
    </tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>
<div class="footer">
  Generated by dfir-attack-lab timeline reporter &mdash;
  <a href="https://github.com/hiagokinlevi/dfir-attack-lab">Cyber Portfolio</a>
</div>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")


def _export_csv(timeline: list[dict], path: Path) -> None:
    """Write a flattened CSV export for spreadsheet-friendly review."""
    fieldnames = [
        "entry_type",
        "timestamp",
        "severity",
        "category",
        "actor",
        "target",
        "action",
        "source_file",
        "raw",
        "metadata",
        "gap_start",
        "gap_end",
        "duration_minutes",
    ]

    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        for entry in timeline:
            if entry.get("_type") == "gap":
                writer.writerow(
                    {
                        "entry_type": "gap",
                        "gap_start": entry.get("start"),
                        "gap_end": entry.get("end"),
                        "duration_minutes": entry.get("duration_minutes"),
                    }
                )
                continue

            writer.writerow(
                {
                    "entry_type": "event",
                    "timestamp": entry.get("timestamp"),
                    "severity": entry.get("severity"),
                    "category": entry.get("category"),
                    "actor": entry.get("actor"),
                    "target": entry.get("target"),
                    "action": entry.get("action"),
                    "source_file": entry.get("source_file"),
                    "raw": entry.get("raw"),
                    "metadata": json.dumps(entry.get("metadata", {}), sort_keys=True),
                }
            )


def _export_txt(timeline: list[dict], path: Path, case_id: str) -> None:
    """Write a plain-text timeline table suitable for terminal or ticket paste."""
    summary = summarize_timeline(timeline)
    lines: list[str] = [
        f"INCIDENT TIMELINE — {case_id}",
        f"{'=' * 60}",
        f"Events: {summary['total_events']}  "
        f"Gaps: {summary['gap_count']} ({summary['total_gap_minutes']} min)",
        f"{'=' * 60}",
        "",
    ]

    for entry in timeline:
        if entry.get("_type") == "gap":
            lines.append(
                f"  *** GAP {entry['duration_minutes']} min: "
                f"{entry['start']} → {entry['end']} ***"
            )
            lines.append("")
            continue

        ts       = entry.get("timestamp", "?")[:19]
        severity = (entry.get("severity") or "info").upper()[:4]
        category = (entry.get("category") or "?")[:14]
        actor    = (entry.get("actor") or "-")[:20]
        action   = (entry.get("action") or "?")[:30]
        lines.append(
            f"[{ts}] [{severity:<4}] [{category:<14}] {actor:<20} {action}"
        )

    lines.append("")
    lines.append(f"End of timeline — {len(timeline)} entries")

    path.write_text("\n".join(lines), encoding="utf-8")
