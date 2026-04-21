from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _to_dict(event: Any) -> Dict[str, Any]:
    """Convert an event object into a serializable dict.

    Supports dataclasses and plain dict-like objects.
    """
    if is_dataclass(event):
        return asdict(event)
    if isinstance(event, dict):
        return dict(event)
    if hasattr(event, "__dict__"):
        return dict(event.__dict__)
    raise TypeError(f"Unsupported event type: {type(event)!r}")


def _safe_iso(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    text = str(value)
    return text


def _extract_attack_tags(event: Dict[str, Any]) -> List[str]:
    candidates = []
    for key in ("attack_tags", "attack_techniques", "mitre_attack", "tags"):
        value = event.get(key)
        if isinstance(value, list):
            candidates.extend([str(v) for v in value if v is not None])
        elif isinstance(value, str) and value.strip():
            candidates.extend([v.strip() for v in value.split(",") if v.strip()])
    # normalize / dedupe preserving order
    seen = set()
    out: List[str] = []
    for tag in candidates:
        t = tag.strip()
        if not t:
            continue
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = value.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _event_timestamp(event: Dict[str, Any]) -> Optional[datetime]:
    for key in ("timestamp", "ts", "time", "event_time"):
        if key in event:
            ts = _parse_ts(str(event.get(key)))
            if ts:
                return ts
    return None


def filter_events(
    events: Iterable[Any],
    severity: Optional[str] = None,
    category: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    attack_only: bool = False,
) -> List[Dict[str, Any]]:
    """Filter normalized timeline events for export."""
    sev = severity.lower().strip() if severity else None
    cat = category.lower().strip() if category else None
    start_dt = _parse_ts(start)
    end_dt = _parse_ts(end)

    out: List[Dict[str, Any]] = []
    for raw in events:
        event = _to_dict(raw)

        if sev:
            ev_sev = str(event.get("severity", "")).lower().strip()
            if ev_sev != sev:
                continue

        if cat:
            ev_cat = str(event.get("category", "")).lower().strip()
            if ev_cat != cat:
                continue

        ts = _event_timestamp(event)
        if start_dt and ts and ts < start_dt:
            continue
        if end_dt and ts and ts > end_dt:
            continue

        if attack_only and not _extract_attack_tags(event):
            continue

        out.append(event)

    return out


def export_csv(events: Iterable[Any], output_path: str | Path) -> Path:
    rows = [_to_dict(e) for e in events]
    dst = Path(output_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        with dst.open("w", newline="", encoding="utf-8") as f:
            f.write("")
        return dst

    fields = sorted({k for row in rows for k in row.keys()})

    with dst.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            normalized = {}
            for k in fields:
                v = row.get(k)
                if isinstance(v, (dict, list)):
                    normalized[k] = json.dumps(v, ensure_ascii=False)
                else:
                    normalized[k] = _safe_iso(v)
            writer.writerow(normalized)

    return dst


def export_jsonl(events: Iterable[Any], output_path: str | Path) -> Path:
    dst = Path(output_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    with dst.open("w", encoding="utf-8") as f:
        for e in events:
            row = _to_dict(e)
            f.write(json.dumps(row, ensure_ascii=False, default=_safe_iso))
            f.write("\n")

    return dst


def _timesketch_row(event: Dict[str, Any]) -> Dict[str, Any]:
    ts = event.get("timestamp") or event.get("ts") or event.get("time") or ""
    message = (
        event.get("message")
        or event.get("description")
        or event.get("summary")
        or event.get("event")
        or ""
    )

    row = {
        "datetime": _safe_iso(ts),
        "timestamp_desc": "event",
        "message": str(message),
        "parser": "dfir-attack-lab",
        "source": str(event.get("source", "timeline")),
        "severity": str(event.get("severity", "")),
        "category": str(event.get("category", "")),
        "hostname": str(event.get("hostname", event.get("host", ""))),
        "user": str(event.get("user", event.get("target_user", ""))),
        "attack_tags": _extract_attack_tags(event),
    }

    # Keep original fields for deeper analysis in Timesketch attributes
    for k, v in event.items():
        if k not in row:
            row[k] = v

    return row


def export_timesketch(events: Iterable[Any], output_path: str | Path) -> Path:
    dst = Path(output_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    with dst.open("w", encoding="utf-8") as f:
        for e in events:
            row = _timesketch_row(_to_dict(e))
            f.write(json.dumps(row, ensure_ascii=False, default=_safe_iso))
            f.write("\n")

    return dst


def add_export_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Attach an `export-timeline` CLI parser.

    This function is intentionally standalone so existing CLI code can import and
    register it with minimal glue.
    """
    p = subparsers.add_parser("export-timeline", help="Export timeline to CSV/JSONL/Timesketch")
    p.add_argument("--input", required=True, help="Path to timeline JSON/JSONL")
    p.add_argument("--output", required=True, help="Destination export path")
    p.add_argument("--format", choices=["csv", "jsonl", "timesketch"], required=True)
    p.add_argument("--severity", help="Filter by severity")
    p.add_argument("--category", help="Filter by category")
    p.add_argument("--start", help="Start timestamp (ISO8601)")
    p.add_argument("--end", help="End timestamp (ISO8601)")
    p.add_argument("--attack-only", action="store_true", help="Export only ATT&CK-tagged events")
    return p


def _load_events(input_path: str | Path) -> List[Dict[str, Any]]:
    src = Path(input_path)
    text = src.read_text(encoding="utf-8").strip()
    if not text:
        return []

    # JSONL by extension or line-wise objects fallback
    if src.suffix.lower() == ".jsonl":
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
        return rows

    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("events", "timeline", "items"):
            if isinstance(data.get(key), list):
                return data[key]
    raise ValueError("Unsupported timeline input structure")


def run_export_from_args(args: argparse.Namespace) -> Path:
    events = _load_events(args.input)
    filtered = filter_events(
        events,
        severity=getattr(args, "severity", None),
        category=getattr(args, "category", None),
        start=getattr(args, "start", None),
        end=getattr(args, "end", None),
        attack_only=bool(getattr(args, "attack_only", False)),
    )

    fmt = getattr(args, "format")
    if fmt == "csv":
        return export_csv(filtered, args.output)
    if fmt == "jsonl":
        return export_jsonl(filtered, args.output)
    if fmt == "timesketch":
        return export_timesketch(filtered, args.output)
    raise ValueError(f"Unsupported export format: {fmt}")
