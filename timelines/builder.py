from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


MITRE_RULES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "event_ids": {4625},
        "category_contains": ["auth_failure", "login_failure"],
        "commandline_patterns": [],
        "process_names": [],
        "attributes": [],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "event_ids": {4624, 4648, 4776},
        "category_contains": ["auth_success", "login_success"],
        "commandline_patterns": [],
        "process_names": [],
        "attributes": [],
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "event_ids": {4720},
        "category_contains": ["user_create", "account_create"],
        "commandline_patterns": ["useradd", "net user", "dscl"],
        "process_names": ["net.exe", "net1.exe"],
        "attributes": ["target_user", "new_user"],
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "event_ids": {4728, 4732, 4756},
        "category_contains": ["group_membership_change", "privilege_change"],
        "commandline_patterns": ["net localgroup", "addgroup"],
        "process_names": ["net.exe", "powershell.exe"],
        "attributes": ["group_name"],
    },
    {
        "id": "T1543.003",
        "name": "Create or Modify System Process: Windows Service",
        "event_ids": {7045},
        "category_contains": ["service_create"],
        "commandline_patterns": ["sc create", "new-service"],
        "process_names": ["sc.exe", "services.exe"],
        "attributes": ["service_name", "service_path"],
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "event_ids": set(),
        "category_contains": ["process_start", "execution"],
        "commandline_patterns": ["powershell", "cmd.exe", "bash", "sh -c", "wscript", "cscript"],
        "process_names": ["powershell.exe", "cmd.exe", "bash", "sh", "wscript.exe", "cscript.exe"],
        "attributes": ["command_line", "process_name"],
    },
]


def _to_dict(event: Any) -> Dict[str, Any]:
    if isinstance(event, dict):
        return dict(event)
    if is_dataclass(event):
        return asdict(event)
    if hasattr(event, "dict") and callable(getattr(event, "dict")):
        return event.dict()
    if hasattr(event, "model_dump") and callable(getattr(event, "model_dump")):
        return event.model_dump()
    if hasattr(event, "__dict__"):
        return dict(event.__dict__)
    return {"raw": event}


def _get_event_id(ev: Dict[str, Any]) -> Optional[int]:
    for key in ("event_id", "eventid", "id"):
        val = ev.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                return None
    return None


def _get_text(ev: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = ev.get(k)
        if isinstance(v, str) and v.strip():
            return v.lower()
    return ""


def tag_mitre_attack(event: Any) -> List[Dict[str, str]]:
    ev = _to_dict(event)
    event_id = _get_event_id(ev)
    category = _get_text(ev, "category", "event_category", "type")
    process_name = _get_text(ev, "process_name", "image", "process", "exe")
    command_line = _get_text(ev, "command_line", "cmdline", "command", "service_path")

    serialized = " ".join([f"{k}={v}" for k, v in ev.items()]).lower()

    matches: List[Dict[str, str]] = []
    for rule in MITRE_RULES:
        matched = False

        if event_id is not None and event_id in rule["event_ids"]:
            matched = True

        if not matched and category and any(token in category for token in rule["category_contains"]):
            matched = True

        if not matched and process_name and any(p in process_name for p in rule["process_names"]):
            matched = True

        if not matched and command_line and any(p in command_line for p in rule["commandline_patterns"]):
            matched = True

        if not matched and any(attr in serialized for attr in rule["attributes"]):
            matched = True

        if matched:
            matches.append({"technique_id": rule["id"], "technique_name": rule["name"]})

    # De-dup while preserving order
    seen = set()
    deduped: List[Dict[str, str]] = []
    for item in matches:
        key = (item["technique_id"], item["technique_name"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def build_timeline(events: Iterable[Any]) -> List[Dict[str, Any]]:
    timeline: List[Dict[str, Any]] = []
    for e in events:
        item = _to_dict(e)
        if "timestamp" not in item:
            item["timestamp"] = datetime.utcnow().isoformat() + "Z"
        item["mitre_attack" if "mitre_attack" not in item else "mitre_attack"] = tag_mitre_attack(item)
        timeline.append(item)

    timeline.sort(key=lambda x: str(x.get("timestamp", "")))
    return timeline
