"""
Windows Event Log XML parser.

Parses Windows Security Event Log entries exported as XML (Get-WinEvent | Export-Clixml
or Event Viewer XML export). Extracts common security-relevant event IDs.

Supported Event IDs:
  4624 — Successful logon
  4625 — Failed logon
  4648 — Explicit credential logon (pass-the-hash indicator)
  4720 — User account created
  4728 — Member added to security-enabled global group
  4732 — Member added to security-enabled local group
  4756 — Member added to security-enabled universal group
  4776 — NTLM authentication attempt
  7045 — New service installed (persistence indicator)
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from normalizers.models import EventCategory, SeverityHint, TriageEvent

# Windows Event Log XML namespace
_NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Mapping from EventID to (category, severity, action_name)
_EVENT_MAP: dict[int, tuple[EventCategory, SeverityHint, str]] = {
    4624: (EventCategory.AUTHENTICATION, SeverityHint.INFO,   "windows_logon_success"),
    4625: (EventCategory.AUTHENTICATION, SeverityHint.MEDIUM, "windows_logon_failure"),
    4648: (EventCategory.AUTHENTICATION, SeverityHint.HIGH,   "windows_explicit_credential_logon"),
    4720: (EventCategory.SYSTEM,         SeverityHint.HIGH,   "windows_user_account_created"),
    4728: (EventCategory.PRIVILEGE_ESCALATION, SeverityHint.HIGH, "windows_group_member_added_global"),
    4732: (EventCategory.PRIVILEGE_ESCALATION, SeverityHint.HIGH, "windows_group_member_added_local"),
    4756: (EventCategory.PRIVILEGE_ESCALATION, SeverityHint.HIGH, "windows_group_member_added_universal"),
    4776: (EventCategory.AUTHENTICATION, SeverityHint.MEDIUM, "windows_ntlm_auth_attempt"),
    7045: (EventCategory.SYSTEM,         SeverityHint.HIGH,   "windows_service_installed"),
}


def _get_data(event_data: ET.Element | None, name: str) -> str:
    """Extract a named Data field from EventData or UserData."""
    if event_data is None:
        return ""
    for item in event_data:
        if item.get("Name") == name:
            return item.text or ""
    return ""


def _parse_system_time(system: ET.Element) -> datetime | None:
    """Return the event timestamp or None when SystemTime is missing or invalid."""
    time_elem = system.find("w:TimeCreated", _NS)
    ts_str = time_elem.get("SystemTime", "") if time_elem is not None else ""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_windows_xml(xml_path: Path) -> list[TriageEvent]:
    """
    Parse a Windows Event Log XML export and return normalized TriageEvents.

    The input should be a valid XML file with one or more <Event> elements,
    either as a root <Events> collection or individual event files.

    Args:
        xml_path: Path to the Windows Event Log XML export file.

    Returns:
        List of TriageEvent objects extracted from the log.
    """
    events: list[TriageEvent] = []
    source = str(xml_path)

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return events

    # Handle both wrapped (<Events>) and unwrapped single-event XML
    event_elements = root.findall(".//w:Event", _NS) or (
        [root] if root.tag.endswith("}Event") or root.tag == "Event" else []
    )

    for elem in event_elements:
        system = elem.find("w:System", _NS)
        if system is None:
            continue

        event_id_elem = system.find("w:EventID", _NS)
        if event_id_elem is None or not event_id_elem.text:
            continue

        try:
            event_id = int(event_id_elem.text)
        except ValueError:
            continue

        ts = _parse_system_time(system)
        if ts is None:
            continue

        event_data = elem.find("w:EventData", _NS)
        category, severity, action = _EVENT_MAP.get(
            event_id,
            (EventCategory.SYSTEM, SeverityHint.INFO, f"windows_event_{event_id}"),
        )

        # Extract common fields based on event type
        metadata: dict = {"event_id": event_id}
        actor: str | None = None
        target: str | None = None

        if event_id in (4624, 4625, 4648):
            actor = _get_data(event_data, "IpAddress") or _get_data(event_data, "WorkstationName")
            target = _get_data(event_data, "TargetUserName")
            metadata["logon_type"] = _get_data(event_data, "LogonType")
            metadata["auth_package"] = _get_data(event_data, "AuthenticationPackageName")

        elif event_id in (4728, 4732, 4756):
            actor = _get_data(event_data, "SubjectUserName")
            target = _get_data(event_data, "MemberName")
            metadata["group_name"] = _get_data(event_data, "TargetUserName")

        elif event_id == 7045:
            target = _get_data(event_data, "ServiceName")
            metadata["service_file"] = _get_data(event_data, "ImagePath")
            metadata["service_type"] = _get_data(event_data, "ServiceType")

        raw_xml = ET.tostring(elem, encoding="unicode")
        events.append(TriageEvent(
            timestamp=ts,
            source_file=source,
            category=category,
            severity=severity,
            actor=actor or None,
            target=target or None,
            action=action,
            raw=raw_xml[:500],  # Truncate long XML for storage efficiency
            metadata=metadata,
        ))

    return events
