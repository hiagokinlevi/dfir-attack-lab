"""Tests for the Windows Event Log XML parser."""
import tempfile
from pathlib import Path
from parsers.windows_evtx import parse_windows_xml
from normalizers.models import EventCategory, SeverityHint

# Minimal valid Windows Event Log XML for a 4625 (failed logon)
_FAILED_LOGON_XML = """\
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-04-06T12:00:00.000000Z"/>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">10.0.0.5</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="AuthenticationPackageName">NTLM</Data>
    </EventData>
  </Event>
</Events>
"""

_SERVICE_INSTALL_XML = """\
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <EventID>7045</EventID>
      <TimeCreated SystemTime="2026-04-06T13:00:00.000000Z"/>
    </System>
    <EventData>
      <Data Name="ServiceName">SuspiciousService</Data>
      <Data Name="ImagePath">C:\\Windows\\Temp\\malware.exe</Data>
      <Data Name="ServiceType">16</Data>
    </EventData>
  </Event>
</Events>
"""


def _write_xml(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def test_failed_logon_parsed():
    path = _write_xml(_FAILED_LOGON_XML)
    events = parse_windows_xml(path)
    assert len(events) == 1
    e = events[0]
    assert e.action == "windows_logon_failure"
    assert e.category == EventCategory.AUTHENTICATION
    assert e.severity == SeverityHint.MEDIUM
    assert e.actor == "10.0.0.5"
    assert e.target == "Administrator"
    assert e.metadata["logon_type"] == "3"


def test_service_install_parsed():
    path = _write_xml(_SERVICE_INSTALL_XML)
    events = parse_windows_xml(path)
    assert len(events) == 1
    e = events[0]
    assert e.action == "windows_service_installed"
    assert e.severity == SeverityHint.HIGH
    assert e.target == "SuspiciousService"
    assert "malware.exe" in e.metadata["service_file"]


def test_invalid_xml_returns_empty():
    path = _write_xml("<not valid xml><<<")
    events = parse_windows_xml(path)
    assert events == []
