"""
Normalized event models for DFIR triage.

Events from diverse log sources (auth.log, syslog, audit.log, Windows Event Log)
are normalized into TriageEvent for uniform timeline processing.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE_SYSTEM = "filesystem"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class SeverityHint(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TriageEvent(BaseModel):
    timestamp: datetime
    source_file: str
    category: EventCategory
    severity: SeverityHint = SeverityHint.INFO
    actor: Optional[str] = None       # User, process, or IP address responsible
    target: Optional[str] = None      # Resource, file, or service affected
    action: str                        # What happened (login_failure, process_start, etc.)
    raw: str                           # Original log line — preserved verbatim for audit trail
    metadata: dict = {}
