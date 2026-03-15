"""
Shared data types for Navil security findings.

All subsystems (scanner, blocklist, honeypot, detector) emit Finding objects
so that downstream consumers (SARIF export, CLI, dashboard) have one unified type.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding emitted by any Navil subsystem.

    Attributes:
        id: Unique identifier for the finding type (e.g. "CRED-API_KEY").
        title: Short human-readable title.
        description: Longer explanation of the issue.
        severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO.
        source: Subsystem that produced the finding
                ("scanner", "blocklist", "honeypot", "detector").
        affected_field: Configuration field or resource that is affected.
        remediation: Suggested fix.
        evidence: Supporting data / match details.
        confidence: 0.0-1.0 confidence score; defaults to 1.0 for
                    deterministic scanner findings.
    """

    id: str
    title: str
    description: str
    severity: str
    source: str
    affected_field: str
    remediation: str
    evidence: str = ""
    confidence: float = 1.0
