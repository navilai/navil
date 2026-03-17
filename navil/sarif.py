"""SARIF v2.1.0 serializer for Navil security findings.

Converts a list of Finding objects into a SARIF 2.1.0 JSON document
suitable for upload to GitHub Code Scanning, Azure DevOps, or any
SARIF-compatible viewer.
"""

from __future__ import annotations

from typing import Any

import orjson

import navil
from navil.types import Finding

# SARIF schema and version constants
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Mapping from Navil severity strings to SARIF result levels.
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _severity_to_sarif_level(severity: str | None) -> str:
    """Map a Finding severity to a SARIF level string.

    Returns ``"note"`` when the severity is ``None`` or unrecognised.
    """
    if severity is None:
        return "note"
    return _SEVERITY_TO_LEVEL.get(severity.upper(), "note")


def findings_to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Convert a list of Finding objects to a SARIF v2.1.0 document.

    Args:
        findings: List of :class:`navil.types.Finding` objects (may be empty).

    Returns:
        A Python dict representing a complete SARIF log object.
    """
    # Build per-rule metadata (deduplicated by Finding.id).
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        # Register the rule if we haven't seen this id yet.
        if finding.id not in rules_by_id:
            rule: dict[str, Any] = {
                "id": finding.id,
                "shortDescription": {"text": finding.title},
            }
            help_text = finding.remediation or ""
            if help_text:
                rule["help"] = {"text": help_text, "markdown": help_text}
            rule["defaultConfiguration"] = {
                "level": _severity_to_sarif_level(finding.severity),
            }
            rules_by_id[finding.id] = rule

        # Build the SARIF result object.
        result: dict[str, Any] = {
            "ruleId": finding.id,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {"text": finding.description},
        }

        # Location — use affected_field as the logical location.
        if finding.affected_field:
            result["locations"] = [
                {
                    "logicalLocations": [
                        {
                            "name": finding.affected_field,
                            "kind": "member",
                        }
                    ]
                }
            ]

        results.append(result)

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "navil",
                        "version": navil.__version__,
                        "informationUri": "https://github.com/ivanlkf/navil",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def findings_to_sarif_bytes(findings: list[Finding]) -> bytes:
    """Serialize findings to SARIF as UTF-8 JSON bytes (via orjson)."""
    return orjson.dumps(findings_to_sarif(findings), option=orjson.OPT_INDENT_2)


def findings_to_sarif_str(findings: list[Finding]) -> str:
    """Serialize findings to SARIF as a JSON string."""
    return findings_to_sarif_bytes(findings).decode("utf-8")
