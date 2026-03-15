"""Tests for the SARIF v2.1.0 serializer."""

from __future__ import annotations

import json
from typing import Any

import pytest

from navil.sarif import (
    _severity_to_sarif_level,
    findings_to_sarif,
    findings_to_sarif_bytes,
    findings_to_sarif_str,
)
from navil.scanner import MCPSecurityScanner
from navil.types import Finding


# ── Helpers ────────────────────────────────────────────────────


def _make_finding(**overrides: Any) -> Finding:
    """Create a Finding with sensible defaults, overriding specific fields."""
    defaults: dict[str, Any] = {
        "id": "TEST-001",
        "title": "Test Finding",
        "description": "A test vulnerability description",
        "severity": "HIGH",
        "source": "scanner",
        "affected_field": "server.protocol",
        "remediation": "Fix the protocol",
        "evidence": "Found issue",
        "confidence": 1.0,
    }
    defaults.update(overrides)
    return Finding(**defaults)


# ── Severity mapping ──────────────────────────────────────────


class TestSeverityMapping:
    """Tests for _severity_to_sarif_level."""

    def test_critical_maps_to_error(self) -> None:
        assert _severity_to_sarif_level("CRITICAL") == "error"

    def test_high_maps_to_error(self) -> None:
        assert _severity_to_sarif_level("HIGH") == "error"

    def test_medium_maps_to_warning(self) -> None:
        assert _severity_to_sarif_level("MEDIUM") == "warning"

    def test_low_maps_to_note(self) -> None:
        assert _severity_to_sarif_level("LOW") == "note"

    def test_info_maps_to_note(self) -> None:
        assert _severity_to_sarif_level("INFO") == "note"

    def test_none_severity_defaults_to_note(self) -> None:
        assert _severity_to_sarif_level(None) == "note"

    def test_unknown_severity_defaults_to_note(self) -> None:
        assert _severity_to_sarif_level("UNKNOWN") == "note"

    def test_case_insensitive(self) -> None:
        assert _severity_to_sarif_level("high") == "error"
        assert _severity_to_sarif_level("Medium") == "warning"
        assert _severity_to_sarif_level("low") == "note"


# ── SARIF structure ───────────────────────────────────────────


class TestSarifStructure:
    """Tests for the SARIF document structure."""

    def test_required_top_level_keys(self) -> None:
        sarif = findings_to_sarif([])
        assert "$schema" in sarif
        assert "version" in sarif
        assert "runs" in sarif

    def test_version_is_2_1_0(self) -> None:
        sarif = findings_to_sarif([])
        assert sarif["version"] == "2.1.0"

    def test_schema_url(self) -> None:
        sarif = findings_to_sarif([])
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_single_run(self) -> None:
        sarif = findings_to_sarif([])
        assert len(sarif["runs"]) == 1

    def test_tool_driver_name(self) -> None:
        sarif = findings_to_sarif([])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "navil"

    def test_tool_driver_version(self) -> None:
        import navil

        sarif = findings_to_sarif([])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == navil.__version__

    def test_results_key_exists(self) -> None:
        sarif = findings_to_sarif([])
        assert "results" in sarif["runs"][0]

    def test_rules_key_exists(self) -> None:
        sarif = findings_to_sarif([])
        driver = sarif["runs"][0]["tool"]["driver"]
        assert "rules" in driver


# ── Empty findings ────────────────────────────────────────────


class TestEmptyFindings:
    """Tests for SARIF output with no findings."""

    def test_empty_findings_produces_valid_sarif(self) -> None:
        sarif = findings_to_sarif([])
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_empty_findings_bytes(self) -> None:
        data = findings_to_sarif_bytes([])
        parsed = json.loads(data)
        assert parsed["version"] == "2.1.0"

    def test_empty_findings_str(self) -> None:
        text = findings_to_sarif_str([])
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"


# ── Single finding ────────────────────────────────────────────


class TestSingleFinding:
    """Tests for SARIF output with a single finding."""

    def test_result_rule_id(self) -> None:
        f = _make_finding(id="CRED-API_KEY")
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "CRED-API_KEY"

    def test_result_level(self) -> None:
        f = _make_finding(severity="CRITICAL")
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_result_message(self) -> None:
        f = _make_finding(description="Found a secret")
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["message"]["text"] == "Found a secret"

    def test_result_location(self) -> None:
        f = _make_finding(affected_field="server.protocol")
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["logicalLocations"][0]
        assert loc["name"] == "server.protocol"

    def test_rule_created(self) -> None:
        f = _make_finding(id="AUTH-MISSING", title="Missing Auth")
        sarif = findings_to_sarif([f])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "AUTH-MISSING"
        assert rules[0]["shortDescription"]["text"] == "Missing Auth"

    def test_rule_help_text(self) -> None:
        f = _make_finding(remediation="Use mTLS")
        sarif = findings_to_sarif([f])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["help"]["text"] == "Use mTLS"


# ── Multiple findings ────────────────────────────────────────


class TestMultipleFindings:
    """Tests for SARIF output with multiple findings."""

    def test_multiple_results(self) -> None:
        findings = [
            _make_finding(id="A", severity="HIGH"),
            _make_finding(id="B", severity="LOW"),
            _make_finding(id="C", severity="MEDIUM"),
        ]
        sarif = findings_to_sarif(findings)
        assert len(sarif["runs"][0]["results"]) == 3

    def test_duplicate_rule_ids_deduplicated(self) -> None:
        findings = [
            _make_finding(id="CRED-API_KEY", severity="CRITICAL"),
            _make_finding(id="CRED-API_KEY", severity="CRITICAL"),
        ]
        sarif = findings_to_sarif(findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert len(sarif["runs"][0]["results"]) == 2

    def test_all_severity_levels(self) -> None:
        findings = [
            _make_finding(id="A", severity="CRITICAL"),
            _make_finding(id="B", severity="HIGH"),
            _make_finding(id="C", severity="MEDIUM"),
            _make_finding(id="D", severity="LOW"),
            _make_finding(id="E", severity="INFO"),
        ]
        sarif = findings_to_sarif(findings)
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note", "note"]


# ── Edge cases ────────────────────────────────────────────────


class TestEdgeCases:
    """Tests for edge cases and failure modes."""

    def test_none_severity_finding(self) -> None:
        f = _make_finding(severity=None)
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "note"

    def test_empty_string_fields(self) -> None:
        f = Finding(
            id="",
            title="",
            description="",
            severity="",
            source="",
            affected_field="",
            remediation="",
            evidence="",
        )
        sarif = findings_to_sarif([f])
        assert len(sarif["runs"][0]["results"]) == 1

    def test_empty_affected_field_no_locations(self) -> None:
        f = _make_finding(affected_field="")
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "locations" not in result

    def test_empty_remediation_no_help(self) -> None:
        f = _make_finding(remediation="")
        sarif = findings_to_sarif([f])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "help" not in rule


# ── Integration with real scanner ─────────────────────────────


class TestSarifWithScanner:
    """Integration tests using real scanner output."""

    def test_scan_to_sarif(self, config_file, sample_vulnerable_config: dict[str, Any]) -> None:
        """Scan a vulnerable config and convert findings to SARIF."""
        path = config_file(sample_vulnerable_config)
        scanner = MCPSecurityScanner()
        result = scanner.scan(path)

        findings = result["findings"]
        assert len(findings) > 0

        sarif = findings_to_sarif(findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == len(findings)

    def test_scan_secure_config_to_sarif(
        self, config_file, sample_secure_config: dict[str, Any]
    ) -> None:
        """Scan a secure config — SARIF should have zero results."""
        path = config_file(sample_secure_config)
        scanner = MCPSecurityScanner()
        result = scanner.scan(path)

        findings = result["findings"]
        sarif = findings_to_sarif(findings)
        assert sarif["runs"][0]["results"] == []

    def test_sarif_bytes_roundtrip(
        self, config_file, sample_vulnerable_config: dict[str, Any]
    ) -> None:
        """orjson bytes output should be valid JSON that matches dict output."""
        path = config_file(sample_vulnerable_config)
        scanner = MCPSecurityScanner()
        result = scanner.scan(path)
        findings = result["findings"]

        sarif_dict = findings_to_sarif(findings)
        sarif_bytes = findings_to_sarif_bytes(findings)
        parsed = json.loads(sarif_bytes)

        assert parsed["version"] == sarif_dict["version"]
        assert len(parsed["runs"][0]["results"]) == len(sarif_dict["runs"][0]["results"])

    def test_sarif_str_roundtrip(
        self, config_file, sample_vulnerable_config: dict[str, Any]
    ) -> None:
        """String output should be valid JSON."""
        path = config_file(sample_vulnerable_config)
        scanner = MCPSecurityScanner()
        result = scanner.scan(path)
        findings = result["findings"]

        text = findings_to_sarif_str(findings)
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"
