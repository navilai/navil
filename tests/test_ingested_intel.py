"""Tests for ingested threat intelligence from VulnerableMCP and NVD CVEs.

Validates that the new entries added from:
  - https://github.com/vineethsai/vulnerablemcp (BL-VDB-* blocklist, VDB attacks)
  - NVD CVE database (BL-CVE-* blocklist, CVE attacks)
load correctly and satisfy structural requirements.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

# ── Paths ──────────────────────────────────────────────────────

DATA_DIR = Path(__file__).resolve().parent.parent / "navil" / "data"
ATTACKS_PATH = DATA_DIR / "public_attacks.yaml"
BLOCKLIST_PATH = DATA_DIR / "blocklist_v1.json"

# ── Fixtures ───────────────────────────────────────────────────


@pytest.fixture(scope="module")
def attacks() -> list[dict]:
    """Load all attack entries from public_attacks.yaml."""
    with open(ATTACKS_PATH) as f:
        data = yaml.safe_load(f)
    return data["attacks"]


@pytest.fixture(scope="module")
def blocklist() -> dict:
    """Load blocklist_v1.json."""
    with open(BLOCKLIST_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def blocklist_patterns(blocklist: dict) -> list[dict]:
    """Extract only real pattern entries (skip comment objects)."""
    return [p for p in blocklist["patterns"] if isinstance(p, dict) and "pattern_id" in p]


@pytest.fixture(scope="module")
def vdb_attacks(attacks: list[dict]) -> list[dict]:
    """Attack entries sourced from VulnerableMCP database."""
    return [a for a in attacks if "vulnerablemcp" in str(a.get("source_reference", "")).lower()]


@pytest.fixture(scope="module")
def cve_attacks(attacks: list[dict]) -> list[dict]:
    """Attack entries sourced from CVE database."""
    return [a for a in attacks if str(a.get("source_reference", "")).startswith("CVE-")]


@pytest.fixture(scope="module")
def vdb_patterns(blocklist_patterns: list[dict]) -> list[dict]:
    """Blocklist patterns with BL-VDB prefix."""
    return [p for p in blocklist_patterns if p["pattern_id"].startswith("BL-VDB")]


@pytest.fixture(scope="module")
def cve_patterns(blocklist_patterns: list[dict]) -> list[dict]:
    """Blocklist patterns with BL-CVE prefix."""
    return [p for p in blocklist_patterns if p["pattern_id"].startswith("BL-CVE")]


# ── File loading tests ─────────────────────────────────────────


class TestFilesLoad:
    """Verify that data files parse without errors."""

    def test_attacks_yaml_loads(self, attacks: list[dict]) -> None:
        assert len(attacks) > 0, "public_attacks.yaml should contain entries"

    def test_blocklist_json_loads(self, blocklist: dict) -> None:
        assert "version" in blocklist
        assert "patterns" in blocklist
        assert len(blocklist["patterns"]) > 0

    def test_blocklist_json_valid_structure(self, blocklist: dict) -> None:
        assert blocklist["version"] == 1
        assert isinstance(blocklist["patterns"], list)


# ── VulnerableMCP attack entry tests ───────────────────────────


class TestVulnerableMCPAttacks:
    """Validate attack entries derived from vulnerablemcp database."""

    def test_vdb_attack_count(self, vdb_attacks: list[dict]) -> None:
        assert len(vdb_attacks) >= 30, (
            f"Expected at least 30 VulnerableMCP-derived attacks, got {len(vdb_attacks)}"
        )

    def test_vdb_attacks_have_required_fields(self, vdb_attacks: list[dict]) -> None:
        required = {
            "name",
            "description",
            "category",
            "severity",
            "attack_steps",
            "indicators",
            "source_reference",
        }
        for attack in vdb_attacks:
            missing = required - set(attack.keys())
            assert not missing, f"Attack {attack.get('name', '?')} missing fields: {missing}"

    def test_vdb_attacks_have_valid_severity(self, vdb_attacks: list[dict]) -> None:
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for attack in vdb_attacks:
            assert attack["severity"] in valid_severities, (
                f"Attack {attack['name']} has invalid severity: {attack['severity']}"
            )

    def test_vdb_attacks_have_valid_category(self, vdb_attacks: list[dict]) -> None:
        valid_categories = {
            "RECONNAISSANCE",
            "DATA_EXFILTRATION",
            "DEFENSE_EVASION",
            "LATERAL_MOVEMENT",
            "SUPPLY_CHAIN",
            "RUG_PULL",
            "PRIVILEGE_ESCALATION",
            "PERSISTENCE",
            "COMMAND_AND_CONTROL",
            "RATE_SPIKE",
        }
        for attack in vdb_attacks:
            assert attack["category"] in valid_categories, (
                f"Attack {attack['name']} has invalid category: {attack['category']}"
            )

    def test_vdb_attacks_reference_vulnerablemcp(self, vdb_attacks: list[dict]) -> None:
        for attack in vdb_attacks:
            assert "vulnerablemcp" in attack["source_reference"].lower(), (
                f"Attack {attack['name']} source_reference should reference vulnerablemcp"
            )

    def test_vdb_attacks_have_nonempty_indicators(self, vdb_attacks: list[dict]) -> None:
        for attack in vdb_attacks:
            assert len(attack["indicators"]) >= 1, (
                f"Attack {attack['name']} must have at least one indicator"
            )

    def test_vdb_attacks_have_nonempty_steps(self, vdb_attacks: list[dict]) -> None:
        for attack in vdb_attacks:
            assert len(attack["attack_steps"]) >= 1, (
                f"Attack {attack['name']} must have at least one attack step"
            )

    def test_specific_vdb_entries_present(self, vdb_attacks: list[dict]) -> None:
        """Check that key vulnerability patterns are represented."""
        names = {a["name"] for a in vdb_attacks}
        expected_names = [
            "line_jumping_attack",
            "consent_fatigue_exploitation",
            "ansi_terminal_code_deception",
            "conversation_history_theft",
            "tool_poisoning_rce_rug_pull",
            "github_mcp_private_repo_exfil",
            "zero_click_rce_google_docs_mcp",
            "dns_rebinding_mcp_sdks",
            "fetch_mcp_server_ssrf",
            "k8s_mcp_command_injection",
            "docker_sandbox_escape_mcp",
        ]
        for name in expected_names:
            assert name in names, f"Expected VDB attack '{name}' not found"


# ── CVE attack entry tests ─────────────────────────────────────


class TestCVEAttacks:
    """Validate attack entries derived from CVE database."""

    def test_cve_attack_count(self, cve_attacks: list[dict]) -> None:
        assert len(cve_attacks) >= 10, (
            f"Expected at least 10 CVE-derived attacks, got {len(cve_attacks)}"
        )

    def test_cve_attacks_have_required_fields(self, cve_attacks: list[dict]) -> None:
        required = {
            "name",
            "description",
            "category",
            "severity",
            "attack_steps",
            "indicators",
            "source_reference",
        }
        for attack in cve_attacks:
            missing = required - set(attack.keys())
            assert not missing, f"Attack {attack.get('name', '?')} missing fields: {missing}"

    def test_cve_attacks_reference_cve_ids(self, cve_attacks: list[dict]) -> None:
        for attack in cve_attacks:
            ref = attack["source_reference"]
            assert ref.startswith("CVE-"), (
                f"Attack {attack['name']} source_reference should start with 'CVE-': got {ref}"
            )

    def test_specific_cves_present(self, cve_attacks: list[dict]) -> None:
        """Check all required CVEs are covered."""
        refs = {a["source_reference"] for a in cve_attacks}
        required_cves = [
            "CVE-2025-6514",
            "CVE-2025-53109",
            "CVE-2025-53110",
            "CVE-2025-68145",
            "CVE-2025-68143",
            "CVE-2025-68144",
            "CVE-2025-49596",
            "CVE-2025-59536",
            "CVE-2026-21852",
            "CVE-2026-25253",
        ]
        for cve in required_cves:
            assert cve in refs, f"CVE {cve} not found in attack entries"

    def test_cve_2025_6514_details(self, cve_attacks: list[dict]) -> None:
        """Validate CVE-2025-6514 mcp-remote OS command injection entry."""
        entry = next(a for a in cve_attacks if a["source_reference"] == "CVE-2025-6514")
        assert entry["severity"] == "CRITICAL"
        assert entry["category"] == "PRIVILEGE_ESCALATION"
        assert "command_injection" in " ".join(entry["indicators"]).lower() or any(
            "command_injection" in i for i in entry["indicators"]
        )

    def test_cve_2026_25253_details(self, cve_attacks: list[dict]) -> None:
        """Validate CVE-2026-25253 OpenClaw WebSocket token leak entry."""
        entry = next(a for a in cve_attacks if a["source_reference"] == "CVE-2026-25253")
        assert entry["severity"] == "CRITICAL"
        assert (
            "websocket" in entry["description"].lower() or "token" in entry["description"].lower()
        )

    def test_cve_2025_53109_details(self, cve_attacks: list[dict]) -> None:
        """Validate CVE-2025-53109 Filesystem MCP symlink bypass."""
        entry = next(a for a in cve_attacks if a["source_reference"] == "CVE-2025-53109")
        assert entry["severity"] == "CRITICAL"
        assert "symlink" in entry["description"].lower()


# ── Blocklist VDB pattern tests ────────────────────────────────


class TestVDBBlocklistPatterns:
    """Validate blocklist patterns derived from VulnerableMCP."""

    def test_vdb_pattern_count(self, vdb_patterns: list[dict]) -> None:
        assert len(vdb_patterns) >= 20, (
            f"Expected at least 20 BL-VDB patterns, got {len(vdb_patterns)}"
        )

    def test_vdb_patterns_have_required_fields(self, vdb_patterns: list[dict]) -> None:
        required = {"pattern_id", "pattern_type", "value", "severity", "description", "confidence"}
        for pattern in vdb_patterns:
            missing = required - set(pattern.keys())
            assert not missing, f"Pattern {pattern['pattern_id']} missing fields: {missing}"

    def test_vdb_patterns_sequential_ids(self, vdb_patterns: list[dict]) -> None:
        """BL-VDB IDs should be sequential starting from 001."""
        ids = sorted([p["pattern_id"] for p in vdb_patterns])
        for i, pid in enumerate(ids, start=1):
            expected = f"BL-VDB-{i:03d}"
            assert pid == expected, f"Expected {expected}, got {pid}"

    def test_vdb_patterns_valid_types(self, vdb_patterns: list[dict]) -> None:
        valid_types = {
            "tool_name",
            "tool_sequence",
            "argument_pattern",
            "argument_content",
            "url_pattern",
            "description_injection",
            "behavioral",
            "env_access",
            "mcp_specific",
        }
        for pattern in vdb_patterns:
            assert pattern["pattern_type"] in valid_types, (
                f"Pattern {pattern['pattern_id']} has invalid type: {pattern['pattern_type']}"
            )

    def test_vdb_patterns_valid_severity(self, vdb_patterns: list[dict]) -> None:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for pattern in vdb_patterns:
            assert pattern["severity"] in valid, (
                f"Pattern {pattern['pattern_id']} has invalid severity: {pattern['severity']}"
            )

    def test_vdb_patterns_confidence_range(self, vdb_patterns: list[dict]) -> None:
        for pattern in vdb_patterns:
            assert 0.0 < pattern["confidence"] <= 1.0, (
                f"Pattern {pattern['pattern_id']} confidence out of range: {pattern['confidence']}"
            )

    def test_vdb_patterns_have_source(self, vdb_patterns: list[dict]) -> None:
        for pattern in vdb_patterns:
            assert "source" in pattern, (
                f"Pattern {pattern['pattern_id']} should have a 'source' field"
            )
            assert "vulnerablemcp" in pattern["source"].lower()


# ── Blocklist CVE pattern tests ────────────────────────────────


class TestCVEBlocklistPatterns:
    """Validate blocklist patterns derived from CVE database."""

    def test_cve_pattern_count(self, cve_patterns: list[dict]) -> None:
        assert len(cve_patterns) >= 15, (
            f"Expected at least 15 BL-CVE patterns, got {len(cve_patterns)}"
        )

    def test_cve_patterns_have_required_fields(self, cve_patterns: list[dict]) -> None:
        required = {"pattern_id", "pattern_type", "value", "severity", "description", "confidence"}
        for pattern in cve_patterns:
            missing = required - set(pattern.keys())
            assert not missing, f"Pattern {pattern['pattern_id']} missing fields: {missing}"

    def test_cve_patterns_sequential_ids(self, cve_patterns: list[dict]) -> None:
        ids = sorted([p["pattern_id"] for p in cve_patterns])
        for i, pid in enumerate(ids, start=1):
            expected = f"BL-CVE-{i:03d}"
            assert pid == expected, f"Expected {expected}, got {pid}"

    def test_cve_patterns_reference_cves(self, cve_patterns: list[dict]) -> None:
        for pattern in cve_patterns:
            assert "source" in pattern, (
                f"Pattern {pattern['pattern_id']} should have a 'source' field"
            )
            assert pattern["source"].startswith("CVE-"), (
                f"Pattern {pattern['pattern_id']} source should"
                f" start with 'CVE-': got {pattern['source']}"
            )

    def test_cve_patterns_confidence_range(self, cve_patterns: list[dict]) -> None:
        for pattern in cve_patterns:
            assert 0.0 < pattern["confidence"] <= 1.0, (
                f"Pattern {pattern['pattern_id']} confidence out of range: {pattern['confidence']}"
            )

    def test_specific_cve_patterns_present(self, cve_patterns: list[dict]) -> None:
        """Verify key CVE-specific signatures exist."""
        sources = {p["source"] for p in cve_patterns}
        expected = [
            "CVE-2025-6514",
            "CVE-2025-53109",
            "CVE-2025-68144",
            "CVE-2025-49596",
            "CVE-2025-59536",
            "CVE-2026-21852",
            "CVE-2026-25253",
        ]
        for cve in expected:
            assert cve in sources, f"No blocklist pattern references {cve}"


# ── Deduplication tests ────────────────────────────────────────


class TestDeduplication:
    """Ensure no duplicate entries across both files."""

    def test_no_duplicate_attack_names(self, attacks: list[dict]) -> None:
        names = [a["name"] for a in attacks]
        seen = set()
        dupes = []
        for name in names:
            if name in seen:
                dupes.append(name)
            seen.add(name)
        assert not dupes, f"Duplicate attack names found: {dupes}"

    def test_no_duplicate_pattern_ids(self, blocklist_patterns: list[dict]) -> None:
        pids = [p["pattern_id"] for p in blocklist_patterns]
        seen = set()
        dupes = []
        for pid in pids:
            if pid in seen:
                dupes.append(pid)
            seen.add(pid)
        assert not dupes, f"Duplicate pattern_ids found: {dupes}"


# ── Cross-reference tests ─────────────────────────────────────


class TestCrossReferences:
    """Validate consistency between attack entries and blocklist signatures."""

    def test_all_cve_attacks_have_blocklist_pattern(
        self, cve_attacks: list[dict], cve_patterns: list[dict]
    ) -> None:
        """Each CVE attack entry should have at least one blocklist pattern."""
        pattern_sources = {p["source"] for p in cve_patterns}
        for attack in cve_attacks:
            cve_id = attack["source_reference"]
            assert cve_id in pattern_sources, (
                f"CVE attack {attack['name']} ({cve_id}) has no corresponding blocklist pattern"
            )

    def test_total_attack_count_increased(self, attacks: list[dict]) -> None:
        """After ingestion, total attacks should be substantially higher than baseline."""
        # Original had ~64 entries before ingestion
        assert len(attacks) >= 100, (
            f"Expected at least 100 total attacks after ingestion, got {len(attacks)}"
        )

    def test_total_blocklist_count_increased(self, blocklist_patterns: list[dict]) -> None:
        """After ingestion, total blocklist patterns should be higher than baseline."""
        # Original had ~288 entries before ingestion
        assert len(blocklist_patterns) >= 300, (
            f"Expected at least 300 total patterns after ingestion, got {len(blocklist_patterns)}"
        )
