"""Tests for OpenClaw-specific threat intelligence additions.

Validates that OpenClaw-specific attacks, blocklist patterns, and the
openclaw_registry honeypot profile are correctly defined and loadable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from navil.honeypot.server import HoneypotMCPServer

# ── Paths ──────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).resolve().parent.parent / "navil" / "data"
_ATTACKS_FILE = _DATA_DIR / "public_attacks.yaml"
_BLOCKLIST_FILE = _DATA_DIR / "blocklist_v1.json"


# ── Fixtures ───────────────────────────────────────────────────


@pytest.fixture(scope="module")
def all_attacks() -> list[dict]:
    """Load all attacks from public_attacks.yaml."""
    with open(_ATTACKS_FILE) as f:
        data = yaml.safe_load(f)
    return data["attacks"]


@pytest.fixture(scope="module")
def openclaw_attacks(all_attacks: list[dict]) -> list[dict]:
    """Filter to only OpenClaw-specific attacks (name starts with 'openclaw_')."""
    return [a for a in all_attacks if a["name"].startswith("openclaw_")]


@pytest.fixture(scope="module")
def blocklist_data() -> dict:
    """Load blocklist_v1.json."""
    with open(_BLOCKLIST_FILE) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def openclaw_patterns(blocklist_data: dict) -> list[dict]:
    """Filter to OpenClaw-specific blocklist patterns (BL-OC-*)."""
    return [p for p in blocklist_data["patterns"] if p["pattern_id"].startswith("BL-OC-")]


@pytest.fixture(scope="module")
def openclaw_honeypot() -> HoneypotMCPServer:
    """Create a HoneypotMCPServer with the openclaw_registry profile."""
    return HoneypotMCPServer(profile="openclaw_registry")


# ── Test: OpenClaw attacks load from public_attacks.yaml ───────


class TestOpenClawAttacks:
    """Tests for OpenClaw-specific attack entries in public_attacks.yaml."""

    def test_openclaw_attacks_exist(self, openclaw_attacks: list[dict]) -> None:
        """At least 10 OpenClaw-specific attacks should be defined."""
        assert len(openclaw_attacks) >= 10

    def test_all_attacks_have_required_fields(self, openclaw_attacks: list[dict]) -> None:
        """Each attack must have name, description, category, severity, and indicators."""
        required_fields = {"name", "description", "category", "severity", "indicators"}
        for attack in openclaw_attacks:
            missing = required_fields - set(attack.keys())
            assert not missing, f"Attack '{attack['name']}' missing fields: {missing}"

    def test_attack_names_unique(self, openclaw_attacks: list[dict]) -> None:
        """All OpenClaw attack names should be unique."""
        names = [a["name"] for a in openclaw_attacks]
        assert len(names) == len(set(names)), f"Duplicate attack names: {names}"

    def test_severity_values_valid(self, openclaw_attacks: list[dict]) -> None:
        """Severity must be one of LOW, MEDIUM, HIGH, CRITICAL."""
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for attack in openclaw_attacks:
            assert (
                attack["severity"] in valid
            ), f"Attack '{attack['name']}' has invalid severity: {attack['severity']}"

    def test_category_values_valid(self, openclaw_attacks: list[dict]) -> None:
        """Category must be a known attack category."""
        valid = {
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
        for attack in openclaw_attacks:
            assert (
                attack["category"] in valid
            ), f"Attack '{attack['name']}' has invalid category: {attack['category']}"

    def test_skill_registry_poisoning_exists(self, openclaw_attacks: list[dict]) -> None:
        """Skill registry poisoning attack should be defined."""
        names = [a["name"] for a in openclaw_attacks]
        assert "openclaw_skill_registry_poisoning" in names

    def test_skill_squatting_exists(self, openclaw_attacks: list[dict]) -> None:
        """Skill squatting (typosquatting) attack should be defined."""
        names = [a["name"] for a in openclaw_attacks]
        assert "openclaw_skill_squatting" in names

    def test_config_manipulation_exists(self, openclaw_attacks: list[dict]) -> None:
        """Config file manipulation attack should be defined."""
        names = [a["name"] for a in openclaw_attacks]
        assert "openclaw_config_file_manipulation" in names

    def test_instance_exposure_exists(self, openclaw_attacks: list[dict]) -> None:
        """Instance exposure attack should be defined."""
        names = [a["name"] for a in openclaw_attacks]
        assert "openclaw_instance_exposure" in names

    def test_analytics_exfiltration_exists(self, openclaw_attacks: list[dict]) -> None:
        """Skill analytics exfiltration attack should be defined."""
        names = [a["name"] for a in openclaw_attacks]
        assert "openclaw_skill_analytics_exfiltration" in names

    def test_all_attacks_have_source_reference(self, openclaw_attacks: list[dict]) -> None:
        """Each attack should have a source_reference for traceability."""
        for attack in openclaw_attacks:
            assert (
                "source_reference" in attack
            ), f"Attack '{attack['name']}' missing source_reference"
            assert len(attack["source_reference"]) > 0

    def test_all_attacks_have_attack_steps(self, openclaw_attacks: list[dict]) -> None:
        """Each attack should have attack_steps defining the attack chain."""
        for attack in openclaw_attacks:
            assert "attack_steps" in attack, f"Attack '{attack['name']}' missing attack_steps"
            assert len(attack["attack_steps"]) > 0

    def test_yaml_file_is_valid(self) -> None:
        """The public_attacks.yaml file should parse without errors."""
        with open(_ATTACKS_FILE) as f:
            data = yaml.safe_load(f)
        assert "attacks" in data
        assert isinstance(data["attacks"], list)
        assert len(data["attacks"]) > 54  # Was 54 generic + now OpenClaw


# ── Test: OpenClaw blocklist patterns ──────────────────────────


class TestOpenClawBlocklist:
    """Tests for OpenClaw-specific blocklist patterns in blocklist_v1.json."""

    def test_openclaw_patterns_exist(self, openclaw_patterns: list[dict]) -> None:
        """At least 30 OpenClaw-specific blocklist patterns should be defined."""
        assert len(openclaw_patterns) >= 30

    def test_all_patterns_have_required_fields(self, openclaw_patterns: list[dict]) -> None:
        """Each pattern must have required fields."""
        required_fields = {
            "pattern_id",
            "pattern_type",
            "value",
            "severity",
            "description",
            "confidence",
        }
        for pattern in openclaw_patterns:
            missing = required_fields - set(pattern.keys())
            assert not missing, f"Pattern '{pattern['pattern_id']}' missing fields: {missing}"

    def test_pattern_ids_unique(self, openclaw_patterns: list[dict]) -> None:
        """All OpenClaw pattern IDs should be unique."""
        ids = [p["pattern_id"] for p in openclaw_patterns]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"

    def test_pattern_ids_follow_convention(self, openclaw_patterns: list[dict]) -> None:
        """All OpenClaw pattern IDs should follow BL-OC-NNN convention."""
        for pattern in openclaw_patterns:
            assert re.match(
                r"^BL-OC-\d{3}$", pattern["pattern_id"]
            ), f"Pattern ID '{pattern['pattern_id']}' doesn't match BL-OC-NNN format"

    def test_severity_values_valid(self, openclaw_patterns: list[dict]) -> None:
        """Severity must be one of LOW, MEDIUM, HIGH, CRITICAL."""
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for pattern in openclaw_patterns:
            assert (
                pattern["severity"] in valid
            ), f"Pattern '{pattern['pattern_id']}' has invalid severity: {pattern['severity']}"

    def test_confidence_values_valid(self, openclaw_patterns: list[dict]) -> None:
        """Confidence must be between 0.0 and 1.0."""
        for pattern in openclaw_patterns:
            assert (
                0.0 <= pattern["confidence"] <= 1.0
            ), f"Pattern '{pattern['pattern_id']}' has invalid confidence: {pattern['confidence']}"

    def test_pattern_types_valid(self, openclaw_patterns: list[dict]) -> None:
        """Pattern types should be from the known set."""
        valid = {
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
        for pattern in openclaw_patterns:
            assert (
                pattern["pattern_type"] in valid
            ), f"Pattern '{pattern['pattern_id']}' has invalid type: {pattern['pattern_type']}"

    def test_skill_squatting_patterns_match_expected(self, openclaw_patterns: list[dict]) -> None:
        """Typosquatting patterns should match their intended inputs."""
        squatting_patterns = [
            p
            for p in openclaw_patterns
            if "squatting" in p["description"].lower() or "typosquat" in p["description"].lower()
        ]
        assert len(squatting_patterns) >= 3, "Should have at least 3 skill squatting patterns"

    def test_config_manipulation_patterns_exist(self, openclaw_patterns: list[dict]) -> None:
        """Config file manipulation patterns should exist."""
        config_patterns = [
            p
            for p in openclaw_patterns
            if "openclaw.json" in p["value"]
            or "openclaw" in p["value"].lower()
            and "config" in p["description"].lower()
        ]
        assert len(config_patterns) >= 1, "Should have config manipulation patterns"

    def test_exfiltration_sequences_exist(self, openclaw_patterns: list[dict]) -> None:
        """Tool sequence patterns for exfiltration should exist."""
        sequences = [p for p in openclaw_patterns if p["pattern_type"] == "tool_sequence"]
        assert len(sequences) >= 4, "Should have at least 4 tool sequence patterns"

    def test_exposed_instance_patterns_exist(self, openclaw_patterns: list[dict]) -> None:
        """Patterns for exposed OpenClaw instances should exist."""
        exposed = [
            p
            for p in openclaw_patterns
            if p["pattern_type"] == "mcp_specific" and "openclaw" in p["value"]
        ]
        assert len(exposed) >= 2, "Should have at least 2 exposed instance patterns"

    def test_regex_patterns_compile(self, openclaw_patterns: list[dict]) -> None:
        """All argument_pattern and argument_content regex values should compile."""
        regex_types = {
            "argument_pattern",
            "argument_content",
            "description_injection",
            "url_pattern",
        }
        for pattern in openclaw_patterns:
            if pattern["pattern_type"] in regex_types:
                try:
                    re.compile(pattern["value"])
                except re.error as e:
                    pytest.fail(f"Pattern '{pattern['pattern_id']}' has invalid regex: {e}")

    def test_blocklist_json_is_valid(self) -> None:
        """The blocklist_v1.json file should parse without errors."""
        with open(_BLOCKLIST_FILE) as f:
            data = json.load(f)
        assert "patterns" in data
        assert isinstance(data["patterns"], list)
        assert len(data["patterns"]) > 253  # Was 253 generic + now OpenClaw

    def test_git_hub_typosquat_matches(self, openclaw_patterns: list[dict]) -> None:
        """The git-hub typosquat pattern should match expected input."""
        pattern = next(
            (p for p in openclaw_patterns if "git-hub" in p["value"]),
            None,
        )
        assert pattern is not None, "git-hub typosquat pattern not found"
        assert re.search(pattern["value"], "skill_name: git-hub")

    def test_secrets_exfil_sequence_exists(self, openclaw_patterns: list[dict]) -> None:
        """A sequence for secrets access followed by network call should exist."""
        seq = next(
            (
                p
                for p in openclaw_patterns
                if p["pattern_type"] == "tool_sequence" and "secrets" in p["value"]
            ),
            None,
        )
        assert seq is not None, "get_skill_secrets,fetch_url sequence not found"


# ── Test: OpenClaw honeypot profile ────────────────────────────


class TestOpenClawHoneypot:
    """Tests for the openclaw_registry honeypot profile."""

    def test_profile_loads(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """The openclaw_registry profile should load without errors."""
        assert openclaw_honeypot.profile_name == "openclaw_registry"

    def test_has_expected_tools(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """The profile should expose all 6 required tools."""
        expected_tools = {
            "search_skills",
            "install_skill",
            "get_skill_config",
            "list_installed_skills",
            "update_skill",
            "get_skill_secrets",
        }
        actual_tools = set(openclaw_honeypot.tool_names)
        missing = expected_tools - actual_tools
        assert not missing, f"Missing tools: {missing}"

    def test_tool_count(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """The profile should have exactly 6 tools."""
        assert len(openclaw_honeypot.tools) == 6

    def test_tools_have_descriptions(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """Each tool should have a non-empty description."""
        for name, info in openclaw_honeypot.tools.items():
            assert "description" in info, f"Tool '{name}' missing description"
            assert len(info["description"]) > 0, f"Tool '{name}' has empty description"

    def test_tools_have_input_schema(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """Each tool should have an inputSchema."""
        for name, info in openclaw_honeypot.tools.items():
            assert "inputSchema" in info, f"Tool '{name}' missing inputSchema"
            assert (
                info["inputSchema"]["type"] == "object"
            ), f"Tool '{name}' inputSchema type should be 'object'"

    def test_tools_have_responses(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """Each tool should have a fake response defined."""
        for name, info in openclaw_honeypot.tools.items():
            assert "response" in info, f"Tool '{name}' missing response"
            assert "status" in info["response"], f"Tool '{name}' response missing status"

    def test_tool_list_format(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """The tool_list property should return MCP-compatible format."""
        tool_list = openclaw_honeypot.tool_list
        assert len(tool_list) == 6
        for tool in tool_list:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_search_skills_has_query_required(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """The search_skills tool should require a query parameter."""
        schema = openclaw_honeypot.tools["search_skills"]["inputSchema"]
        assert "query" in schema.get("required", [])

    def test_install_skill_has_skill_name_required(
        self, openclaw_honeypot: HoneypotMCPServer
    ) -> None:
        """The install_skill tool should require a skill_name parameter."""
        schema = openclaw_honeypot.tools["install_skill"]["inputSchema"]
        assert "skill_name" in schema.get("required", [])

    def test_get_skill_secrets_response_has_secrets(
        self, openclaw_honeypot: HoneypotMCPServer
    ) -> None:
        """The get_skill_secrets response should contain fake secrets."""
        response = openclaw_honeypot.tools["get_skill_secrets"]["response"]
        assert "secrets" in response
        assert len(response["secrets"]) > 0

    def test_handle_tools_list_request(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """The server should handle a tools/list request correctly."""
        response = openclaw_honeypot.handle_request(
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            source_ip="127.0.0.1",
            headers={},
        )
        assert response["jsonrpc"] == "2.0"
        assert "result" in response
        assert "tools" in response["result"]
        assert len(response["result"]["tools"]) == 6

    def test_handle_tool_call_request(self, openclaw_honeypot: HoneypotMCPServer) -> None:
        """The server should handle a tools/call request and record it."""
        response = openclaw_honeypot.handle_request(
            body={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "get_skill_secrets",
                    "arguments": {"skill_name": "github-assistant"},
                },
            },
            source_ip="10.0.0.1",
            headers={"User-Agent": "test-agent"},
        )
        assert response["jsonrpc"] == "2.0"
        assert "result" in response
        assert response["result"]["status"] == "ok"

        # Check interaction was recorded
        records = openclaw_honeypot.records
        tool_calls = [r for r in records if r.tool_name == "get_skill_secrets"]
        assert len(tool_calls) >= 1
        assert tool_calls[-1].source_ip == "10.0.0.1"

    def test_profile_available_in_deployer(self) -> None:
        """The openclaw_registry profile should be registered in AVAILABLE_PROFILES."""
        from navil.honeypot.deploy import AVAILABLE_PROFILES

        assert "openclaw_registry" in AVAILABLE_PROFILES

    def test_profile_has_service_mapping(self) -> None:
        """The openclaw_registry profile should have a Docker service mapping."""
        from navil.honeypot.deploy import _PROFILE_SERVICE_MAP

        assert "openclaw_registry" in _PROFILE_SERVICE_MAP
        assert _PROFILE_SERVICE_MAP["openclaw_registry"] == "honeypot-openclaw-registry"
