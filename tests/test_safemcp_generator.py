"""Tests for SAFE-MCP parameterized scenario generator."""

from __future__ import annotations

import json
import os

import pytest

from navil.safemcp.generator import (
    _CATEGORY_TO_GENERATOR,
    AttackVariantGenerator,
    generate_all_variants,
    load_attack_catalog,
)

# ── Catalog Loading ──────────────────────────────────────────


class TestLoadAttackCatalog:
    """Tests for loading the YAML attack catalog."""

    def test_load_default_catalog(self):
        """Should load the bundled public_attacks.yaml."""
        attacks = load_attack_catalog()
        assert len(attacks) >= 30, f"Expected 30+ attacks, got {len(attacks)}"

    def test_catalog_has_50_plus_attacks(self):
        """Catalog should contain 50+ attack patterns for comprehensive coverage."""
        attacks = load_attack_catalog()
        assert len(attacks) >= 50, f"Expected 50+ attacks, got {len(attacks)}"

    def test_each_attack_has_required_fields(self):
        """Every attack must have name, category, severity, attack_steps."""
        attacks = load_attack_catalog()
        for attack in attacks:
            assert "name" in attack, f"Attack missing 'name': {attack}"
            assert "category" in attack, f"Attack {attack['name']} missing 'category'"
            assert "severity" in attack, f"Attack {attack['name']} missing 'severity'"
            assert "attack_steps" in attack, f"Attack {attack['name']} missing 'attack_steps'"
            assert "description" in attack, f"Attack {attack['name']} missing 'description'"

    def test_each_attack_has_indicators(self):
        """Every attack should have indicators for detection mapping."""
        attacks = load_attack_catalog()
        for attack in attacks:
            assert "indicators" in attack, f"Attack {attack['name']} missing 'indicators'"
            assert len(attack["indicators"]) >= 1, f"Attack {attack['name']} has no indicators"

    def test_each_attack_has_source_reference(self):
        """Every attack should cite a source reference."""
        attacks = load_attack_catalog()
        for attack in attacks:
            assert (
                "source_reference" in attack
            ), f"Attack {attack['name']} missing 'source_reference'"
            assert (
                len(attack["source_reference"]) > 0
            ), f"Attack {attack['name']} has empty source_reference"

    def test_categories_map_to_generators(self):
        """Every attack category should have a corresponding variant generator."""
        attacks = load_attack_catalog()
        categories = {a["category"] for a in attacks}
        for cat in categories:
            assert cat in _CATEGORY_TO_GENERATOR, f"No generator for category: {cat}"

    def test_severity_values_are_valid(self):
        """Severity must be one of LOW, MEDIUM, HIGH, CRITICAL."""
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        attacks = load_attack_catalog()
        for attack in attacks:
            assert (
                attack["severity"] in valid
            ), f"Invalid severity '{attack['severity']}' in attack '{attack['name']}'"

    def test_no_duplicate_names(self):
        """Attack names must be unique."""
        attacks = load_attack_catalog()
        names = [a["name"] for a in attacks]
        assert len(names) == len(set(names)), "Duplicate attack names found"

    def test_all_ten_categories_present(self):
        """Catalog must cover all 10 threat categories."""
        expected_categories = {
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
        attacks = load_attack_catalog()
        actual_categories = {a["category"] for a in attacks}
        missing = expected_categories - actual_categories
        assert not missing, f"Missing categories: {missing}"

    def test_each_category_has_multiple_attacks(self):
        """Every category should have at least 2 attacks for variety."""
        attacks = load_attack_catalog()
        category_counts: dict[str, int] = {}
        for attack in attacks:
            cat = attack["category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1

        for cat, count in category_counts.items():
            assert count >= 2, f"Category '{cat}' has only {count} attack(s), need at least 2"

    def test_known_attacks_present(self):
        """Key real-world attacks from research should be in the catalog."""
        attacks = load_attack_catalog()
        names = {a["name"] for a in attacks}
        expected = {
            "github_data_heist_via_copilot",
            "whatsapp_message_exfiltration",
            "cursor_ide_workspace_hijack",
            "tool_poisoning_description_injection",
            "rug_pull_tool_behavior_change",
            "c2_beaconing_via_tool_calls",
            "tool_shadowing_attack",
        }
        missing = expected - names
        assert not missing, f"Missing expected attacks: {missing}"

    def test_attack_steps_are_lists(self):
        """Each attack_steps field must be a list."""
        attacks = load_attack_catalog()
        for attack in attacks:
            assert isinstance(
                attack["attack_steps"], list
            ), f"Attack {attack['name']} has non-list attack_steps"
            assert (
                len(attack["attack_steps"]) >= 1
            ), f"Attack {attack['name']} has empty attack_steps"

    def test_custom_catalog_path(self, tmp_path):
        """Should load from a custom path if provided."""
        import yaml

        custom = [
            {
                "name": "custom_test",
                "category": "RECONNAISSANCE",
                "severity": "LOW",
                "description": "Test attack",
                "attack_steps": [{"method": "tools/list"}],
                "indicators": ["test"],
                "source_reference": "test",
            }
        ]
        path = tmp_path / "custom.yaml"
        path.write_text(yaml.dump({"attacks": custom}))
        loaded = load_attack_catalog(str(path))
        assert len(loaded) == 1
        assert loaded[0]["name"] == "custom_test"


# ── Variant Generation ───────────────────────────────────────


class TestAttackVariantGenerator:
    """Tests for the parameterized variant generator."""

    @pytest.fixture
    def generator(self):
        gen = AttackVariantGenerator(variants_per_attack=5)
        gen.load()
        return gen

    def test_load_succeeds(self, generator):
        assert len(generator.attacks) >= 30

    def test_lazy_load(self):
        """Accessing .attacks should trigger lazy loading."""
        gen = AttackVariantGenerator(variants_per_attack=5)
        assert not gen._loaded
        _ = gen.attacks
        assert gen._loaded

    def test_attack_names_populated(self, generator):
        names = generator.attack_names
        assert len(names) >= 30
        assert "github_data_heist_via_copilot" in names

    def test_generate_variants_all(self, generator):
        """Should generate variants for all attacks."""
        variants = generator.generate_variants()
        assert len(variants) >= 25  # some categories might not map

        for attack_name, variant_list in variants.items():
            assert (
                len(variant_list) >= 5
            ), f"Attack '{attack_name}' produced only {len(variant_list)} variants (expected >=5)"
            assert (
                len(variant_list) <= 10
            ), f"Attack '{attack_name}' produced {len(variant_list)} variants (expected <=10)"

    def test_generate_variants_single(self, generator):
        """Should generate variants for a single named attack."""
        variants = generator.generate_variants("github_data_heist_via_copilot")
        assert len(variants) == 1
        assert "github_data_heist_via_copilot" in variants

    def test_generate_variants_nonexistent_attack(self, generator):
        """Should return empty dict for a nonexistent attack name."""
        variants = generator.generate_variants("nonexistent_attack_xyz")
        assert len(variants) == 0

    def test_variant_invocation_format(self, generator):
        """Each variant invocation must have agent_name and tool_name."""
        variants = generator.generate_variants()
        for attack_name, variant_list in variants.items():
            for variant in variant_list:
                assert isinstance(variant, list), f"Variant for {attack_name} is not a list"
                for inv in variant:
                    assert isinstance(inv, dict), "Invocation is not a dict"
                    assert "agent_name" in inv, f"Missing agent_name in {attack_name}"
                    assert "tool_name" in inv, f"Missing tool_name in {attack_name}"

    def test_generate_scenario_generators(self, generator):
        """Should produce callable generators compatible with seed.py."""
        generators = generator.generate_scenario_generators()
        assert len(generators) >= 25

        for name, gen_fn in generators.items():
            result = gen_fn("test-agent-42", 0)
            assert isinstance(result, list), f"Generator {name} returned non-list"
            assert len(result) >= 1, f"Generator {name} returned empty list"

            for inv in result:
                assert (
                    inv["agent_name"] == "test-agent-42"
                ), f"Generator {name} didn't override agent_name"

    def test_scenario_generators_50_plus_with_full_catalog(self, generator):
        """With the full catalog, should produce 50+ scenario generators."""
        generators = generator.generate_scenario_generators()
        assert len(generators) >= 50, f"Expected 50+ generators, got {len(generators)}"

    def test_export_scenarios(self, generator):
        """Should produce JSON-serializable scenario definitions."""
        exported = generator.export_scenarios()
        assert len(exported) >= 30

        # Verify JSON-serializable
        json_str = json.dumps(exported)
        parsed = json.loads(json_str)
        assert len(parsed) == len(exported)

        for entry in exported:
            assert "name" in entry
            assert "category" in entry
            assert "severity" in entry

    def test_export_includes_attack_steps(self, generator):
        """Exported scenarios should include attack_steps."""
        exported = generator.export_scenarios()
        for entry in exported:
            assert "attack_steps" in entry, f"Missing attack_steps in {entry['name']}"

    def test_export_includes_indicators(self, generator):
        """Exported scenarios should include indicators."""
        exported = generator.export_scenarios()
        for entry in exported:
            assert "indicators" in entry, f"Missing indicators in {entry['name']}"

    def test_variants_per_attack_clamping(self):
        """variants_per_attack should be clamped to [5, 10]."""
        gen_low = AttackVariantGenerator(variants_per_attack=1)
        assert gen_low.variants_per_attack == 5

        gen_high = AttackVariantGenerator(variants_per_attack=100)
        assert gen_high.variants_per_attack == 10

        gen_mid = AttackVariantGenerator(variants_per_attack=7)
        assert gen_mid.variants_per_attack == 7


class TestGenerateAllVariants:
    """Tests for the convenience function."""

    def test_generates_variants(self):
        result = generate_all_variants(variants_per_attack=5)
        assert isinstance(result, dict)
        assert len(result) >= 25

    def test_generates_all_attack_variants(self):
        """Should generate variants for every attack in catalog."""
        result = generate_all_variants(variants_per_attack=5)
        attacks = load_attack_catalog()
        # Every attack should have variants generated
        for attack in attacks:
            assert (
                attack["name"] in result
            ), f"Attack '{attack['name']}' missing from generated variants"


# ── Parameter Bounds ─────────────────────────────────────────


class TestParameterBounds:
    """Ensure generated variants respect expected bounds."""

    @pytest.fixture
    def all_variants(self):
        gen = AttackVariantGenerator(variants_per_attack=5)
        gen.load()
        return gen.generate_variants()

    def test_agent_names_are_unique_per_variant(self, all_variants):
        """Different variants should generally have different agent names."""
        for attack_name, variant_list in all_variants.items():
            agents = set()
            for variant in variant_list:
                if variant:
                    agents.add(variant[0]["agent_name"])
            # With random agent names, most should be unique
            assert (
                len(agents) >= 3
            ), f"Attack '{attack_name}' has too few unique agents: {len(agents)}"

    def test_invocations_have_valid_durations(self, all_variants):
        """duration_ms should be positive."""
        for attack_name, variant_list in all_variants.items():
            for variant in variant_list:
                for inv in variant:
                    if "duration_ms" in inv:
                        assert inv["duration_ms"] >= 0, f"Negative duration in {attack_name}"

    def test_arguments_size_non_negative(self, all_variants):
        """arguments_size_bytes should be non-negative when present."""
        for attack_name, variant_list in all_variants.items():
            for variant in variant_list:
                for inv in variant:
                    if "arguments_size_bytes" in inv:
                        assert (
                            inv["arguments_size_bytes"] >= 0
                        ), f"Negative arguments_size in {attack_name}"

    def test_response_size_non_negative(self, all_variants):
        """response_size_bytes should be non-negative when present."""
        for attack_name, variant_list in all_variants.items():
            for variant in variant_list:
                for inv in variant:
                    if "response_size_bytes" in inv:
                        assert (
                            inv["response_size_bytes"] >= 0
                        ), f"Negative response_size in {attack_name}"

    def test_data_accessed_bytes_non_negative(self, all_variants):
        """data_accessed_bytes should be non-negative when present."""
        for attack_name, variant_list in all_variants.items():
            for variant in variant_list:
                for inv in variant:
                    if "data_accessed_bytes" in inv:
                        assert (
                            inv["data_accessed_bytes"] >= 0
                        ), f"Negative data_accessed_bytes in {attack_name}"


# ── Category-specific Variant Tests ──────────────────────────


class TestCategoryVariants:
    """Verify that each category produces valid variants."""

    @pytest.fixture
    def all_variants(self):
        gen = AttackVariantGenerator(variants_per_attack=5)
        gen.load()
        return gen.generate_variants()

    @pytest.fixture
    def attacks_by_category(self):
        attacks = load_attack_catalog()
        by_cat: dict[str, list[str]] = {}
        for a in attacks:
            by_cat.setdefault(a["category"], []).append(a["name"])
        return by_cat

    def test_reconnaissance_variants_have_is_list_tools(self, all_variants, attacks_by_category):
        """Reconnaissance variants should set is_list_tools flag."""
        for name in attacks_by_category.get("RECONNAISSANCE", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                for inv in variant:
                    if inv.get("tool_name") == "__tools_list__":
                        assert inv.get("is_list_tools") is True

    def test_data_exfiltration_has_high_data_volume(self, all_variants, attacks_by_category):
        """Data exfiltration variants should have elevated data_accessed_bytes."""
        for name in attacks_by_category.get("DATA_EXFILTRATION", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                for inv in variant:
                    if "data_accessed_bytes" in inv:
                        assert (
                            inv["data_accessed_bytes"] >= 1000
                        ), f"Low data volume in exfil variant {name}"

    def test_defense_evasion_has_large_payload(self, all_variants, attacks_by_category):
        """Defense evasion variants should have large argument payloads."""
        for name in attacks_by_category.get("DEFENSE_EVASION", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                for inv in variant:
                    if "arguments_size_bytes" in inv:
                        assert (
                            inv["arguments_size_bytes"] >= 5000
                        ), f"Small payload in defense evasion variant {name}"

    def test_lateral_movement_has_target_server(self, all_variants, attacks_by_category):
        """Lateral movement variants should reference target servers."""
        for name in attacks_by_category.get("LATERAL_MOVEMENT", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                servers_seen = set()
                for inv in variant:
                    if "target_server" in inv:
                        servers_seen.add(inv["target_server"])
                assert (
                    len(servers_seen) >= 4
                ), f"Lateral movement variant {name} only accessed {len(servers_seen)} servers"

    def test_supply_chain_has_unregistered_tool(self, all_variants, attacks_by_category):
        """Supply chain variants should reference unregistered tools."""
        for name in attacks_by_category.get("SUPPLY_CHAIN", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                for inv in variant:
                    if "_register_server" in inv:
                        # Should have a tool call to unregistered tool
                        registered = inv["_register_server"][1]
                        assert (
                            inv["tool_name"] not in registered
                        ), f"Tool '{inv['tool_name']}' should NOT be in registered list"

    def test_persistence_has_timestamps(self, all_variants, attacks_by_category):
        """Persistence variants should have _raw_timestamp for timing analysis."""
        for name in attacks_by_category.get("PERSISTENCE", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                has_timestamps = any("_raw_timestamp" in inv for inv in variant)
                assert has_timestamps, f"Persistence variant {name} missing timestamps"

    def test_c2_has_timestamps_and_consistent_response(self, all_variants, attacks_by_category):
        """C2 variants should have timestamps and relatively consistent response sizes."""
        for name in attacks_by_category.get("COMMAND_AND_CONTROL", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                has_timestamps = any("_raw_timestamp" in inv for inv in variant)
                assert has_timestamps, f"C2 variant {name} missing timestamps"

    def test_rate_spike_has_many_invocations(self, all_variants, attacks_by_category):
        """Rate spike variants should have a large number of invocations."""
        for name in attacks_by_category.get("RATE_SPIKE", []):
            if name not in all_variants:
                continue
            for variant in all_variants[name]:
                assert (
                    len(variant) >= 20
                ), f"Rate spike variant {name} has only {len(variant)} invocations"


# ── Blocklist Integration Tests ──────────────────────────────


class TestBlocklistV1:
    """Tests for the blocklist_v1.json signature file."""

    @pytest.fixture
    def blocklist(self):
        path = os.path.join(os.path.dirname(__file__), "..", "navil", "data", "blocklist_v1.json")
        with open(path) as f:
            return json.load(f)

    def test_blocklist_has_200_plus_patterns(self, blocklist):
        """Blocklist should contain 200+ signature patterns."""
        assert (
            len(blocklist["patterns"]) >= 200
        ), f"Expected 200+ patterns, got {len(blocklist['patterns'])}"

    def test_blocklist_has_version(self, blocklist):
        """Blocklist should have a version field."""
        assert "version" in blocklist
        assert blocklist["version"] >= 1

    def test_blocklist_has_description(self, blocklist):
        """Blocklist should have a description."""
        assert "description" in blocklist
        assert len(blocklist["description"]) > 0

    def test_each_pattern_has_required_fields(self, blocklist):
        """Every pattern must have the required fields."""
        required = {"pattern_id", "pattern_type", "value", "severity", "description", "confidence"}
        for pattern in blocklist["patterns"]:
            for field in required:
                assert (
                    field in pattern
                ), f"Pattern {pattern.get('pattern_id', '?')} missing field: {field}"

    def test_pattern_ids_are_unique(self, blocklist):
        """Pattern IDs must be unique."""
        ids = [p["pattern_id"] for p in blocklist["patterns"]]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"

    def test_confidence_in_range(self, blocklist):
        """Confidence scores must be between 0.0 and 1.0."""
        for pattern in blocklist["patterns"]:
            assert (
                0.0 <= pattern["confidence"] <= 1.0
            ), f"Pattern {pattern['pattern_id']} confidence out of range: {pattern['confidence']}"

    def test_severity_values_valid(self, blocklist):
        """Pattern severity must be one of LOW, MEDIUM, HIGH, CRITICAL."""
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for pattern in blocklist["patterns"]:
            assert (
                pattern["severity"] in valid
            ), f"Invalid severity '{pattern['severity']}' in pattern {pattern['pattern_id']}"

    def test_pattern_types_diverse(self, blocklist):
        """Blocklist should cover multiple pattern types."""
        types = {p["pattern_type"] for p in blocklist["patterns"]}
        assert len(types) >= 5, f"Expected 5+ pattern types, got {len(types)}: {types}"

    def test_has_tool_name_patterns(self, blocklist):
        """Blocklist should have tool_name patterns."""
        tool_patterns = [p for p in blocklist["patterns"] if p["pattern_type"] == "tool_name"]
        assert len(tool_patterns) >= 10

    def test_has_argument_patterns(self, blocklist):
        """Blocklist should have argument_pattern entries."""
        arg_patterns = [p for p in blocklist["patterns"] if p["pattern_type"] == "argument_pattern"]
        assert len(arg_patterns) >= 10

    def test_has_sequence_patterns(self, blocklist):
        """Blocklist should have tool_sequence patterns."""
        seq_patterns = [p for p in blocklist["patterns"] if p["pattern_type"] == "tool_sequence"]
        assert len(seq_patterns) >= 10

    def test_has_env_access_patterns(self, blocklist):
        """Blocklist should have env_access patterns for environment variable theft."""
        env_patterns = [p for p in blocklist["patterns"] if p["pattern_type"] == "env_access"]
        assert len(env_patterns) >= 10

    def test_has_url_patterns(self, blocklist):
        """Blocklist should have url_pattern entries."""
        url_patterns = [p for p in blocklist["patterns"] if p["pattern_type"] == "url_pattern"]
        assert len(url_patterns) >= 5

    def test_has_description_injection_patterns(self, blocklist):
        """Blocklist should have description_injection patterns."""
        desc_patterns = [
            p for p in blocklist["patterns"] if p["pattern_type"] == "description_injection"
        ]
        assert len(desc_patterns) >= 5


# ── Seed Integration Tests ───────────────────────────────────


class TestSeedIntegration:
    """Test that the generator integrates correctly with seed.py."""

    def test_seed_export_includes_expanded(self):
        """export_scenarios should include both builtin and expanded scenarios."""
        from navil.seed import export_scenarios

        scenarios = export_scenarios(include_expanded=True)
        sources = {s.get("source", "?") for s in scenarios}
        assert "builtin" in sources
        assert "public_attacks_catalog" in sources
        assert len(scenarios) >= 50

    def test_seed_export_without_expanded(self):
        """export_scenarios without expanded should only have builtins."""
        from navil.seed import export_scenarios

        scenarios = export_scenarios(include_expanded=False)
        sources = {s.get("source", "?") for s in scenarios}
        assert "builtin" in sources
        # Should be just the builtin scenarios (about 10)
        assert len(scenarios) <= 15

    def test_seed_database_basic(self):
        """seed_database should run without errors for small iterations."""
        from navil.seed import seed_database

        stats = seed_database(iterations=1, show_progress=False, mock_server=False)
        assert stats.iterations == 1
        assert stats.total_invocations > 0
        assert len(stats.scenarios_run) >= 5

    def test_seed_database_full_mode(self):
        """seed_database with full=True should run expanded scenarios."""
        from navil.seed import seed_database

        stats = seed_database(iterations=1, show_progress=False, mock_server=False, full=True)
        assert stats.iterations == 1
        # Full mode should run many more scenarios
        assert len(stats.scenarios_run) >= 50
        assert stats.total_invocations > 100


# ── Edge Cases ───────────────────────────────────────────────


class TestEdgeCases:
    """Edge case and regression tests."""

    def test_generator_with_empty_catalog(self, tmp_path):
        """Generator should handle empty catalog gracefully."""
        import yaml

        path = tmp_path / "empty.yaml"
        path.write_text(yaml.dump({"attacks": []}))
        gen = AttackVariantGenerator(catalog_path=str(path), variants_per_attack=5)
        gen.load()
        assert len(gen.attacks) == 0
        variants = gen.generate_variants()
        assert len(variants) == 0

    def test_generator_multiple_loads(self):
        """Loading multiple times should not cause issues."""
        gen = AttackVariantGenerator(variants_per_attack=5)
        gen.load()
        count1 = len(gen.attacks)
        gen.load()
        count2 = len(gen.attacks)
        assert count1 == count2

    def test_variant_determinism_with_seed(self):
        """With the same random seed, variants should be deterministic."""
        import random

        random.seed(42)
        gen1 = AttackVariantGenerator(variants_per_attack=5)
        gen1.load()
        v1 = gen1.generate_variants("tools_list_enumeration")

        random.seed(42)
        gen2 = AttackVariantGenerator(variants_per_attack=5)
        gen2.load()
        v2 = gen2.generate_variants("tools_list_enumeration")

        # Should produce identical results with same seed
        assert len(v1) == len(v2)
        for name in v1:
            assert len(v1[name]) == len(v2[name])

    def test_all_category_generators_callable(self):
        """Every entry in _CATEGORY_TO_GENERATOR should be callable."""
        for cat, gen_fn in _CATEGORY_TO_GENERATOR.items():
            assert callable(gen_fn), f"Generator for {cat} is not callable"

    def test_all_category_generators_produce_variants(self):
        """Each category generator should produce valid variant lists."""
        dummy_attack = {
            "name": "test",
            "category": "TEST",
            "severity": "HIGH",
            "attack_steps": [{"method": "tools/call"}],
        }
        for cat, gen_fn in _CATEGORY_TO_GENERATOR.items():
            variants = gen_fn(dummy_attack, n=2)
            assert isinstance(variants, list), f"Generator for {cat} returned non-list"
            assert len(variants) == 2, f"Generator for {cat} returned {len(variants)} variants"
            for variant in variants:
                assert isinstance(variant, list), f"Variant from {cat} is not a list"
                assert len(variant) >= 1, f"Variant from {cat} is empty"
