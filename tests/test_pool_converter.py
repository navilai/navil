"""Tests for the Pool-to-SafeMCP converter."""

from __future__ import annotations

import pytest

from navil.safemcp.pool_converter import (
    _VECTOR_GROUPS,
    VECTOR_TO_SAFEMCP,
    convert_all,
    convert_vector,
    get_vector_category,
    get_vector_class,
    get_vectors_for_category,
)

# ── Mapping Coverage ─────────────────────────────────────────────


class TestVectorMapping:
    """Tests that the VECTOR_TO_SAFEMCP mapping covers all 200 vectors."""

    def test_mapping_has_200_entries(self):
        """All 200 vector IDs (101-300) must be in the mapping."""
        assert len(VECTOR_TO_SAFEMCP) == 200

    def test_all_ids_101_to_300_present(self):
        """Every ID from 101 to 300 inclusive must be mapped."""
        for vid in range(101, 301):
            assert vid in VECTOR_TO_SAFEMCP, f"Vector ID {vid} missing from mapping"

    def test_no_extra_ids(self):
        """No IDs outside 101-300 should be in the mapping."""
        for vid in VECTOR_TO_SAFEMCP:
            assert 101 <= vid <= 300, f"Unexpected vector ID {vid} in mapping"

    def test_each_entry_has_required_keys(self):
        """Every mapping entry must have required config keys."""
        required = {
            "category",
            "class_name",
            "tool_pool",
            "timing",
            "payload_range",
            "response_range",
        }
        for vid, cfg in VECTOR_TO_SAFEMCP.items():
            for key in required:
                assert key in cfg, f"Vector {vid} missing key: {key}"


# ── Attack Class → Category Mapping ──────────────────────────────


class TestAttackClassMapping:
    """Tests that each attack class maps to the correct category."""

    _EXPECTED_CLASS_CATEGORIES = {
        (101, 115): "multimodal_smuggling",
        (116, 130): "handshake_hijacking",
        (131, 150): "rag_memory_poisoning",
        (151, 170): "supply_chain",
        (171, 190): "privilege_escalation",
        (191, 200): "defense_evasion",
        (201, 220): "agent_collusion",
        (221, 240): "cognitive_exploitation",
        (241, 260): "temporal_stateful",
        (261, 280): "output_weaponization",
        (281, 300): "code_execution",
    }

    @pytest.mark.parametrize(
        "id_range,expected_category",
        list(_EXPECTED_CLASS_CATEGORIES.items()),
        ids=[f"IDs_{lo}-{hi}" for lo, hi in _EXPECTED_CLASS_CATEGORIES],
    )
    def test_class_maps_to_correct_category(self, id_range, expected_category):
        lo, hi = id_range
        for vid in range(lo, hi + 1):
            actual = get_vector_category(vid)
            assert actual == expected_category, (
                f"Vector {vid}: expected category '{expected_category}', got '{actual}'"
            )


# ── convert_vector ───────────────────────────────────────────────


class TestConvertVector:
    """Tests for the convert_vector function."""

    def test_returns_list_of_lists(self):
        result = convert_vector(101, count=3)
        assert isinstance(result, list)
        assert len(result) == 3
        for variant in result:
            assert isinstance(variant, list)
            assert len(variant) >= 1

    def test_default_count_is_5(self):
        result = convert_vector(150)
        assert len(result) == 5

    def test_invocation_has_required_fields(self):
        """Each invocation must have fields compatible with _inject_invocations."""
        required_fields = {
            "agent_name",
            "tool_name",
            "action",
            "duration_ms",
            "arguments_size_bytes",
            "response_size_bytes",
            "_raw_timestamp",
            "arguments_hash",
        }
        result = convert_vector(200, count=2)
        for variant in result:
            for inv in variant:
                for field in required_fields:
                    assert field in inv, f"Missing field '{field}' in invocation"

    def test_agent_name_is_string(self):
        result = convert_vector(101, count=1)
        for inv in result[0]:
            assert isinstance(inv["agent_name"], str)
            assert len(inv["agent_name"]) > 0

    def test_tool_name_from_pool(self):
        """Tool names should come from the configured tool pool."""
        from navil.safemcp.generator import _TOOL_POOLS

        cfg = VECTOR_TO_SAFEMCP[101]
        pool = _TOOL_POOLS[cfg["tool_pool"]]
        result = convert_vector(101, count=3)
        for variant in result:
            for inv in variant:
                assert inv["tool_name"] in pool, (
                    f"Tool '{inv['tool_name']}' not in pool '{cfg['tool_pool']}'"
                )

    def test_action_is_valid(self):
        valid_actions = {"call", "list", "read"}
        result = convert_vector(101, count=2)
        for variant in result:
            for inv in variant:
                assert inv["action"] in valid_actions

    def test_duration_ms_positive(self):
        result = convert_vector(150, count=3)
        for variant in result:
            for inv in variant:
                assert inv["duration_ms"] >= 0

    def test_arguments_size_non_negative(self):
        result = convert_vector(250, count=3)
        for variant in result:
            for inv in variant:
                assert inv["arguments_size_bytes"] >= 0

    def test_response_size_non_negative(self):
        result = convert_vector(250, count=3)
        for variant in result:
            for inv in variant:
                assert inv["response_size_bytes"] >= 0

    def test_arguments_hash_is_sha256(self):
        result = convert_vector(101, count=1)
        for inv in result[0]:
            h = inv["arguments_hash"]
            assert isinstance(h, str)
            assert len(h) == 64  # SHA256 hex digest

    def test_raw_timestamp_is_iso_string(self):
        result = convert_vector(101, count=1)
        for inv in result[0]:
            ts = inv["_raw_timestamp"]
            assert isinstance(ts, str)
            assert "T" in ts  # ISO format

    def test_invalid_vector_id_raises(self):
        with pytest.raises(KeyError):
            convert_vector(99)
        with pytest.raises(KeyError):
            convert_vector(301)
        with pytest.raises(KeyError):
            convert_vector(0)

    def test_variants_have_different_agents(self):
        """Different variants should generally have different random agents."""
        result = convert_vector(101, count=10)
        agents = {variant[0]["agent_name"] for variant in result}
        # With 10 random agents, most should be unique
        assert len(agents) >= 5

    def test_all_200_vectors_produce_valid_invocations(self):
        """Smoke test: every vector ID produces at least one valid invocation."""
        for vid in range(101, 301):
            result = convert_vector(vid, count=1)
            assert len(result) == 1, f"Vector {vid} did not produce 1 variant"
            assert len(result[0]) >= 1, f"Vector {vid} variant is empty"
            inv = result[0][0]
            assert "agent_name" in inv
            assert "tool_name" in inv


# ── convert_all ──────────────────────────────────────────────────


class TestConvertAll:
    """Tests for the convert_all batch conversion function."""

    def test_returns_200_entries(self):
        result = convert_all(count_per_vector=1)
        assert len(result) == 200

    def test_all_ids_present(self):
        result = convert_all(count_per_vector=1)
        for vid in range(101, 301):
            assert vid in result, f"Vector {vid} missing from convert_all output"

    def test_each_entry_has_correct_count(self):
        result = convert_all(count_per_vector=3)
        for vid, variants in result.items():
            assert len(variants) == 3, f"Vector {vid} has {len(variants)} variants, expected 3"

    def test_output_is_dict_of_lists(self):
        result = convert_all(count_per_vector=1)
        assert isinstance(result, dict)
        for vid, variants in result.items():
            assert isinstance(vid, int)
            assert isinstance(variants, list)
            for variant in variants:
                assert isinstance(variant, list)


# ── Helper Functions ─────────────────────────────────────────────


class TestHelpers:
    """Tests for helper functions."""

    def test_get_vector_category(self):
        assert get_vector_category(101) == "multimodal_smuggling"
        assert get_vector_category(200) == "defense_evasion"
        assert get_vector_category(300) == "code_execution"

    def test_get_vector_class(self):
        assert get_vector_class(101) == "Multi-Modal Smuggling"
        assert get_vector_class(151) == "Supply Chain/Discovery"

    def test_get_vectors_for_category(self):
        vids = get_vectors_for_category("multimodal_smuggling")
        assert len(vids) == 15
        assert all(101 <= v <= 115 for v in vids)

    def test_get_vectors_for_unknown_category(self):
        vids = get_vectors_for_category("nonexistent_category")
        assert vids == []

    def test_vector_groups_cover_full_range(self):
        """Verify _VECTOR_GROUPS cover IDs 101-300 with no gaps or overlaps."""
        all_ids: set[int] = set()
        for group in _VECTOR_GROUPS:
            lo, hi = group["id_range"]
            for vid in range(lo, hi + 1):
                assert vid not in all_ids, f"Vector ID {vid} appears in multiple groups"
                all_ids.add(vid)
        assert all_ids == set(range(101, 301)), "Vector groups do not cover 101-300 exactly"


# ── Output Schema Compatibility ──────────────────────────────────


class TestOutputSchema:
    """Tests that output matches _inject_invocations expected format."""

    def test_schema_matches_inject_invocations_format(self):
        """The output schema must be compatible with seed._inject_invocations."""
        # These are the fields that _inject_invocations reads
        known_fields = {
            "agent_name",
            "tool_name",
            "action",
            "duration_ms",
            "data_accessed_bytes",
            "success",
            "location",
            "target_server",
            "arguments_hash",
            "arguments_size_bytes",
            "response_size_bytes",
            "is_list_tools",
            "_raw_timestamp",
            "_needs_baseline",
            "_register_server",
        }
        result = convert_vector(101, count=1)
        for inv in result[0]:
            for key in inv:
                assert key in known_fields, (
                    f"Unknown field '{key}' in invocation — not handled by _inject_invocations"
                )

    def test_agent_name_and_tool_name_always_present(self):
        """_inject_invocations requires agent_name and tool_name."""
        for vid in [101, 150, 200, 250, 300]:
            result = convert_vector(vid, count=1)
            for inv in result[0]:
                assert "agent_name" in inv
                assert "tool_name" in inv
                assert isinstance(inv["agent_name"], str)
                assert isinstance(inv["tool_name"], str)
