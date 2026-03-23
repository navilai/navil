"""Tests for the navil redteam command."""

from __future__ import annotations

import json

from navil.commands.redteam import (
    MAX_HYPOTHESES,
    compare_prediction,
    parse_hypotheses,
)


class TestParseHypotheses:
    """Tests for parse_hypotheses."""

    def test_valid_json_array(self) -> None:
        response = json.dumps(
            [
                {
                    "hypothesis": "Inject malicious context via shared memory pool",
                    "category": "rag_memory_poisoning",
                    "novelty_rationale": "Exploits shared RAG memory across agents",
                    "expected_detection": "missed",
                },
                {
                    "hypothesis": "Abuse delegation chain to escalate privileges",
                    "category": "delegation_abuse",
                    "novelty_rationale": "Multi-hop trust laundering",
                    "expected_detection": "blocked",
                },
            ]
        )
        result = parse_hypotheses(response)
        assert len(result) == 2
        assert result[0]["category"] == "rag_memory_poisoning"
        assert result[1]["expected_detection"] == "blocked"

    def test_wrapped_in_object(self) -> None:
        response = json.dumps(
            {
                "hypotheses": [
                    {
                        "hypothesis": "Side-channel via timing of tool responses",
                        "category": "covert_channel",
                        "novelty_rationale": "Timing-based exfil",
                        "expected_detection": "missed",
                    },
                ]
            }
        )
        result = parse_hypotheses(response)
        assert len(result) == 1

    def test_markdown_fences_stripped(self) -> None:
        response = (
            "```json\n"
            + json.dumps(
                [
                    {
                        "hypothesis": "Test hypothesis",
                        "category": "prompt_injection",
                        "novelty_rationale": "Novel approach",
                        "expected_detection": "missed",
                    },
                ]
            )
            + "\n```"
        )
        result = parse_hypotheses(response)
        assert len(result) == 1

    def test_invalid_category_skipped(self) -> None:
        response = json.dumps(
            [
                {
                    "hypothesis": "Valid hypothesis",
                    "category": "totally_fake_category",
                    "novelty_rationale": "N/A",
                    "expected_detection": "missed",
                },
            ]
        )
        result = parse_hypotheses(response)
        assert len(result) == 0

    def test_fuzzy_category_match(self) -> None:
        response = json.dumps(
            [
                {
                    "hypothesis": "Test",
                    "category": "prompt_injection_advanced",
                    "novelty_rationale": "N/A",
                    "expected_detection": "missed",
                },
            ]
        )
        result = parse_hypotheses(response)
        assert len(result) == 1
        assert result[0]["category"] == "prompt_injection"

    def test_missing_required_fields(self) -> None:
        response = json.dumps(
            [
                {"hypothesis": "No category"},
                {"category": "prompt_injection"},
                {},
            ]
        )
        result = parse_hypotheses(response)
        assert len(result) == 0

    def test_invalid_expected_detection_defaults_to_missed(self) -> None:
        response = json.dumps(
            [
                {
                    "hypothesis": "Test",
                    "category": "prompt_injection",
                    "novelty_rationale": "N/A",
                    "expected_detection": "unknown",
                },
            ]
        )
        result = parse_hypotheses(response)
        assert len(result) == 1
        assert result[0]["expected_detection"] == "missed"

    def test_empty_response(self) -> None:
        assert parse_hypotheses("") == []
        assert parse_hypotheses("not json at all") == []

    def test_sanitization_strips_control_chars(self) -> None:
        """Sanitization strips control chars and terminal escapes, not backticks/HTML."""
        response = json.dumps(
            [
                {
                    "hypothesis": "Test `with code` and <html>\x1b[31mRED\x1b[0m\x00null\x07bell",
                    "category": "prompt_injection",
                    "novelty_rationale": "N/A",
                    "expected_detection": "missed",
                },
            ]
        )
        result = parse_hypotheses(response)
        assert len(result) == 1
        # Backticks and HTML are safe text — preserved
        assert "`" in result[0]["hypothesis"]
        assert "<" in result[0]["hypothesis"]
        # Control chars and terminal escapes are stripped
        assert "\x1b" not in result[0]["hypothesis"]
        assert "\x00" not in result[0]["hypothesis"]
        assert "\x07" not in result[0]["hypothesis"]


class TestComparePrediction:
    """Tests for compare_prediction."""

    def test_real_gap(self) -> None:
        assert compare_prediction("missed", False) == "REAL GAP"

    def test_coverage_ok(self) -> None:
        assert compare_prediction("missed", True) == "COVERAGE OK"

    def test_surprise_gap(self) -> None:
        assert compare_prediction("blocked", False) == "SURPRISE GAP"

    def test_expected_block(self) -> None:
        assert compare_prediction("blocked", True) == "EXPECTED BLOCK"


class TestMaxHypotheses:
    """Test guard rails."""

    def test_max_hypotheses_value(self) -> None:
        assert MAX_HYPOTHESES == 50
