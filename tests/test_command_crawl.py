"""Tests for the navil crawl threat-scan command."""

from __future__ import annotations

import os
import tempfile

import yaml

from navil.commands.crawl import (
    THREAT_INTEL_SOURCES,
    _dedup_against_existing,
)


class TestThreatIntelSources:
    """Tests for the threat intel source list."""

    def test_source_count(self) -> None:
        assert len(THREAT_INTEL_SOURCES) == 7

    def test_all_sources_have_required_fields(self) -> None:
        for source in THREAT_INTEL_SOURCES:
            assert "name" in source, f"Missing 'name' in source: {source}"
            assert "url_pattern" in source, f"Missing 'url_pattern' in source: {source}"
            assert "keywords" in source, f"Missing 'keywords' in source: {source}"
            assert isinstance(source["keywords"], list)
            assert len(source["keywords"]) > 0

    def test_expected_source_names(self) -> None:
        names = {s["name"] for s in THREAT_INTEL_SOURCES}
        expected = {
            "arXiv",
            "GitHub Advisory Database",
            "GitHub Search",
            "Invariant Labs Blog",
            "Trail of Bits Blog",
            "HuggingFace Reports",
            "NIST NVD",
        }
        assert names == expected


class TestDedup:
    """Tests for _dedup_against_existing."""

    def test_novel_vectors_pass_through(self) -> None:
        new = [
            {
                "description": "A completely novel attack using quantum entanglement",
                "source": "test",
            },
        ]
        # With no existing vectors file
        result = _dedup_against_existing(new, existing_vectors_path="/nonexistent/path.yaml")
        assert len(result) == 1

    def test_duplicate_vectors_filtered(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(
                {
                    "vectors": [
                        {"description": "attack using prompt injection to steal credentials"},
                    ]
                },
                f,
            )
            f.flush()
            path = f.name

        try:
            new = [
                {
                    "description": "attack using prompt injection to steal credentials via method",
                    "source": "test",
                },
                {
                    "description": "entirely different approach quantum side channel",
                    "source": "test",
                },
            ]
            result = _dedup_against_existing(new, existing_vectors_path=path)
            # First should be deduped (high overlap), second should pass
            assert len(result) == 1
            assert "quantum" in result[0]["description"]
        finally:
            os.unlink(path)

    def test_empty_new_vectors(self) -> None:
        result = _dedup_against_existing([])
        assert result == []

    def test_empty_existing_vectors(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"vectors": []}, f)
            f.flush()
            path = f.name

        try:
            new = [
                {"description": "some new attack vector", "source": "test"},
            ]
            result = _dedup_against_existing(new, existing_vectors_path=path)
            assert len(result) == 1
        finally:
            os.unlink(path)

    def test_missing_description_field(self) -> None:
        new = [
            {"source": "test"},  # no description
        ]
        result = _dedup_against_existing(new, existing_vectors_path="/nonexistent/path.yaml")
        # Empty description should still pass through (no overlap possible)
        assert len(result) == 1
