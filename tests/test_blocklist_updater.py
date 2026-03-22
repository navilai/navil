"""Tests for the cloud blocklist auto-updater.

Covers:
- Version comparison (local < cloud = update needed)
- Atomic merge (new patterns added, existing preserved)
- No-op when already up to date
- Graceful failure when cloud is unreachable
- Configuration loading
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from navil.cloud.blocklist_updater import (
    check_for_updates,
    get_blocklist_config,
    get_local_version,
    merge_patterns,
)

# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def blocklist_file(tmp_path: Path) -> str:
    """Create a temporary blocklist JSON file with sample patterns."""
    data = {
        "version": 3,
        "description": "Test blocklist",
        "created_at": "2026-03-15T00:00:00Z",
        "patterns": [
            {
                "pattern_id": "BL-TOOL-001",
                "pattern_type": "tool_name",
                "value": "inject_backdoor",
                "severity": "CRITICAL",
                "description": "Known malicious tool",
                "confidence": 0.95,
                "source": "local",
            },
            {
                "pattern_id": "BL-TOOL-002",
                "pattern_type": "tool_name",
                "value": "shadow_deploy",
                "severity": "CRITICAL",
                "description": "Covert deployment tool",
                "confidence": 0.90,
                "source": "local",
            },
        ],
    }
    path = tmp_path / "blocklist.json"
    path.write_text(json.dumps(data, indent=2))
    return str(path)


@pytest.fixture
def empty_blocklist_file(tmp_path: Path) -> str:
    """Create an empty blocklist JSON file."""
    data: dict[str, Any] = {"version": 0, "description": "Empty blocklist", "patterns": []}
    path = tmp_path / "empty_blocklist.json"
    path.write_text(json.dumps(data, indent=2))
    return str(path)


# ── get_local_version ─────────────────────────────────────────


class TestGetLocalVersion:
    def test_reads_version_from_file(self, blocklist_file: str) -> None:
        """Should return the version from the blocklist JSON."""
        version = get_local_version(blocklist_file)
        assert version == 3

    def test_returns_zero_for_missing_file(self, tmp_path: Path) -> None:
        """Should return 0 if the file does not exist."""
        missing = str(tmp_path / "nonexistent.json")
        version = get_local_version(missing)
        assert version == 0

    def test_returns_zero_for_invalid_json(self, tmp_path: Path) -> None:
        """Should return 0 if the file is not valid JSON."""
        bad = tmp_path / "bad.json"
        bad.write_text("not json {{{")
        version = get_local_version(str(bad))
        assert version == 0

    def test_returns_zero_for_missing_version_key(self, tmp_path: Path) -> None:
        """Should return 0 if the JSON has no version key."""
        no_ver = tmp_path / "no_version.json"
        no_ver.write_text(json.dumps({"patterns": []}))
        version = get_local_version(str(no_ver))
        assert version == 0

    def test_empty_file_version(self, empty_blocklist_file: str) -> None:
        """Version 0 for an empty blocklist."""
        version = get_local_version(empty_blocklist_file)
        assert version == 0


# ── check_for_updates ─────────────────────────────────────────


class TestCheckForUpdates:
    def test_returns_patterns_when_cloud_has_updates(self) -> None:
        """Should return new patterns when cloud has a newer version."""
        cloud_response = {
            "version": 5,
            "patterns": [
                {
                    "pattern_id": "BL-NEW-001",
                    "pattern_type": "tool_name",
                    "value": "evil_tool",
                    "severity": "HIGH",
                    "description": "Newly discovered threat",
                    "confidence": 0.85,
                },
            ],
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = cloud_response

        with patch("httpx.get", return_value=mock_response):
            result = check_for_updates("https://api.test/blocklist", 3)

        assert result is not None
        assert len(result) == 1
        assert result[0]["pattern_id"] == "BL-NEW-001"

    def test_returns_none_when_up_to_date(self) -> None:
        """Should return None when cloud responds with 304."""
        mock_response = MagicMock()
        mock_response.status_code = 304

        with patch("httpx.get", return_value=mock_response):
            result = check_for_updates("https://api.test/blocklist", 3)

        assert result is None

    def test_returns_none_on_http_error(self) -> None:
        """Should return None on HTTP error (4xx/5xx)."""
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("httpx.get", return_value=mock_response):
            result = check_for_updates("https://api.test/blocklist", 3)

        assert result is None

    def test_returns_none_on_network_error(self) -> None:
        """Should return None gracefully when cloud is unreachable."""
        with patch("httpx.get", side_effect=Exception("Connection refused")):
            result = check_for_updates("https://api.test/blocklist", 3)

        assert result is None

    def test_returns_none_when_no_patterns_in_response(self) -> None:
        """Should return None when cloud returns empty patterns list."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"version": 5, "patterns": []}

        with patch("httpx.get", return_value=mock_response):
            result = check_for_updates("https://api.test/blocklist", 3)

        assert result is None

    def test_sends_since_version_param(self) -> None:
        """Should include since_version in query params."""
        mock_response = MagicMock()
        mock_response.status_code = 304

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_for_updates("https://api.test/blocklist", 7)

        call_args = mock_get.call_args
        assert call_args.kwargs["params"]["since_version"] == "7"

    def test_sends_auth_header_when_provided(self) -> None:
        """Should include Authorization header if provided."""
        mock_response = MagicMock()
        mock_response.status_code = 304

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_for_updates(
                "https://api.test/blocklist",
                3,
                headers={"Authorization": "Bearer test-key"},
            )

        call_args = mock_get.call_args
        assert call_args.kwargs["headers"]["Authorization"] == "Bearer test-key"


# ── merge_patterns ────────────────────────────────────────────


class TestMergePatterns:
    def test_adds_new_patterns(self, blocklist_file: str) -> None:
        """New patterns should be added to the blocklist."""
        new_patterns = [
            {
                "pattern_id": "BL-NEW-001",
                "pattern_type": "tool_name",
                "value": "evil_tool",
                "severity": "HIGH",
                "description": "Newly discovered threat",
                "confidence": 0.85,
            },
        ]

        result = merge_patterns(blocklist_file, new_patterns)

        assert result["added"] == 1
        assert result["updated"] == 0
        assert result["total"] == 3  # 2 existing + 1 new

        # Verify the file was updated
        with open(blocklist_file) as fh:
            data = json.load(fh)
        assert data["version"] == 4  # incremented from 3
        pattern_ids = [p["pattern_id"] for p in data["patterns"]]
        assert "BL-NEW-001" in pattern_ids

    def test_preserves_existing_patterns(self, blocklist_file: str) -> None:
        """Existing patterns should remain untouched."""
        new_patterns = [
            {
                "pattern_id": "BL-NEW-001",
                "pattern_type": "tool_name",
                "value": "new_tool",
                "severity": "MEDIUM",
                "description": "New pattern",
                "confidence": 0.7,
            },
        ]

        merge_patterns(blocklist_file, new_patterns)

        with open(blocklist_file) as fh:
            data = json.load(fh)

        by_id = {p["pattern_id"]: p for p in data["patterns"]}
        assert by_id["BL-TOOL-001"]["value"] == "inject_backdoor"
        assert by_id["BL-TOOL-002"]["value"] == "shadow_deploy"

    def test_updates_on_higher_confidence(self, blocklist_file: str) -> None:
        """Should update an existing pattern if the new one has higher confidence."""
        new_patterns = [
            {
                "pattern_id": "BL-TOOL-001",
                "pattern_type": "tool_name",
                "value": "inject_backdoor",
                "severity": "CRITICAL",
                "description": "Updated description",
                "confidence": 0.99,  # higher than existing 0.95
            },
        ]

        result = merge_patterns(blocklist_file, new_patterns)

        assert result["updated"] == 1
        assert result["added"] == 0

        with open(blocklist_file) as fh:
            data = json.load(fh)

        by_id = {p["pattern_id"]: p for p in data["patterns"]}
        assert by_id["BL-TOOL-001"]["confidence"] == 0.99

    def test_skips_lower_confidence(self, blocklist_file: str) -> None:
        """Should not update when the new pattern has lower confidence."""
        new_patterns = [
            {
                "pattern_id": "BL-TOOL-001",
                "pattern_type": "tool_name",
                "value": "inject_backdoor",
                "severity": "CRITICAL",
                "description": "Lower confidence",
                "confidence": 0.50,  # lower than existing 0.95
            },
        ]

        result = merge_patterns(blocklist_file, new_patterns)

        assert result["updated"] == 0
        assert result["added"] == 0
        assert result["total"] == 2

        with open(blocklist_file) as fh:
            data = json.load(fh)
        by_id = {p["pattern_id"]: p for p in data["patterns"]}
        assert by_id["BL-TOOL-001"]["confidence"] == 0.95  # unchanged

    def test_atomic_write(self, blocklist_file: str) -> None:
        """File should be updated atomically (no corrupt partial writes)."""
        new_patterns = [
            {
                "pattern_id": "BL-NEW-001",
                "pattern_type": "tool_name",
                "value": "new_tool",
                "severity": "HIGH",
                "description": "Test",
                "confidence": 0.8,
            },
        ]

        merge_patterns(blocklist_file, new_patterns)

        # The file should be valid JSON after the write
        with open(blocklist_file) as fh:
            data = json.load(fh)
        assert isinstance(data, dict)
        assert "patterns" in data
        assert "version" in data
        assert "updated_at" in data

    def test_creates_file_from_scratch(self, tmp_path: Path) -> None:
        """Should create a new blocklist file if none exists."""
        new_file = str(tmp_path / "new_blocklist.json")

        new_patterns = [
            {
                "pattern_id": "BL-FIRST-001",
                "pattern_type": "tool_name",
                "value": "first_pattern",
                "severity": "HIGH",
                "description": "First pattern",
                "confidence": 0.9,
            },
        ]

        result = merge_patterns(new_file, new_patterns)

        assert result["added"] == 1
        assert result["total"] == 1
        assert result["new_version"] == 1

        with open(new_file) as fh:
            data = json.load(fh)
        assert len(data["patterns"]) == 1

    def test_increments_version(self, blocklist_file: str) -> None:
        """Version should be incremented after merge."""
        new_patterns = [
            {
                "pattern_id": "BL-NEW-001",
                "pattern_type": "tool_name",
                "value": "new_tool",
                "severity": "HIGH",
                "description": "Test",
                "confidence": 0.8,
            },
        ]

        result = merge_patterns(blocklist_file, new_patterns)
        assert result["new_version"] == 4  # was 3, now 4

    def test_handles_empty_pattern_list(self, blocklist_file: str) -> None:
        """Should handle an empty new pattern list gracefully."""
        result = merge_patterns(blocklist_file, [])

        assert result["added"] == 0
        assert result["updated"] == 0
        assert result["total"] == 2  # existing patterns unchanged

    def test_skips_patterns_without_id(self, blocklist_file: str) -> None:
        """Patterns missing pattern_id should be skipped."""
        new_patterns: list[dict[str, Any]] = [
            {
                "pattern_type": "tool_name",
                "value": "no_id_tool",
                "severity": "HIGH",
                "confidence": 0.8,
            },
        ]

        result = merge_patterns(blocklist_file, new_patterns)
        assert result["added"] == 0

    def test_multiple_new_patterns(self, blocklist_file: str) -> None:
        """Should handle multiple new patterns at once."""
        new_patterns = [
            {
                "pattern_id": "BL-NEW-001",
                "pattern_type": "tool_name",
                "value": "evil_tool_1",
                "severity": "HIGH",
                "description": "Threat 1",
                "confidence": 0.85,
            },
            {
                "pattern_id": "BL-NEW-002",
                "pattern_type": "argument_pattern",
                "value": ".*etc/passwd.*",
                "severity": "CRITICAL",
                "description": "Threat 2",
                "confidence": 0.90,
            },
            {
                "pattern_id": "BL-NEW-003",
                "pattern_type": "tool_sequence",
                "value": "read_file,write_file,execute",
                "severity": "HIGH",
                "description": "Threat 3",
                "confidence": 0.75,
            },
        ]

        result = merge_patterns(blocklist_file, new_patterns)

        assert result["added"] == 3
        assert result["total"] == 5


# ── get_blocklist_config ──────────────────────────────────────


class TestGetBlocklistConfig:
    def test_defaults_when_no_config(self) -> None:
        """Should return sensible defaults when no config file exists."""
        with patch("navil.commands.init.load_config", return_value={}):
            config = get_blocklist_config()

        assert config["auto_update"] is True
        assert "blocklist" in config["update_url"]

    def test_reads_config_values(self) -> None:
        """Should read auto_update and update_url from config."""
        mock_config: dict[str, Any] = {
            "blocklist": {
                "auto_update": False,
                "update_url": "https://custom.api/blocklist",
            }
        }
        with patch("navil.commands.init.load_config", return_value=mock_config):
            config = get_blocklist_config()

        assert config["auto_update"] is False
        assert config["update_url"] == "https://custom.api/blocklist"

    def test_partial_config(self) -> None:
        """Should use defaults for missing keys."""
        mock_config: dict[str, Any] = {"blocklist": {"auto_update": False}}
        with patch("navil.commands.init.load_config", return_value=mock_config):
            config = get_blocklist_config()

        assert config["auto_update"] is False
        assert "blocklist" in config["update_url"]  # default URL


# ── Integration: end-to-end update flow ───────────────────────


class TestEndToEndUpdateFlow:
    def test_full_update_cycle(self, blocklist_file: str) -> None:
        """Simulate a complete check-and-merge cycle."""
        cloud_patterns = [
            {
                "pattern_id": "BL-CLOUD-001",
                "pattern_type": "tool_name",
                "value": "cloud_discovered_threat",
                "severity": "HIGH",
                "description": "Found by cloud analysis",
                "confidence": 0.88,
                "source": "cloud",
            },
        ]

        # Step 1: Check current version
        current_version = get_local_version(blocklist_file)
        assert current_version == 3

        # Step 2: Simulate cloud returning new patterns
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": 4,
            "patterns": cloud_patterns,
        }

        with patch("httpx.get", return_value=mock_response):
            new_patterns = check_for_updates("https://api.test/blocklist", current_version)

        assert new_patterns is not None
        assert len(new_patterns) == 1

        # Step 3: Merge
        result = merge_patterns(blocklist_file, new_patterns)
        assert result["added"] == 1
        assert result["new_version"] == 4

        # Step 4: Verify updated file
        new_version = get_local_version(blocklist_file)
        assert new_version == 4

    def test_no_op_when_already_current(self, blocklist_file: str) -> None:
        """No changes when cloud returns 304 Not Modified."""
        mock_response = MagicMock()
        mock_response.status_code = 304

        with patch("httpx.get", return_value=mock_response):
            new_patterns = check_for_updates("https://api.test/blocklist", 3)

        assert new_patterns is None

        # Version should be unchanged
        assert get_local_version(blocklist_file) == 3
