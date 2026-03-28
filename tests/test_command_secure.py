"""Tests for `navil secure` command — discovery, orchestration, and full flow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ── Discovery tests ────────────────────────────────────────────


class TestDiscoverConfigs:
    """Tests for navil.discovery.discover_configs."""

    def _make_mcp_config(self, tmp_path: Path, name: str, servers: dict[str, Any]) -> Path:
        """Write a valid MCP config file and return its path."""
        path = tmp_path / name
        path.write_text(json.dumps({"mcpServers": servers}))
        return path

    def test_finds_explicit_path(self, tmp_path: Path) -> None:
        from navil.discovery import discover_configs

        cfg_path = self._make_mcp_config(
            tmp_path, "mcp.json", {"fs": {"command": "npx", "args": ["server-fs"]}}
        )
        results = discover_configs(extra_paths=[str(cfg_path)])
        assert len(results) == 1
        assert results[0]["server_count"] == 1
        assert results[0]["client_name"] == "Custom"

    def test_returns_empty_for_missing_files(self) -> None:
        from navil.discovery import discover_configs

        # Patch standard paths to non-existent locations
        with patch("navil.discovery._STANDARD_PATHS", [("/nonexistent/path.json", "Test")]):
            results = discover_configs()
            assert results == []

    def test_skips_invalid_json(self, tmp_path: Path) -> None:
        from navil.discovery import discover_configs

        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json {{{")
        results = discover_configs(extra_paths=[str(bad_file)])
        assert results == []

    def test_skips_config_with_no_servers(self, tmp_path: Path) -> None:
        from navil.discovery import discover_configs

        empty = tmp_path / "empty.json"
        empty.write_text(json.dumps({"mcpServers": {}}))
        results = discover_configs(extra_paths=[str(empty)])
        assert results == []

    def test_env_var_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from navil.discovery import discover_configs

        cfg_path = self._make_mcp_config(
            tmp_path,
            "env-config.json",
            {"github": {"command": "npx", "args": ["mcp-github"]}},
        )
        monkeypatch.setenv("NAVIL_MCP_CONFIG", str(cfg_path))

        with patch("navil.discovery._STANDARD_PATHS", []):
            results = discover_configs()
            assert len(results) == 1
            assert results[0]["client_name"] == "NAVIL_MCP_CONFIG"

    def test_deduplicates_same_file(self, tmp_path: Path) -> None:
        from navil.discovery import discover_configs

        cfg_path = self._make_mcp_config(
            tmp_path, "mcp.json", {"fs": {"command": "npx", "args": ["server-fs"]}}
        )
        # Pass the same path twice
        results = discover_configs(extra_paths=[str(cfg_path), str(cfg_path)])
        assert len(results) == 1

    def test_sorts_by_server_count(self, tmp_path: Path) -> None:
        from navil.discovery import discover_configs

        small = self._make_mcp_config(
            tmp_path, "small.json", {"fs": {"command": "npx", "args": ["server-fs"]}}
        )
        big = self._make_mcp_config(
            tmp_path,
            "big.json",
            {
                "fs": {"command": "npx", "args": ["server-fs"]},
                "git": {"command": "npx", "args": ["mcp-git"]},
                "db": {"command": "npx", "args": ["mcp-db"]},
            },
        )
        results = discover_configs(extra_paths=[str(small), str(big)])
        assert len(results) == 2
        assert results[0]["server_count"] == 3  # big first
        assert results[1]["server_count"] == 1


# ── Secure command tests ───────────────────────────────────────


class TestSecureCommand:
    """Tests for navil.commands.secure._secure_command."""

    def _make_mcp_config(self, tmp_path: Path, servers: dict[str, Any]) -> Path:
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({"mcpServers": servers}))
        return path

    def _make_wrapped_config(self, tmp_path: Path) -> Path:
        """Create a config that's already wrapped with navil shim."""
        path = tmp_path / "mcp.json"
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "fs": {
                            "command": "navil",
                            "args": ["shim", "--cmd", "npx server-fs", "--agent", "navil-fs"],
                        }
                    }
                }
            )
        )
        return path

    def test_dry_run_no_modifications(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        import argparse

        from navil.cli import MCPGuardianCLI
        from navil.commands.secure import _secure_command

        cfg_path = self._make_mcp_config(
            tmp_path,
            {"fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]}},
        )
        original_content = cfg_path.read_text()

        args = argparse.Namespace(
            config=str(cfg_path),
            dry_run=True,
            skip_policy=True,
            no_color=True,
            policy_output=str(tmp_path / "policy.yaml"),
        )
        cli = MCPGuardianCLI()
        _secure_command(cli, args)

        # Config file should be unchanged
        assert cfg_path.read_text() == original_content
        # No backup should exist
        assert not (tmp_path / "mcp.backup.json").exists()
        # No policy file should be written
        assert not (tmp_path / "policy.yaml").exists()

    def test_idempotent_already_wrapped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        import argparse

        from navil.cli import MCPGuardianCLI
        from navil.commands.secure import _secure_command

        cfg_path = self._make_wrapped_config(tmp_path)

        args = argparse.Namespace(
            config=str(cfg_path),
            dry_run=False,
            skip_policy=True,
            no_color=True,
            policy_output=str(tmp_path / "policy.yaml"),
        )
        cli = MCPGuardianCLI()
        exit_code = _secure_command(cli, args)

        captured = capsys.readouterr()
        assert exit_code == 0
        assert "Already wrapped" in captured.err or "already wrapped" in captured.err.lower()

    def test_no_configs_found(self, capsys: pytest.CaptureFixture) -> None:
        import argparse

        from navil.cli import MCPGuardianCLI
        from navil.commands.secure import _secure_command

        args = argparse.Namespace(
            config="/nonexistent/path/mcp.json",
            dry_run=False,
            skip_policy=True,
            no_color=True,
            policy_output="policy.yaml",
        )
        cli = MCPGuardianCLI()
        exit_code = _secure_command(cli, args)

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "No MCP config" in captured.err

    def test_full_flow_creates_backup(self, tmp_path: Path) -> None:
        import argparse

        from navil.cli import MCPGuardianCLI
        from navil.commands.secure import _secure_command

        cfg_path = self._make_mcp_config(
            tmp_path,
            {
                "fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem", "/tmp"]},
                "git": {"command": "npx", "args": ["-y", "mcp-git"]},
            },
        )

        args = argparse.Namespace(
            config=str(cfg_path),
            dry_run=False,
            skip_policy=True,
            no_color=True,
            policy_output=str(tmp_path / "policy.yaml"),
        )
        cli = MCPGuardianCLI()
        exit_code = _secure_command(cli, args)

        assert exit_code == 0
        # Backup should exist
        backup = tmp_path / "mcp.backup.json"
        assert backup.exists()
        # Config should now have navil shim entries
        new_config = json.loads(cfg_path.read_text())
        for _name, entry in new_config["mcpServers"].items():
            assert entry["command"] == "navil"
            assert entry["args"][0] == "shim"

    def test_outputs_before_after_coverage(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        import argparse

        from navil.cli import MCPGuardianCLI
        from navil.commands.secure import _secure_command

        cfg_path = self._make_mcp_config(
            tmp_path,
            {"fs": {"command": "npx", "args": ["-y", "@mcp/server-filesystem"]}},
        )

        args = argparse.Namespace(
            config=str(cfg_path),
            dry_run=False,
            skip_policy=True,
            no_color=True,
            policy_output=str(tmp_path / "policy.yaml"),
        )
        cli = MCPGuardianCLI()
        _secure_command(cli, args)

        captured = capsys.readouterr()
        # Should contain before/after with arrow
        assert "Before:" in captured.err
        assert "After:" in captured.err
        assert "\u2192" in captured.err  # →


# ── Coverage helper tests ──────────────────────────────────────


class TestCoverageComputation:
    """Tests for the coverage computation helper."""

    def test_compute_coverage_returns_tuple(self) -> None:
        from navil.cli import MCPGuardianCLI
        from navil.commands.secure import _compute_coverage

        cli = MCPGuardianCLI()
        results, pct, protected, total = _compute_coverage(cli)

        assert isinstance(results, dict)
        assert isinstance(pct, float)
        assert 0.0 <= pct <= 100.0
        assert protected >= 0
        assert total >= 0

    def test_gap_categories(self) -> None:
        from navil.commands.secure import _gap_categories

        results = {
            "prompt_injection": {"total": 10, "blocked": 8, "missed": 2},
            "data_exfiltration": {"total": 10, "blocked": 0, "missed": 10},
            "lateral_movement": {"total": 5, "blocked": 0, "missed": 5},
        }
        gaps = _gap_categories(results)
        assert "Data Exfiltration" in gaps
        assert "Lateral Movement" in gaps
        assert "Prompt Injection" not in gaps
