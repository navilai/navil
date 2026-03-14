"""Tests for navil wrap — config patcher."""

import json
import os
from pathlib import Path

import pytest

from navil.wrap import wrap_config

# —— Fixtures ————————————————————————————————————————————————

SAMPLE_CONFIG = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        },
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_TOKEN": "ghp_xxx"},
        },
        "sqlite": {
            "command": "python",
            "args": ["-m", "mcp_server_sqlite", "--db", "test.db"],
        },
    }
}


def _write_config(tmpdir: str, config: dict | None = None) -> str:
    path = os.path.join(tmpdir, "openclaw.json")
    with open(path, "w") as f:
        json.dump(config or SAMPLE_CONFIG, f)
    return path


def _read_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


# —— Tests ———————————————————————————————————————————————————


class TestWrapAll:
    def test_wraps_all_servers(self, tmp_path):
        path = _write_config(str(tmp_path))
        result = wrap_config(path)

        assert set(result["wrapped"]) == {"filesystem", "github", "sqlite"}
        assert result["skipped"] == []
        assert result["total"] == 3

        patched = _read_json(path)
        for _name, entry in patched["mcpServers"].items():
            assert entry["command"] == "navil"
            assert entry["args"][0] == "shim"
            assert "--cmd" in entry["args"]
            assert "--agent" in entry["args"]

    def test_preserves_env(self, tmp_path):
        path = _write_config(str(tmp_path))
        wrap_config(path)

        patched = _read_json(path)
        assert patched["mcpServers"]["github"]["env"] == {"GITHUB_TOKEN": "ghp_xxx"}

    def test_creates_backup(self, tmp_path):
        path = _write_config(str(tmp_path))
        wrap_config(path)

        backup = path.replace(".json", ".backup.json")
        assert os.path.exists(backup)
        original = _read_json(backup)
        assert original == SAMPLE_CONFIG


class TestWrapFiltering:
    def test_only_wraps_specified(self, tmp_path):
        path = _write_config(str(tmp_path))
        result = wrap_config(path, only=["filesystem", "github"])

        assert set(result["wrapped"]) == {"filesystem", "github"}
        assert "sqlite" in result["skipped"]

        patched = _read_json(path)
        # sqlite should be untouched
        assert patched["mcpServers"]["sqlite"]["command"] == "python"

    def test_skip_excludes_servers(self, tmp_path):
        path = _write_config(str(tmp_path))
        result = wrap_config(path, skip=["github"])

        assert "github" not in result["wrapped"]
        assert "github" in result["skipped"]

        patched = _read_json(path)
        assert patched["mcpServers"]["github"]["command"] == "npx"


class TestIdempotency:
    def test_skips_already_wrapped(self, tmp_path):
        path = _write_config(str(tmp_path))

        # Wrap once
        r1 = wrap_config(path)
        assert len(r1["wrapped"]) == 3

        # Wrap again — should skip all
        r2 = wrap_config(path)
        assert len(r2["wrapped"]) == 0
        assert len(r2["skipped"]) == 3


class TestPolicy:
    def test_attaches_policy(self, tmp_path):
        path = _write_config(str(tmp_path))
        wrap_config(path, policy_path="/etc/navil/policy.yaml")

        patched = _read_json(path)
        for entry in patched["mcpServers"].values():
            assert "--policy" in entry["args"]
            idx = entry["args"].index("--policy")
            assert entry["args"][idx + 1] == "/etc/navil/policy.yaml"


class TestAgentNaming:
    def test_default_agent_names(self, tmp_path):
        path = _write_config(str(tmp_path))
        wrap_config(path)

        patched = _read_json(path)
        fs = patched["mcpServers"]["filesystem"]
        idx = fs["args"].index("--agent")
        assert fs["args"][idx + 1] == "navil-filesystem"

    def test_custom_prefix(self, tmp_path):
        path = _write_config(str(tmp_path))
        wrap_config(path, agent_prefix="prod")

        patched = _read_json(path)
        fs = patched["mcpServers"]["filesystem"]
        idx = fs["args"].index("--agent")
        assert fs["args"][idx + 1] == "prod-filesystem"


class TestUndo:
    def test_undo_restores_backup(self, tmp_path):
        path = _write_config(str(tmp_path))
        wrap_config(path)
        result = wrap_config(path, undo=True)

        assert result["restored"] is True
        restored = _read_json(path)
        assert restored == SAMPLE_CONFIG

    def test_undo_without_backup_unwraps_inline(self, tmp_path):
        path = _write_config(str(tmp_path))
        wrap_config(path)

        # Delete the backup
        backup = path.replace(".json", ".backup.json")
        os.remove(backup)

        result = wrap_config(path, undo=True)
        assert set(result["unwrapped"]) == {"filesystem", "github", "sqlite"}

        restored = _read_json(path)
        assert restored["mcpServers"]["filesystem"]["command"] == "npx"
        assert restored["mcpServers"]["github"]["command"] == "npx"


class TestDryRun:
    def test_dry_run_doesnt_modify(self, tmp_path):
        path = _write_config(str(tmp_path))
        original = Path(path).read_text()

        result = wrap_config(path, dry_run=True)
        assert len(result["wrapped"]) == 3

        # File unchanged
        assert Path(path).read_text() == original
        # No backup created
        assert not os.path.exists(path.replace(".json", ".backup.json"))


class TestEdgeCases:
    def test_no_mcp_servers_raises(self, tmp_path):
        path = _write_config(str(tmp_path), config={"other": "stuff"})
        with pytest.raises(ValueError, match="No mcpServers"):
            wrap_config(path)

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            wrap_config("/nonexistent/path.json")

    def test_empty_args(self, tmp_path):
        config = {
            "mcpServers": {
                "simple": {"command": "my-mcp-server"},
            }
        }
        path = _write_config(str(tmp_path), config=config)
        wrap_config(path)

        patched = _read_json(path)
        entry = patched["mcpServers"]["simple"]
        assert entry["command"] == "navil"
        cmd_idx = entry["args"].index("--cmd")
        assert entry["args"][cmd_idx + 1] == "my-mcp-server"
