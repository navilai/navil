"""Tests for the `navil init` command."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import yaml

from navil.commands.init import (
    DEFAULT_BACKEND_URL,
    DEFAULT_LISTEN_PORT,
    DEFAULT_POLICY_PATH,
    _init_command,
    build_config,
    validate_api_key,
    write_config,
    write_starter_policy,
)

# ── build_config ──────────────────────────────────────────────


class TestBuildConfig:
    """Tests for the build_config helper."""

    def test_default_config(self) -> None:
        cfg = build_config("navil_live_abc123")
        assert cfg["cloud"]["api_key"] == "navil_live_abc123"
        assert cfg["cloud"]["backend_url"] == DEFAULT_BACKEND_URL
        assert cfg["cloud"]["sync_enabled"] is True
        assert cfg["proxy"]["listen_port"] == DEFAULT_LISTEN_PORT
        assert cfg["policy"]["path"] == DEFAULT_POLICY_PATH

    def test_custom_values(self) -> None:
        cfg = build_config(
            "navil_test_xyz",
            backend_url="https://custom.api.com",
            listen_port=9090,
            policy_path="/tmp/policy.yaml",
            sync_enabled=False,
        )
        assert cfg["cloud"]["api_key"] == "navil_test_xyz"
        assert cfg["cloud"]["backend_url"] == "https://custom.api.com"
        assert cfg["cloud"]["sync_enabled"] is False
        assert cfg["proxy"]["listen_port"] == 9090
        assert cfg["policy"]["path"] == "/tmp/policy.yaml"


# ── write_config ──────────────────────────────────────────────


class TestWriteConfig:
    """Tests for writing config files."""

    def test_creates_config_file(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"
        cfg = build_config("navil_live_test")
        result = write_config(cfg, config_path)

        assert result == config_path
        assert config_path.exists()

        content = config_path.read_text()
        assert "Navil Configuration" in content
        assert "navil_live_test" in content

        # Verify it's valid YAML (skip comment header)
        parsed = yaml.safe_load(content)
        assert parsed["cloud"]["api_key"] == "navil_live_test"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        config_path = tmp_path / "deep" / "nested" / "config.yaml"
        cfg = build_config("navil_live_test")
        write_config(cfg, config_path)
        assert config_path.exists()

    def test_overwrites_existing_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("old content")

        cfg = build_config("navil_live_new")
        write_config(cfg, config_path)

        content = config_path.read_text()
        assert "navil_live_new" in content
        assert "old content" not in content


# ── write_starter_policy ──────────────────────────────────────


class TestWriteStarterPolicy:
    """Tests for starter policy generation."""

    def test_creates_policy_file(self, tmp_path: Path) -> None:
        policy_path = str(tmp_path / "navil-policy.yaml")
        result = write_starter_policy(policy_path)
        assert result == Path(policy_path)
        assert Path(policy_path).exists()

        content = Path(policy_path).read_text()
        assert "Navil Policy" in content
        assert "default-deny-dangerous-tools" in content


# ── validate_api_key ──────────────────────────────────────────


class TestValidateApiKey:
    """Tests for API key validation."""

    def test_valid_key(self) -> None:
        mock_resp = httpx.Response(
            200,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp):
            assert validate_api_key("navil_live_valid") is True

    def test_invalid_key_returns_false(self) -> None:
        mock_resp = httpx.Response(
            401,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp):
            assert validate_api_key("navil_live_bad") is False

    def test_connection_error_raises(self) -> None:
        with patch(
            "navil.commands.init.httpx.get",
            side_effect=httpx.ConnectError("Connection refused"),
        ), pytest.raises(httpx.ConnectError):
            validate_api_key("navil_live_test")

    def test_timeout_error_raises(self) -> None:
        with patch(
            "navil.commands.init.httpx.get",
            side_effect=httpx.TimeoutException("timed out"),
        ), pytest.raises(httpx.TimeoutException):
            validate_api_key("navil_live_test")

    def test_custom_backend_url(self) -> None:
        mock_resp = httpx.Response(
            200,
            request=httpx.Request("GET", "https://custom.api.com/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp) as mock_get:
            validate_api_key("navil_live_test", backend_url="https://custom.api.com")
            call_args = mock_get.call_args
            assert "custom.api.com" in call_args[0][0]


# ── _init_command (integration-level) ─────────────────────────


def _make_args(**kwargs: Any) -> argparse.Namespace:
    """Build an argparse.Namespace with defaults for init command."""
    defaults = {
        "api_key": "navil_live_testkey",
        "backend_url": DEFAULT_BACKEND_URL,
        "port": DEFAULT_LISTEN_PORT,
        "with_policy": False,
        "policy_path": DEFAULT_POLICY_PATH,
        "machine_label": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestInitCommand:
    """Integration tests for the _init_command handler."""

    def test_successful_init(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"

        mock_resp = httpx.Response(
            200,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp), \
             patch("navil.commands.init.CONFIG_FILE", config_path):
            args = _make_args()
            result = _init_command(None, args)

        assert result == 0
        assert config_path.exists()
        parsed = yaml.safe_load(config_path.read_text())
        assert parsed["cloud"]["api_key"] == "navil_live_testkey"

    def test_existing_config_overwrite_yes(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("old config")

        mock_resp = httpx.Response(
            200,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp), \
             patch("navil.commands.init.CONFIG_FILE", config_path), \
             patch("builtins.input", return_value="y"):
            args = _make_args()
            result = _init_command(None, args)

        assert result == 0
        assert "navil_live_testkey" in config_path.read_text()

    def test_existing_config_overwrite_no(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("old config")

        with patch("navil.commands.init.CONFIG_FILE", config_path), \
             patch("builtins.input", return_value="n"):
            args = _make_args()
            result = _init_command(None, args)

        assert result == 1
        assert config_path.read_text() == "old config"

    def test_invalid_api_key(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"

        mock_resp = httpx.Response(
            401,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp), \
             patch("navil.commands.init.CONFIG_FILE", config_path):
            args = _make_args(api_key="navil_live_bad")
            result = _init_command(None, args)

        assert result == 1
        assert not config_path.exists()

    def test_no_internet(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"

        with patch(
            "navil.commands.init.httpx.get",
            side_effect=httpx.ConnectError("Connection refused"),
        ), patch("navil.commands.init.CONFIG_FILE", config_path):
            args = _make_args(api_key="navil_live_test")
            result = _init_command(None, args)

        assert result == 1
        assert not config_path.exists()

    def test_empty_api_key(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"

        with patch("navil.commands.init.CONFIG_FILE", config_path), \
             patch("builtins.input", return_value=""):
            args = _make_args(api_key=None)
            result = _init_command(None, args)

        assert result == 1

    def test_interactive_prompt(self, tmp_path: Path) -> None:
        """When no --api-key is given, prompt the user."""
        config_path = tmp_path / ".navil" / "config.yaml"

        mock_resp = httpx.Response(
            200,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp), \
             patch("navil.commands.init.CONFIG_FILE", config_path), \
             patch("builtins.input", return_value="navil_live_prompted"):
            args = _make_args(api_key=None)
            result = _init_command(None, args)

        assert result == 0
        parsed = yaml.safe_load(config_path.read_text())
        assert parsed["cloud"]["api_key"] == "navil_live_prompted"

    def test_with_starter_policy(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".navil" / "config.yaml"
        policy_path = str(tmp_path / "navil-policy.yaml")

        mock_resp = httpx.Response(
            200,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp), \
             patch("navil.commands.init.CONFIG_FILE", config_path):
            args = _make_args(with_policy=True, policy_path=policy_path)
            result = _init_command(None, args)

        assert result == 0
        assert Path(policy_path).exists()
        assert "default-deny-dangerous-tools" in Path(policy_path).read_text()

    def test_creates_navil_directory(self, tmp_path: Path) -> None:
        """Ensure ~/.navil/ is created if it doesn't exist."""
        config_path = tmp_path / "brand_new" / ".navil" / "config.yaml"

        mock_resp = httpx.Response(
            200,
            request=httpx.Request("GET", "https://api.navil.ai/v1/health"),
        )
        with patch("navil.commands.init.httpx.get", return_value=mock_resp), \
             patch("navil.commands.init.CONFIG_FILE", config_path):
            args = _make_args()
            result = _init_command(None, args)

        assert result == 0
        assert config_path.parent.exists()
        assert config_path.exists()
