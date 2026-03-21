"""Tests for scope support in PolicyEngine.

Tests cover:
- Scope extraction from policy YAML
- Default scope fallback behavior
- get_scope_tools() for known/unknown/default scopes
- Scope merge with auto policy (policy.yaml wins)
- serialize_to_yaml() writes valid YAML with version header
- Community template parsing
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from navil.policy_engine import PolicyEngine


@pytest.fixture
def policy_with_scopes(tmp_path: Path) -> Path:
    """Create a policy.yaml with scope definitions."""
    policy = {
        "version": "1.0",
        "agents": {
            "default": {
                "tools_allowed": ["*"],
                "tools_denied": [],
                "rate_limit_per_hour": 1000,
            }
        },
        "scopes": {
            "github-pr-review": {
                "description": "Code review agent",
                "tools": ["pulls/get", "pulls/list", "reviews/create"],
            },
            "read-only": {
                "description": "Read-only access",
                "tools": ["read_file", "list_directory"],
            },
            "default": {
                "description": "All tools visible",
                "tools": "*",
            },
        },
    }
    policy_file = tmp_path / "policy.yaml"
    with open(policy_file, "w") as f:
        yaml.dump(policy, f)
    return policy_file


@pytest.fixture
def auto_policy_file(tmp_path: Path) -> Path:
    """Create a policy.auto.yaml with additional scopes."""
    auto_policy = {
        "scopes": {
            "auto-scope": {
                "description": "Auto-generated scope",
                "tools": ["tool_a", "tool_b"],
            },
            # This should NOT override the human-owned github-pr-review scope
            "github-pr-review": {
                "description": "Should be ignored — human policy wins",
                "tools": ["only_this_tool"],
            },
        },
    }
    auto_file = tmp_path / "policy.auto.yaml"
    with open(auto_file, "w") as f:
        yaml.dump(auto_policy, f)
    return auto_file


class TestScopeExtraction:
    """Test scope extraction from policy YAML."""

    def test_scopes_extracted_from_policy(self, policy_with_scopes: Path) -> None:
        engine = PolicyEngine(policy_file=str(policy_with_scopes))

        assert "github-pr-review" in engine.scopes
        assert engine.scopes["github-pr-review"] == [
            "pulls/get",
            "pulls/list",
            "reviews/create",
        ]

    def test_wildcard_scope(self, policy_with_scopes: Path) -> None:
        engine = PolicyEngine(policy_file=str(policy_with_scopes))

        assert "default" in engine.scopes
        assert engine.scopes["default"] == ["*"]

    def test_multiple_scopes_extracted(self, policy_with_scopes: Path) -> None:
        engine = PolicyEngine(policy_file=str(policy_with_scopes))

        assert len(engine.scopes) == 3
        assert "github-pr-review" in engine.scopes
        assert "read-only" in engine.scopes
        assert "default" in engine.scopes

    def test_default_policy_has_default_scope(self, tmp_path: Path) -> None:
        """Even with no policy file, default policy includes a default scope."""
        engine = PolicyEngine(policy_file=str(tmp_path / "nonexistent.yaml"))

        assert "default" in engine.scopes
        assert engine.scopes["default"] == ["*"]


class TestGetScopeTools:
    """Test get_scope_tools() method."""

    def test_known_scope_returns_tools(self, policy_with_scopes: Path) -> None:
        engine = PolicyEngine(policy_file=str(policy_with_scopes))

        tools = engine.get_scope_tools("github-pr-review")
        assert tools == ["pulls/get", "pulls/list", "reviews/create"]

    def test_unknown_scope_falls_through_to_default(
        self, policy_with_scopes: Path
    ) -> None:
        engine = PolicyEngine(policy_file=str(policy_with_scopes))

        tools = engine.get_scope_tools("nonexistent-scope")
        # Should fall through to default scope (wildcard)
        assert tools == ["*"]

    def test_unknown_scope_no_default_returns_none(self, tmp_path: Path) -> None:
        """When no default scope exists, unknown scope returns None."""
        policy = {"version": "1.0", "scopes": {"only-this": {"tools": ["tool_a"]}}}
        policy_file = tmp_path / "policy.yaml"
        with open(policy_file, "w") as f:
            yaml.dump(policy, f)

        engine = PolicyEngine(policy_file=str(policy_file))
        tools = engine.get_scope_tools("nonexistent")
        assert tools is None

    def test_wildcard_scope_returns_star(self, policy_with_scopes: Path) -> None:
        engine = PolicyEngine(policy_file=str(policy_with_scopes))

        tools = engine.get_scope_tools("default")
        assert tools == ["*"]


class TestAutoMerge:
    """Test policy.auto.yaml merging behavior."""

    def test_auto_scopes_merged(
        self, policy_with_scopes: Path, auto_policy_file: Path
    ) -> None:
        engine = PolicyEngine(
            policy_file=str(policy_with_scopes),
            auto_policy_file=str(auto_policy_file),
        )

        # Auto scope should be present
        assert "auto-scope" in engine.scopes

    def test_human_policy_wins_on_conflict(
        self, policy_with_scopes: Path, auto_policy_file: Path
    ) -> None:
        engine = PolicyEngine(
            policy_file=str(policy_with_scopes),
            auto_policy_file=str(auto_policy_file),
        )

        # Human-owned github-pr-review should NOT be overwritten by auto policy
        tools = engine.get_scope_tools("github-pr-review")
        assert tools == ["pulls/get", "pulls/list", "reviews/create"]
        assert tools != ["only_this_tool"]  # auto policy value should NOT win


class TestSerializeToYaml:
    """Test serialize_to_yaml() method."""

    def test_serialize_writes_valid_yaml(self, policy_with_scopes: Path) -> None:
        auto_path = policy_with_scopes.parent / "policy.auto.yaml"
        engine = PolicyEngine(
            policy_file=str(policy_with_scopes),
            auto_policy_file=str(auto_path),
        )

        result = engine.serialize_to_yaml()
        assert result is True
        assert auto_path.exists()

        # Verify written YAML is valid
        with open(auto_path) as f:
            content = f.read()

        assert "auto-generated by navil at" in content
        parsed = yaml.safe_load(content.split("\n\n", 1)[1])
        assert parsed["version"] == "1.0"

    def test_serialize_no_output_path_returns_false(
        self, policy_with_scopes: Path
    ) -> None:
        engine = PolicyEngine(policy_file=str(policy_with_scopes))
        # No auto_policy_file set
        result = engine.serialize_to_yaml()
        assert result is False

    def test_serialize_creates_parent_dirs(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        with open(policy_file, "w") as f:
            yaml.dump({"version": "1.0"}, f)

        deep_path = tmp_path / "sub" / "dir" / "policy.auto.yaml"
        engine = PolicyEngine(
            policy_file=str(policy_file),
            auto_policy_file=str(deep_path),
        )

        result = engine.serialize_to_yaml()
        assert result is True
        assert deep_path.exists()


class TestCommunityTemplates:
    """Test that community template files parse correctly."""

    TEMPLATE_DIR = Path(__file__).parent.parent / "navil" / "templates"

    @pytest.mark.parametrize("template_name", ["github.yaml", "filesystem.yaml", "kubectl.yaml"])
    def test_template_parses_as_valid_yaml(self, template_name: str) -> None:
        template_path = self.TEMPLATE_DIR / template_name
        if not template_path.exists():
            pytest.skip(f"Template {template_name} not found at {template_path}")

        with open(template_path) as f:
            data = yaml.safe_load(f)

        assert "scopes" in data
        assert isinstance(data["scopes"], dict)
        assert len(data["scopes"]) > 0

    @pytest.mark.parametrize("template_name", ["github.yaml", "filesystem.yaml", "kubectl.yaml"])
    def test_template_scopes_have_required_fields(self, template_name: str) -> None:
        template_path = self.TEMPLATE_DIR / template_name
        if not template_path.exists():
            pytest.skip(f"Template {template_name} not found at {template_path}")

        with open(template_path) as f:
            data = yaml.safe_load(f)

        for scope_name, scope_def in data["scopes"].items():
            assert "description" in scope_def, f"Scope '{scope_name}' missing description"
            assert "tools" in scope_def, f"Scope '{scope_name}' missing tools"
            # tools is either "*" (wildcard) or a list
            tools = scope_def["tools"]
            assert tools == "*" or isinstance(tools, list), (
                f"Scope '{scope_name}' tools must be '*' or a list"
            )

    def test_github_template_has_expected_scopes(self) -> None:
        template_path = self.TEMPLATE_DIR / "github.yaml"
        if not template_path.exists():
            pytest.skip("GitHub template not found")

        with open(template_path) as f:
            data = yaml.safe_load(f)

        scope_names = set(data["scopes"].keys())
        assert "github-pr-review" in scope_names
        assert "github-deploy" in scope_names
        assert "github-read-only" in scope_names
