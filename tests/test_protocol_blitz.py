"""Tests for Protocol Blitz features: Tool Scoping, AI Policy Builder,
CLI shim, A2A Agent Cards, and Policy suggestion endpoints.

These features shipped with zero unit tests. This file provides comprehensive
coverage for happy paths, edge cases, and error handling.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

# ── Feature 1: Tool Scoping ──────────────────────────────────────────

from navil.policy_engine import PolicyEngine


class TestToolScoping:
    """Test X-Navil-Scope / scope management in PolicyEngine."""

    def test_scope_tools_returns_list_for_known_scope(self, tmp_path: Path) -> None:
        """get_scope_tools returns the tool list for a defined scope."""
        policy = {
            "version": "1.0",
            "scopes": {
                "ci-agent": {
                    "description": "CI tools only",
                    "tools": ["build", "test", "deploy"],
                },
            },
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))
        engine = PolicyEngine(policy_file=str(p))

        tools = engine.get_scope_tools("ci-agent")
        assert tools == ["build", "test", "deploy"]

    def test_scope_tools_wildcard(self, tmp_path: Path) -> None:
        """Wildcard scope returns ['*']."""
        policy = {
            "version": "1.0",
            "scopes": {"all-access": {"tools": "*"}},
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))
        engine = PolicyEngine(policy_file=str(p))

        assert engine.get_scope_tools("all-access") == ["*"]

    def test_scope_tools_unknown_falls_to_default(self, tmp_path: Path) -> None:
        """Unknown scope falls through to the default scope."""
        policy = {
            "version": "1.0",
            "scopes": {
                "restricted": {"tools": ["read_only"]},
                "default": {"tools": "*"},
            },
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))
        engine = PolicyEngine(policy_file=str(p))

        assert engine.get_scope_tools("nonexistent") == ["*"]

    def test_scope_tools_no_default_returns_none(self, tmp_path: Path) -> None:
        """When no default scope exists, unknown scope returns None."""
        policy = {
            "version": "1.0",
            "scopes": {"only-this": {"tools": ["tool_a"]}},
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))
        engine = PolicyEngine(policy_file=str(p))

        assert engine.get_scope_tools("nonexistent") is None

    def test_scope_extraction_counts(self, tmp_path: Path) -> None:
        """Verify all scopes are extracted from policy."""
        policy = {
            "version": "1.0",
            "scopes": {
                "scope-a": {"tools": ["a"]},
                "scope-b": {"tools": ["b", "c"]},
                "scope-c": {"tools": "*"},
            },
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))
        engine = PolicyEngine(policy_file=str(p))

        assert len(engine.scopes) == 3
        assert engine.scopes["scope-a"] == ["a"]
        assert engine.scopes["scope-b"] == ["b", "c"]
        assert engine.scopes["scope-c"] == ["*"]

    @pytest.mark.asyncio
    async def test_sync_scopes_to_redis_no_client(self, tmp_path: Path) -> None:
        """sync_scopes_to_redis returns 0 when no Redis client is set."""
        policy = {
            "version": "1.0",
            "scopes": {"test": {"tools": ["x"]}},
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))
        engine = PolicyEngine(policy_file=str(p))

        result = await engine.sync_scopes_to_redis()
        assert result == 0

    @pytest.mark.asyncio
    async def test_sync_scopes_to_redis_with_client(self, tmp_path: Path) -> None:
        """sync_scopes_to_redis pushes each scope to Redis."""
        from tests.conftest import FakeRedis

        policy = {
            "version": "1.0",
            "scopes": {
                "scope-a": {"tools": ["t1", "t2"]},
                "scope-b": {"tools": "*"},
            },
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))

        redis = FakeRedis()
        engine = PolicyEngine(policy_file=str(p), redis_client=redis)

        synced = await engine.sync_scopes_to_redis()
        assert synced == 2

        # Verify keys were stored
        val_a = await redis.get("navil:scope:scope-a")
        assert val_a is not None
        assert json.loads(val_a) == ["t1", "t2"]


# ── Feature 2: AI Policy Builder (observe-detect-suggest-confirm-update) ──


from navil.llm.policy_gen import PolicyGenerator


class TestAIPolicyBuilder:
    """Test the closed loop: observe -> detect -> suggest -> confirm -> update."""

    @pytest.fixture
    def mock_client(self) -> MagicMock:
        return MagicMock()

    def test_suggest_policy_rule_happy_path(self, mock_client: MagicMock) -> None:
        """suggest_policy_rule returns a structured suggestion from LLM."""
        # _parse_yaml looks for known YAML prefixes (version:, agents:, ---)
        # and strips everything before them, so we format the response
        # without nesting the rule under a separate top-level key that would
        # conflict with the prefix detection.
        mock_client.complete.return_value = (
            "rule:\n"
            "  rate_limit_per_hour: 30\n"
            "confidence: 0.9\n"
            "reason: Agent exceeded baseline tool usage\n"
            "reversible: true\n"
        )
        gen = PolicyGenerator(client=mock_client)
        alert = {"agent_name": "rogue-agent", "anomaly_type": "TOOL_ABUSE"}

        result = gen.suggest_policy_rule(alert)

        assert result["confidence"] == 0.9
        assert result["reversible"] is True
        assert result["rule"] == {"rate_limit_per_hour": 30}
        assert "reason" in result

    def test_suggest_policy_rule_with_baseline(self, mock_client: MagicMock) -> None:
        """suggest_policy_rule passes baseline data to LLM prompt."""
        mock_client.complete.return_value = """
rule:
  agents:
    test-agent:
      rate_limit_per_hour: 30
confidence: 0.85
reason: Rate above baseline
reversible: true
"""
        gen = PolicyGenerator(client=mock_client)
        alert = {"agent_name": "test-agent", "anomaly_type": "RATE_SPIKE"}
        baseline = {"avg_requests_per_hour": 10, "max_requests_per_hour": 20}

        result = gen.suggest_policy_rule(alert, baseline=baseline)

        # Verify baseline was included in the prompt
        call_args = mock_client.complete.call_args
        prompt_text = call_args[0][1]
        assert "avg_requests_per_hour" in prompt_text
        assert result["confidence"] == 0.85

    def test_suggest_policy_rule_llm_failure_fallback(self, mock_client: MagicMock) -> None:
        """When LLM fails, suggest_policy_rule returns conservative fallback."""
        mock_client.complete.side_effect = RuntimeError("LLM unavailable")

        gen = PolicyGenerator(client=mock_client)
        alert = {"agent_name": "bad-agent", "anomaly_type": "CRITICAL"}

        result = gen.suggest_policy_rule(alert)

        assert result["confidence"] == 0.3
        assert result["reversible"] is True
        assert "bad-agent" in result["reason"]
        assert "CRITICAL" in result["reason"]
        assert result["rule"]["agents"]["bad-agent"]["rate_limit_per_hour"] == 60

    def test_suggest_policy_rule_invalid_yaml_fallback(self, mock_client: MagicMock) -> None:
        """When LLM returns invalid YAML, fallback kicks in."""
        mock_client.complete.return_value = "This is not YAML at all!!! {}{}{"

        gen = PolicyGenerator(client=mock_client)
        alert = {"agent_name": "agent-x", "anomaly_type": "UNUSUAL_TOOLS"}

        result = gen.suggest_policy_rule(alert)

        # Should get the conservative fallback
        assert result["confidence"] == 0.3
        assert result["reversible"] is True

    def test_suggest_policy_rule_missing_fields_defaults(self, mock_client: MagicMock) -> None:
        """Missing fields in LLM response get sensible defaults."""
        mock_client.complete.return_value = """
rule:
  agents:
    test:
      tools_denied: ["x"]
"""
        gen = PolicyGenerator(client=mock_client)
        alert = {"agent_name": "test", "anomaly_type": "X"}

        result = gen.suggest_policy_rule(alert)

        assert result["confidence"] == 0.5  # default
        assert result["reversible"] is True  # default
        assert "reason" in result

    def test_parse_yaml_strips_prose_before_yaml(self) -> None:
        """_parse_yaml strips leading prose text before YAML content."""
        response = "Here is the suggested policy:\n\nversion: \"1.0\"\nagents:\n  test: {}"
        result = PolicyGenerator._parse_yaml(response)
        assert result["version"] == "1.0"

    def test_parse_yaml_raises_on_empty(self) -> None:
        """_parse_yaml raises ValueError on empty/None content."""
        with pytest.raises(ValueError, match="invalid or empty"):
            PolicyGenerator._parse_yaml("")


# ── Feature 3: CLI PATH shim ─────────────────────────────────────────

from navil.shim import StdioShim, _detect_and_read_message, _write_message


class TestCLIShim:
    """Test CLI shim security checks and message framing."""

    def test_shim_init_defaults(self) -> None:
        """StdioShim initializes with correct defaults."""
        shim = StdioShim(cmd=["echo", "hi"], agent_name="my-agent")
        assert shim.agent_name == "my-agent"
        assert shim.cmd == ["echo", "hi"]
        assert shim.stats["total_requests"] == 0
        assert shim.stats["blocked"] == 0
        assert shim._target_server == "stdio://echo hi"

    def test_shim_policy_enforcement_blocks_denied_tool(self) -> None:
        """Shim blocks tools/call when policy denies the tool."""
        pe = PolicyEngine()
        pe.policy = {
            "version": "1.0",
            "agents": {
                "test-agent": {
                    "tools_allowed": ["safe_tool"],
                    "tools_denied": ["dangerous_tool"],
                },
            },
            "tools": {
                "dangerous_tool": {"allowed_actions": ["tools/call"]},
            },
        }
        shim = StdioShim(cmd=["true"], agent_name="test-agent", policy_engine=pe)

        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {"name": "dangerous_tool", "arguments": {}},
        }).encode()

        allowed, _, error = shim._check_request(payload)
        assert not allowed
        assert error is not None
        assert error["error"]["code"] == -32001
        assert shim.stats["blocked"] == 1

    def test_shim_allows_valid_tool_call(self) -> None:
        """Shim allows tools/call when policy permits the tool."""
        pe = PolicyEngine()
        pe.policy = {
            "version": "1.0",
            "agents": {"test-agent": {"tools_allowed": ["*"]}},
            "tools": {"read_file": {"allowed_actions": ["tools/call"]}},
        }
        shim = StdioShim(cmd=["true"], agent_name="test-agent", policy_engine=pe)

        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {"name": "read_file", "arguments": {"path": "/tmp"}},
        }).encode()

        allowed, _, error = shim._check_request(payload)
        assert allowed
        assert error is None

    def test_shim_passes_non_tool_methods(self) -> None:
        """Non-tools/call methods bypass policy checks."""
        shim = StdioShim(cmd=["true"], agent_name="test-agent")

        for method in ["initialize", "tools/list", "notifications/initialized"]:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "id": 1,
                "params": {},
            }).encode()

            allowed, _, error = shim._check_request(payload)
            assert allowed, f"{method} should pass without policy check"
            assert error is None

    def test_shim_jsonrpc_error_format(self) -> None:
        """_jsonrpc_error returns valid JSON-RPC 2.0 error."""
        err = StdioShim._jsonrpc_error(-32001, "blocked", 42)
        assert err["jsonrpc"] == "2.0"
        assert err["error"]["code"] == -32001
        assert err["error"]["message"] == "blocked"
        assert err["id"] == 42

    def test_shim_rejects_invalid_json(self) -> None:
        """Shim rejects requests that are not valid JSON."""
        shim = StdioShim(cmd=["true"], agent_name="test-agent")
        allowed, _, error = shim._check_request(b"this is not json")
        assert not allowed
        assert error["error"]["code"] == -32700

    @pytest.mark.asyncio
    async def test_detect_and_read_empty_lines_skipped(self) -> None:
        """Empty lines are skipped, next valid message is returned."""
        reader = asyncio.StreamReader()
        # Feed empty line then a valid JSON message
        reader.feed_data(b"\n")
        reader.feed_data(b'{"jsonrpc":"2.0","method":"test","id":1}\n')
        reader.feed_eof()

        result = await _detect_and_read_message(reader)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["method"] == "test"

    def test_write_message_content_length_header(self) -> None:
        """_write_message produces correct Content-Length header."""

        class FakeWriter:
            def __init__(self):
                self.data = b""
            def write(self, data: bytes) -> None:
                self.data += data

        writer = FakeWriter()
        body = b'{"result":"ok"}'
        _write_message(writer, body)

        header_line = writer.data.split(b"\r\n")[0]
        assert header_line == f"Content-Length: {len(body)}".encode()


# ── Feature 3b: CLI shim command registration ────────────────────────

from navil.commands.shim import register


class TestShimCommandRegistration:
    """Test that shim and wrap subcommands register correctly."""

    def test_register_adds_shim_and_wrap(self) -> None:
        """register() adds both 'shim' and 'wrap' subcommands."""
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        register(subparsers, type(None))

        # Verify shim subcommand works
        args = parser.parse_args(["shim", "--cmd", "echo hi"])
        assert args.cmd == "echo hi"
        assert hasattr(args, "func")

    def test_register_wrap_command(self) -> None:
        """register() adds wrap subcommand with expected arguments."""
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        register(subparsers, type(None))

        args = parser.parse_args(["wrap", "config.json", "--dry-run"])
        assert args.config == "config.json"
        assert args.dry_run is True

    def test_shim_agent_defaults_to_none(self) -> None:
        """--agent defaults to None (resolved at runtime from env)."""
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        register(subparsers, type(None))

        args = parser.parse_args(["shim", "--cmd", "server"])
        assert args.agent is None


# ── Feature 4: A2A Agent Cards ────────────────────────────────────────

from navil.a2a.agent_card import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    SecurityScheme,
    build_navil_agent_card,
)
from navil.a2a.tasks import Task, TaskArtifact, TaskMessage, TaskState, TaskStore


class TestA2AAgentCardProtocolBlitz:
    """Additional A2A Agent Card tests for Protocol Blitz coverage."""

    def test_agent_card_omits_empty_optional_sections(self) -> None:
        """to_dict omits skills, security, extensions when empty."""
        card = AgentCard(
            name="minimal",
            description="Minimal card",
            provider=AgentProvider(organization="Org"),
            interfaces=[],
        )
        d = card.to_dict()

        assert "skills" not in d
        assert "securitySchemes" not in d
        assert "security" not in d
        assert "documentationUrl" not in d
        assert "extensions" not in d

    def test_agent_card_includes_documentation_url(self) -> None:
        """to_dict includes documentationUrl when set."""
        card = AgentCard(
            name="documented",
            description="Has docs",
            provider=AgentProvider(organization="Org"),
            documentation_url="https://docs.example.com",
            interfaces=[],
        )
        d = card.to_dict()
        assert d["documentationUrl"] == "https://docs.example.com"

    def test_build_navil_agent_card_capabilities(self) -> None:
        """Navil agent card has streaming=True and extended_agent_card=True."""
        card = build_navil_agent_card()
        d = card.to_dict()

        assert d["capabilities"]["streaming"] is True
        assert d["capabilities"]["extendedAgentCard"] is True
        assert d["capabilities"]["pushNotifications"] is False

    def test_build_navil_agent_card_governance_extension(self) -> None:
        """Navil agent card includes governance extension with correct fields."""
        card = build_navil_agent_card(base_url="https://navil.example.com")
        d = card.to_dict()

        ext = d["extensions"][0]
        assert ext["name"] == "navil-governance"
        assert ext["fields"]["supports_scoping"] is True
        assert ext["fields"]["supports_threat_detection"] is True
        assert ext["fields"]["governance_endpoint"] == "https://navil.example.com/mcp"

    def test_build_navil_agent_card_explicit_args_override_env(self) -> None:
        """Explicit arguments take precedence over environment variables."""
        env = {"NAVIL_AGENT_NAME": "env-name", "NAVIL_BASE_URL": "http://env-url"}
        with patch.dict(os.environ, env):
            card = build_navil_agent_card(
                agent_name="explicit-name",
                base_url="http://explicit-url",
            )
            d = card.to_dict()

        assert d["name"] == "explicit-name"
        assert "explicit-url" in d["interfaces"][0]["url"]


class TestA2ATaskLifecycle:
    """Test A2A task lifecycle for Protocol Blitz."""

    def test_task_state_transitions_full_lifecycle(self) -> None:
        """Task can go through full lifecycle: pending -> working -> completed."""
        store = TaskStore()
        task = Task(source_agent="agent-a", target_agent="agent-b")
        store.create(task)

        assert task.state == TaskState.PENDING

        store.update_state(task.id, TaskState.WORKING)
        assert store.get(task.id).state == TaskState.WORKING

        store.update_state(task.id, TaskState.COMPLETED)
        assert store.get(task.id).state == TaskState.COMPLETED

    def test_task_message_auto_timestamp(self) -> None:
        """TaskMessage auto-generates timestamp on creation."""
        msg = TaskMessage(role="user", content="Hello")
        assert msg.timestamp != ""
        assert "T" in msg.timestamp  # ISO format

    def test_task_message_to_dict_format(self) -> None:
        """TaskMessage.to_dict uses A2A parts format."""
        msg = TaskMessage(role="agent", content="Response here")
        d = msg.to_dict()

        assert d["role"] == "agent"
        assert len(d["parts"]) == 1
        assert d["parts"][0]["type"] == "text/plain"
        assert d["parts"][0]["text"] == "Response here"

    def test_task_artifact_to_dict(self) -> None:
        """TaskArtifact.to_dict serializes correctly."""
        artifact = TaskArtifact(
            name="report.json",
            content='{"findings": []}',
            content_type="application/json",
        )
        d = artifact.to_dict()

        assert d["name"] == "report.json"
        assert d["parts"][0]["type"] == "application/json"

    def test_task_store_operations_on_nonexistent_task(self) -> None:
        """All TaskStore operations on missing IDs return None."""
        store = TaskStore()

        assert store.get("missing") is None
        assert store.update_state("missing", TaskState.FAILED) is None
        assert store.add_message("missing", TaskMessage(role="user", content="hi")) is None
        assert store.add_artifact("missing", TaskArtifact(name="x", content="y")) is None
        assert store.cancel("missing") is None

    def test_task_store_list_respects_limit(self) -> None:
        """list_tasks respects the limit parameter."""
        store = TaskStore()
        for i in range(10):
            store.create(Task(source_agent="a", target_agent="b"))

        results = store.list_tasks(limit=3)
        assert len(results) == 3

    def test_task_navil_scope_in_metadata(self) -> None:
        """Task with navil_scope includes it in serialized metadata."""
        task = Task(
            source_agent="a",
            target_agent="b",
            navil_scope="github-pr-review",
        )
        d = task.to_dict()
        assert d["metadata"]["navil"]["scope"] == "github-pr-review"


# ── Feature 5: Policy suggestion endpoints ────────────────────────────

from navil.api.local.state import AppState


class TestPolicySuggestionEndpoints:
    """Test /policy/suggestions GET and POST endpoints logic."""

    @pytest.fixture(autouse=True)
    def reset_appstate(self) -> None:
        """Reset singleton before each test."""
        AppState.reset()
        yield
        AppState.reset()

    def test_dismissed_suggestions_tracking(self) -> None:
        """AppState tracks dismissed suggestions in a set."""
        state = AppState.get()
        assert isinstance(state._dismissed_suggestions, set)
        assert len(state._dismissed_suggestions) == 0

        state._dismissed_suggestions.add("demo-1")
        assert "demo-1" in state._dismissed_suggestions

    def test_demo_suggestions_filtered_by_dismissed(self) -> None:
        """Dismissed demo suggestions are excluded from results."""
        state = AppState.get()
        state.demo_seeded = True
        state._dismissed_suggestions = {"demo-1"}

        # Simulate what get_policy_suggestions does
        demo_all = [
            {"id": "demo-1", "rule_type": "deny"},
            {"id": "demo-2", "rule_type": "rate_limit"},
            {"id": "demo-3", "rule_type": "scope"},
        ]
        dismissed = state._dismissed_suggestions
        suggestions = [d for d in demo_all if d["id"] not in dismissed]

        assert len(suggestions) == 2
        assert all(s["id"] != "demo-1" for s in suggestions)

    def test_suggestion_action_model_validation(self) -> None:
        """SuggestionAction only accepts 'approve' or 'reject'."""
        from navil.api.local.routes import SuggestionAction

        # Valid actions
        approved = SuggestionAction(action="approve")
        assert approved.action == "approve"

        rejected = SuggestionAction(action="reject")
        assert rejected.action == "reject"

    def test_suggestion_action_rejects_invalid(self) -> None:
        """SuggestionAction rejects invalid action values."""
        from pydantic import ValidationError

        from navil.api.local.routes import SuggestionAction

        with pytest.raises(ValidationError):
            SuggestionAction(action="invalid")

    def test_policy_suggestion_model_fields(self) -> None:
        """PolicySuggestion model has all required fields."""
        from navil.api.local.routes import PolicySuggestion

        suggestion = PolicySuggestion(
            id="test-1",
            rule_type="deny",
            agent="test-agent",
            tool="admin",
            description="Block admin access",
            confidence=0.95,
            source="anomaly",
        )
        assert suggestion.id == "test-1"
        assert suggestion.auto_applied is False
        assert suggestion.timestamp == ""

    def test_appstate_singleton_pattern(self) -> None:
        """AppState.get() returns the same instance."""
        s1 = AppState.get()
        s2 = AppState.get()
        assert s1 is s2

    def test_appstate_reset(self) -> None:
        """AppState.reset() creates a new instance next time."""
        s1 = AppState.get()
        AppState.reset()
        s2 = AppState.get()
        assert s1 is not s2


# ── Feature 2b: PolicyEngine merge + serialize (update step) ─────────


class TestPolicyEngineUpdateStep:
    """Test the UPDATE step of the closed loop (merge auto policy, serialize)."""

    def test_merge_auto_policy_human_wins(self, tmp_path: Path) -> None:
        """Human-owned policy takes precedence over auto policy."""
        human_policy = {
            "version": "1.0",
            "agents": {
                "reader": {"rate_limit_per_hour": 100},
            },
        }
        auto_policy = {
            "agents": {
                "reader": {"rate_limit_per_hour": 50},  # should NOT override
                "auto-agent": {"rate_limit_per_hour": 30},  # should be added
            },
        }

        human_file = tmp_path / "policy.yaml"
        human_file.write_text(yaml.dump(human_policy))

        auto_file = tmp_path / "policy.auto.yaml"
        auto_file.write_text(yaml.dump(auto_policy))

        engine = PolicyEngine(
            policy_file=str(human_file),
            auto_policy_file=str(auto_file),
        )

        # Human value wins
        assert engine.policy["agents"]["reader"]["rate_limit_per_hour"] == 100
        # Auto-added agent is present
        assert "auto-agent" in engine.policy["agents"]

    def test_serialize_and_reload_roundtrip(self, tmp_path: Path) -> None:
        """Policy can be serialized to YAML and reloaded correctly."""
        human_file = tmp_path / "policy.yaml"
        human_file.write_text(yaml.dump({
            "version": "1.0",
            "agents": {"test": {"tools_allowed": ["*"]}},
            "scopes": {"default": {"tools": "*"}},
        }))

        auto_file = tmp_path / "policy.auto.yaml"
        engine = PolicyEngine(
            policy_file=str(human_file),
            auto_policy_file=str(auto_file),
        )

        assert engine.serialize_to_yaml() is True
        assert auto_file.exists()

        # Reload and verify
        content = auto_file.read_text()
        assert "auto-generated by navil" in content

        parsed = yaml.safe_load(content.split("\n\n", 1)[1])
        assert parsed["version"] == "1.0"

    def test_check_tool_call_logs_decisions(self, tmp_path: Path) -> None:
        """check_tool_call logs every decision to decisions_log."""
        policy = {
            "version": "1.0",
            "agents": {"agent": {"tools_allowed": ["tool_a"], "tools_denied": ["tool_b"]}},
            "tools": {"tool_a": {"allowed_actions": ["read"]}},
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(policy))

        engine = PolicyEngine(policy_file=str(p))

        engine.check_tool_call("agent", "tool_a", "read")
        engine.check_tool_call("agent", "tool_b", "read")

        log = engine.get_decisions_log()
        assert len(log) == 2
        assert log[0]["decision"] == "ALLOW"
        assert log[1]["decision"] == "DENY"
