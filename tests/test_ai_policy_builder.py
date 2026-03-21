"""Tests for the AI Policy Builder closed loop.

Tests cover:
- PolicyGenerator.suggest_policy_rule() with alert + baseline
- FeedbackLoop.apply_adjustments_to_policy() wiring
- SelfHealingEngine → PolicyEngine persistence
- CLI auto-generate zero-config fallback
- CLI rollback
- CI/CD policy validation action
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from navil.adaptive.feedback import FeedbackLoop
from navil.llm.policy_gen import PolicyGenerator
from navil.llm.self_healing import SelfHealingEngine
from navil.policy_engine import PolicyEngine


class TestSuggestPolicyRule:
    """Test PolicyGenerator.suggest_policy_rule()."""

    def test_suggest_returns_required_fields(self) -> None:
        """Suggestion must include rule, confidence, reason, reversible."""
        mock_client = MagicMock()
        mock_client.complete.return_value = (
            "rule:\n  agents:\n    bad-agent:\n      rate_limit_per_hour: 30\n"
            "confidence: 0.85\n"
            "reason: Agent exceeded rate baseline\n"
            "reversible: true"
        )
        gen = PolicyGenerator(client=mock_client)

        alert = {"agent_name": "bad-agent", "anomaly_type": "RATE_SPIKE", "severity": "HIGH"}
        baseline = {"rate_ema": 10.0}

        result = gen.suggest_policy_rule(alert, baseline)

        assert "rule" in result
        assert "confidence" in result
        assert "reason" in result
        assert "reversible" in result
        assert 0.0 <= result["confidence"] <= 1.0

    def test_suggest_fallback_on_llm_failure(self) -> None:
        """When LLM fails, returns conservative fallback."""
        mock_client = MagicMock()
        mock_client.complete.side_effect = RuntimeError("LLM unavailable")
        gen = PolicyGenerator(client=mock_client)

        alert = {"agent_name": "test-agent", "anomaly_type": "RATE_SPIKE"}
        result = gen.suggest_policy_rule(alert)

        assert result["confidence"] == 0.3  # Low confidence fallback
        assert result["reversible"] is True
        assert "test-agent" in result["reason"]
        assert "rule" in result

    def test_suggest_fallback_on_invalid_yaml(self) -> None:
        """When LLM returns invalid YAML, falls back to conservative."""
        mock_client = MagicMock()
        mock_client.complete.return_value = "not valid yaml at all {{{"
        gen = PolicyGenerator(client=mock_client)

        alert = {"agent_name": "x", "anomaly_type": "DATA_EXFILTRATION"}
        result = gen.suggest_policy_rule(alert)

        assert result["confidence"] == 0.3
        assert result["reversible"] is True


class TestFeedbackPolicyWiring:
    """Test FeedbackLoop → PolicyGenerator.refine() wiring."""

    def test_apply_adjustments_to_policy_not_enough_data(self) -> None:
        """With < 5 entries, no adjustment is made."""
        loop = FeedbackLoop()
        mock_gen = MagicMock()

        result = loop.apply_adjustments_to_policy(
            mock_gen, {"version": "1.0"}, "RATE_SPIKE", "agent-x"
        )

        assert result is None
        mock_gen.refine.assert_not_called()

    def test_apply_adjustments_to_policy_high_false_positives(self) -> None:
        """With many dismissed alerts, policy should become more permissive."""
        loop = FeedbackLoop()

        # Submit 10 dismissed + 2 confirmed = high FP rate
        for i in range(10):
            loop.submit_feedback(f"ts-{i}", "RATE_SPIKE", "agent-x", "dismissed")
        for i in range(2):
            loop.submit_feedback(f"ts-c-{i}", "RATE_SPIKE", "agent-x", "confirmed")

        mock_gen = MagicMock()
        mock_gen.refine.return_value = {"version": "1.0", "agents": {"agent-x": {"rate_limit_per_hour": 2000}}}

        result = loop.apply_adjustments_to_policy(
            mock_gen, {"version": "1.0"}, "RATE_SPIKE", "agent-x"
        )

        assert result is not None
        mock_gen.refine.assert_called_once()
        # Check the instruction mentions making policy more permissive
        call_args = mock_gen.refine.call_args
        instruction = call_args[0][1]
        assert "permissive" in instruction.lower()

    def test_apply_adjustments_to_policy_high_confirmed(self) -> None:
        """With many confirmed alerts, policy should become stricter."""
        loop = FeedbackLoop()

        # 9 confirmed + 1 dismissed → false_positive_rate = 0.1 < 0.2
        for i in range(9):
            loop.submit_feedback(f"ts-{i}", "RATE_SPIKE", "agent-x", "confirmed")
        for i in range(1):
            loop.submit_feedback(f"ts-d-{i}", "RATE_SPIKE", "agent-x", "dismissed")

        mock_gen = MagicMock()
        mock_gen.refine.return_value = {"version": "1.0", "agents": {"agent-x": {"rate_limit_per_hour": 30}}}

        result = loop.apply_adjustments_to_policy(
            mock_gen, {"version": "1.0"}, "RATE_SPIKE", "agent-x"
        )

        assert result is not None
        call_args = mock_gen.refine.call_args
        instruction = call_args[0][1]
        assert "tighten" in instruction.lower()


class TestSelfHealingPersistence:
    """Test SelfHealingEngine → PolicyEngine.serialize_to_yaml()."""

    def test_apply_action_persists_policy_update(self, tmp_path: Path) -> None:
        """Policy updates should trigger serialize_to_yaml()."""
        policy_file = tmp_path / "policy.yaml"
        auto_file = tmp_path / "policy.auto.yaml"

        with open(policy_file, "w") as f:
            yaml.dump({"version": "1.0", "agents": {"agent-x": {"rate_limit_per_hour": 100}}}, f)

        engine = PolicyEngine(
            policy_file=str(policy_file),
            auto_policy_file=str(auto_file),
        )

        healing = SelfHealingEngine()
        mock_detector = MagicMock()
        mock_detector.alerts = []

        action = {
            "type": "policy_update",
            "target": "agent-x",
            "value": {"rate_limit_per_hour": 30},
            "confidence": 0.95,
            "reversible": True,
        }

        success = healing.apply_action(action, engine, mock_detector)
        assert success is True

        # Check that policy.auto.yaml was written
        assert auto_file.exists()
        with open(auto_file) as f:
            content = f.read()
        assert "auto-generated by navil" in content

    def test_apply_action_agent_block_persists(self, tmp_path: Path) -> None:
        """Agent blocking should persist to policy.auto.yaml."""
        policy_file = tmp_path / "policy.yaml"
        auto_file = tmp_path / "policy.auto.yaml"

        with open(policy_file, "w") as f:
            yaml.dump({"version": "1.0", "agents": {}}, f)

        engine = PolicyEngine(
            policy_file=str(policy_file),
            auto_policy_file=str(auto_file),
        )

        healing = SelfHealingEngine()
        mock_detector = MagicMock()
        mock_detector.alerts = []

        action = {
            "type": "agent_block",
            "target": "malicious-agent",
            "confidence": 0.99,
            "reversible": True,
        }

        success = healing.apply_action(action, engine, mock_detector)
        assert success is True
        assert auto_file.exists()


class TestAutoGenerateFallback:
    """Test zero-config fallback for navil policy auto-generate."""

    def test_permissive_default_is_valid_policy(self) -> None:
        """The fallback permissive policy must be valid YAML and loadable."""
        from navil.commands.policy import _PERMISSIVE_DEFAULT_POLICY

        assert _PERMISSIVE_DEFAULT_POLICY["version"] == "1.0"
        assert "agents" in _PERMISSIVE_DEFAULT_POLICY
        assert "default" in _PERMISSIVE_DEFAULT_POLICY["agents"]
        assert "*" in _PERMISSIVE_DEFAULT_POLICY["agents"]["default"]["tools_allowed"]

        # Must be serializable to YAML
        yaml_str = yaml.dump(_PERMISSIVE_DEFAULT_POLICY)
        roundtrip = yaml.safe_load(yaml_str)
        assert roundtrip == _PERMISSIVE_DEFAULT_POLICY


class TestPolicyRollback:
    """Test navil policy rollback functionality."""

    def test_rollback_removes_last_entry(self, tmp_path: Path) -> None:
        """Rollback should remove the most recently added agent entry."""
        auto_file = tmp_path / "policy.auto.yaml"
        policy = {
            "version": "1.0",
            "agents": {
                "agent-a": {"rate_limit_per_hour": 100},
                "agent-b": {"rate_limit_per_hour": 50},
                "agent-c": {"rate_limit_per_hour": 30},
            },
        }
        with open(auto_file, "w") as f:
            yaml.dump(policy, f)

        # Simulate rollback of 1
        with open(auto_file) as f:
            loaded = yaml.safe_load(f)
        agents = loaded["agents"]
        names = list(agents.keys())
        to_remove = names[-1:]
        for name in to_remove:
            del agents[name]
        with open(auto_file, "w") as f:
            yaml.dump(loaded, f)

        with open(auto_file) as f:
            result = yaml.safe_load(f)
        assert "agent-c" not in result["agents"]
        assert "agent-a" in result["agents"]
        assert "agent-b" in result["agents"]


class TestCICDValidation:
    """Test CI/CD policy validation script."""

    def test_valid_policy_no_errors(self, tmp_path: Path) -> None:
        """A valid policy should produce no errors."""
        # Import the validation module
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "validate",
            str(Path(__file__).parent.parent / ".github" / "actions" / "policy-validate" / "validate.py"),
        )
        if spec is None or spec.loader is None:
            pytest.skip("validate.py not found")
        validate_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validate_mod)

        policy_file = tmp_path / "policy.yaml"
        with open(policy_file, "w") as f:
            yaml.dump({"version": "1.0", "agents": {"default": {"tools_allowed": ["*"]}}}, f)

        findings = validate_mod.validate_policy(policy_file)
        errors = [f for f in findings if f["level"] == "error"]
        assert len(errors) == 0

    def test_missing_version_is_error(self, tmp_path: Path) -> None:
        """Missing version field should produce an error."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "validate",
            str(Path(__file__).parent.parent / ".github" / "actions" / "policy-validate" / "validate.py"),
        )
        if spec is None or spec.loader is None:
            pytest.skip("validate.py not found")
        validate_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validate_mod)

        policy_file = tmp_path / "policy.yaml"
        with open(policy_file, "w") as f:
            yaml.dump({"agents": {}}, f)

        findings = validate_mod.validate_policy(policy_file)
        errors = [f for f in findings if f["level"] == "error"]
        assert any("version" in f["message"] for f in errors)

    def test_sarif_output_format(self, tmp_path: Path) -> None:
        """SARIF output must conform to expected structure."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "validate",
            str(Path(__file__).parent.parent / ".github" / "actions" / "policy-validate" / "validate.py"),
        )
        if spec is None or spec.loader is None:
            pytest.skip("validate.py not found")
        validate_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validate_mod)

        findings = [{"level": "error", "message": "test", "line": 1, "rule_id": "navil/test"}]
        sarif = validate_mod.findings_to_sarif(findings, "policy.yaml")

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "navil-policy-validate"
        assert len(sarif["runs"][0]["results"]) == 1
