"""Tests for Pydantic request model field validation."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from navil.api.local.routes import (
    CredentialIssueRequest,
    InvocationRequest,
    PolicyCheckRequest,
    FeedbackRequest,
    AutoRemediateRequest,
    LLMConfigRequest,
)


def test_policy_check_rejects_oversized_agent_name() -> None:
    with pytest.raises(ValidationError):
        PolicyCheckRequest(agent_name="a" * 300, tool_name="read", action="tools/call")


def test_policy_check_rejects_oversized_tool_name() -> None:
    with pytest.raises(ValidationError):
        PolicyCheckRequest(agent_name="agent", tool_name="t" * 300, action="tools/call")


def test_policy_check_accepts_valid_input() -> None:
    req = PolicyCheckRequest(agent_name="my-agent", tool_name="read_file", action="tools/call")
    assert req.agent_name == "my-agent"
    assert req.tool_name == "read_file"


def test_invocation_request_rejects_oversized_agent_name() -> None:
    with pytest.raises(ValidationError):
        InvocationRequest(
            agent_name="a" * 300,
            tool_name="tool",
            action="tools/call",
            duration_ms=100,
        )


def test_credential_issue_rejects_oversized_scope() -> None:
    with pytest.raises(ValidationError):
        CredentialIssueRequest(agent_name="agent", scope="s" * 600)


def test_credential_issue_rejects_negative_ttl() -> None:
    with pytest.raises(ValidationError):
        CredentialIssueRequest(agent_name="agent", scope="read:tools", ttl_seconds=-1)


def test_feedback_rejects_oversized_notes() -> None:
    with pytest.raises(ValidationError):
        FeedbackRequest(
            alert_timestamp="2026-01-01T00:00:00",
            anomaly_type="ANOMALY",
            agent_name="agent",
            verdict="false_positive",
            operator_notes="x" * 3000,
        )


def test_auto_remediate_rejects_threshold_out_of_range() -> None:
    with pytest.raises(ValidationError):
        AutoRemediateRequest(confidence_threshold=1.5)


def test_auto_remediate_accepts_default() -> None:
    req = AutoRemediateRequest()
    assert req.confidence_threshold == 0.9


def test_llm_config_rejects_oversized_api_key() -> None:
    with pytest.raises(ValidationError):
        LLMConfigRequest(provider="openai", api_key="k" * 600)
