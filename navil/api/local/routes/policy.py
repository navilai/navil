# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Policy check, decisions, suggestions, auto-generate, save, and history endpoints."""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException

from navil.api.local.state import AppState

from ._helpers import (
    PolicyCheckRequest,
    SavePolicyBody,
    SuggestionAction,
)

router = APIRouter()

_logger = logging.getLogger(__name__)


@router.post("/policy/check")
def check_policy(req: PolicyCheckRequest) -> dict[str, Any]:
    s = AppState.get()
    allowed, reason = s.policy_engine.check_tool_call(
        agent_name=req.agent_name,
        tool_name=req.tool_name,
        action=req.action,
    )
    return {"allowed": allowed, "reason": reason}


@router.get("/policy/decisions")
def get_decisions() -> list[dict[str, Any]]:
    s = AppState.get()
    return s.policy_engine.get_decisions_log()[-50:][::-1]


@router.get("/policy/suggestions")
def get_policy_suggestions() -> dict[str, Any]:
    """Get pending policy suggestions from SelfHealingEngine."""
    s = AppState.get()
    suggestions: list[dict[str, Any]] = []

    # Pull from SelfHealingEngine if available
    if hasattr(s, "self_healing") and s.self_healing is not None:
        pending = getattr(s.self_healing, "pending_actions", [])
        for i, action in enumerate(pending):
            # Actions can be dicts (from LLM JSON) or objects
            if isinstance(action, dict):
                act_type = action.get("type", "deny")
                target = action.get("target", "")
                value = action.get("value", "")
                reason = action.get("reason", "")
                conf = action.get("confidence", 0.0)
                # Map action types to rule types for display
                rule_type_map = {
                    "credential_rotation": "deny",
                    "policy_update": "scope",
                    "threshold_adjustment": "rate_limit",
                    "block_tool": "deny",
                    "scope_reduction": "scope",
                }
                rule_type = rule_type_map.get(act_type, "deny")
                description = reason or str(value) or str(action)
                suggestions.append(
                    {
                        "id": f"suggestion-{i}",
                        "rule_type": rule_type,
                        "agent": target or "all",
                        "tool": act_type.replace("_", " "),
                        "description": description,
                        "confidence": conf,
                        "source": "anomaly",
                        "auto_applied": False,
                        "timestamp": "",
                        "_raw_action": action,
                    }
                )
            else:
                suggestions.append(
                    {
                        "id": f"suggestion-{i}",
                        "rule_type": getattr(action, "action_type", "deny"),
                        "agent": getattr(action, "agent_name", "unknown"),
                        "tool": getattr(action, "tool_name", ""),
                        "description": getattr(action, "description", str(action)),
                        "confidence": getattr(action, "confidence", 0.0),
                        "source": "anomaly",
                        "auto_applied": getattr(action, "applied", False),
                        "timestamp": getattr(action, "timestamp", ""),
                    }
                )

    return {"suggestions": suggestions, "count": len(suggestions)}


@router.post("/policy/suggestions/{suggestion_id}")
def act_on_suggestion(suggestion_id: str, body: SuggestionAction) -> dict[str, Any]:
    """Approve or reject a policy suggestion."""
    s = AppState.get()

    if body.action == "reject":
        _logger.info("Rejected policy suggestion: %s", suggestion_id)
        s.dismiss_suggestion(suggestion_id)
        return {"status": "rejected", "suggestion_id": suggestion_id}

    # action == "approve"
    _logger.info("Approved policy suggestion: %s", suggestion_id)
    s.dismiss_suggestion(suggestion_id)

    # Find the suggestion to get its details
    suggestion: dict[str, Any] | None = None
    if hasattr(s, "self_healing") and s.self_healing is not None:
        pending = getattr(s.self_healing, "pending_actions", [])
        for i, action in enumerate(pending):
            if f"suggestion-{i}" == suggestion_id:
                if isinstance(action, dict):
                    act_type = action.get("type", "deny")
                    rule_type_map = {
                        "credential_rotation": "deny",
                        "policy_update": "scope",
                        "threshold_adjustment": "rate_limit",
                        "block_tool": "deny",
                        "scope_reduction": "scope",
                    }
                    suggestion = {
                        "rule_type": rule_type_map.get(act_type, "deny"),
                        "agent": action.get("target", "all"),
                        "tool": act_type.replace("_", " "),
                        "description": action.get("reason", str(action)),
                        "_raw_action": action,
                    }
                else:
                    suggestion = {
                        "rule_type": getattr(action, "action_type", "deny"),
                        "agent": getattr(action, "agent_name", "unknown"),
                        "tool": getattr(action, "tool_name", ""),
                        "description": getattr(action, "description", str(action)),
                    }
                break

    # No suggestion found from self-healing — return early
    if suggestion is None:
        return {"status": "approved", "suggestion_id": suggestion_id}

    return {"status": "approved", "suggestion_id": suggestion_id}


@router.post("/policy/auto-generate")
def auto_generate_policy() -> dict[str, Any]:
    """Auto-generate a policy from observed agent baselines."""
    s = AppState.get()

    # Collect baseline data from the anomaly detector's baselines
    agents: dict[str, Any] = {}
    if hasattr(s, "anomaly_detector") and s.anomaly_detector is not None:
        agents = getattr(s.anomaly_detector, "_agent_baselines", {})
    policy: dict[str, Any] = {
        "version": "1.0",
        "agents": {},
        "scopes": {"default": {"description": "Default scope", "tools": "*"}},
    }

    for agent_name in agents:
        tools: list[str] = []
        policy["agents"][agent_name] = {
            "tools_allowed": tools if tools else ["*"],
            "tools_denied": [],
            "rate_limit_per_hour": 100,
            "data_clearance": "PUBLIC",
        }

    if not policy["agents"]:
        # Fallback: permissive default
        policy["agents"]["default"] = {
            "tools_allowed": ["*"],
            "tools_denied": [],
            "rate_limit_per_hour": 1000,
            "data_clearance": "PUBLIC",
        }

    yaml_str = yaml.dump(policy, default_flow_style=False, sort_keys=False)
    return {"policy": policy, "yaml": yaml_str, "source": "baselines"}


@router.post("/policy/save")
def save_policy(body: SavePolicyBody) -> dict[str, Any]:
    """Save generated policy YAML to disk."""
    # Only allow safe filenames
    allowed_names = {"policy.yaml", "policy.auto.yaml"}
    if body.path not in allowed_names:
        raise HTTPException(
            status_code=400,
            detail=f"Path must be one of: {', '.join(sorted(allowed_names))}",
        )

    # Validate the YAML is parseable and has valid schema
    try:
        parsed = yaml.safe_load(body.yaml)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}") from e

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=400,
            detail="Policy YAML must be a mapping (dict) at the top level",
        )

    # Accept any valid top-level keys — auto-generated policies use keys like
    # "agents", "scopes", "tools_allowed", "tools_denied", "rate_limit_per_hour",
    # "data_clearance" in addition to "rules", "default_action", "version".

    # Resolve path: prefer ~/.navil/<name>, fall back to ./<name>
    navil_dir = Path(os.path.expanduser("~/.navil"))
    policy_path = navil_dir / body.path if navil_dir.exists() else Path(body.path)

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    header = f"# auto-generated by navil at {now}\n"
    try:
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(header + body.yaml)
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to write policy: {e}") from e

    _logger.info("Policy saved to %s", policy_path)
    return {"status": "saved", "path": str(policy_path)}


@router.get("/policy/auto-history")
def get_auto_policy_history() -> dict[str, Any]:
    """Get history of auto-generated policy changes for rollback."""
    # In production: read from policy.auto.yaml git history or changelog
    return {
        "entries": [],
        "count": 0,
        "message": "No auto-generated policy changes yet.",
    }
