# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""LLM-powered feature endpoints (explain, analyze, generate, remediate)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import yaml
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from navil.api.local.state import AppState

from ._helpers import (
    AnalyzeConfigRequest,
    ApplyActionRequest,
    AutoRemediateRequest,
    ExplainAnomalyRequest,
    GeneratePolicyRequest,
    RefinePolicyRequest,
    _call_llm,
    _get_llm_cache,
    _make_sse_response,
    _require_llm,
    _sse_event,
    _stream_llm_sse,
    cache_key,
)

router = APIRouter()


@router.get("/llm/status")
def llm_status() -> dict[str, Any]:
    return AppState.get().get_llm_config()


@router.post("/llm/explain-anomaly")
def explain_anomaly(req: ExplainAnomalyRequest) -> StreamingResponse:
    """Stream an anomaly explanation via SSE. Returns cached result instantly if available."""
    s = AppState.get()
    _require_llm(s)

    from navil.llm.analyzer import ANOMALY_EXPLANATION_PROMPT

    user_msg = f"Explain this behavioral anomaly:\n\n{json.dumps(req.anomaly_data, indent=2)}"
    ck = cache_key(ANOMALY_EXPLANATION_PROMPT, user_msg)

    # Cache hit -> instant JSON response (no SSE overhead)
    cached = _get_llm_cache().get_sync(ck)
    if cached is not None:
        from navil.llm import extract_json

        try:
            result = json.loads(extract_json(cached))
        except (json.JSONDecodeError, ValueError):
            result = {
                "explanation": cached[:500],
                "likely_threat": False,
                "recommended_actions": [],
            }

        def _cached_sse() -> Iterator[str]:
            yield _sse_event(json.dumps({"text": cached, "cached": True}), event="chunk")
            yield _sse_event(json.dumps(result), event="done")

        return _make_sse_response(_cached_sse())

    def _post_process(text: str) -> dict[str, Any]:
        from navil.llm import extract_json

        try:
            return json.loads(extract_json(text))
        except (json.JSONDecodeError, ValueError):
            return {"explanation": text[:500], "likely_threat": False, "recommended_actions": []}

    return _make_sse_response(
        _stream_llm_sse(
            ANOMALY_EXPLANATION_PROMPT,
            user_msg,
            s.llm_analyzer.client,
            ck,
            _post_process,
        )
    )


@router.post("/llm/analyze-config")
def analyze_config_llm(req: AnalyzeConfigRequest) -> StreamingResponse:
    """Stream a config security analysis via SSE. Cached by config hash."""
    s = AppState.get()
    _require_llm(s)

    from navil.llm.analyzer import ANALYSIS_SYSTEM_PROMPT

    config_str = json.dumps(req.config, indent=2)
    user_msg = f"Analyze this MCP server configuration:\n\n{config_str}"
    ck = cache_key(ANALYSIS_SYSTEM_PROMPT, user_msg)

    cached = _get_llm_cache().get_sync(ck)
    if cached is not None:
        from navil.llm import extract_json

        try:
            result = json.loads(extract_json(cached))
        except (json.JSONDecodeError, ValueError):
            result = {
                "explanation": cached[:500],
                "risks": [],
                "remediations": [],
                "severity": "UNKNOWN",
            }

        def _cached_sse() -> Iterator[str]:
            yield _sse_event(json.dumps({"text": cached, "cached": True}), event="chunk")
            yield _sse_event(json.dumps(result), event="done")

        return _make_sse_response(_cached_sse())

    def _post_process(text: str) -> dict[str, Any]:
        from navil.llm import extract_json

        try:
            return json.loads(extract_json(text))
        except (json.JSONDecodeError, ValueError):
            return {
                "explanation": text[:500],
                "risks": [],
                "remediations": [],
                "severity": "UNKNOWN",
            }

    return _make_sse_response(
        _stream_llm_sse(ANALYSIS_SYSTEM_PROMPT, user_msg, s.llm_analyzer.client, ck, _post_process)
    )


@router.post("/llm/generate-policy")
def generate_policy(req: GeneratePolicyRequest) -> StreamingResponse:
    """Stream policy generation via SSE. Cached by description hash."""
    s = AppState.get()
    _require_llm(s)

    from navil.llm.policy_gen import POLICY_GEN_SYSTEM_PROMPT, PolicyGenerator

    ck = cache_key(POLICY_GEN_SYSTEM_PROMPT, req.description)

    cached = _get_llm_cache().get_sync(ck)
    if cached is not None:
        try:
            policy = PolicyGenerator._parse_yaml(cached)
        except (ValueError, yaml.YAMLError):
            policy = {}
        result = {"policy": policy, "yaml": yaml.dump(policy, default_flow_style=False)}

        def _cached_sse() -> Iterator[str]:
            yield _sse_event(json.dumps({"text": cached, "cached": True}), event="chunk")
            yield _sse_event(json.dumps(result), event="done")

        return _make_sse_response(_cached_sse())

    def _post_process(text: str) -> dict[str, Any]:
        try:
            policy = PolicyGenerator._parse_yaml(text)
        except (ValueError, yaml.YAMLError):
            policy = {}
        return {"policy": policy, "yaml": yaml.dump(policy, default_flow_style=False)}

    return _make_sse_response(
        _stream_llm_sse(
            POLICY_GEN_SYSTEM_PROMPT,
            req.description,
            s.policy_generator.client,
            ck,
            _post_process,
        )
    )


@router.post("/llm/refine-policy")
def refine_policy(req: RefinePolicyRequest) -> StreamingResponse:
    """Stream policy refinement via SSE."""
    s = AppState.get()
    _require_llm(s)

    from navil.llm.policy_gen import POLICY_GEN_SYSTEM_PROMPT, PolicyGenerator

    policy_yaml = yaml.dump(req.existing_policy, default_flow_style=False)
    user_msg = f"Current policy:\n\n{policy_yaml}\n\nModification requested:\n{req.instruction}"
    ck = cache_key(POLICY_GEN_SYSTEM_PROMPT, user_msg)

    cached = _get_llm_cache().get_sync(ck)
    if cached is not None:
        try:
            policy = PolicyGenerator._parse_yaml(cached)
        except (ValueError, yaml.YAMLError):
            policy = {}
        result = {"policy": policy, "yaml": yaml.dump(policy, default_flow_style=False)}

        def _cached_sse() -> Iterator[str]:
            yield _sse_event(json.dumps({"text": cached, "cached": True}), event="chunk")
            yield _sse_event(json.dumps(result), event="done")

        return _make_sse_response(_cached_sse())

    def _post_process(text: str) -> dict[str, Any]:
        try:
            policy = PolicyGenerator._parse_yaml(text)
        except (ValueError, yaml.YAMLError):
            policy = {}
        return {"policy": policy, "yaml": yaml.dump(policy, default_flow_style=False)}

    return _make_sse_response(
        _stream_llm_sse(
            POLICY_GEN_SYSTEM_PROMPT,
            user_msg,
            s.policy_generator.client,
            ck,
            _post_process,
        )
    )


@router.post("/llm/suggest-remediation")
def suggest_remediation() -> StreamingResponse:
    """Stream remediation suggestions via SSE."""
    s = AppState.get()
    _require_llm(s)

    alerts = s.anomaly_detector.get_alerts()
    if not alerts:
        no_threat = {
            "summary": "No active threats detected. The system is healthy.",
            "risk_assessment": "LOW",
            "actions": [],
        }

        def _empty_sse() -> Iterator[str]:
            yield _sse_event(json.dumps(no_threat), event="done")

        return _make_sse_response(_empty_sse())

    critical = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]
    selected = critical[-10:] if critical else alerts[-10:]
    current_policy = getattr(s.policy_engine, "policy", {})
    baselines: dict[str, Any] = {}
    for name, bl in s.anomaly_detector.adaptive_baselines.items():
        baselines[name] = {
            "duration_mean": bl.duration_ema.mean,
            "data_volume_mean": bl.data_volume_ema.mean,
            "known_tools": list(bl.known_tools),
        }

    from navil.llm.self_healing import SELF_HEALING_SYSTEM_PROMPT

    context = {"alerts": selected, "current_policy": current_policy, "baselines": baselines}
    user_msg = f"Analyze and suggest remediations:\n\n{json.dumps(context, indent=2)}"
    ck = cache_key(SELF_HEALING_SYSTEM_PROMPT, user_msg)

    cached = _get_llm_cache().get_sync(ck)
    if cached is not None:
        from navil.llm import extract_json

        try:
            result = json.loads(extract_json(cached))
        except (json.JSONDecodeError, ValueError):
            result = {"actions": [], "summary": cached[:500], "risk_assessment": "UNKNOWN"}

        def _cached_sse() -> Iterator[str]:
            yield _sse_event(json.dumps({"text": cached, "cached": True}), event="chunk")
            yield _sse_event(json.dumps(result), event="done")

        return _make_sse_response(_cached_sse())

    def _post_process(text: str) -> dict[str, Any]:
        from navil.llm import extract_json

        try:
            return json.loads(extract_json(text))
        except (json.JSONDecodeError, ValueError):
            return {"actions": [], "summary": text[:500], "risk_assessment": "UNKNOWN"}

    # Use higher max_tokens for remediation
    prev_max = getattr(s.self_healing.client, "max_tokens", 1024)
    if isinstance(prev_max, int) and prev_max < 4096:
        s.self_healing.client.max_tokens = 4096
    try:
        return _make_sse_response(
            _stream_llm_sse(
                SELF_HEALING_SYSTEM_PROMPT,
                user_msg,
                s.self_healing.client,
                ck,
                _post_process,
            )
        )
    finally:
        s.self_healing.client.max_tokens = prev_max


@router.post("/llm/apply-action")
def apply_action(req: ApplyActionRequest) -> dict[str, Any]:
    """Apply a single remediation action (non-streaming -- instant action)."""
    s = AppState.get()
    _require_llm(s)
    success = _call_llm(
        s.self_healing.apply_action, req.action, s.policy_engine, s.anomaly_detector
    )
    return {"success": success, "action": req.action}


@router.post("/llm/auto-remediate")
def auto_remediate(req: AutoRemediateRequest) -> dict[str, Any]:
    """Full auto-remediation cycle: analyze, auto-apply safe actions, verify.

    Not streamed -- actions are applied server-side and the full result returned.
    """
    s = AppState.get()
    _require_llm(s)

    alerts = s.anomaly_detector.get_alerts()
    if not alerts:
        return {
            "initial_analysis": {
                "summary": "No active threats detected. The system is healthy.",
                "risk_assessment": "LOW",
            },
            "auto_applied": [],
            "failed_to_apply": [],
            "manual_review": [],
            "post_status": {"healthy": True, "remaining_alert_count": 0},
            "llm_calls_used": 0,
        }

    critical = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]
    selected = critical[-10:] if critical else alerts[-10:]
    current_policy = getattr(s.policy_engine, "policy", {})
    baselines: dict[str, Any] = {}
    for name, bl in s.anomaly_detector.adaptive_baselines.items():
        baselines[name] = {
            "duration_mean": bl.duration_ema.mean,
            "data_volume_mean": bl.data_volume_ema.mean,
            "known_tools": list(bl.known_tools),
        }

    result = _call_llm(
        s.self_healing.full_auto_remediate,
        selected,
        current_policy,
        baselines,
        s.policy_engine,
        s.anomaly_detector,
        req.confidence_threshold,
    )

    return result
