# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""REST API endpoints for the local Navil dashboard."""

from __future__ import annotations

import datetime
import hmac
import json
import logging
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from navil.api.local.state import AppState
from navil.llm.cache import LLMResponseCache, cache_key

router = APIRouter(prefix="/api/local")

_logger = logging.getLogger(__name__)


def _require_llm(s: AppState) -> None:
    """Raise HTTPException if LLM features are not available."""
    if not s.llm_available:
        raise HTTPException(
            status_code=501,
            detail={
                "error": "llm_not_available",
                "message": "LLM features require navil[llm]. Install with: pip install navil[llm]",
                "error_type": "auth",
            },
        )


def _require_dashboard_auth(request: Request) -> None:
    """Verify dashboard bearer token for sensitive endpoints.

    If NAVIL_DASHBOARD_TOKEN is set, all credential-management requests
    must include ``Authorization: Bearer <token>``.  When the env var is
    unset the guard is a no-op (local-only dev mode).
    """
    expected = os.environ.get("NAVIL_DASHBOARD_TOKEN", "").strip()
    if not expected:
        _logger.warning(
            "NAVIL_DASHBOARD_TOKEN is not set — credential endpoints are unprotected. "
            "Set this env var in production to require authentication."
        )
        return  # no token configured — allow (local dev mode)
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not hmac.compare_digest(auth_header[7:], expected):
        raise HTTPException(status_code=401, detail="Invalid dashboard token")


def _call_llm(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Call an LLM function, converting auth/runtime errors to HTTPException."""
    try:
        return fn(*args, **kwargs)
    except TypeError as e:
        err = str(e)
        if "api_key" in err or "authentication" in err.lower() or "auth_token" in err:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "llm_auth_error",
                    "message": "API key not configured or invalid. Configure in Settings.",
                    "error_type": "auth",
                },
            ) from e
        raise HTTPException(
            status_code=500,
            detail={"error": "llm_error", "message": err, "error_type": "unknown"},
        ) from e
    except Exception as e:
        err_str = str(e)
        err_lower = err_str.lower()
        error_type = "unknown"
        status = 500
        message = err_str

        if "429" in err_str or ("rate" in err_lower and "limit" in err_lower):
            error_type = "rate_limit"
            status = 429
            message = "Rate limit exceeded. Please wait a moment and try again."
        elif (
            "quota" in err_lower
            or "billing" in err_lower
            or "exceeded" in err_lower
            and "limit" in err_lower
        ):
            error_type = "quota"
            status = 503
            message = "API quota exceeded. Check your provider account or wait for quota reset."
        elif "auth" in err_lower or "api_key" in err_lower or "401" in err_str or "403" in err_str:
            error_type = "auth"
            status = 503
            message = "API key is invalid or expired. Check your key in Settings."

        _logger.error(f"LLM call failed ({error_type}): {e}")
        raise HTTPException(
            status_code=status,
            detail={"error": "llm_error", "message": message, "error_type": error_type},
        ) from e


# ── LLM Response Cache ────────────────────────────────────

_llm_cache = LLMResponseCache()


def _get_llm_cache() -> LLMResponseCache:
    """Return the module-level LLM response cache (test-friendly accessor)."""
    return _llm_cache


# ── SSE Streaming Helpers ─────────────────────────────────


def _sse_event(data: str, event: str | None = None) -> str:
    """Format a single SSE event."""
    lines = []
    if event:
        lines.append(f"event: {event}")
    # SSE spec: multi-line data needs each line prefixed with "data: "
    for line in data.split("\n"):
        lines.append(f"data: {line}")
    lines.append("")  # trailing blank line = event boundary
    lines.append("")
    return "\n".join(lines)


def _stream_llm_sse(
    system_prompt: str,
    user_message: str,
    llm_client: Any,
    ck: str,
    post_process: Any = None,
) -> Iterator[str]:
    """Generator that streams LLM output as SSE events.

    Yields:
      event: chunk   → each text delta from the LLM
      event: done    → final assembled JSON result
      event: error   → if something goes wrong mid-stream

    After streaming completes, the full response is cached under *ck*.

    *post_process* is an optional ``fn(full_text) -> dict`` that converts
    the raw LLM output to a structured result for the ``done`` event.
    If None, the raw text is sent as-is in the ``done`` payload.
    """
    accumulated = ""
    try:
        for chunk in llm_client.stream(system_prompt, user_message):
            accumulated += chunk
            yield _sse_event(json.dumps({"text": chunk}), event="chunk")

        # Cache the raw completion
        _get_llm_cache().put_sync(ck, accumulated)

        # Build final structured result
        if post_process:
            try:
                result = post_process(accumulated)
            except Exception:
                result = {"raw": accumulated}
        else:
            result = {"raw": accumulated}

        yield _sse_event(json.dumps(result), event="done")
    except Exception as e:
        _logger.error(f"SSE stream error: {e}")
        yield _sse_event(
            json.dumps({"error": "llm_error", "message": str(e)}),
            event="error",
        )


def _make_sse_response(generator: Iterator[str]) -> StreamingResponse:
    """Wrap an SSE generator in a properly-typed StreamingResponse."""
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )


# ── Request / Response Models ───────────────────────────────


class ScanRequest(BaseModel):
    config: dict[str, Any]


class InvocationRequest(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=256)
    tool_name: str = Field(..., min_length=1, max_length=256)
    action: str = Field(..., min_length=1, max_length=128)
    duration_ms: int
    data_accessed_bytes: int = 0
    success: bool = True


class CredentialIssueRequest(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=256)
    scope: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 365)


class CredentialExchangeRequest(BaseModel):
    oidc_token: str = Field(..., min_length=1)
    agent_name: str = Field(..., min_length=1, max_length=256)
    scope: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 365)
    issuer: str | None = None
    audience: str | None = None


class CredentialDelegateRequest(BaseModel):
    parent_credential_id: str = Field(..., min_length=1)
    agent_name: str = Field(..., min_length=1, max_length=256)
    scope: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 365)
    max_depth: int | None = None


class PolicyCheckRequest(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=256)
    tool_name: str = Field(..., min_length=1, max_length=256)
    action: str = Field(..., min_length=1, max_length=128)


class FeedbackRequest(BaseModel):
    alert_timestamp: str = Field(..., max_length=64)
    anomaly_type: str = Field(..., max_length=128)
    agent_name: str = Field(..., min_length=1, max_length=256)
    verdict: str = Field(..., max_length=64)
    operator_notes: str = Field(default="", max_length=2048)


class ExplainAnomalyRequest(BaseModel):
    anomaly_data: dict[str, Any]


class AnalyzeConfigRequest(BaseModel):
    config: dict[str, Any]


class GeneratePolicyRequest(BaseModel):
    description: str = Field(..., min_length=1, max_length=4096)


class RefinePolicyRequest(BaseModel):
    existing_policy: dict[str, Any]
    instruction: str = Field(..., min_length=1, max_length=4096)


class ApplyActionRequest(BaseModel):
    action: dict[str, Any]


class AutoRemediateRequest(BaseModel):
    confidence_threshold: float = Field(default=0.9, ge=0.0, le=1.0)


class LLMConfigRequest(BaseModel):
    provider: str = Field(..., max_length=64)
    api_key: str = Field(..., max_length=512)
    base_url: str = Field(default="", max_length=512)
    model: str = Field(default="", max_length=128)


# ── Overview ────────────────────────────────────────────────


@router.get("/overview")
def get_overview() -> dict[str, Any]:
    s = AppState.get()
    alerts = s.anomaly_detector.get_alerts()
    agents = list(s.anomaly_detector.adaptive_baselines.keys())
    creds = s.credential_manager.list_credentials()
    active_creds = [c for c in creds if c.get("status") == "ACTIVE"]

    # Per-agent health summary
    agent_health = []
    for agent in agents:
        agent_alerts = [a for a in alerts if a.get("agent") == agent]
        max_sev = "OK"
        for a in agent_alerts:
            sev = a.get("severity", "LOW")
            if sev == "CRITICAL":
                max_sev = "CRITICAL"
                break
            elif sev == "HIGH" and max_sev not in ("CRITICAL",):
                max_sev = "HIGH"
            elif sev == "MEDIUM" and max_sev not in ("CRITICAL", "HIGH"):
                max_sev = "MEDIUM"
            elif sev == "LOW" and max_sev == "OK":
                max_sev = "LOW"
        bl = s.anomaly_detector.adaptive_baselines.get(agent)
        agent_health.append(
            {
                "name": agent,
                "status": max_sev,
                "observations": bl.duration_ema.count if bl else 0,
                "alert_count": len(agent_alerts),
            }
        )

    return {
        "total_agents": len(agents),
        "total_alerts": len(alerts),
        "critical_alerts": len([a for a in alerts if a.get("severity") == "CRITICAL"]),
        "active_credentials": len(active_creds),
        "total_credentials": len(creds),
        "total_invocations": len(s.anomaly_detector.invocations),
        "recent_alerts": alerts[-10:][::-1],
        "agent_health": agent_health,
    }


# ── Scanner ─────────────────────────────────────────────────


@router.post("/scan")
def scan_config(req: ScanRequest) -> dict[str, Any]:
    s = AppState.get()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(req.config, f)
        tmp_path = f.name
    try:
        result = s.scanner.scan(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return result


# ── Agents ──────────────────────────────────────────────────


@router.get("/agents")
def list_agents() -> list[dict[str, Any]]:
    s = AppState.get()
    alerts = s.anomaly_detector.get_alerts()
    result = []
    for name, bl in s.anomaly_detector.adaptive_baselines.items():
        agent_alerts = [a for a in alerts if a.get("agent") == name]
        result.append(
            {
                "name": name,
                "observations": bl.duration_ema.count,
                "alert_count": len(agent_alerts),
                "known_tools": list(bl.known_tools),
                "duration_mean": round(bl.duration_ema.mean, 1),
                "data_volume_mean": round(bl.data_volume_ema.mean, 1),
            }
        )
    return result


@router.get("/agents/{name}")
def get_agent_detail(name: str) -> dict[str, Any]:
    s = AppState.get()
    baseline = s.anomaly_detector.get_adaptive_baseline(name)
    alerts = s.anomaly_detector.get_alerts(agent_name=name)
    scores = s.anomaly_detector.score_anomaly(name)
    return {
        "baseline": baseline,
        "alerts": alerts,
        "anomaly_scores": scores,
    }


# ── Alerts ──────────────────────────────────────────────────


@router.get("/alerts")
def list_alerts(severity: str | None = None, agent: str | None = None) -> list[dict[str, Any]]:
    s = AppState.get()
    alerts = s.anomaly_detector.get_alerts(agent_name=agent, severity=severity)
    return alerts[::-1]


# ── Invocations ─────────────────────────────────────────────


@router.post("/invocations")
async def record_invocation(req: InvocationRequest) -> dict[str, str]:
    s = AppState.get()

    # Redis LPUSH path: enqueue canonical event for the TelemetryWorker.
    if s.redis_client is not None:
        from navil.telemetry_event import TELEMETRY_QUEUE, build_telemetry_event

        event_bytes = build_telemetry_event(
            agent_name=req.agent_name,
            tool_name=req.tool_name,
            method="tools/call",
            action=req.action,
            response_bytes=req.data_accessed_bytes,
            duration_ms=req.duration_ms,
        )
        await s.redis_client.lpush(TELEMETRY_QUEUE, event_bytes)
        return {"status": "recorded"}

    s.anomaly_detector.record_invocation(
        agent_name=req.agent_name,
        tool_name=req.tool_name,
        action=req.action,
        duration_ms=req.duration_ms,
        data_accessed_bytes=req.data_accessed_bytes,
        success=req.success,
    )
    return {"status": "recorded"}


# ── Credentials ─────────────────────────────────────────────


@router.get("/credentials", dependencies=[Depends(_require_dashboard_auth)])
def list_credentials(agent: str | None = None) -> list[dict[str, Any]]:
    s = AppState.get()
    return s.credential_manager.list_credentials(agent_name=agent)


@router.post("/credentials", dependencies=[Depends(_require_dashboard_auth)])
def issue_credential(req: CredentialIssueRequest) -> dict[str, Any]:
    s = AppState.get()
    return s.credential_manager.issue_credential(
        agent_name=req.agent_name,
        scope=req.scope,
        ttl_seconds=req.ttl_seconds,
    )


@router.delete("/credentials/{token_id}", dependencies=[Depends(_require_dashboard_auth)])
def revoke_credential(token_id: str, cascade: bool = False) -> dict[str, str]:
    s = AppState.get()
    try:
        if cascade:
            count = s.credential_manager.cascade_revoke(token_id)
            return {"status": "cascade_revoked", "count": str(count)}
        s.credential_manager.revoke_credential(token_id, reason="Dashboard revocation")
        return {"status": "revoked"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/credentials/exchange", dependencies=[Depends(_require_dashboard_auth)])
def exchange_credential(req: CredentialExchangeRequest) -> dict[str, Any]:
    """Exchange an OIDC token for a Navil credential with human identity context."""
    from navil.oidc import exchange_oidc_token

    s = AppState.get()
    try:
        return exchange_oidc_token(
            oidc_token=req.oidc_token,
            agent_name=req.agent_name,
            scope=req.scope,
            credential_manager=s.credential_manager,
            ttl_seconds=req.ttl_seconds,
            issuer=req.issuer,
            audience=req.audience,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/credentials/delegate", dependencies=[Depends(_require_dashboard_auth)])
def delegate_credential(req: CredentialDelegateRequest) -> dict[str, Any]:
    """Delegate a credential to a child agent with narrowed scope."""
    s = AppState.get()
    try:
        return s.credential_manager.delegate_credential(
            parent_credential_id=req.parent_credential_id,
            agent_name=req.agent_name,
            narrowed_scope=req.scope,
            ttl_seconds=req.ttl_seconds,
            max_depth=req.max_depth,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/credentials/{token_id}/chain", dependencies=[Depends(_require_dashboard_auth)])
def get_credential_chain(token_id: str) -> dict[str, Any]:
    """Get the full delegation chain for a credential."""
    s = AppState.get()
    cred_info = s.credential_manager.get_credential_info(token_id)
    if not cred_info:
        raise HTTPException(status_code=404, detail=f"Credential not found: {token_id}")

    chain = cred_info.get("delegation_chain", [])
    chain_details = []

    # Build chain from root to current
    for ancestor_id in chain:
        ancestor_info = s.credential_manager.get_credential_info(ancestor_id)
        if ancestor_info:
            chain_details.append(ancestor_info)

    # Add current credential
    chain_details.append(cred_info)

    return {
        "credential_id": token_id,
        "chain_length": len(chain),
        "human_context": cred_info.get("human_context"),
        "chain": chain_details,
    }


# ── Policy ──────────────────────────────────────────────────


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


# ── Feedback ────────────────────────────────────────────────


@router.post("/feedback")
def submit_feedback(req: FeedbackRequest) -> dict[str, str]:
    s = AppState.get()
    s.feedback_loop.submit_feedback(
        alert_timestamp=req.alert_timestamp,
        anomaly_type=req.anomaly_type,
        agent_name=req.agent_name,
        verdict=req.verdict,  # type: ignore[arg-type]
        operator_notes=req.operator_notes,
    )
    return {"status": "recorded"}


@router.get("/feedback/stats")
def get_feedback_stats() -> dict[str, Any]:
    s = AppState.get()
    return s.feedback_loop.get_stats()


# ── Settings ───────────────────────────────────────────────


@router.get("/settings/llm")
def get_llm_settings() -> dict[str, Any]:
    return AppState.get().get_llm_config()


@router.post("/settings/llm")
def update_llm_settings(req: LLMConfigRequest) -> dict[str, Any]:
    s = AppState.get()
    valid_providers = ("anthropic", "openai", "gemini", "openai_compatible", "ollama")
    if req.provider not in valid_providers:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_provider",
                "message": f"Provider must be one of: {', '.join(valid_providers)}",
            },
        )
    if req.provider == "openai_compatible" and not req.base_url:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "missing_base_url",
                "message": "Base URL is required for OpenAI-compatible providers.",
            },
        )
    # Ollama doesn't require an API key — use a placeholder
    api_key = req.api_key if req.provider != "ollama" else (req.api_key or "ollama")
    try:
        s.configure_llm(
            req.provider,
            api_key,
            base_url=req.base_url or None,
            model=req.model or None,
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=501,
            detail={"error": "llm_not_available", "message": str(e)},
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "llm_config_error", "message": f"Failed to configure: {e}"},
        ) from e
    return s.get_llm_config()


class LLMTestRequest(BaseModel):
    provider: str = ""
    api_key: str = ""
    base_url: str = ""
    model: str = ""


@router.post("/settings/llm/test")
def test_llm_connection(req: LLMTestRequest) -> dict[str, Any]:
    """Test LLM connection using the provided form values (unsaved).

    When form values are supplied, a temporary client is created to test them
    without changing the saved configuration.  If no provider is given, the
    already-saved configuration is tested instead.
    """
    from navil.llm.client import LLMClient

    s = AppState.get()
    _require_llm(s)

    if req.provider:
        # ── Test with the *unsaved* form values ──
        api_key = req.api_key if req.provider != "ollama" else (req.api_key or "ollama")
        try:
            client = LLMClient(
                provider=req.provider,
                api_key=api_key or None,
                base_url=req.base_url or None,
                model=req.model or None,
            )
        except Exception as e:
            return {"success": False, "error": f"Configuration error: {e}"}
    else:
        # ── Fallback: test the saved config ──
        if not s.llm_api_key_configured:
            return {"success": False, "error": "No API key configured."}
        client = s.llm_analyzer.client

    try:
        result = client.complete(
            "You are a connection test. Respond with exactly: OK",
            "Test.",
        )
        return {"success": True, "response_preview": result[:100]}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/settings/telemetry")
def get_telemetry_settings() -> dict[str, Any]:
    """Return community threat feed / cloud sync settings."""
    from navil.threat_intel import get_intel_mode

    enabled = os.environ.get("NAVIL_DISABLE_CLOUD_SYNC", "").lower() not in (
        "1",
        "true",
        "yes",
    )
    api_key_present = bool(os.environ.get("NAVIL_API_KEY", "").strip())
    return {
        "cloud_sync_enabled": enabled,
        "api_key_present": api_key_present,
        "mode": get_intel_mode(),
    }


class TelemetrySettingsRequest(BaseModel):
    enabled: bool = True


@router.post("/settings/telemetry")
def update_telemetry_settings(req: TelemetrySettingsRequest) -> dict[str, Any]:
    """Toggle community threat feed (cloud sync).

    Community mode: cannot disable sync (give-to-get enforcement).
    Paid mode (NAVIL_API_KEY): can disable sync ("privacy premium").
    """
    from navil.threat_intel import get_intel_mode

    api_key_present = bool(os.environ.get("NAVIL_API_KEY", "").strip())

    if not req.enabled and not api_key_present:
        raise HTTPException(
            status_code=403,
            detail=(
                "Community tier requires sharing anonymous threat data "
                "to receive threat intelligence. Provide a NAVIL_API_KEY "
                "for privacy premium (paid mode)."
            ),
        )

    if req.enabled:
        os.environ.pop("NAVIL_DISABLE_CLOUD_SYNC", None)
    else:
        os.environ["NAVIL_DISABLE_CLOUD_SYNC"] = "1"

    return {
        "cloud_sync_enabled": req.enabled,
        "api_key_present": api_key_present,
        "mode": get_intel_mode(),
    }


# ── LLM-Powered Features ──────────────────────────────────


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

    # Cache hit → instant JSON response (no SSE overhead)
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
    """Apply a single remediation action (non-streaming — instant action)."""
    s = AppState.get()
    _require_llm(s)
    success = _call_llm(
        s.self_healing.apply_action, req.action, s.policy_engine, s.anomaly_detector
    )
    return {"success": success, "action": req.action}


@router.post("/llm/auto-remediate")
def auto_remediate(req: AutoRemediateRequest) -> dict[str, Any]:
    """Full auto-remediation cycle: analyze, auto-apply safe actions, verify.

    Not streamed — actions are applied server-side and the full result returned.
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


# ── Pentest ────────────────────────────────────────────────


class PentestRequest(BaseModel):
    scenario: str | None = None  # None = run all scenarios


@router.post("/pentest")
def run_pentest(req: PentestRequest) -> dict[str, Any]:
    """Run SAFE-MCP attack simulations against the anomaly detectors."""
    from navil.pentest import PentestEngine

    s = AppState.get()
    engine = PentestEngine(s.anomaly_detector, s.policy_engine)

    if req.scenario:
        result = engine.run_scenario(req.scenario)
        return {
            "status": "completed",
            "total_scenarios": 1,
            "passed": 1 if result.verdict == "PASS" else 0,
            "failed": 1 if result.verdict == "FAIL" else 0,
            "partial": 1 if result.verdict == "PARTIAL" else 0,
            "detection_rate": (
                100.0 if result.verdict == "PASS" else 50.0 if result.verdict == "PARTIAL" else 0.0
            ),
            "results": [result.to_dict()],
        }
    return engine.run_all()


# ── Proxy endpoints ──────────────────────────────────────────


@router.get("/proxy/status")
def proxy_status() -> dict[str, Any]:
    """Get MCP proxy status."""
    s = AppState.get()
    if s.proxy is not None and s.proxy_running:
        return s.proxy.get_status()
    return {
        "running": False,
        "target_url": "",
        "stats": {"total_requests": 0, "blocked": 0, "alerts_generated": 0, "forwarded": 0},
        "uptime_seconds": 0,
        "traffic_log_size": 0,
    }


@router.get("/proxy/traffic")
def proxy_traffic(
    limit: int = 100,
    agent: str | None = None,
    blocked_only: bool = False,
) -> list[dict[str, Any]]:
    """Get recent proxy traffic log."""
    s = AppState.get()
    if s.proxy is not None and s.proxy_running:
        return s.proxy.get_traffic(limit=limit, agent=agent, blocked_only=blocked_only)
    return []


class ProxyStartRequest(BaseModel):
    target_url: str
    port: int = 9090
    require_auth: bool = True


@router.post("/proxy/start")
def proxy_start_endpoint(req: ProxyStartRequest) -> dict[str, Any]:
    """Start the MCP proxy in a background thread."""
    import threading

    s = AppState.get()

    if s.proxy_running:
        return {"status": "already_running", "target_url": s.proxy.target_url}

    from navil.proxy import MCPSecurityProxy, create_proxy_app

    proxy = MCPSecurityProxy(
        target_url=req.target_url,
        policy_engine=s.policy_engine,
        anomaly_detector=s.anomaly_detector,
        credential_manager=s.credential_manager,
        require_auth=req.require_auth,
        redis_client=s.redis_client,
    )
    s.proxy = proxy
    s.proxy_running = True

    app = create_proxy_app(proxy)

    def _run() -> None:
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=req.port, log_level="warning")

    thread = threading.Thread(target=_run, daemon=True, name="navil-proxy")
    thread.start()

    return {
        "status": "started",
        "target_url": req.target_url,
        "port": req.port,
        "require_auth": req.require_auth,
    }


# ── Machine identity ──────────────────────────────────────────


@router.get("/machine")
def get_machine_info() -> dict[str, Any]:
    """Return machine identity (machine_id and label) from local config."""
    from navil.commands.init import get_machine_id, get_machine_label

    return {
        "machine_id": get_machine_id() or "",
        "machine_label": get_machine_label() or "",
    }


# ── Health check ──────────────────────────────────────────────


@router.get("/health")
def health_check() -> dict[str, Any]:
    """Health check endpoint.  Returns component status."""
    components: dict[str, str] = {}

    # Database check
    try:
        from sqlalchemy import text

        from navil.cloud.database import get_session

        with get_session() as session:
            session.execute(text("SELECT 1"))
        components["database"] = "ok"
    except Exception as e:
        components["database"] = f"error: {e}"

    all_ok = all(v == "ok" or v == "not_configured" for v in components.values())
    return {
        "status": "healthy" if all_ok else "degraded",
        "components": components,
        "version": "0.1.0",
    }


# ── AI Policy Builder ────────────────────────────────────────


class PolicySuggestion(BaseModel):
    """A pending policy rule suggestion from the AI Policy Builder."""

    id: str
    rule_type: str  # "deny", "allow", "rate_limit", "scope"
    agent: str
    tool: str
    description: str
    confidence: float
    source: str  # "anomaly", "baseline", "operator"
    auto_applied: bool = False
    timestamp: str = ""


@router.get("/policy/suggestions")
def get_policy_suggestions() -> dict[str, Any]:
    """Get pending policy suggestions from SelfHealingEngine."""
    s = AppState.get()
    suggestions: list[dict[str, Any]] = []

    # Pull from SelfHealingEngine if available
    if hasattr(s, "self_healing") and s.self_healing is not None:
        pending = getattr(s.self_healing, "pending_actions", [])
        for i, action in enumerate(pending):
            suggestions.append({
                "id": f"suggestion-{i}",
                "rule_type": getattr(action, "action_type", "deny"),
                "agent": getattr(action, "agent_name", "unknown"),
                "tool": getattr(action, "tool_name", ""),
                "description": getattr(action, "description", str(action)),
                "confidence": getattr(action, "confidence", 0.0),
                "source": "anomaly",
                "auto_applied": getattr(action, "applied", False),
                "timestamp": getattr(action, "timestamp", ""),
            })

    # Also check for demo suggestions if no real ones
    if not suggestions and getattr(s, "demo_seeded", False):
        # Track which demo suggestions have been acted on
        dismissed: set[str] = getattr(s, "_dismissed_suggestions", set())
        demo_all = [
            {
                "id": "demo-1",
                "rule_type": "deny",
                "agent": "monitoring-agent",
                "tool": "admin_panel",
                "description": "Agent accessed admin tools 47 times, baseline is 3. Suggest denying admin_panel access.",
                "confidence": 0.95,
                "source": "anomaly",
                "auto_applied": False,
                "timestamp": "",
            },
            {
                "id": "demo-2",
                "rule_type": "rate_limit",
                "agent": "data-reader",
                "tool": "files",
                "description": "Data volume 5.2x above baseline. Suggest rate limiting to 30 req/hr.",
                "confidence": 0.82,
                "source": "baseline",
                "auto_applied": False,
                "timestamp": "",
            },
            {
                "id": "demo-3",
                "rule_type": "scope",
                "agent": "code-assistant",
                "tool": "terminal",
                "description": "Agent only uses read-related tools. Suggest scoping to read-only.",
                "confidence": 0.71,
                "source": "baseline",
                "auto_applied": False,
                "timestamp": "",
            },
        ]
        suggestions = [d for d in demo_all if d["id"] not in dismissed]

    return {"suggestions": suggestions, "count": len(suggestions)}


class SuggestionAction(BaseModel):
    action: str = Field(..., pattern="^(approve|reject)$")


@router.post("/policy/suggestions/{suggestion_id}")
def act_on_suggestion(suggestion_id: str, body: SuggestionAction) -> dict[str, Any]:
    """Approve or reject a policy suggestion."""
    s = AppState.get()

    # Track dismissed suggestions on AppState
    if not hasattr(s, "_dismissed_suggestions"):
        s._dismissed_suggestions = set()

    if body.action == "reject":
        _logger.info("Rejected policy suggestion: %s", suggestion_id)
        s._dismissed_suggestions.add(suggestion_id)
        return {"status": "rejected", "suggestion_id": suggestion_id}

    # action == "approve"
    _logger.info("Approved policy suggestion: %s", suggestion_id)
    s._dismissed_suggestions.add(suggestion_id)

    # Find the suggestion to get its details
    suggestion: dict[str, Any] | None = None
    if hasattr(s, "self_healing") and s.self_healing is not None:
        pending = getattr(s.self_healing, "pending_actions", [])
        for i, action in enumerate(pending):
            if f"suggestion-{i}" == suggestion_id:
                suggestion = {
                    "rule_type": getattr(action, "action_type", "deny"),
                    "agent": getattr(action, "agent_name", "unknown"),
                    "tool": getattr(action, "tool_name", ""),
                    "description": getattr(action, "description", str(action)),
                }
                break

    # Fall back to demo suggestions
    if suggestion is None and getattr(s, "demo_seeded", False):
        demo_suggestions = {
            "demo-1": {"rule_type": "deny", "agent": "monitoring-agent", "tool": "admin_panel", "description": "Deny admin_panel access"},
            "demo-2": {"rule_type": "rate_limit", "agent": "data-reader", "tool": "files", "description": "Rate limit to 30 req/hr"},
            "demo-3": {"rule_type": "scope", "agent": "code-assistant", "tool": "terminal", "description": "Scope to read-only"},
        }
        suggestion = demo_suggestions.get(suggestion_id)

        if suggestion is None:
            return {"status": "approved", "suggestion_id": suggestion_id}

        # Read existing policy.auto.yaml
        policy_path = Path(os.path.expanduser("~/.navil/policy.auto.yaml"))
        if not policy_path.exists():
            policy_path = Path("policy.auto.yaml")

        policy: dict[str, Any] = {}
        if policy_path.exists():
            try:
                policy = yaml.safe_load(policy_path.read_text()) or {}
            except Exception:
                policy = {}

        if "version" not in policy:
            policy["version"] = "1.0"
        if "agents" not in policy:
            policy["agents"] = {}

        agent_name = suggestion["agent"]
        if agent_name not in policy["agents"]:
            policy["agents"][agent_name] = {
                "tools_allowed": ["*"],
                "tools_denied": [],
                "rate_limit_per_hour": 1000,
                "data_clearance": "PUBLIC",
            }

        agent_cfg = policy["agents"][agent_name]
        rule_type = suggestion["rule_type"]

        if rule_type == "deny":
            denied = agent_cfg.get("tools_denied", [])
            if suggestion["tool"] not in denied:
                denied.append(suggestion["tool"])
            agent_cfg["tools_denied"] = denied
        elif rule_type == "rate_limit":
            # Extract rate limit from description if possible, default 30
            agent_cfg["rate_limit_per_hour"] = 30
        elif rule_type == "scope":
            if "scopes" not in policy:
                policy["scopes"] = {}
            scope_name = f"{agent_name}_scope"
            policy["scopes"][scope_name] = {
                "description": suggestion["description"],
                "tools": "read-only",
            }
            agent_cfg["scope"] = scope_name

        # Write back to disk
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        header = f"# auto-generated by navil at {now}\n"
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(header + yaml.dump(policy, default_flow_style=False, sort_keys=False))
        _logger.info("Policy updated at %s", policy_path)

        return {"status": "approved", "suggestion_id": suggestion_id, "policy": policy}


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


class SavePolicyBody(BaseModel):
    yaml: str = Field(..., min_length=1)
    path: str = Field(default="policy.auto.yaml")


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

    # Validate the YAML is parseable
    try:
        yaml.safe_load(body.yaml)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}") from e

    # Resolve path: prefer ~/.navil/<name>, fall back to ./<name>
    navil_dir = Path(os.path.expanduser("~/.navil"))
    if navil_dir.exists():
        policy_path = navil_dir / body.path
    else:
        policy_path = Path(body.path)

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
