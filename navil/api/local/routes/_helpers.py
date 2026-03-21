# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Shared helpers, models, and utilities for local API route modules."""

from __future__ import annotations

import hmac
import json
import logging
import os
from collections.abc import Iterator
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from navil.api.local.state import AppState
from navil.llm.cache import LLMResponseCache, cache_key  # noqa: F401 – re-export

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


# -- LLM Response Cache -------------------------------------------------------

_llm_cache = LLMResponseCache()


def _get_llm_cache() -> LLMResponseCache:
    """Return the module-level LLM response cache (test-friendly accessor)."""
    return _llm_cache


# -- SSE Streaming Helpers ----------------------------------------------------


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
      event: chunk   -> each text delta from the LLM
      event: done    -> final assembled JSON result
      event: error   -> if something goes wrong mid-stream

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


# -- Request / Response Models ------------------------------------------------


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


class LLMTestRequest(BaseModel):
    provider: str = ""
    api_key: str = ""
    base_url: str = ""
    model: str = ""


class PentestRequest(BaseModel):
    scenario: str | None = None  # None = run all scenarios


class ProxyStartRequest(BaseModel):
    target_url: str
    port: int = 9090
    require_auth: bool = True


class TelemetrySettingsRequest(BaseModel):
    enabled: bool = True


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


class SuggestionAction(BaseModel):
    action: str = Field(..., pattern="^(approve|reject)$")


class SavePolicyBody(BaseModel):
    yaml: str = Field(..., min_length=1)
    path: str = Field(default="policy.auto.yaml")
