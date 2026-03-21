# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""LLM and telemetry settings endpoints."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException

from navil.api.local.state import AppState

from ._helpers import (
    LLMConfigRequest,
    LLMTestRequest,
    TelemetrySettingsRequest,
    _require_llm,
)

router = APIRouter()


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
    # Ollama doesn't require an API key -- use a placeholder
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
        # -- Test with the *unsaved* form values --
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
        # -- Fallback: test the saved config --
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
