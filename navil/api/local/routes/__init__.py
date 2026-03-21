# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Local API routes package — combines domain-specific route modules."""

from __future__ import annotations

from fastapi import APIRouter

from .credentials import router as credentials_router
from .feedback import router as feedback_router
from .llm import router as llm_router
from .overview import router as overview_router
from .policy import router as policy_router
from .proxy import router as proxy_router
from .scan import router as scan_router
from .settings import router as settings_router
from .system import router as system_router

router = APIRouter(prefix="/api/local")

router.include_router(overview_router)
router.include_router(credentials_router)
router.include_router(policy_router)
router.include_router(llm_router)
router.include_router(settings_router)
router.include_router(proxy_router)
router.include_router(scan_router)
router.include_router(feedback_router)
router.include_router(system_router)

# Re-export models, helpers, and internal functions so that existing
# ``from navil.api.local.routes import …`` imports keep working.
from ._helpers import (  # noqa: E402, F401 – public re-exports
    AnalyzeConfigRequest,
    ApplyActionRequest,
    AutoRemediateRequest,
    CredentialDelegateRequest,
    CredentialExchangeRequest,
    CredentialIssueRequest,
    ExplainAnomalyRequest,
    FeedbackRequest,
    GeneratePolicyRequest,
    InvocationRequest,
    LLMConfigRequest,
    LLMTestRequest,
    PentestRequest,
    PolicyCheckRequest,
    PolicySuggestion,
    ProxyStartRequest,
    RefinePolicyRequest,
    SavePolicyBody,
    ScanRequest,
    SuggestionAction,
    TelemetrySettingsRequest,
    _call_llm,
    _get_llm_cache,
    _make_sse_response,
    _require_dashboard_auth,
    _require_llm,
    _sse_event,
    _stream_llm_sse,
)

__all__ = ["router"]
