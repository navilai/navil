# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Feedback submission and stats endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from navil.api.local.state import AppState

from ._helpers import FeedbackRequest

router = APIRouter()


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
