# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Machine identity and health check endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.get("/machine")
def get_machine_info() -> dict[str, Any]:
    """Return machine identity (machine_id and label) from local config."""
    from navil.commands.init import get_machine_id, get_machine_label

    return {
        "machine_id": get_machine_id() or "",
        "machine_label": get_machine_label() or "",
    }


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
