# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""MCP proxy status, traffic, and start endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from navil.api.local.state import AppState

from ._helpers import ProxyStartRequest

router = APIRouter()


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
