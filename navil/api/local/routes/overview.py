# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Overview, agents, alerts, and invocations endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from navil.api.local.state import AppState

from ._helpers import InvocationRequest

router = APIRouter()


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


@router.get("/alerts")
def list_alerts(severity: str | None = None, agent: str | None = None) -> list[dict[str, Any]]:
    s = AppState.get()
    alerts = s.anomaly_detector.get_alerts(agent_name=agent, severity=severity)
    return alerts[::-1]


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
