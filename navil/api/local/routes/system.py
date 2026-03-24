# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Machine identity and health check endpoints."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter

from navil.api.local.state import AppState

router = APIRouter()

# Track server start time for uptime calculation
_SERVER_START_TIME = time.monotonic()
_SERVER_START_ISO = datetime.now(timezone.utc).isoformat()


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


@router.get("/health/dashboard")
def health_dashboard() -> dict[str, Any]:
    """Comprehensive health dashboard data for the self-healing page.

    Aggregates data from all subsystems: proxy, anomaly detector,
    pattern store, policy engine, and cloud sync.
    """
    s = AppState.get()

    # --- Uptime & system info ---
    uptime_seconds = int(time.monotonic() - _SERVER_START_TIME)

    # --- Proxy status ---
    proxy_running = s.proxy_running and s.proxy is not None
    proxy_stats = {"total_requests": 0, "blocked": 0, "alerts_generated": 0, "forwarded": 0}
    proxy_uptime = 0
    if proxy_running:
        try:
            status = s.proxy.get_status()
            proxy_stats = status.get("stats", proxy_stats)
            proxy_uptime = status.get("uptime_seconds", 0)
        except Exception:
            pass

    # --- Anomaly detector stats ---
    total_invocations = len(s.anomaly_detector.invocations)
    total_alerts = len(s.anomaly_detector.get_alerts())
    critical_alerts = len(s.anomaly_detector.get_alerts(severity="CRITICAL"))
    high_alerts = len(s.anomaly_detector.get_alerts(severity="HIGH"))
    total_agents = len(s.anomaly_detector.adaptive_baselines)

    # --- Pattern store stats ---
    patterns_count = len(s.pattern_store.patterns)
    patterns_by_source: dict[str, int] = {}
    for p in s.pattern_store.patterns:
        src = getattr(p, "source", "local")
        patterns_by_source[src] = patterns_by_source.get(src, 0) + 1

    # --- Policy engine stats ---
    policy_loaded = s.policy_engine is not None
    policy_decisions = []
    try:
        decisions = s.policy_engine.get_decisions_log()
        policy_decisions = decisions[-20:][::-1]  # last 20, newest first
    except Exception:
        pass
    total_policy_decisions = len(policy_decisions)
    denied_decisions = len([d for d in policy_decisions if d.get("decision") == "DENY"])

    # --- Cloud sync status ---
    cloud_sync_enabled = os.environ.get("NAVIL_DISABLE_CLOUD_SYNC", "").lower() not in (
        "1",
        "true",
        "yes",
    )
    # Check env var first, then ~/.navil/config.yaml
    api_key = os.environ.get("NAVIL_API_KEY", "").strip()
    if not api_key:
        try:
            import yaml

            cfg_path = Path.home() / ".navil" / "config.yaml"
            if cfg_path.exists():
                cfg = yaml.safe_load(cfg_path.read_text()) or {}
                api_key = (cfg.get("cloud", {}).get("api_key") or "").strip()
        except Exception:
            pass
    api_key_present = bool(api_key)

    # --- LLM status ---
    llm_available = s.llm_available
    llm_configured = s.llm_api_key_configured

    # --- Build recent heals log from alerts + policy decisions ---
    recent_heals: list[dict[str, Any]] = []

    # Add blocked requests from proxy
    if proxy_running and proxy_stats.get("blocked", 0) > 0:
        recent_heals.append(
            {
                "event": "Blocked malicious requests via proxy",
                "detail": f"{proxy_stats['blocked']} request(s) blocked",
                "category": "proxy",
                "severity": "medium",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    # Add pattern-based detections
    for pattern in s.pattern_store.patterns[-5:][::-1]:
        if getattr(pattern, "match_count", 0) > 0:
            recent_heals.append(
                {
                    "event": f"Pattern matched: {pattern.description[:80]}",
                    "detail": f"Matched {pattern.match_count} time(s)",
                    "category": "pattern",
                    "severity": "low",
                    "timestamp": getattr(pattern, "created_at", ""),
                }
            )

    # Add recent DENY decisions as auto-heals
    for decision in policy_decisions[:5]:
        if decision.get("decision") == "DENY":
            recent_heals.append(
                {
                    "event": (
                        f"Blocked {decision.get('tool', 'unknown')} "
                        f"access for {decision.get('agent', 'unknown')}"
                    ),
                    "detail": decision.get("reason", "Policy violation"),
                    "category": "policy",
                    "severity": decision.get("severity", "medium").lower(),
                    "timestamp": decision.get("timestamp", ""),
                }
            )

    # Add critical/high alerts as events
    all_alerts = s.anomaly_detector.get_alerts()
    for alert in all_alerts[-5:][::-1]:
        sev = alert.get("severity", "LOW")
        if sev in ("CRITICAL", "HIGH"):
            recent_heals.append(
                {
                    "event": f"Anomaly detected: {alert.get('anomaly_type', 'unknown')}",
                    "detail": alert.get("description", ""),
                    "category": "anomaly",
                    "severity": sev.lower(),
                    "timestamp": alert.get("timestamp", ""),
                }
            )

    # Sort by timestamp descending and limit
    recent_heals.sort(key=lambda h: h.get("timestamp", ""), reverse=True)
    recent_heals = recent_heals[:10]

    # --- Subsystem health checks ---
    subsystems: list[dict[str, str]] = []

    # Proxy
    subsystems.append(
        {
            "name": "MCP Proxy",
            "status": "running" if proxy_running else "stopped",
            "detail": f"{proxy_stats.get('total_requests', 0)} requests processed"
            if proxy_running
            else "Not started",
        }
    )

    # Cloud sync
    if cloud_sync_enabled:
        subsystems.append(
            {
                "name": "Cloud Sync",
                "status": "connected" if api_key_present else "community",
                "detail": "Paid mode" if api_key_present else "Community threat feed",
            }
        )
    else:
        subsystems.append(
            {
                "name": "Cloud Sync",
                "status": "disconnected",
                "detail": "Disabled",
            }
        )

    # Pattern store / blocklist
    subsystems.append(
        {
            "name": "Pattern Store",
            "status": "loaded" if patterns_count > 0 else "empty",
            "detail": f"{patterns_count} learned pattern(s)",
        }
    )

    # Policy engine
    subsystems.append(
        {
            "name": "Policy Engine",
            "status": "loaded" if policy_loaded else "error",
            "detail": f"{total_policy_decisions} recent decisions",
        }
    )

    # Anomaly detector
    subsystems.append(
        {
            "name": "Anomaly Detector",
            "status": "active" if total_agents > 0 else "idle",
            "detail": f"Monitoring {total_agents} agent(s)",
        }
    )

    # LLM
    if llm_available:
        subsystems.append(
            {
                "name": "LLM Engine",
                "status": "ready" if llm_configured else "no_key",
                "detail": f"{s.llm_provider}/{s.llm_model}"
                if llm_configured
                else "API key not set",
            }
        )
    else:
        subsystems.append(
            {
                "name": "LLM Engine",
                "status": "not_installed",
                "detail": "Install with: pip install navil[llm]",
            }
        )

    return {
        "server_uptime_seconds": uptime_seconds,
        "server_started_at": _SERVER_START_ISO,
        "proxy": {
            "running": proxy_running,
            "uptime_seconds": proxy_uptime,
            "stats": proxy_stats,
        },
        "detection": {
            "total_invocations": total_invocations,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "total_agents": total_agents,
            "patterns_learned": patterns_count,
            "patterns_by_source": patterns_by_source,
        },
        "policy": {
            "loaded": policy_loaded,
            "recent_decisions": total_policy_decisions,
            "denied": denied_decisions,
        },
        "cloud_sync": {
            "enabled": cloud_sync_enabled,
            "api_key_present": api_key_present,
        },
        "subsystems": subsystems,
        "recent_heals": recent_heals,
    }
