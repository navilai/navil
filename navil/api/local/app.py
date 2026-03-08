# Copyright (c) 2026 Pantheon Lab Limited
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Navil local dashboard — FastAPI application."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from navil.api.local.demo import seed_demo_data
from navil.api.local.routes import router
from navil.api.local.state import AppState

logger = logging.getLogger(__name__)

DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent.parent / "dashboard" / "dist"

# ALLOWED_ORIGINS: comma-separated allowed origins.
# Defaults to "*" when unset (local dev).
_origins_env = os.environ.get("ALLOWED_ORIGINS", "")
_allow_origins: list[str] = (
    [o.strip() for o in _origins_env.split(",") if o.strip()] if _origins_env else ["*"]
)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:  # type: ignore[override]
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # HSTS only in production (when ALLOWED_ORIGINS is set)
        if _origins_env:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response


def create_app(with_demo: bool = True) -> FastAPI:
    """Create the FastAPI application."""

    worker_task: asyncio.Task[None] | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        nonlocal worker_task

        # Initialize persistent storage (creates tables if needed)
        try:
            from navil.cloud.database import init_db

            init_db()
        except Exception:
            logger.warning("Database initialization skipped (sqlalchemy not installed?)")

        state = AppState.get()
        if with_demo:
            seed_demo_data(state)
            logger.info("Demo data seeded: 5 agents, ~150 invocations, 5 credentials")

        # ── Redis + TelemetryWorker bootstrap ────────────────────
        redis_url = os.environ.get("NAVIL_REDIS_URL")
        worker = None
        threat_intel_task: asyncio.Task[None] | None = None
        consumer: ThreatIntelConsumer | None = None
        cloud_sync_worker: CloudSyncWorker | None = None
        cloud_sync_task: asyncio.Task[None] | None = None
        if redis_url:
            try:
                import redis.asyncio as aioredis

                from navil.telemetry_worker import TelemetryWorker

                state.redis_client = aioredis.from_url(redis_url)
                # Attach to anomaly detector so it can sync thresholds
                state.anomaly_detector.redis = state.redis_client

                worker = TelemetryWorker(
                    redis_client=state.redis_client,
                    detector=state.anomaly_detector,
                )
                worker_task = asyncio.create_task(worker.run())
                logger.info("Redis connected, TelemetryWorker started (%s)", redis_url)

                # ── ThreatIntelConsumer ───────────────────────────
                from navil.threat_intel import ThreatIntelConsumer

                consumer = ThreatIntelConsumer(
                    redis_client=state.redis_client,
                    pattern_store=state.anomaly_detector.pattern_store,
                )
                if consumer.is_enabled():
                    threat_intel_task = asyncio.create_task(consumer.run())

                # ── CloudSyncWorker (Give-to-Get outbound) ──────
                from navil.cloud.telemetry_sync import CloudSyncWorker

                cloud_sync_worker = CloudSyncWorker(
                    detector=state.anomaly_detector,
                    api_key=os.environ.get("NAVIL_API_KEY", ""),
                    deployment_secret=(
                        os.environ.get("NAVIL_DEPLOYMENT_SECRET", "").encode()
                        or None
                    ),
                )
                if cloud_sync_worker.enabled:
                    cloud_sync_task = asyncio.create_task(
                        cloud_sync_worker.run()
                    )
                    logger.info(
                        "CloudSyncWorker started (mode=%s, interval=%ss)",
                        "paid" if cloud_sync_worker.api_key else "community",
                        cloud_sync_worker.sync_interval,
                    )
            except Exception:
                logger.warning(
                    "Redis unavailable (%s) — running in standalone mode",
                    redis_url,
                )
                state.redis_client = None

        yield

        # ── Shutdown: stop workers, close Redis ──────────────────
        if consumer is not None:
            consumer.stop()
        if threat_intel_task is not None:
            threat_intel_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await threat_intel_task
        if cloud_sync_worker is not None:
            cloud_sync_worker.stop()
        if cloud_sync_task is not None:
            cloud_sync_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cloud_sync_task
        if cloud_sync_worker is not None:
            with contextlib.suppress(Exception):
                await cloud_sync_worker.close()
        if worker is not None:
            worker.stop()
        if worker_task is not None:
            worker_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker_task
        if state.redis_client is not None:
            with contextlib.suppress(Exception):
                await state.redis_client.aclose()
            state.redis_client = None

    app = FastAPI(
        title="Navil",
        description="Security dashboard for AI agent fleet monitoring",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Security headers (outermost → runs first)
    app.add_middleware(SecurityHeadersMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)

    # Serve frontend static files if built
    if DASHBOARD_DIR.exists():
        app.mount("/assets", StaticFiles(directory=str(DASHBOARD_DIR / "assets")), name="assets")

        @app.get("/{path:path}")
        def serve_frontend(path: str) -> FileResponse:
            """Serve the React SPA — all non-API routes go to index.html."""
            file_path = DASHBOARD_DIR / path
            if file_path.exists() and file_path.is_file():
                return FileResponse(str(file_path))
            # Never cache index.html so new builds are picked up immediately
            return FileResponse(
                str(DASHBOARD_DIR / "index.html"),
                headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
            )
    else:

        @app.get("/")
        def no_frontend() -> dict[str, str]:
            return {
                "message": "Navil API is running. Frontend not built yet.",
                "hint": "Run: cd dashboard && npm install && npm run build",
            }

    return app


def serve(host: str = "0.0.0.0", port: int = 8484) -> None:
    """Launch the Navil server."""
    import uvicorn

    app = create_app()
    logger.info(f"Starting Navil at http://localhost:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
