# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Fetches threat patterns from Navil Cloud and publishes to local Redis."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_FETCH_INTERVAL = 3600  # 1 hour
_DEFAULT_CLOUD_URL = "https://api.navil.ai"

THREAT_INTEL_CHANNEL = "navil:threat_intel:inbound"

# Fields allowed in pattern_data to prevent unexpected keys from leaking through
_PATTERN_FIELDS = frozenset({
    "pattern_id", "anomaly_type", "description", "features",
    "created_at", "match_count", "confidence_boost", "source",
})


class ThreatIntelFetcher:
    """Polls GET /v1/threat-intel/patterns and publishes to Redis pubsub.

    On proxy startup, fetches the full pattern catalog from Navil Cloud to
    seed the local PatternStore.  Then periodically re-fetches with an
    incremental cursor so the existing ThreatIntelConsumer picks up new
    community patterns automatically.
    """

    def __init__(
        self,
        redis_client: Any,
        api_key: str = "",
        cloud_url: str = "",
        fetch_interval: int | None = None,
    ) -> None:
        self.redis = redis_client
        self.api_key = api_key or os.environ.get("NAVIL_API_KEY", "")
        self.cloud_url = (
            cloud_url or os.environ.get("NAVIL_CLOUD_URL", _DEFAULT_CLOUD_URL)
        ).rstrip("/")
        self.fetch_interval = fetch_interval or int(
            os.environ.get("NAVIL_INTEL_FETCH_INTERVAL", str(_DEFAULT_FETCH_INTERVAL))
        )
        self._last_cursor: str | None = None
        self._running = False
        self._published_count = 0
        self._http_client: httpx.AsyncClient | None = None

    def is_enabled(self) -> bool:
        """Fetcher requires an API key to authenticate with the cloud."""
        return bool(self.api_key)

    def _get_client(self) -> httpx.AsyncClient:
        """Return a persistent httpx client (created once, reused across fetches)."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30,
            )
        return self._http_client

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self.is_enabled(),
            "published_count": self._published_count,
            "last_cursor": self._last_cursor,
        }

    async def run(self) -> None:
        """Main loop: fetch patterns periodically."""
        if not self.is_enabled():
            logger.info("ThreatIntelFetcher disabled: no NAVIL_API_KEY set")
            return

        self._running = True
        logger.info(
            "ThreatIntelFetcher started (interval=%ds, url=%s)",
            self.fetch_interval,
            self.cloud_url,
        )

        # Initial fetch on startup (seed the PatternStore)
        await self._fetch_and_publish()

        while self._running:
            try:
                await asyncio.sleep(self.fetch_interval)
            except asyncio.CancelledError:
                break
            if not self._running:
                break
            await self._fetch_and_publish()

    async def stop(self) -> None:
        """Signal the run loop to stop and close the HTTP client."""
        self._running = False
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _fetch_and_publish(self) -> int:
        """Fetch patterns from cloud and publish to Redis pubsub.

        Returns the number of patterns published.
        """
        try:
            url = f"{self.cloud_url}/v1/threat-intel/patterns"
            params: dict[str, str] = {"limit": "500"}
            if self._last_cursor:
                params["since"] = self._last_cursor

            client = self._get_client()
            resp = await client.get(url, params=params)

            if resp.status_code == 403:
                # Give-to-Get enforcement — log but don't crash
                detail = ""
                try:
                    detail = resp.json().get("detail", "")
                except Exception:
                    detail = resp.text[:200]
                logger.warning("Threat intel fetch blocked (Give-to-Get): %s", detail)
                return 0

            resp.raise_for_status()
            data = resp.json()

            patterns = data.get("patterns", [])
            if not patterns:
                logger.debug("No new patterns from cloud")
                return 0

            # Update cursor for incremental sync
            self._last_cursor = data.get("as_of")

            # Publish each pattern to Redis pubsub as a ThreatIntelEntry
            published = 0
            for pattern in patterns:
                entry = {
                    "source": "navil-cloud",
                    "entry_type": "pattern",
                    "agent_name_hash": None,
                    "tool_name": None,
                    "pattern_data": {
                        k: v for k, v in pattern.items() if k in _PATTERN_FIELDS
                    },
                }
                await self.redis.publish(
                    THREAT_INTEL_CHANNEL,
                    json.dumps(entry),
                )
                published += 1

            self._published_count += published
            logger.info(
                "Published %d threat patterns from cloud (cursor: %s)",
                published,
                self._last_cursor,
            )
            return published

        except Exception:
            logger.exception("Threat intel fetch failed")
            return 0
