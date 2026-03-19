# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Blocklist Distribution — tier-aware threat signature distribution.

Distributes threat intelligence blocklist patterns to deployments based
on their subscription tier.  Community tier receives updates with a 48-hour
delay; Pro/Team/Enterprise tiers receive real-time updates.

Tier is determined from the API key metadata returned by the cloud backend
(not from a local env var, unlike the simpler BlocklistUpdater).

Rate limiting is enforced per-tier to protect the cloud API:
  - community:   1 request per 48 hours
  - pro:         1 request per 5 minutes
  - team:        1 request per 1 minute
  - enterprise:  1 request per 30 seconds

Usage::

    from navil.cloud.blocklist_distribution import BlocklistDistributor

    dist = BlocklistDistributor(blocklist_manager=mgr, api_key="navil_...")
    result = await dist.pull_updates()
    # result = {"fetched": 12, "merged": 5, "tier": "pro", ...}
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

# Cloud endpoint
_DEFAULT_ENDPOINT = "https://api.navil.ai/v1/threat-intel/blocklist"

# Tier delay policies (seconds between allowed fetches)
_TIER_RATE_LIMITS: dict[str, float] = {
    "community": 48 * 3600,  # 48 hours
    "pro": 5 * 60,  # 5 minutes
    "team": 60,  # 1 minute
    "enterprise": 30,  # 30 seconds
}

# Community-tier content delay (patterns older than this threshold)
_COMMUNITY_CONTENT_DELAY_H = 48

# Tiers that receive real-time (undelayed) content
_REALTIME_TIERS = frozenset({"pro", "team", "enterprise"})


class BlocklistDistributor:
    """Tier-aware blocklist distribution client.

    Pulls blocklist updates from Navil Cloud with tier-based access
    controls.  The tier is resolved from the API key metadata returned
    by the ``/v1/auth/whoami`` endpoint on first call, then cached.

    Args:
        blocklist_manager: A BlocklistManager instance for merging.
        api_key: Navil API key.
        endpoint: Cloud blocklist endpoint URL.
    """

    def __init__(
        self,
        blocklist_manager: Any,
        api_key: str = "",
        endpoint: str = _DEFAULT_ENDPOINT,
    ) -> None:
        from navil.blocklist import BlocklistManager

        self.manager: BlocklistManager = blocklist_manager
        self.api_key = api_key or os.environ.get("NAVIL_API_KEY", "")
        self.endpoint = endpoint
        self._tier: str | None = None  # resolved lazily from API key metadata
        self._last_fetch_time: float = 0.0
        self._fetch_count: int = 0
        self._http_client: Any = None

    # ── HTTP Client ─────────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazy-initialize the httpx async client."""
        if self._http_client is None:
            import httpx

            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._http_client = httpx.AsyncClient(headers=headers, timeout=30.0)
        return self._http_client

    # ── Tier Resolution ─────────────────────────────────────────

    @property
    def tier(self) -> str:
        """Return the resolved tier (may be 'unknown' if not yet resolved)."""
        return self._tier or "unknown"

    async def resolve_tier(self) -> str:
        """Resolve the subscription tier from API key metadata.

        Calls ``GET /v1/auth/whoami`` to retrieve the tier associated
        with the current API key.  Falls back to ``"community"`` if
        no API key is set or the endpoint is unreachable.

        The resolved tier is cached for the lifetime of this instance.

        Returns:
            Tier string: "community", "pro", "team", or "enterprise".
        """
        if self._tier is not None:
            return self._tier

        # No API key means community tier
        if not self.api_key:
            self._tier = "community"
            return self._tier

        # Check env override first (useful for testing)
        env_tier = os.environ.get("NAVIL_TIER", "").lower().strip()
        if env_tier in _TIER_RATE_LIMITS:
            self._tier = env_tier
            logger.info("Tier resolved from NAVIL_TIER env var: %s", self._tier)
            return self._tier

        # Resolve from API key metadata
        try:
            client = self._get_client()
            base_url = self.endpoint.rsplit("/v1/", 1)[0]
            resp = await client.get(f"{base_url}/v1/auth/whoami")

            if resp.status_code == 200:
                data = resp.json()
                self._tier = data.get("tier", "community").lower()
                logger.info("Tier resolved from API key metadata: %s", self._tier)
            else:
                logger.warning(
                    "Could not resolve tier from API key (HTTP %d), defaulting to community",
                    resp.status_code,
                )
                self._tier = "community"

        except Exception:
            logger.debug("Tier resolution failed, defaulting to community")
            self._tier = "community"

        return self._tier

    # ── Rate Limiting ───────────────────────────────────────────

    def _get_rate_limit(self) -> float:
        """Get the rate limit interval in seconds for the current tier."""
        return _TIER_RATE_LIMITS.get(self._tier or "community", _TIER_RATE_LIMITS["community"])

    def _is_rate_limited(self) -> bool:
        """Check if we should throttle the next request."""
        if self._last_fetch_time == 0.0:
            return False  # first request is always allowed
        elapsed = time.time() - self._last_fetch_time
        return elapsed < self._get_rate_limit()

    def time_until_next_fetch(self) -> float:
        """Return seconds until the next fetch is allowed.

        Returns 0.0 if a fetch is allowed now.
        """
        if self._last_fetch_time == 0.0:
            return 0.0
        remaining = self._get_rate_limit() - (time.time() - self._last_fetch_time)
        return max(0.0, remaining)

    # ── Pull Updates ────────────────────────────────────────────

    async def pull_updates(self) -> dict[str, Any]:
        """Pull blocklist updates from the cloud.

        Resolves tier from API key metadata, enforces rate limits and
        content delay, fetches new patterns, merges with local blocklist,
        and pushes to Redis.

        Returns:
            Summary dict:
                fetched:        Number of patterns received from cloud.
                merged:         Number of new/updated patterns applied.
                new_version:    Blocklist version after merge.
                tier:           Resolved subscription tier.
                rate_limited:   True if request was throttled.
                delayed:        True if community delay was applied.
        """
        from navil.blocklist import BlocklistEntry

        # 1. Resolve tier
        tier = await self.resolve_tier()

        result: dict[str, Any] = {
            "fetched": 0,
            "merged": 0,
            "new_version": self.manager.version,
            "tier": tier,
            "rate_limited": False,
            "delayed": False,
        }

        # 2. Check rate limit
        if self._is_rate_limited():
            result["rate_limited"] = True
            remaining = self.time_until_next_fetch()
            logger.info(
                "Rate limited (%s tier): next fetch in %.0fs",
                tier,
                remaining,
            )
            return result

        # 3. Build request params
        params: dict[str, Any] = {
            "current_version": self.manager.version,
            "tier": tier,
        }

        # Community tier gets delayed content
        if tier not in _REALTIME_TIERS:
            params["delay_hours"] = _COMMUNITY_CONTENT_DELAY_H
            result["delayed"] = True

        # 4. Fetch from cloud
        try:
            client = self._get_client()
            resp = await client.get(self.endpoint, params=params)

            if resp.status_code == 304:
                logger.info("Blocklist is up to date (v%d)", self.manager.version)
                self._last_fetch_time = time.time()
                self._fetch_count += 1
                return result

            if resp.status_code == 429:
                # Server-side rate limiting
                retry_after = int(resp.headers.get("Retry-After", "60"))
                logger.warning("Server rate limited, retry after %ds", retry_after)
                result["rate_limited"] = True
                return result

            if resp.status_code >= 400:
                logger.warning("Blocklist fetch failed: HTTP %d", resp.status_code)
                return result

            data = resp.json()
            patterns = data.get("patterns", [])
            result["fetched"] = len(patterns)

            if not patterns:
                self._last_fetch_time = time.time()
                self._fetch_count += 1
                return result

            # 5. Convert to BlocklistEntry objects
            entries = []
            for p in patterns:
                try:
                    entries.append(BlocklistEntry.from_dict(p))
                except (KeyError, TypeError):
                    continue

            # 6. Merge with local blocklist
            merged = self.manager.merge(entries)
            result["merged"] = merged

            # 7. Push to Redis if there were changes
            if merged > 0 and self.manager.redis is not None:
                self.manager.save_to_redis()
                result["new_version"] = self.manager.version

            self._last_fetch_time = time.time()
            self._fetch_count += 1

            logger.info(
                "Blocklist distribution: fetched=%d, merged=%d, version=%d, tier=%s",
                result["fetched"],
                result["merged"],
                result["new_version"],
                tier,
            )

        except ImportError:
            logger.warning("httpx not installed, cannot fetch blocklist")
        except Exception:
            logger.error("Blocklist distribution fetch failed", exc_info=True)

        return result

    # ── Status ──────────────────────────────────────────────────

    @property
    def stats(self) -> dict[str, Any]:
        """Return distributor statistics."""
        return {
            "tier": self._tier or "unresolved",
            "fetch_count": self._fetch_count,
            "last_fetch_time": self._last_fetch_time,
            "rate_limit_seconds": self._get_rate_limit(),
            "time_until_next_fetch": self.time_until_next_fetch(),
            "blocklist_version": self.manager.version,
            "blocklist_pattern_count": self.manager.pattern_count,
        }

    # ── Cleanup ─────────────────────────────────────────────────

    async def close(self) -> None:
        """Clean up the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
