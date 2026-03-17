"""Blocklist Auto-Updater — fetch, merge, and push updated threat signatures.

Fetches the latest blocklist from the Navil Cloud backend, merges with
the local blocklist, and pushes the merged result to Redis.

Tier-based update policy:
    - community:   48-hour delayed updates
    - pro/team/enterprise: real-time updates

Can be invoked as a background task or via CLI:
    navil blocklist update
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

# Cloud endpoint for threat intel blocklist
_DEFAULT_ENDPOINT = "https://api.navil.ai/v1/threat-intel"

# Tier delay: community gets 48-hour delayed updates
_COMMUNITY_DELAY_S = 48 * 3600  # 48 hours in seconds

# Real-time tiers
_REALTIME_TIERS = {"pro", "team", "enterprise"}


def _get_tier() -> str:
    """Determine the deployment tier from environment / API key.

    Returns 'community' if no API key is set, otherwise checks for tier
    in the NAVIL_TIER env var or defaults to 'pro'.
    """
    api_key = os.environ.get("NAVIL_API_KEY", "").strip()
    if not api_key:
        return "community"
    return os.environ.get("NAVIL_TIER", "pro").lower()


class BlocklistUpdater:
    """Fetches and merges blocklist updates from the cloud backend.

    Usage::

        updater = BlocklistUpdater(blocklist_manager=mgr)
        result = await updater.fetch_and_merge()
    """

    def __init__(
        self,
        blocklist_manager: Any,
        endpoint: str = _DEFAULT_ENDPOINT,
        api_key: str = "",
    ) -> None:
        from navil.blocklist import BlocklistManager

        self.manager: BlocklistManager = blocklist_manager
        self.endpoint = endpoint
        self.api_key = api_key or os.environ.get("NAVIL_API_KEY", "")
        self.tier = _get_tier()
        self._last_fetch: float = 0.0
        self._http_client: Any = None

    def _get_client(self) -> Any:
        if self._http_client is None:
            import httpx

            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._http_client = httpx.AsyncClient(headers=headers, timeout=30.0)
        return self._http_client

    def _should_delay(self) -> bool:
        """Check if the community tier delay applies."""
        if self.tier in _REALTIME_TIERS:
            return False
        # Community: enforce 48h delay
        elapsed = time.time() - self._last_fetch
        return elapsed < _COMMUNITY_DELAY_S

    async def fetch_and_merge(self) -> dict[str, Any]:
        """Fetch latest blocklist from cloud, merge, and push to Redis.

        Returns:
            Summary dict with keys: fetched, merged, new_version, tier.
        """
        from navil.blocklist import BlocklistEntry

        result: dict[str, Any] = {
            "fetched": 0,
            "merged": 0,
            "new_version": self.manager.version,
            "tier": self.tier,
            "delayed": False,
        }

        # Check tier-based delay
        if self._should_delay():
            result["delayed"] = True
            logger.info(
                "Community tier: blocklist update delayed (48h policy). "
                "Upgrade to pro/team/enterprise for real-time updates."
            )
            return result

        try:
            client = self._get_client()
            params: dict[str, Any] = {"current_version": self.manager.version}
            if self.tier != "community":
                params["tier"] = self.tier

            resp = await client.get(self.endpoint, params=params)

            if resp.status_code == 304:
                # No updates available
                logger.info("Blocklist is up to date (v%d)", self.manager.version)
                return result

            if resp.status_code >= 400:
                logger.warning("Blocklist fetch failed: HTTP %d", resp.status_code)
                return result

            data = resp.json()
            patterns = data.get("patterns", [])
            result["fetched"] = len(patterns)

            if not patterns:
                return result

            # Convert to BlocklistEntry objects
            entries = []
            for p in patterns:
                try:
                    entries.append(BlocklistEntry.from_dict(p))
                except (KeyError, TypeError):
                    continue

            # Merge with local blocklist
            merged = self.manager.merge(entries)
            result["merged"] = merged

            # Push to Redis
            if merged > 0:
                self.manager.save_to_redis()
                result["new_version"] = self.manager.version

            self._last_fetch = time.time()
            logger.info(
                "Blocklist updated: fetched=%d, merged=%d, version=%d",
                result["fetched"],
                result["merged"],
                result["new_version"],
            )

        except ImportError:
            logger.warning("httpx not installed, cannot fetch remote blocklist")
        except Exception:
            logger.error("Blocklist fetch failed", exc_info=True)

        return result

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


def update_blocklist_sync(
    redis_client: Any | None = None,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Synchronous blocklist update — loads from file and pushes to Redis.

    Used by the CLI command when async is not available.

    Args:
        redis_client: Optional Redis client for persistence.
        file_path: Path to blocklist JSON file to load.

    Returns:
        Summary dict.
    """
    from navil.blocklist import BlocklistManager

    mgr = BlocklistManager(redis_client=redis_client)

    loaded = 0
    if redis_client is not None:
        loaded = mgr.load_from_redis()

    if file_path:
        loaded += mgr.load_from_file(file_path)
    elif loaded == 0:
        loaded = mgr.load_from_file()

    saved = False
    if redis_client is not None:
        saved = mgr.save_to_redis()

    return {
        "loaded": loaded,
        "version": mgr.version,
        "saved_to_redis": saved,
        "pattern_count": mgr.pattern_count,
    }
