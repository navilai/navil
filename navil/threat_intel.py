"""Community threat intelligence consumer.

Receives inbound threat intel from Navil Cloud or community sources
and applies it to the local detection system via two landing zones:

1. **Redis thresholds** — blocklist entries set ``blocked=1`` on agent
   threshold hashes, causing the Rust proxy to block in O(1).
2. **PatternStore** — attack patterns are added to the local pattern
   store for confidence boosting during anomaly detection.

Respects the ``NAVIL_DISABLE_CLOUD_SYNC`` opt-out flag.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import orjson

logger = logging.getLogger(__name__)

THREAT_INTEL_CHANNEL = "navil:threat_intel:inbound"


@dataclass
class ThreatIntelEntry:
    """A single inbound threat intelligence entry."""
    source: str  # "community", "navil-cloud", "manual"
    entry_type: str  # "blocklist" or "pattern"
    # For blocklist entries:
    agent_name_hash: str | None = None
    tool_name: str | None = None
    # For pattern entries (dict that can construct a LearnedPattern):
    pattern_data: dict[str, Any] = field(default_factory=dict)


class ThreatIntelConsumer:
    """Receives community threat intel and applies to local system.

    Two landing zones:
    - Blocklist -> HSET navil:agent:{hash}:thresholds blocked=1 (Rust blocks in O(1))
    - Pattern -> PatternStore.add_community_pattern() (detector confidence boost)
    """

    def __init__(
        self,
        redis_client: Any,
        pattern_store: Any,
    ) -> None:
        self.redis = redis_client
        self.pattern_store = pattern_store
        self._running = False
        self._processed = 0
        self._errors = 0

    @property
    def stats(self) -> dict[str, int]:
        return {"processed": self._processed, "errors": self._errors}

    @staticmethod
    def is_enabled() -> bool:
        """Check if cloud sync / threat intel is enabled."""
        return os.environ.get("NAVIL_DISABLE_CLOUD_SYNC", "").lower() not in (
            "1", "true", "yes",
        )

    async def run(self) -> None:
        """Run the consumer loop. Subscribes to THREAT_INTEL_CHANNEL via Redis pub/sub."""
        if not self.is_enabled():
            logger.info("Cloud sync disabled, ThreatIntelConsumer not starting")
            return

        self._running = True
        logger.info("ThreatIntelConsumer started — listening on %s", THREAT_INTEL_CHANNEL)

        try:
            pubsub = self.redis.pubsub()
            await pubsub.subscribe(THREAT_INTEL_CHANNEL)

            while self._running:
                try:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=5.0,
                    )
                    if message and message.get("type") == "message":
                        data = message.get("data", b"")
                        try:
                            entry_dict = orjson.loads(data)
                            entry = ThreatIntelEntry(**entry_dict)
                            await self.apply_entry(entry)
                            self._processed += 1
                        except Exception:
                            logger.warning("Invalid threat intel entry, skipping")
                            self._errors += 1
                except asyncio.CancelledError:
                    break
                except Exception:
                    self._errors += 1
                    logger.exception("ThreatIntelConsumer error")
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("ThreatIntelConsumer failed to start pub/sub")
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False

    async def apply_entry(self, entry: ThreatIntelEntry) -> None:
        """Apply a single threat intel entry to the local system."""
        if entry.entry_type == "blocklist" and entry.agent_name_hash:
            key = f"navil:agent:{entry.agent_name_hash}:thresholds"
            await self.redis.hset(key, mapping={"blocked": "1"})
            logger.info(
                "Blocklist applied: agent_hash=%s source=%s",
                entry.agent_name_hash[:12], entry.source,
            )
        elif entry.entry_type == "pattern" and entry.pattern_data:
            if self.pattern_store is None:
                logger.warning("PatternStore not configured, skipping pattern entry")
                return
            from navil.adaptive.pattern_store import LearnedPattern
            try:
                pattern = LearnedPattern(**entry.pattern_data)
                self.pattern_store.add_community_pattern(pattern)
                logger.info(
                    "Community pattern applied: %s source=%s",
                    pattern.pattern_id, entry.source,
                )
            except Exception:
                logger.warning("Invalid pattern data in threat intel entry")
                self._errors += 1
