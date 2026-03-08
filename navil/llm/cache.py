# Copyright (c) 2026 Pantheon Lab Limited
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""LRU cache for LLM responses — avoids redundant API calls.

Uses Redis when available (shared across processes), falls back to an
in-memory ``OrderedDict`` (single-process, still useful for dev/testing).

Cache key = SHA-256(system_prompt + "||" + user_message).
TTL defaults to 1 hour (3600 s).
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TTL = 3600  # 1 hour
DEFAULT_MAX_SIZE = 256  # in-memory LRU cap
REDIS_KEY_PREFIX = "navil:llm:cache:"


def cache_key(system_prompt: str, user_message: str) -> str:
    """Deterministic SHA-256 hash of the prompt pair."""
    raw = f"{system_prompt}||{user_message}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class LLMResponseCache:
    """Hybrid Redis / in-memory LRU cache for LLM completions.

    Parameters
    ----------
    redis_client:
        An async Redis client (``redis.asyncio.Redis``). When *None*,
        the cache operates in pure in-memory mode.
    max_size:
        Maximum entries kept in the in-memory LRU (ignored for Redis,
        which uses TTL-based expiry).
    ttl:
        Time-to-live in seconds for both Redis and in-memory entries.
    """

    def __init__(
        self,
        redis_client: Any = None,
        max_size: int = DEFAULT_MAX_SIZE,
        ttl: int = DEFAULT_TTL,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl
        self._max_size = max_size

        # In-memory fallback
        self._mem: OrderedDict[str, str] = OrderedDict()
        self._lock = threading.Lock()

        # Stats
        self.hits = 0
        self.misses = 0

    @property
    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
            "mem_size": len(self._mem),
            "backend": "redis" if self._redis else "memory",
        }

    # ── Sync API (used by non-streaming endpoints) ──────────

    def get_sync(self, key: str) -> str | None:
        """Retrieve a cached response (sync, in-memory only)."""
        with self._lock:
            val = self._mem.get(key)
            if val is not None:
                self._mem.move_to_end(key)
                self.hits += 1
                return val
        self.misses += 1
        return None

    def put_sync(self, key: str, value: str) -> None:
        """Store a response in the in-memory cache (sync)."""
        with self._lock:
            self._mem[key] = value
            self._mem.move_to_end(key)
            while len(self._mem) > self._max_size:
                self._mem.popitem(last=False)

    # ── Async API (uses Redis when available) ───────────────

    async def get(self, key: str) -> str | None:
        """Retrieve a cached response, trying Redis first."""
        if self._redis:
            try:
                val = await self._redis.get(f"{REDIS_KEY_PREFIX}{key}")
                if val is not None:
                    self.hits += 1
                    return val.decode("utf-8") if isinstance(val, bytes) else val
            except Exception:
                logger.debug("Redis cache get failed, falling back to memory")

        return self.get_sync(key)

    async def put(self, key: str, value: str) -> None:
        """Store a response in Redis (with TTL) and in-memory."""
        self.put_sync(key, value)

        if self._redis:
            try:
                await self._redis.set(
                    f"{REDIS_KEY_PREFIX}{key}", value, ex=self._ttl,
                )
            except Exception:
                logger.debug("Redis cache put failed")

    def clear(self) -> None:
        """Clear the in-memory cache (Redis entries expire via TTL)."""
        with self._lock:
            self._mem.clear()
        self.hits = 0
        self.misses = 0
