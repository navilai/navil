"""Shared test fixtures for the Navil (MCP Guardian) test suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

# ── Fake Redis for unit tests (no real server needed) ─────────


class FakeRedis:
    """Minimal async Redis mock that stores data in a plain dict.

    Supports the subset of commands used by BehavioralAnomalyDetector:
    hset, hmget, incr, expire, get, set, delete, pipeline.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._expiry: dict[str, float] = {}  # not enforced, just tracked

    # ── Hash commands ──────────────────────────────────────────

    async def hset(self, name: str, mapping: dict[str, Any] | None = None, **kwargs: Any) -> int:
        if name not in self._data or not isinstance(self._data[name], dict):
            self._data[name] = {}
        fields = mapping or {}
        fields.update(kwargs)
        for k, v in fields.items():
            self._data[name][str(k)] = str(v).encode()
        return len(fields)

    async def hmget(self, name: str, keys: list[str], *args: str) -> list[bytes | None]:
        h = self._data.get(name, {})
        if not isinstance(h, dict):
            return [None] * len(keys)
        return [h.get(k) for k in keys]

    # ── String commands ────────────────────────────────────────

    async def incr(self, name: str) -> int:
        val = int(self._data.get(name, b"0"))
        val += 1
        self._data[name] = str(val).encode()
        return val

    async def get(self, name: str) -> bytes | None:
        v = self._data.get(name)
        return v if isinstance(v, bytes) else None

    async def set(self, name: str, value: Any, **kwargs: Any) -> bool:
        self._data[name] = str(value).encode()
        return True

    async def delete(self, *names: str) -> int:
        count = 0
        for n in names:
            if n in self._data:
                del self._data[n]
                count += 1
        return count

    async def expire(self, name: str, time: int) -> bool:
        self._expiry[name] = float(time)
        return True

    # ── List commands ─────────────────────────────────────────

    async def lpush(self, name: str, *values: Any) -> int:
        if name not in self._data or not isinstance(self._data[name], list):
            self._data[name] = []
        for v in values:
            if isinstance(v, str):
                val = v.encode()
            elif isinstance(v, bytes):
                val = v
            else:
                val = str(v).encode()
            self._data[name].insert(0, val)
        return len(self._data[name])

    async def llen(self, name: str) -> int:
        lst = self._data.get(name, [])
        return len(lst) if isinstance(lst, list) else 0

    async def ltrim(self, name: str, start: int, stop: int) -> bool:
        lst = self._data.get(name, [])
        if isinstance(lst, list):
            if stop == -1:
                self._data[name] = lst[start:]
            else:
                self._data[name] = lst[start : stop + 1]
        return True

    async def brpop(self, keys: str | list[str], timeout: int = 0) -> tuple[bytes, bytes] | None:
        """Pop from the right of the first non-empty list.

        Unlike real Redis BRPOP this doesn't block — it returns immediately
        if nothing is available (sufficient for unit tests).
        """
        if isinstance(keys, str):
            keys = [keys]
        for key in keys:
            lst = self._data.get(key)
            if isinstance(lst, list) and lst:
                val = lst.pop()  # right-pop
                return (key.encode(), val)
        return None

    # ── Pipeline (batches commands, returns list of results) ───

    def pipeline(self) -> FakeRedisPipeline:
        return FakeRedisPipeline(self)


class FakeRedisPipeline:
    """Batch-execute wrapper around FakeRedis."""

    def __init__(self, redis: FakeRedis) -> None:
        self._redis = redis
        self._commands: list[tuple[str, tuple, dict]] = []

    def hset(
        self,
        name: str,
        mapping: dict[str, Any] | None = None,
        **kw: Any,
    ) -> FakeRedisPipeline:
        self._commands.append(("hset", (name,), {"mapping": mapping, **kw}))
        return self

    def hmget(self, name: str, keys: list[str]) -> FakeRedisPipeline:
        self._commands.append(("hmget", (name, keys), {}))
        return self

    def incr(self, name: str) -> FakeRedisPipeline:
        self._commands.append(("incr", (name,), {}))
        return self

    def expire(self, name: str, time: int) -> FakeRedisPipeline:
        self._commands.append(("expire", (name, time), {}))
        return self

    async def execute(self) -> list[Any]:
        results: list[Any] = []
        for cmd, args, kwargs in self._commands:
            fn = getattr(self._redis, cmd)
            results.append(await fn(*args, **kwargs))
        self._commands.clear()
        return results

    async def __aenter__(self) -> FakeRedisPipeline:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        pass


@pytest.fixture
def fake_redis() -> FakeRedis:
    """Provide a FakeRedis instance for tests that need Redis."""
    return FakeRedis()


@pytest.fixture
def sample_secure_config() -> dict[str, Any]:
    """A secure MCP server configuration with no vulnerabilities."""
    return {
        "server": {"name": "Secure Server", "protocol": "https", "verified": True},
        "authentication": {"type": "mTLS", "key_rotation": True},
        "tools": [
            {
                "name": "safe_tool",
                "permissions": ["read"],
                "restrictions": {"max_size": "10MB"},
                "rate_limit": 100,
            }
        ],
    }


@pytest.fixture
def sample_vulnerable_config() -> dict[str, Any]:
    """A vulnerable MCP server configuration."""
    return {
        "server": {"protocol": "http"},
        "tools": [
            {"name": "dangerous_tool", "permissions": ["*"]},
            {"name": "fs", "permissions": ["file_system"]},
        ],
    }


@pytest.fixture
def config_file(tmp_path: Path):
    """Factory fixture: write a dict to a temp JSON file and return the path."""

    def _make(config: dict[str, Any]) -> str:
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        return str(path)

    return _make


@pytest.fixture
def sample_policy_dict() -> dict[str, Any]:
    """A sample policy for testing PolicyEngine."""
    return {
        "version": "1.0",
        "agents": {
            "reader": {
                "tools_allowed": ["logs", "metrics"],
                "tools_denied": ["admin_panel"],
                "rate_limit_per_hour": 10,
                "data_clearance": "INTERNAL",
                "action_restrictions": {"logs": ["delete"]},
            },
            "admin": {
                "tools_allowed": ["*"],
                "tools_denied": [],
                "rate_limit_per_hour": 10000,
                "data_clearance": "RESTRICTED",
                "action_restrictions": {},
            },
        },
        "tools": {
            "logs": {"allowed_actions": ["read", "export"]},
            "metrics": {"allowed_actions": ["read"]},
            "admin_panel": {"allowed_actions": ["read", "write"]},
        },
        "suspicious_patterns": [
            {
                "name": "test_pattern",
                "tool": "logs",
                "actions": ["export"],
                "conditions": {},
            }
        ],
    }


@pytest.fixture
def policy_file(tmp_path: Path, sample_policy_dict: dict[str, Any]) -> str:
    """Write the sample policy to a YAML file and return its path."""
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.dump(sample_policy_dict))
    return str(path)
