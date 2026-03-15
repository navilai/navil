"""Tests for LLM streaming, SSE formatting, and response caching."""

from __future__ import annotations

import json
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

# ── LLM Response Cache ─────────────────────────────────────


class TestLLMResponseCache:
    def test_sync_put_and_get(self) -> None:
        from navil.llm.cache import LLMResponseCache

        cache = LLMResponseCache()
        cache.put_sync("k1", "hello world")
        assert cache.get_sync("k1") == "hello world"
        assert cache.hits == 1

    def test_sync_miss(self) -> None:
        from navil.llm.cache import LLMResponseCache

        cache = LLMResponseCache()
        assert cache.get_sync("missing") is None
        assert cache.misses == 1

    def test_lru_eviction(self) -> None:
        from navil.llm.cache import LLMResponseCache

        cache = LLMResponseCache(max_size=3)
        cache.put_sync("a", "1")
        cache.put_sync("b", "2")
        cache.put_sync("c", "3")
        cache.put_sync("d", "4")  # evicts "a"

        assert cache.get_sync("a") is None  # evicted
        assert cache.get_sync("b") == "2"
        assert cache.get_sync("d") == "4"

    def test_lru_access_refreshes(self) -> None:
        from navil.llm.cache import LLMResponseCache

        cache = LLMResponseCache(max_size=3)
        cache.put_sync("a", "1")
        cache.put_sync("b", "2")
        cache.put_sync("c", "3")

        # Access "a" to move it to end
        cache.get_sync("a")
        # Insert "d" — should evict "b" (oldest untouched)
        cache.put_sync("d", "4")

        assert cache.get_sync("a") is not None
        assert cache.get_sync("b") is None  # evicted

    def test_cache_key_deterministic(self) -> None:
        from navil.llm.cache import cache_key

        k1 = cache_key("system", "user")
        k2 = cache_key("system", "user")
        assert k1 == k2
        assert len(k1) == 64  # SHA-256 hex

    def test_cache_key_differs_for_different_input(self) -> None:
        from navil.llm.cache import cache_key

        k1 = cache_key("system", "user A")
        k2 = cache_key("system", "user B")
        assert k1 != k2

    def test_stats(self) -> None:
        from navil.llm.cache import LLMResponseCache

        cache = LLMResponseCache()
        cache.put_sync("k1", "v1")
        cache.get_sync("k1")  # hit
        cache.get_sync("miss")  # miss

        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5
        assert stats["backend"] == "memory"

    def test_clear(self) -> None:
        from navil.llm.cache import LLMResponseCache

        cache = LLMResponseCache()
        cache.put_sync("k1", "v1")
        cache.clear()
        assert cache.get_sync("k1") is None
        assert cache.hits == 0

    async def test_async_get_put_memory_fallback(self) -> None:
        """Async API without Redis falls back to in-memory."""
        from navil.llm.cache import LLMResponseCache

        cache = LLMResponseCache(redis_client=None)
        await cache.put("ak1", "async-value")
        result = await cache.get("ak1")
        assert result == "async-value"
        assert cache.hits == 1

    async def test_async_redis_get_put(self, fake_redis) -> None:
        """Async API with FakeRedis uses Redis."""
        from navil.llm.cache import REDIS_KEY_PREFIX, LLMResponseCache

        cache = LLMResponseCache(redis_client=fake_redis, ttl=300)
        await cache.put("rk1", "redis-value")

        # Verify it's in Redis
        redis_key = f"{REDIS_KEY_PREFIX}rk1"
        assert redis_key in fake_redis._data

        result = await cache.get("rk1")
        assert result == "redis-value"
        assert cache.hits == 1


# ── LLM Client Streaming ──────────────────────────────────


class TestLLMClientStream:
    @patch("navil._compat.require_llm")
    def test_stream_anthropic(self, mock_req: MagicMock) -> None:
        """Anthropic streaming yields text chunks via messages.stream()."""
        with patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_anthropic.return_value = mock_client

            # Mock the streaming context manager
            mock_stream = MagicMock()
            mock_stream.text_stream = iter(["Hello", " ", "World"])
            mock_stream.__enter__ = MagicMock(return_value=mock_stream)
            mock_stream.__exit__ = MagicMock(return_value=False)
            mock_client.messages.stream.return_value = mock_stream

            from navil.llm.client import LLMClient

            client = LLMClient(provider="anthropic", api_key="test-key")
            chunks = list(client.stream("system", "user"))
            assert chunks == ["Hello", " ", "World"]
            mock_client.messages.stream.assert_called_once()

    @patch("navil._compat.require_llm")
    def test_stream_openai(self, mock_req: MagicMock) -> None:
        """OpenAI streaming yields delta.content chunks."""
        with patch("openai.OpenAI") as mock_openai:
            mock_client = MagicMock()
            mock_openai.return_value = mock_client

            # Build mock streaming chunks
            def _make_chunk(content: str | None) -> MagicMock:
                c = MagicMock()
                c.choices = [MagicMock(delta=MagicMock(content=content))]
                return c

            mock_client.chat.completions.create.return_value = iter(
                [
                    _make_chunk("chunk1"),
                    _make_chunk("chunk2"),
                    _make_chunk(None),  # empty delta
                    _make_chunk("chunk3"),
                ]
            )

            from navil.llm.client import LLMClient

            client = LLMClient(provider="openai", api_key="test-key")
            chunks = list(client.stream("system", "user"))
            assert chunks == ["chunk1", "chunk2", "chunk3"]
            mock_client.chat.completions.create.assert_called_once()
            # Verify stream=True was passed
            call_kwargs = mock_client.chat.completions.create.call_args[1]
            assert call_kwargs["stream"] is True


# ── SSE Formatting ─────────────────────────────────────────


class TestSSEFormatting:
    def test_sse_event_basic(self) -> None:
        from navil.api.local.routes import _sse_event

        result = _sse_event('{"text": "hello"}', event="chunk")
        assert "event: chunk\n" in result
        assert 'data: {"text": "hello"}' in result
        # Must end with double newline (SSE spec)
        assert result.endswith("\n\n")

    def test_sse_event_no_event_type(self) -> None:
        from navil.api.local.routes import _sse_event

        result = _sse_event("simple data")
        assert "event:" not in result
        assert "data: simple data" in result

    def test_sse_event_multiline_data(self) -> None:
        from navil.api.local.routes import _sse_event

        result = _sse_event("line1\nline2", event="chunk")
        assert "data: line1\n" in result
        assert "data: line2\n" in result


class TestStreamLLMSSE:
    def test_stream_yields_chunks_and_done(self) -> None:
        """_stream_llm_sse should yield chunk events then a done event."""
        from navil.api.local.routes import _stream_llm_sse

        mock_client = MagicMock()
        mock_client.stream.return_value = iter(["Hello", " World"])

        events = list(_stream_llm_sse("sys", "usr", mock_client, "test-key"))

        # Should have 2 chunk events + 1 done event
        assert len(events) == 3

        # Parse first chunk
        assert "event: chunk" in events[0]
        chunk_data = json.loads(events[0].split("data: ")[1].split("\n")[0])
        assert chunk_data["text"] == "Hello"

        # Parse done event
        assert "event: done" in events[2]

    def test_stream_with_post_process(self) -> None:
        """Post-process function should transform the done payload."""
        from navil.api.local.routes import _stream_llm_sse

        mock_client = MagicMock()
        mock_client.stream.return_value = iter(['{"result": "ok"}'])

        def post_process(text: str) -> dict:
            return json.loads(text)

        events = list(_stream_llm_sse("sys", "usr", mock_client, "ck", post_process))

        done_event = events[-1]
        assert "event: done" in done_event
        done_data = json.loads(done_event.split("data: ")[1].split("\n")[0])
        assert done_data == {"result": "ok"}

    def test_stream_caches_result(self) -> None:
        """After streaming, the full text should be in the cache."""
        from navil.api.local.routes import _get_llm_cache, _stream_llm_sse

        cache = _get_llm_cache()
        cache.clear()

        mock_client = MagicMock()
        mock_client.stream.return_value = iter(["part1", "part2"])

        # Consume the generator
        list(_stream_llm_sse("sys", "usr", mock_client, "cache-test-key"))

        assert cache.get_sync("cache-test-key") == "part1part2"

    def test_stream_error_yields_error_event(self) -> None:
        """If the LLM raises during streaming, yield an error SSE event."""
        from navil.api.local.routes import _stream_llm_sse

        mock_client = MagicMock()

        def _failing_stream(*a, **kw):
            yield "partial"
            raise RuntimeError("API timeout")

        mock_client.stream.return_value = _failing_stream()

        events = list(_stream_llm_sse("sys", "usr", mock_client, "err-key"))

        # Should have a chunk event, then an error event
        has_error = any("event: error" in e for e in events)
        assert has_error

        error_event = [e for e in events if "event: error" in e][0]
        error_data = json.loads(error_event.split("data: ")[1].split("\n")[0])
        assert error_data["error"] == "llm_error"
        assert "API timeout" in error_data["message"]


# ── Integration: SSE Endpoint Tests via TestClient ─────────


class TestSSEEndpoints:
    """Test the streaming endpoints via FastAPI TestClient.

    These tests mock the LLM client to avoid real API calls but exercise
    the full SSE pipeline: cache check → stream → SSE format → response.
    """

    @pytest.fixture(autouse=True)
    def _reset_state(self) -> Iterator[None]:
        """Reset AppState singleton between tests."""
        from navil.api.local.state import AppState

        AppState.reset()
        yield
        AppState.reset()

    @pytest.fixture
    def app(self):
        """Create a test FastAPI app with mocked LLM components."""
        from navil.api.local.app import create_app
        from navil.api.local.routes import _get_llm_cache
        from navil.api.local.state import AppState

        # Clear cache between tests
        _get_llm_cache().clear()

        app = create_app(with_demo=False)
        s = AppState.get()

        # Mock LLM availability + components
        s.llm_available = True
        s.llm_api_key_configured = True

        mock_client = MagicMock()
        mock_json = (
            '{"explanation": "test analysis", "risks": [],'
            ' "remediations": [], "severity": "LOW", "confidence": 0.9}'
        )
        mock_client.stream.return_value = iter([mock_json])
        mock_client.complete.return_value = '{"explanation": "test analysis"}'
        mock_client.max_tokens = 1024

        mock_analyzer = MagicMock()
        mock_analyzer.client = mock_client

        mock_policy_gen = MagicMock()
        mock_policy_gen.client = mock_client

        mock_self_healing = MagicMock()
        mock_self_healing.client = mock_client

        s.llm_analyzer = mock_analyzer
        s.policy_generator = mock_policy_gen
        s.self_healing = mock_self_healing

        return app

    @pytest.fixture
    def client(self, app):
        from starlette.testclient import TestClient

        return TestClient(app)

    def test_analyze_config_returns_sse(self, client) -> None:
        """POST /api/llm/analyze-config should return text/event-stream."""
        resp = client.post(
            "/api/local/llm/analyze-config",
            json={"config": {"server": {"protocol": "http"}}},
        )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]

        body = resp.text
        assert "event: chunk" in body
        assert "event: done" in body

    def test_explain_anomaly_returns_sse(self, client) -> None:
        """POST /api/llm/explain-anomaly should return SSE stream."""
        resp = client.post(
            "/api/local/llm/explain-anomaly",
            json={"anomaly_data": {"agent": "test", "type": "rate_spike"}},
        )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        assert "event: chunk" in resp.text

    def test_generate_policy_returns_sse(self, client) -> None:
        """POST /api/llm/generate-policy should return SSE stream."""
        from navil.api.local.state import AppState

        s = AppState.get()
        # Return valid YAML from stream
        s.policy_generator.client.stream.return_value = iter(
            ['version: "1.0"\nagents: {}\ntools: {}']
        )

        resp = client.post(
            "/api/local/llm/generate-policy",
            json={"description": "Allow read-only access to logs"},
        )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]

    def test_cache_hit_returns_instantly(self, client) -> None:
        """Second identical request should return from cache (no LLM call)."""
        from navil.api.local.state import AppState

        s = AppState.get()
        call_count = 0

        def counting_stream(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            fresh_json = (
                '{"explanation": "fresh", "risks": [], "remediations": [], "severity": "LOW"}'
            )
            return iter([fresh_json])

        s.llm_analyzer.client.stream = counting_stream

        payload = {"config": {"server": {"protocol": "https"}}}

        # First call — should hit LLM
        resp1 = client.post("/api/local/llm/analyze-config", json=payload)
        assert resp1.status_code == 200
        assert call_count == 1

        # Second call — should hit cache
        resp2 = client.post("/api/local/llm/analyze-config", json=payload)
        assert resp2.status_code == 200
        assert call_count == 1  # no additional LLM call

        # Verify cached response includes cached flag
        assert '"cached": true' in resp2.text

    def test_suggest_remediation_no_alerts(self, client) -> None:
        """When no alerts exist, suggest-remediation returns done event immediately."""
        resp = client.post("/api/local/llm/suggest-remediation")
        assert resp.status_code == 200
        assert "event: done" in resp.text
        # Parse the done event payload
        for line in resp.text.split("\n"):
            if line.startswith("data: ") and "No active threats" in line:
                data = json.loads(line.removeprefix("data: "))
                assert data["risk_assessment"] == "LOW"
                break
        else:
            pytest.fail("Expected 'No active threats' in done event")

    def test_apply_action_not_streamed(self, client) -> None:
        """apply-action should return plain JSON, not SSE."""
        from navil.api.local.state import AppState

        s = AppState.get()
        s.self_healing.apply_action.return_value = True

        resp = client.post(
            "/api/local/llm/apply-action",
            json={"action": {"type": "agent_block", "target": "bad-agent"}},
        )
        assert resp.status_code == 200
        assert "text/event-stream" not in resp.headers.get("content-type", "")
        data = resp.json()
        assert data["success"] is True

    def test_auto_remediate_not_streamed(self, client) -> None:
        """auto-remediate returns plain JSON (applies actions server-side)."""
        resp = client.post(
            "/api/local/llm/auto-remediate",
            json={"confidence_threshold": 0.9},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "initial_analysis" in data
        assert data["llm_calls_used"] == 0  # no alerts

    def test_sse_headers(self, client) -> None:
        """SSE responses should include proper no-cache headers."""
        resp = client.post(
            "/api/local/llm/analyze-config",
            json={"config": {"test": True}},
        )
        assert resp.headers.get("cache-control") == "no-cache"
        assert resp.headers.get("x-accel-buffering") == "no"
