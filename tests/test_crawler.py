"""Tests for the registry crawler."""

from __future__ import annotations

import asyncio
import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from navil.crawler.registry_crawler import (
    CrawlResult,
    RegistryCrawler,
    _DomainRateLimiter,
    _npm_config_example,
)


# ── CrawlResult ──────────────────────────────────────────────


class TestCrawlResult:
    """Tests for the CrawlResult dataclass."""

    def test_to_dict(self) -> None:
        r = CrawlResult(server_name="test", source="npm", url="https://example.com")
        d = r.to_dict()
        assert d["server_name"] == "test"
        assert d["source"] == "npm"
        assert d["url"] == "https://example.com"
        assert d["description"] == ""
        assert d["config_example"] is None

    def test_with_config_example(self) -> None:
        cfg = {"mcpServers": {"test": {"command": "npx"}}}
        r = CrawlResult(
            server_name="test",
            source="npm",
            url="https://example.com",
            config_example=cfg,
        )
        assert r.config_example == cfg


# ── npm config helper ─────────────────────────────────────────


class TestNpmConfigExample:
    """Tests for _npm_config_example."""

    def test_generates_npx_config(self) -> None:
        cfg = _npm_config_example("@example/mcp-server")
        assert cfg["mcpServers"]["@example/mcp-server"]["command"] == "npx"
        assert "-y" in cfg["mcpServers"]["@example/mcp-server"]["args"]


# ── Rate limiter ──────────────────────────────────────────────


class TestDomainRateLimiter:
    """Tests for the per-domain rate limiter."""

    @pytest.mark.asyncio
    async def test_acquire_does_not_raise(self) -> None:
        limiter = _DomainRateLimiter(max_rps=100.0)
        await limiter.acquire("example.com")

    @pytest.mark.asyncio
    async def test_different_domains_independent(self) -> None:
        limiter = _DomainRateLimiter(max_rps=100.0)
        await limiter.acquire("a.com")
        await limiter.acquire("b.com")


# ── Mock HTTP responses ──────────────────────────────────────

# Minimal awesome-mcp-servers README content
AWESOME_README = """
# Awesome MCP Servers

## Servers

- [FileServer](https://github.com/example/fileserver) - A file management MCP server
- **[DBServer](https://github.com/example/dbserver)** - Database access server
- [NotALink](relative/path) - Should be skipped
- Regular text that is not a link
"""

# Minimal npm search response
NPM_RESPONSE = {
    "total": 2,
    "objects": [
        {
            "package": {
                "name": "@example/mcp-server-files",
                "description": "File server for MCP",
                "links": {"npm": "https://www.npmjs.com/package/@example/mcp-server-files"},
            }
        },
        {
            "package": {
                "name": "mcp-server-db",
                "description": "Database MCP server",
                "links": {},
            }
        },
    ],
}

# Minimal PyPI XML-RPC response
PYPI_XMLRPC_RESPONSE = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>name</name>
                  <value><string>mcp-server-python</string></value>
                </member>
                <member>
                  <name>summary</name>
                  <value><string>Python MCP server</string></value>
                </member>
              </struct>
            </value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>
"""


def _mock_response(
    status_code: int = 200,
    text: str = "",
    json_data: dict | None = None,
) -> httpx.Response:
    """Create a mock httpx.Response."""
    resp = httpx.Response(
        status_code=status_code,
        text=text,
        request=httpx.Request("GET", "https://example.com"),
    )
    if json_data is not None:
        import orjson

        resp._content = orjson.dumps(json_data)
    return resp


# ── Crawler tests with mocked HTTP ───────────────────────────


class TestRegistryCrawlerAwesome:
    """Tests for crawling awesome-mcp-servers."""

    @pytest.mark.asyncio
    async def test_parses_markdown_links(self) -> None:
        crawler = RegistryCrawler(limit=100)
        mock_resp = _mock_response(text=AWESOME_README)

        async def mock_get(self_: Any, client: Any, url: str) -> httpx.Response:
            return mock_resp

        with patch.object(RegistryCrawler, "_fetch", mock_get):
            async with httpx.AsyncClient() as client:
                results = await crawler._crawl_awesome_mcp(client)

        assert len(results) == 2
        assert results[0].server_name == "FileServer"
        assert results[0].source == "awesome-mcp-servers"
        assert "github.com" in results[0].url
        assert results[1].server_name == "DBServer"

    @pytest.mark.asyncio
    async def test_handles_fetch_error(self) -> None:
        crawler = RegistryCrawler()

        async def mock_get(self_: Any, client: Any, url: str) -> httpx.Response:
            raise httpx.HTTPError("Connection failed")

        with patch.object(RegistryCrawler, "_fetch", mock_get):
            async with httpx.AsyncClient() as client:
                results = await crawler._crawl_awesome_mcp(client)
        assert results == []


class TestRegistryCrawlerNpm:
    """Tests for crawling npm."""

    @pytest.mark.asyncio
    async def test_parses_npm_packages(self) -> None:
        crawler = RegistryCrawler(limit=100)
        mock_resp = _mock_response(json_data=NPM_RESPONSE)

        async def mock_get(self_: Any, client: Any, url: str) -> httpx.Response:
            return mock_resp

        with patch.object(RegistryCrawler, "_fetch", mock_get):
            async with httpx.AsyncClient() as client:
                results = await crawler._crawl_npm(client)

        assert len(results) == 2
        assert results[0].server_name == "@example/mcp-server-files"
        assert results[0].source == "npm"
        assert results[0].config_example is not None
        # Second package should get a generated npm URL
        assert "mcp-server-db" in results[1].url

    @pytest.mark.asyncio
    async def test_handles_npm_error(self) -> None:
        crawler = RegistryCrawler()

        async def mock_get(self_: Any, client: Any, url: str) -> httpx.Response:
            raise httpx.HTTPError("npm down")

        with patch.object(RegistryCrawler, "_fetch", mock_get):
            async with httpx.AsyncClient() as client:
                results = await crawler._crawl_npm(client)
        assert results == []


class TestRegistryCrawlerPyPI:
    """Tests for crawling PyPI."""

    @pytest.mark.asyncio
    async def test_parses_pypi_xmlrpc(self) -> None:
        crawler = RegistryCrawler(limit=100)
        mock_resp = _mock_response(text=PYPI_XMLRPC_RESPONSE)

        async def mock_post(*args: Any, **kwargs: Any) -> httpx.Response:
            return mock_resp

        async with httpx.AsyncClient() as client:
            with patch.object(client, "post", side_effect=mock_post):
                # Bypass semaphore and rate limiter
                crawler._semaphore = asyncio.Semaphore(10)
                results = await crawler._crawl_pypi(client)

        assert len(results) >= 1
        assert results[0].server_name == "mcp-server-python"
        assert results[0].source == "pypi"

    @pytest.mark.asyncio
    async def test_pypi_xmlrpc_error_falls_back(self) -> None:
        crawler = RegistryCrawler(limit=100)

        async def mock_post(*args: Any, **kwargs: Any) -> httpx.Response:
            raise httpx.HTTPError("XML-RPC failed")

        simple_html = '<a href="/simple/mcp-test/">mcp-test</a>'
        mock_simple_resp = _mock_response(text=simple_html)

        async def mock_fetch(self_: Any, client: Any, url: str) -> httpx.Response:
            return mock_simple_resp

        async with httpx.AsyncClient() as client:
            with patch.object(client, "post", side_effect=mock_post), \
                 patch.object(RegistryCrawler, "_fetch", mock_fetch):
                crawler._semaphore = asyncio.Semaphore(10)
                results = await crawler._crawl_pypi(client)

        assert len(results) >= 1
        assert results[0].server_name == "mcp-test"


class TestRegistryCrawlerIntegration:
    """Integration-level tests for the full crawl pipeline."""

    @pytest.mark.asyncio
    async def test_crawl_respects_limit(self) -> None:
        crawler = RegistryCrawler(limit=3)

        awesome_resp = _mock_response(text=AWESOME_README)
        npm_resp = _mock_response(json_data=NPM_RESPONSE)
        pypi_resp = _mock_response(text=PYPI_XMLRPC_RESPONSE)

        async def mock_get(self_: Any, client: Any, url: str) -> httpx.Response:
            if "raw.githubusercontent.com" in url:
                return awesome_resp
            if "registry.npmjs.org" in url:
                return npm_resp
            return _mock_response(text="")

        async def mock_post(*args: Any, **kwargs: Any) -> httpx.Response:
            return pypi_resp

        with patch.object(RegistryCrawler, "_fetch", mock_get), \
             patch("httpx.AsyncClient.post", side_effect=mock_post):
            results = await crawler.crawl()

        assert len(results) <= 3

    @pytest.mark.asyncio
    async def test_crawl_handles_all_sources_failing(self) -> None:
        crawler = RegistryCrawler()

        async def mock_get(self_: Any, client: Any, url: str) -> httpx.Response:
            raise httpx.HTTPError("Everything is down")

        async def mock_post(*args: Any, **kwargs: Any) -> httpx.Response:
            raise httpx.HTTPError("Everything is down")

        with patch.object(RegistryCrawler, "_fetch", mock_get), \
             patch("httpx.AsyncClient.post", side_effect=mock_post):
            results = await crawler.crawl()

        assert results == []
