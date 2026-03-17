"""Registry crawler — discovers MCP servers from public package registries.

Supported sources:
  - awesome-mcp-servers (GitHub README)
  - npm registry (keyword search)
  - PyPI (simple API / XML-RPC search)

Uses httpx.AsyncClient with per-domain rate limiting, exponential back-off
on 429/5xx, and a global concurrency semaphore.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from xml.etree import ElementTree

import httpx
import orjson

logger = logging.getLogger(__name__)

# ── Data types ────────────────────────────────────────────────


@dataclass
class CrawlResult:
    """A single discovered MCP server entry."""

    server_name: str
    source: str
    url: str
    description: str = ""
    config_example: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Rate limiter ──────────────────────────────────────────────


class _DomainRateLimiter:
    """Per-domain token-bucket rate limiter (max_rps requests per second)."""

    def __init__(self, max_rps: float = 2.0) -> None:
        self._min_interval = 1.0 / max_rps
        self._last_request: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def acquire(self, domain: str) -> None:
        if domain not in self._locks:
            self._locks[domain] = asyncio.Lock()
        async with self._locks[domain]:
            now = time.monotonic()
            last = self._last_request.get(domain, 0.0)
            wait = self._min_interval - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request[domain] = time.monotonic()


# ── Core crawler ──────────────────────────────────────────────


class RegistryCrawler:
    """Crawls package registries to discover MCP servers."""

    # Default crawl targets
    SOURCES = [
        {"name": "awesome-mcp-servers", "type": "github_readme"},
        {"name": "npm", "type": "npm_search"},
        {"name": "pypi", "type": "pypi_search"},
    ]

    def __init__(
        self,
        *,
        concurrency: int = 10,
        max_rps_per_domain: float = 2.0,
        timeout: float = 30.0,
        limit: int = 0,
    ) -> None:
        self._semaphore = asyncio.Semaphore(concurrency)
        self._rate_limiter = _DomainRateLimiter(max_rps_per_domain)
        self._timeout = timeout
        self._limit = limit  # 0 = unlimited

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        """Fetch a URL with rate limiting, semaphore, and exponential back-off."""
        domain = httpx.URL(url).host or "unknown"

        async with self._semaphore:
            backoff = 1.0
            for attempt in range(4):  # initial + 3 retries
                await self._rate_limiter.acquire(domain)
                try:
                    resp = await client.get(url, timeout=self._timeout)
                    if resp.status_code == 429 or resp.status_code >= 500:
                        logger.warning(
                            "HTTP %d from %s (attempt %d), backing off %.1fs",
                            resp.status_code,
                            url,
                            attempt + 1,
                            backoff,
                        )
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    resp.raise_for_status()
                    return resp
                except httpx.HTTPStatusError:
                    raise
                except httpx.HTTPError as exc:
                    if attempt == 3:
                        raise
                    logger.warning("HTTP error %s (attempt %d), retrying", exc, attempt + 1)
                    await asyncio.sleep(backoff)
                    backoff *= 2
            # Should not reach here, but satisfy type checker
            raise httpx.HTTPError(f"Failed after retries: {url}")

    # ── Source-specific crawlers ──────────────────────────────

    async def _crawl_awesome_mcp(self, client: httpx.AsyncClient) -> list[CrawlResult]:
        """Parse the awesome-mcp-servers README for server entries."""
        url = "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md"
        try:
            resp = await self._fetch(client, url)
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch awesome-mcp-servers: %s", exc)
            return []

        results: list[CrawlResult] = []
        # Match markdown links: - [Name](URL) - Description
        # or: - **[Name](URL)** - Description
        pattern = re.compile(
            r"^\s*[-*]\s+\*{0,2}\[([^\]]+)\]\(([^)]+)\)\*{0,2}\s*[-–—]?\s*(.*)",
            re.MULTILINE,
        )
        for m in pattern.finditer(resp.text):
            name = m.group(1).strip()
            link = m.group(2).strip()
            desc = m.group(3).strip()
            if not link.startswith("http"):
                continue
            results.append(
                CrawlResult(
                    server_name=name,
                    source="awesome-mcp-servers",
                    url=link,
                    description=desc,
                )
            )
        return results

    async def _crawl_npm(self, client: httpx.AsyncClient) -> list[CrawlResult]:
        """Search npm for packages with 'mcp-server' keyword."""
        results: list[CrawlResult] = []
        size = 250
        offset = 0
        while True:
            url = (
                f"https://registry.npmjs.org/-/v1/search"
                f"?text=keywords:mcp-server&size={size}&from={offset}"
            )
            try:
                resp = await self._fetch(client, url)
            except httpx.HTTPError as exc:
                logger.error("npm search failed at offset %d: %s", offset, exc)
                break

            data = resp.json()
            objects = data.get("objects", [])
            if not objects:
                break

            for obj in objects:
                pkg = obj.get("package", {})
                name = pkg.get("name", "")
                desc = pkg.get("description", "")
                links = pkg.get("links", {})
                npm_url = links.get("npm", f"https://www.npmjs.com/package/{name}")
                results.append(
                    CrawlResult(
                        server_name=name,
                        source="npm",
                        url=npm_url,
                        description=desc,
                        config_example=_npm_config_example(name),
                    )
                )

            offset += size
            if offset >= data.get("total", 0):
                break
            if self._limit and len(results) >= self._limit:
                break

        return results

    async def _crawl_pypi(self, client: httpx.AsyncClient) -> list[CrawlResult]:
        """Search PyPI for packages matching 'mcp' keyword via XML-RPC."""
        results: list[CrawlResult] = []
        url = "https://pypi.org/pypi"
        body = (
            '<?xml version="1.0"?>'
            "<methodCall><methodName>search</methodName>"
            "<params><param><value><struct>"
            "<member><name>name</name><value><string>mcp</string></value></member>"
            "</struct></value></param>"
            "<param><value><string>or</string></value></param>"
            "</params></methodCall>"
        )
        try:
            async with self._semaphore:
                await self._rate_limiter.acquire("pypi.org")
                resp = await client.post(
                    url,
                    content=body,
                    headers={"Content-Type": "text/xml"},
                    timeout=self._timeout,
                )
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("PyPI XML-RPC search failed: %s — falling back to simple API", exc)
            return await self._crawl_pypi_simple(client)

        try:
            root = ElementTree.fromstring(resp.text)
            for member_struct in root.iter("struct"):
                fields: dict[str, str] = {}
                for member in member_struct.findall("member"):
                    name_el = member.find("name")
                    value_el = member.find("value")
                    if name_el is not None and value_el is not None:
                        str_el = value_el.find("string")
                        if str_el is not None and str_el.text:
                            fields[name_el.text or ""] = str_el.text
                pkg_name = fields.get("name", "")
                if not pkg_name:
                    continue
                results.append(
                    CrawlResult(
                        server_name=pkg_name,
                        source="pypi",
                        url=f"https://pypi.org/project/{pkg_name}/",
                        description=fields.get("summary", ""),
                    )
                )
        except ElementTree.ParseError as exc:
            logger.error("Failed to parse PyPI XML-RPC response: %s", exc)
            return await self._crawl_pypi_simple(client)

        return results

    async def _crawl_pypi_simple(self, client: httpx.AsyncClient) -> list[CrawlResult]:
        """Fallback: search PyPI simple index for MCP-related packages."""
        url = "https://pypi.org/simple/"
        try:
            resp = await self._fetch(client, url)
        except httpx.HTTPError as exc:
            logger.error("PyPI simple API failed: %s", exc)
            return []

        results: list[CrawlResult] = []
        pattern = re.compile(r'<a[^>]+href="[^"]*">([^<]*mcp[^<]*)</a>', re.IGNORECASE)
        for m in pattern.finditer(resp.text):
            name = m.group(1).strip()
            results.append(
                CrawlResult(
                    server_name=name,
                    source="pypi",
                    url=f"https://pypi.org/project/{name}/",
                )
            )
        return results

    # ── Main entry point ──────────────────────────────────────

    async def crawl(self) -> list[CrawlResult]:
        """Crawl all configured registry sources and return discovered servers."""
        async with httpx.AsyncClient(
            follow_redirects=True,
            headers={"User-Agent": "navil-crawler/0.1"},
        ) as client:
            tasks = [
                self._crawl_awesome_mcp(client),
                self._crawl_npm(client),
                self._crawl_pypi(client),
            ]
            all_results_nested = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[CrawlResult] = []
        for batch in all_results_nested:
            if isinstance(batch, Exception):
                logger.error("Crawl source failed: %s", batch)
                continue
            results.extend(batch)

        if self._limit:
            results = results[: self._limit]

        return results


# ── Helpers ───────────────────────────────────────────────────


def _npm_config_example(package_name: str) -> dict[str, Any]:
    """Generate a sample MCP config snippet for an npm package."""
    return {
        "mcpServers": {
            package_name: {
                "command": "npx",
                "args": ["-y", package_name],
            }
        }
    }


async def crawl_registries(*, limit: int = 0) -> list[CrawlResult]:
    """Convenience wrapper: crawl all registries and return results."""
    crawler = RegistryCrawler(limit=limit)
    return await crawler.crawl()
