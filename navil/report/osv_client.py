"""OSV.dev batch API client.

Two-phase lookup:
  Phase 1 — POST /v1/querybatch to resolve (name, version, ecosystem) → vuln IDs.
  Phase 2 — GET  /v1/vulns/{id}  to fetch full details for each unique ID.

Phase 2 is parallelised with a semaphore to stay within OSV's rate limits.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
_CHUNK_SIZE = 500
_DETAIL_CONCURRENCY = 20  # parallel detail requests
_TIMEOUT = 30.0
_MAX_RETRIES = 3


# ── Public types ──────────────────────────────────────────────────


class OsvVuln:
    """Thin wrapper around a single OSV vulnerability record."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.id: str = raw.get("id", "")
        self.summary: str = raw.get("summary", "")
        self.details: str = raw.get("details", "")
        self.aliases: list[str] = raw.get("aliases", [])
        self.published: str = raw.get("published", "")
        self.modified: str = raw.get("modified", "")
        self.severity: str = self._extract_severity(raw)
        self.cvss_score: float | None = self._extract_cvss(raw)
        self.cwe_ids: list[str] = self._extract_cwes(raw)
        self._raw = raw

    def _extract_severity(self, raw: dict[str, Any]) -> str:
        for sev in raw.get("severity", []):
            score = self._score_from_str(sev.get("score", ""))
            if score is not None:
                return _cvss_label(score)
        db = raw.get("database_specific", {})
        severity = db.get("severity", db.get("cvss_severity", ""))
        normalized = severity.upper() if severity else "UNKNOWN"
        # GitHub Advisory uses "MODERATE" instead of "MEDIUM"
        return "MEDIUM" if normalized == "MODERATE" else normalized

    def _extract_cvss(self, raw: dict[str, Any]) -> float | None:
        for sev in raw.get("severity", []):
            score = self._score_from_str(sev.get("score", ""))
            if score is not None:
                return score
        return None

    def _extract_cwes(self, raw: dict[str, Any]) -> list[str]:
        cwes: list[str] = []
        for ref in raw.get("references", []):
            url = ref.get("url", "")
            if "cwe" in url.lower():
                cwes.append(url)
        cwes.extend(raw.get("database_specific", {}).get("cwes", []))
        return cwes

    @staticmethod
    def _score_from_str(s: str) -> float | None:
        try:
            # CVSS vector strings start with "CVSS:3.1/..." — skip those
            if s.startswith("CVSS"):
                return None
            return float(s.split("/")[0] if "/" in s else s)
        except (ValueError, AttributeError):
            return None

    def __repr__(self) -> str:
        return f"OsvVuln(id={self.id!r}, severity={self.severity!r})"


def _cvss_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ── Core fetch ────────────────────────────────────────────────────


async def query_packages(
    packages: list[tuple[str, str, str]],  # (name, version, ecosystem)
    *,
    timeout: float = _TIMEOUT,
) -> dict[tuple[str, str], list[OsvVuln]]:
    """Two-phase OSV lookup for a list of (name, version, ecosystem) tuples."""
    sem = asyncio.Semaphore(_DETAIL_CONCURRENCY)

    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"User-Agent": "navil-audit-deps/1.0 (https://navil.ai)"},
    ) as client:
        # Phase 1: resolve vuln IDs per package
        pkg_to_ids: dict[tuple[str, str], list[str]] = {}
        for chunk_start in range(0, len(packages), _CHUNK_SIZE):
            chunk = packages[chunk_start : chunk_start + _CHUNK_SIZE]
            queries = [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for name, version, ecosystem in chunk
            ]
            raw_results = await _post_with_retry(client, {"queries": queries})
            for (name, version, _eco), result in zip(chunk, raw_results, strict=False):
                ids = [v.get("id", "") for v in result.get("vulns", []) if v.get("id")]
                if ids:
                    pkg_to_ids[(name, version)] = ids

        # Phase 2: fetch full details for unique vuln IDs
        all_ids: set[str] = set()
        for ids in pkg_to_ids.values():
            all_ids.update(ids)

        logger.info("Fetching full details for %d unique vulnerabilities…", len(all_ids))
        id_to_vuln: dict[str, OsvVuln] = {}
        tasks = [_fetch_vuln_detail(client, vid, sem) for vid in all_ids]
        results = await asyncio.gather(*tasks)
        for vuln in results:
            if vuln is not None:
                id_to_vuln[vuln.id] = vuln

        # Build final mapping: (name, version) → [OsvVuln]
        out: dict[tuple[str, str], list[OsvVuln]] = {}
        for key, ids in pkg_to_ids.items():
            out[key] = [id_to_vuln[vid] for vid in ids if vid in id_to_vuln]

    return out


async def _fetch_vuln_detail(
    client: httpx.AsyncClient,
    vuln_id: str,
    sem: asyncio.Semaphore,
) -> OsvVuln | None:
    async with sem:
        url = _OSV_VULN_URL.format(id=vuln_id)
        for attempt in range(_MAX_RETRIES):
            try:
                resp = await client.get(url)
                if resp.status_code == 429:
                    await asyncio.sleep(2**attempt)
                    continue
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                return OsvVuln(resp.json())
            except httpx.HTTPStatusError:
                if attempt == _MAX_RETRIES - 1:
                    logger.debug("Vuln detail failed for %s", vuln_id)
                    return None
                await asyncio.sleep(2**attempt)
            except httpx.RequestError as exc:
                if attempt == _MAX_RETRIES - 1:
                    logger.debug("Network error for %s: %s", vuln_id, exc)
                    return None
                await asyncio.sleep(2**attempt)
    return None


async def _post_with_retry(
    client: httpx.AsyncClient,
    payload: dict[str, Any],
    retries: int = _MAX_RETRIES,
) -> list[dict[str, Any]]:
    n = len(payload["queries"])
    for attempt in range(retries):
        try:
            resp = await client.post(_OSV_BATCH_URL, json=payload)
            if resp.status_code == 429:
                await asyncio.sleep(2**attempt)
                continue
            resp.raise_for_status()
            return resp.json().get("results", [{}] * n)
        except httpx.HTTPStatusError as exc:
            if attempt == retries - 1:
                logger.error("OSV batch failed: %s", exc)
                return [{}] * n
            await asyncio.sleep(2**attempt)
        except httpx.RequestError as exc:
            if attempt == retries - 1:
                logger.error("OSV network error: %s", exc)
                return [{}] * n
            await asyncio.sleep(2**attempt)
    return [{}] * n
