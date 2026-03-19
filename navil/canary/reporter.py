"""MCP Canary Reporter — anonymized contribution back to Navil Cloud.

Reports anonymized detection data from canary deployments to the Navil
threat intelligence pool.  All data is sanitized before transmission:

  - No raw arguments or payloads
  - No source IPs
  - No request headers
  - Only tool sequence hashes, anomaly types, and statistical metadata

This module is self-contained and uses only stdlib + httpx for HTTP.

Usage::

    from navil.canary.reporter import CanaryReporter

    reporter = CanaryReporter(api_key="...")
    result = await reporter.report(collector.records, profile="dev_tools")
    # result = {"submitted": 5, "status": "ok"}
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# Cloud endpoint for canary contributions
_DEFAULT_ENDPOINT = "https://api.navil.ai/v1/threat-intel/contribute"

# Strict allowlist — only these fields may leave the deployment
_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "tool_sequence_hash",
        "anomaly_type",
        "severity",
        "confidence",
        "tool_count",
        "unique_tool_count",
        "timestamp",
        "contribution_uuid",
        "source_type",
        "profile_name",
        "interaction_count",
        "method",
    }
)

# Fields that MUST NEVER be transmitted
_BANNED_FIELDS: frozenset[str] = frozenset(
    {
        "source_ip",
        "arguments",
        "raw_body",
        "request_headers",
        "content",
        "params",
        "tool_name",
        "agent_name",
        "path",
        "url",
        "email",
        "ip_address",
    }
)


def sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Sanitize a single canary interaction record for contribution.

    Strips all PII, arguments, IPs, and headers.  Returns only
    statistical metadata safe for public sharing.

    Args:
        record: Raw canary interaction record.

    Returns:
        Sanitized dict containing only allowed fields.

    Raises:
        ValueError: If a banned field would leak through.
    """
    out: dict[str, Any] = {}

    # Hash the tool name (not the raw name)
    tool_name = record.get("tool_name", "")
    if tool_name:
        out["tool_sequence_hash"] = hashlib.sha256(tool_name.encode()).hexdigest()

    # Copy allowed metadata
    for key in (
        "anomaly_type",
        "severity",
        "confidence",
        "timestamp",
        "source_type",
        "profile_name",
        "method",
    ):
        if key in record:
            out[key] = record[key]

    # Statistical aggregates only
    if "tool_count" in record:
        out["tool_count"] = int(record["tool_count"])
    if "unique_tool_count" in record:
        out["unique_tool_count"] = int(record["unique_tool_count"])
    if "interaction_count" in record:
        out["interaction_count"] = int(record["interaction_count"])

    # Generate deterministic contribution UUID
    uuid_input = f"{out.get('tool_sequence_hash', '')}:{out.get('timestamp', '')}"
    out["contribution_uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, uuid_input))

    # Defence-in-depth: verify NO banned field leaked through
    leaked = _BANNED_FIELDS & set(out.keys())
    if leaked:
        raise ValueError(f"Privacy violation: banned fields in contribution: {leaked}")

    # Final allowlist gate
    return {k: v for k, v in out.items() if k in _ALLOWED_FIELDS}


def sanitize_batch(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitize a batch of records for contribution."""
    results: list[dict[str, Any]] = []
    for record in records:
        try:
            results.append(sanitize_record(record))
        except Exception:
            logger.debug("Skipped unsanitizable contribution record")
    return results


def summarize_records(
    records: list[dict[str, Any]],
    profile_name: str = "",
) -> dict[str, Any]:
    """Create a statistical summary from canary records for contribution.

    Instead of sending individual records, creates an aggregate summary
    with tool call counts and timing statistics.

    Args:
        records: List of canary interaction records.
        profile_name: Canary profile name.

    Returns:
        Summary dict safe for contribution.
    """
    if not records:
        return {}

    tool_counts: dict[str, int] = {}
    for r in records:
        tool = r.get("tool_name", "unknown")
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    # Hash all tool names for privacy
    {hashlib.sha256(name.encode()).hexdigest(): count for name, count in tool_counts.items()}

    timestamps = [r.get("timestamp", "") for r in records if r.get("timestamp")]
    min(timestamps) if timestamps else ""
    last_seen = max(timestamps) if timestamps else ""

    summary = {
        "source_type": "canary",
        "profile_name": profile_name,
        "interaction_count": len(records),
        "unique_tool_count": len(tool_counts),
        "timestamp": last_seen,
        "contribution_uuid": str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"summary:{last_seen}:{len(records)}")
        ),
    }

    return {k: v for k, v in summary.items() if k in _ALLOWED_FIELDS}


class CanaryReporter:
    """Reports anonymized canary data to Navil Cloud.

    Handles sanitization, batching, and HTTP submission.  Designed to
    be self-contained with only httpx as an external dependency.

    Args:
        endpoint: Cloud API endpoint for contributions.
        api_key: Navil API key for authentication.
    """

    def __init__(
        self,
        endpoint: str = _DEFAULT_ENDPOINT,
        api_key: str = "",
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key or os.environ.get(
            "NAVIL_API_KEY", os.environ.get("CANARY_API_KEY", "")
        )
        self._http_client: Any = None

    def _get_client(self) -> Any:
        """Lazy-initialize the HTTP client."""
        if self._http_client is None:
            import httpx

            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._http_client = httpx.AsyncClient(headers=headers, timeout=30.0)
        return self._http_client

    async def report(
        self,
        records: list[dict[str, Any]],
        profile: str = "",
    ) -> dict[str, Any]:
        """Report anonymized canary records to Navil Cloud.

        Sanitizes all records before transmission.  Only statistical
        metadata is sent; no raw arguments, IPs, or headers.

        Args:
            records: Raw interaction records from the canary collector.
            profile: Canary profile name for metadata tagging.

        Returns:
            Summary dict with submitted count and status.
        """
        # Annotate with source metadata
        annotated = []
        for r in records:
            enriched = dict(r)
            enriched["source_type"] = "canary"
            if profile:
                enriched["profile_name"] = profile
            annotated.append(enriched)

        sanitized = sanitize_batch(annotated)

        if not sanitized:
            return {"submitted": 0, "status": "no_data"}

        try:
            client = self._get_client()
            resp = await client.post(
                self.endpoint,
                json={"contributions": sanitized},
            )

            if resp.status_code < 300:
                logger.info("Canary reported %d anonymized interactions", len(sanitized))
                return {"submitted": len(sanitized), "status": "ok"}
            else:
                logger.warning("Canary report failed: HTTP %d", resp.status_code)
                return {"submitted": 0, "status": f"error_{resp.status_code}"}

        except ImportError:
            logger.warning("httpx not installed, cannot submit canary report")
            return {"submitted": 0, "status": "no_httpx"}
        except Exception:
            logger.error("Canary report submission failed", exc_info=True)
            return {"submitted": 0, "status": "error"}

    async def report_summary(
        self,
        records: list[dict[str, Any]],
        profile: str = "",
    ) -> dict[str, Any]:
        """Report an aggregate summary instead of individual records.

        More privacy-preserving than per-record reporting.

        Args:
            records: Raw interaction records from the canary collector.
            profile: Canary profile name.

        Returns:
            Summary dict with submitted count and status.
        """
        summary = summarize_records(records, profile_name=profile)
        if not summary:
            return {"submitted": 0, "status": "no_data"}

        try:
            client = self._get_client()
            resp = await client.post(
                self.endpoint,
                json={"contributions": [summary]},
            )

            if resp.status_code < 300:
                logger.info(
                    "Canary summary reported (%d interactions)", summary.get("interaction_count", 0)
                )
                return {"submitted": 1, "status": "ok"}
            else:
                logger.warning("Canary summary report failed: HTTP %d", resp.status_code)
                return {"submitted": 0, "status": f"error_{resp.status_code}"}

        except ImportError:
            logger.warning("httpx not installed, cannot submit canary summary")
            return {"submitted": 0, "status": "no_httpx"}
        except Exception:
            logger.error("Canary summary submission failed", exc_info=True)
            return {"submitted": 0, "status": "error"}

    async def close(self) -> None:
        """Clean up the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
