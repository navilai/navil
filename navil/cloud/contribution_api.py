"""Contribution API — submit and receive anonymized detection results.

Client-side: sanitizes and submits anonymized scan/detection results
from community deployments to Navil Cloud.

Server-side: validates incoming data format, deduplicates against
existing patterns, and queues contributions for the aggregation pipeline.

Uses the same privacy-preserving sanitization as telemetry_sync.py.
Accepts: tool sequences, anomaly types, severity, confidence (no raw payloads).

Can be called from the canary kit to feed data back to the intel pool.

Usage::

    # Client (submitting)
    from navil.cloud.contribution_api import ContributionClient
    client = ContributionClient()
    await client.submit_detections(records)

    # Server (receiving)
    from navil.cloud.contribution_api import ContributionReceiver
    receiver = ContributionReceiver()
    result = receiver.receive(contributions)
    # result = {"accepted": 5, "duplicates": 2, "rejected": 1, ...}
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Cloud endpoint for contributions
_DEFAULT_ENDPOINT = "https://api.navil.ai/v1/threat-intel/contribute"

# Strict allowlist — only these fields may be transmitted
CONTRIBUTION_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "tool_sequence_hash",
        "anomaly_type",
        "severity",
        "confidence",
        "tool_count",
        "unique_tool_count",
        "timestamp",
        "contribution_uuid",
        "source_type",  # "canary", "honeypot", "detector"
        "profile_name",
    }
)

# Fields that MUST NEVER be transmitted
CONTRIBUTION_BANNED_FIELDS: frozenset[str] = frozenset(
    {
        "source_ip",
        "arguments",
        "raw_body",
        "request_headers",
        "content",
        "params",
        "tool_name",  # individual tool names could reveal infrastructure
        "agent_name",
        "path",
        "url",
        "email",
    }
)


def sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Sanitize a single interaction record for contribution.

    Strips all PII, arguments, IPs, and headers.
    Returns only statistical metadata safe for public sharing.

    Args:
        record: Raw honeypot/detection record.

    Returns:
        Sanitized dict containing only allowed fields.

    Raises:
        ValueError: If a banned field would leak through.
    """
    out: dict[str, Any] = {}

    # Hash the tool sequence (not individual tool names)
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
    ):
        if key in record:
            out[key] = record[key]

    # Statistical aggregates only
    if "tool_count" in record:
        out["tool_count"] = int(record["tool_count"])
    if "unique_tool_count" in record:
        out["unique_tool_count"] = int(record["unique_tool_count"])

    # Generate deterministic contribution UUID
    uuid_input = f"{out.get('tool_sequence_hash', '')}:{out.get('timestamp', '')}"
    out["contribution_uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, uuid_input))

    # Defence-in-depth: verify NO banned field leaked through
    leaked = CONTRIBUTION_BANNED_FIELDS & set(out.keys())
    if leaked:
        raise ValueError(f"Privacy violation: banned fields in contribution: {leaked}")

    # Final allowlist gate
    return {k: v for k, v in out.items() if k in CONTRIBUTION_ALLOWED_FIELDS}


def sanitize_batch(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitize a batch of records for contribution."""
    results: list[dict[str, Any]] = []
    for record in records:
        try:
            results.append(sanitize_record(record))
        except Exception:
            logger.debug("Skipped unsanitizable contribution record")
    return results


class ContributionClient:
    """Client for submitting anonymized detections to Navil Cloud.

    Usage::

        client = ContributionClient()
        result = await client.submit_detections(records)
    """

    def __init__(
        self,
        endpoint: str = _DEFAULT_ENDPOINT,
        api_key: str = "",
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key or os.environ.get("NAVIL_API_KEY", "")
        self._http_client: Any = None

    def _get_client(self) -> Any:
        if self._http_client is None:
            import httpx

            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._http_client = httpx.AsyncClient(headers=headers, timeout=30.0)
        return self._http_client

    async def submit_detections(
        self,
        records: list[dict[str, Any]],
        source_type: str = "canary",
        profile_name: str = "",
    ) -> dict[str, Any]:
        """Submit anonymized detection records to the cloud.

        Args:
            records: Raw interaction records from honeypot/collector.
            source_type: Type of source ("canary", "honeypot", "detector").
            profile_name: Honeypot profile name (if applicable).

        Returns:
            Summary dict with submitted count and status.
        """
        # Annotate records with source metadata
        annotated = []
        for r in records:
            enriched = dict(r)
            enriched["source_type"] = source_type
            if profile_name:
                enriched["profile_name"] = profile_name
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
                logger.info("Contributed %d anonymized detections", len(sanitized))
                return {"submitted": len(sanitized), "status": "ok"}
            else:
                logger.warning("Contribution failed: HTTP %d", resp.status_code)
                return {"submitted": 0, "status": f"error_{resp.status_code}"}

        except ImportError:
            logger.warning("httpx not installed, cannot submit contributions")
            return {"submitted": 0, "status": "no_httpx"}
        except Exception:
            logger.error("Contribution submission failed", exc_info=True)
            return {"submitted": 0, "status": "error"}

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# ── Server-Side: Contribution Receiver ──────────────────────────


# Validation schema for incoming contributions
_REQUIRED_FIELDS = {"contribution_uuid"}
_VALID_SOURCE_TYPES = {"canary", "honeypot", "detector"}
_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_MAX_BATCH_SIZE = 500
_MAX_FIELD_LENGTH = 256


class ValidationError(Exception):
    """Raised when an incoming contribution fails validation."""

    def __init__(self, message: str, field: str = "") -> None:
        super().__init__(message)
        self.field = field


def validate_contribution(entry: dict[str, Any]) -> dict[str, Any]:
    """Validate a single incoming contribution entry.

    Checks:
      1. Required fields are present.
      2. All fields are in the allowed set (rejects unknown keys).
      3. Field types and value ranges are correct.
      4. No banned fields are present.

    Args:
        entry: A single contribution dict from an external submitter.

    Returns:
        The validated (and cleaned) entry dict.

    Raises:
        ValidationError: If validation fails.
    """
    if not isinstance(entry, dict):
        raise ValidationError("Contribution must be a dict")

    # Check for banned fields (safety gate)
    leaked = CONTRIBUTION_BANNED_FIELDS & set(entry.keys())
    if leaked:
        raise ValidationError(
            f"Contribution contains banned fields: {leaked}",
            field=str(leaked),
        )

    # Check all keys are in allowlist
    unknown = set(entry.keys()) - CONTRIBUTION_ALLOWED_FIELDS
    if unknown:
        raise ValidationError(
            f"Unknown fields in contribution: {unknown}",
            field=str(unknown),
        )

    # Required fields
    for field in _REQUIRED_FIELDS:
        if field not in entry:
            raise ValidationError(f"Missing required field: {field}", field=field)

    # Type and value validation
    if "contribution_uuid" in entry:
        val = entry["contribution_uuid"]
        if not isinstance(val, str) or len(val) > _MAX_FIELD_LENGTH:
            raise ValidationError("Invalid contribution_uuid", field="contribution_uuid")

    if "tool_sequence_hash" in entry:
        val = entry["tool_sequence_hash"]
        if not isinstance(val, str) or len(val) > 128:
            raise ValidationError("Invalid tool_sequence_hash", field="tool_sequence_hash")

    if "severity" in entry:
        val = entry["severity"]
        if not isinstance(val, str) or val.upper() not in _VALID_SEVERITIES:
            raise ValidationError(
                f"Invalid severity: {val}. Must be one of {_VALID_SEVERITIES}",
                field="severity",
            )

    if "confidence" in entry:
        val = entry["confidence"]
        if not isinstance(val, int | float) or not (0.0 <= val <= 1.0):
            raise ValidationError(
                "Confidence must be a number between 0.0 and 1.0",
                field="confidence",
            )

    if "source_type" in entry:
        val = entry["source_type"]
        if not isinstance(val, str) or val not in _VALID_SOURCE_TYPES:
            raise ValidationError(
                f"Invalid source_type: {val}. Must be one of {_VALID_SOURCE_TYPES}",
                field="source_type",
            )

    if "timestamp" in entry:
        val = entry["timestamp"]
        if not isinstance(val, str) or len(val) > _MAX_FIELD_LENGTH:
            raise ValidationError("Invalid timestamp", field="timestamp")

    for int_field in ("tool_count", "unique_tool_count"):
        if int_field in entry:
            val = entry[int_field]
            if not isinstance(val, int) or val < 0:
                raise ValidationError(
                    f"{int_field} must be a non-negative integer",
                    field=int_field,
                )

    return entry


def validate_batch(
    entries: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Validate a batch of incoming contributions.

    Args:
        entries: List of contribution dicts.

    Returns:
        Tuple of (valid_entries, errors) where errors is a list of
        dicts with "index" and "error" keys.
    """
    if len(entries) > _MAX_BATCH_SIZE:
        return [], [
            {"index": "batch", "error": f"Batch too large: {len(entries)} > {_MAX_BATCH_SIZE}"}
        ]

    valid: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for i, entry in enumerate(entries):
        try:
            validated = validate_contribution(entry)
            valid.append(validated)
        except ValidationError as e:
            errors.append({"index": str(i), "error": str(e)})

    return valid, errors


class ContributionReceiver:
    """Server-side contribution receiver with validation, deduplication, and queuing.

    Accepts anonymized scan/detection results from community deployments,
    validates the data format, deduplicates against previously seen
    patterns, and queues accepted contributions for the aggregation
    pipeline.

    Usage::

        receiver = ContributionReceiver()
        result = receiver.receive(contributions)
        queued = receiver.drain_queue()  # for pipeline processing
    """

    def __init__(self, max_queue_size: int = 10000) -> None:
        self._seen_uuids: set[str] = set()
        self._queue: deque[dict[str, Any]] = deque(maxlen=max_queue_size)
        self._lock = threading.Lock()
        self._stats = {
            "total_received": 0,
            "total_accepted": 0,
            "total_duplicates": 0,
            "total_rejected": 0,
        }

    def receive(
        self,
        contributions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Receive and process a batch of contributions.

        Steps:
          1. Validate each entry.
          2. Deduplicate against seen UUIDs.
          3. Queue valid, non-duplicate entries for the aggregation pipeline.

        Args:
            contributions: List of contribution dicts from a submitter.

        Returns:
            Summary dict:
                accepted:    Number of new contributions accepted.
                duplicates:  Number of duplicate contributions skipped.
                rejected:    Number of invalid contributions rejected.
                errors:      List of validation error details.
        """
        # 1. Validate
        valid, errors = validate_batch(contributions)
        rejected = len(errors)

        # 2. Deduplicate and queue
        accepted = 0
        duplicates = 0

        with self._lock:
            for entry in valid:
                contrib_uuid = entry.get("contribution_uuid", "")

                if contrib_uuid in self._seen_uuids:
                    duplicates += 1
                    continue

                # Mark as seen and queue
                self._seen_uuids.add(contrib_uuid)
                self._queue.append(
                    {
                        **entry,
                        "_received_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                accepted += 1

            # Update stats
            self._stats["total_received"] += len(contributions)
            self._stats["total_accepted"] += accepted
            self._stats["total_duplicates"] += duplicates
            self._stats["total_rejected"] += rejected

        result = {
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected,
            "errors": errors,
        }

        logger.info(
            "Contribution batch: accepted=%d, duplicates=%d, rejected=%d",
            accepted,
            duplicates,
            rejected,
        )
        return result

    def drain_queue(self, max_items: int = 0) -> list[dict[str, Any]]:
        """Drain queued contributions for pipeline processing.

        Args:
            max_items: Maximum items to drain (0 = drain all).

        Returns:
            List of contribution dicts ready for aggregation.
        """
        with self._lock:
            if max_items <= 0:
                items = list(self._queue)
                self._queue.clear()
            else:
                items = []
                for _ in range(min(max_items, len(self._queue))):
                    items.append(self._queue.popleft())
            return items

    @property
    def queue_size(self) -> int:
        """Number of contributions waiting in the queue."""
        with self._lock:
            return len(self._queue)

    @property
    def stats(self) -> dict[str, int]:
        """Return cumulative receiver statistics."""
        with self._lock:
            return dict(self._stats)

    def clear_seen(self) -> int:
        """Clear the deduplication set. Returns the number of UUIDs cleared."""
        with self._lock:
            count = len(self._seen_uuids)
            self._seen_uuids.clear()
            return count
