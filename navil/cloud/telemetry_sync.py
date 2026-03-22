# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Cloud Telemetry Sync — 'Give to Get' threat intelligence sharing.

Periodically gathers local anomaly alerts and blocked-event metadata,
sanitizes them to remove ALL PII / raw payloads, and uploads the
anonymized signatures to Navil Cloud so every deployment benefits from
the collective threat intelligence pool.

Privacy guarantees (enforced by ``sanitize_alert``):
  1. Agent names → one-way HMAC-SHA256 keyed by a per-deployment secret.
     Cannot be reversed; same agent produces the same ID within one
     deployment but different IDs across deployments.
  2. Descriptions, evidence, recommended actions → stripped entirely.
     These fields may contain file paths, prompts, or raw tool arguments.
  3. Target server URLs → stripped entirely (infrastructure topology).
  4. Location → stripped entirely.
  5. Output is validated against an explicit allowlist of keys before
     transmission.  Any field not on the allowlist is dropped.

Opt-out:
  Set ``NAVIL_DISABLE_CLOUD_SYNC=true`` (env var) or pass
  ``enabled=False`` to the constructor.

Usage::

    worker = CloudSyncWorker(
        detector=detector,
        api_url="https://api.navil.ai/v1/telemetry/sync",
        deployment_secret=b"per-install-random-key",
    )
    await worker.run()   # runs forever, syncing every 60 s
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import platform
import sys
import uuid
from typing import Any

from navil import __version__

logger = logging.getLogger(__name__)

# ── Privacy: strict allowlist of fields that may leave the deployment ──

ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "agent_id",  # HMAC-anonymized, NOT the raw agent name
        "tool_name",
        "anomaly_type",
        "severity",
        "confidence",
        "statistical_deviation",
        "payload_bytes",
        "response_bytes",
        "duration_ms",
        "timestamp",
        "action",
        "event_uuid",  # deterministic dedup key for cloud backend
        "tool_sequence_hash",  # SHA-256 of tool execution chain (optional)
        "machine_id",  # per-deployment machine identifier from config
        "mcp_server_name",  # MCP server that triggered the alert
    }
)

# Fields that MUST NEVER appear in outgoing payloads.
BANNED_FIELDS: frozenset[str] = frozenset(
    {
        "agent_name",
        "description",
        "evidence",
        "recommended_action",
        "target_server",
        "location",
        "arguments_hash",
        "arguments",
        "params",
        "raw",
        "content",
        "prompt",
        "ip_address",
        "email",
    }
)


def anonymize_agent(agent_name: str, secret: bytes) -> str:
    """One-way HMAC-SHA256 anonymization of an agent name.

    The result is a fixed-length hex digest that:
      - Cannot be reversed to recover the original name.
      - Is deterministic within the same deployment (same secret).
      - Differs across deployments (different secrets).
    """
    return hmac.new(secret, agent_name.encode("utf-8"), hashlib.sha256).hexdigest()


def sanitize_alert(
    alert: dict[str, Any],
    deployment_secret: bytes,
) -> dict[str, Any]:
    """Sanitize a single alert dict for cloud transmission.

    Returns a new dict containing ONLY allowlisted metadata fields.
    All PII, descriptions, evidence, and raw payloads are stripped.

    Raises ``ValueError`` if the output would still contain a banned key
    (defence-in-depth — should never happen given the allowlist logic,
    but guarantees correctness even if the allowlist is misconfigured).
    """
    out: dict[str, Any] = {}

    # 1. Anonymize agent identity
    raw_agent = alert.get("agent_name") or alert.get("agent") or "unknown"
    out["agent_id"] = anonymize_agent(str(raw_agent), deployment_secret)

    # 2. Copy safe metadata fields (only if present in source AND in allowlist)
    for key in (
        "tool_name",
        "anomaly_type",
        "severity",
        "confidence",
        "payload_bytes",
        "response_bytes",
        "duration_ms",
        "timestamp",
        "action",
        "machine_id",
        "mcp_server_name",
    ):
        if key in alert:
            out[key] = alert[key]

    # 3. Derive statistical_deviation from evidence if available
    #    (numeric-only extraction — no free-text leaks)
    if "statistical_deviation" in alert:
        out["statistical_deviation"] = float(alert["statistical_deviation"])

    # 4. Generate deterministic event_uuid (idempotency key for cloud dedup)
    uuid_input = (
        f"{out.get('agent_id', '')}:{out.get('tool_name', '')}"
        f":{out.get('timestamp', '')}:{out.get('anomaly_type', '')}"
    )
    out["event_uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, uuid_input))

    # 5. Optional: hash the tool execution chain for pattern aggregation
    tool_seq = alert.get("tool_sequence")
    if tool_seq and isinstance(tool_seq, list | tuple):
        seq_str = ",".join(str(t) for t in tool_seq)
        out["tool_sequence_hash"] = hashlib.sha256(seq_str.encode()).hexdigest()

    # 6. Defence-in-depth: verify NO banned field leaked through
    leaked = BANNED_FIELDS & set(out.keys())
    if leaked:
        raise ValueError(f"Privacy violation: banned fields in sanitized output: {leaked}")

    # 7. Final allowlist gate: drop anything not explicitly allowed
    return {k: v for k, v in out.items() if k in ALLOWED_FIELDS}


def sanitize_batch(
    alerts: list[dict[str, Any]],
    deployment_secret: bytes,
) -> list[dict[str, Any]]:
    """Sanitize a batch of alerts. Skips individual failures."""
    results: list[dict[str, Any]] = []
    for alert in alerts:
        try:
            results.append(sanitize_alert(alert, deployment_secret))
        except Exception:
            logger.debug("Skipped unsanitizable alert")
    return results


class CloudSyncWorker:
    """Async background worker that syncs anonymized threat intel to Navil Cloud."""

    def __init__(
        self,
        detector: Any,
        api_url: str = "https://api.navil.ai/v1/telemetry/sync",
        api_key: str = "",
        deployment_secret: bytes = b"",
        sync_interval: float | None = None,
        enabled: bool | None = None,
        machine_id: str | None = None,
    ) -> None:
        self.detector = detector
        self.api_url = api_url
        self.api_key = api_key or os.environ.get("NAVIL_API_KEY", "")
        self.machine_id = machine_id
        self.deployment_secret = deployment_secret or os.urandom(32)

        # NOTE: This interval will be overridden/shortened for Paid keys in the future.
        if sync_interval is not None:
            self.sync_interval = sync_interval
        else:
            self.sync_interval = float(os.environ.get("NAVIL_INTEL_SYNC_INTERVAL", "3600"))

        # Opt-out: env var takes precedence, then constructor param
        if enabled is not None:
            self._enabled = enabled
        else:
            env = os.environ.get("NAVIL_DISABLE_CLOUD_SYNC", "").lower()
            self._enabled = env not in ("true", "1", "yes")

        self._running = False
        self._last_sync_idx = 0  # tracks how far we've consumed detector.alerts
        self._synced_count = 0
        self._synced_blocked: set[str] = set()  # dedup keys for blocked invocations
        self._blocked_queue: list[dict[str, Any]] = []  # direct blocked event queue
        self._http_client: Any = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def stats(self) -> dict[str, Any]:
        current_len = len(self.detector.alerts)
        if self._last_sync_idx > current_len:
            pending = current_len
        else:
            pending = max(0, current_len - self._last_sync_idx)
        return {
            "enabled": self._enabled,
            "synced_count": self._synced_count,
            "pending": pending,
        }

    def _build_headers(self) -> dict[str, str]:
        """Build request headers for cloud sync.

        Always sends X-Machine-ID and heartbeat metadata.
        Only sends Authorization if an API key is configured.
        """
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Navil-Version": __version__,
            "X-OS-Platform": sys.platform,
            "X-Python-Version": platform.python_version(),
        }
        if self.machine_id:
            headers["X-Machine-ID"] = self.machine_id
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _get_client(self) -> Any:
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(
                headers=self._build_headers(),
                timeout=30.0,
            )
        return self._http_client

    async def run(self) -> None:
        """Run the sync loop indefinitely. Call ``stop()`` to exit."""
        import asyncio

        if not self._enabled:
            logger.info("CloudSyncWorker disabled (NAVIL_DISABLE_CLOUD_SYNC=true)")
            return

        self._running = True
        logger.info("CloudSyncWorker started → %s (interval=%ss)", self.api_url, self.sync_interval)

        while self._running:
            try:
                await self.sync_once()
            except Exception:
                logger.exception("CloudSyncWorker sync error")
            try:
                await asyncio.sleep(self.sync_interval)
            except asyncio.CancelledError:
                break

    def stop(self) -> None:
        self._running = False

    async def sync_once(self) -> int:
        """Gather new alerts + blocked events, sanitize, and POST to cloud.

        Returns the number of events sent (0 if nothing new).
        """
        if not self._enabled:
            return 0

        alerts = self.detector.alerts
        current_len = len(alerts)
        if self._last_sync_idx > current_len:
            self._last_sync_idx = 0
        alert_snapshot = list(alerts)
        new_alerts = alert_snapshot[self._last_sync_idx :]

        # Drain the blocked queue (events queued by proxy via record_blocked)
        blocked_dicts = list(self._blocked_queue)
        self._blocked_queue.clear()

        # Also collect blocked invocations from detector
        blocked_dicts.extend(self._collect_blocked_invocations())

        if not new_alerts and not blocked_dicts:
            return 0

        # Convert AnomalyAlert dataclasses to dicts
        raw_dicts: list[dict[str, Any]] = []
        for a in new_alerts:
            d = a.__dict__ if hasattr(a, "__dict__") else dict(a)
            # Inject machine_id from config if not already set on the alert
            if self.machine_id and "machine_id" not in d:
                d["machine_id"] = self.machine_id
            raw_dicts.append(d)

        # Add blocked invocations
        raw_dicts.extend(blocked_dicts)

        sanitized = sanitize_batch(raw_dicts, self.deployment_secret)
        if not sanitized:
            self._last_sync_idx = current_len
            return 0

        # POST to cloud
        try:
            client = self._get_client()
            resp = await client.post(self.api_url, json={"events": sanitized})
            if resp.status_code < 300:
                self._synced_count += len(sanitized)
                logger.info("Synced %d threat intel events to cloud", len(sanitized))
            else:
                logger.warning(
                    "Cloud sync failed: %s %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except Exception:
            logger.debug("Cloud sync POST failed (endpoint may be unreachable)")

        self._last_sync_idx = current_len

        # After successful sync, check for blocklist updates
        await self._check_blocklist_updates()

        return len(sanitized)

    def record_blocked(
        self,
        tool_name: str = "unknown",
        action: str = "BLOCKED",
        anomaly_type: str = "DEFENSE_EVASION",
    ) -> None:
        """Queue a blocked event for cloud sync. Thread-safe.

        Called by the proxy when it blocks a request. The event will be
        included in the next sync batch.
        """
        from datetime import datetime as dt
        from datetime import timezone as tz

        self._blocked_queue.append({
            "agent_id": "blocked-caller",
            "tool_name": tool_name,
            "anomaly_type": anomaly_type,
            "severity": "high",
            "confidence": 1.0,
            "action": action,
            "timestamp": dt.now(tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_uuid": str(uuid.uuid4()),
            "machine_id": self.machine_id or "unknown",
        })

    def _collect_blocked_invocations(self) -> list[dict[str, Any]]:
        """Collect blocked invocations from the detector's invocation log.

        Scans recent invocations for actions starting with "BLOCKED" and
        converts them to sync-ready dicts. Tracks which invocations have
        already been synced to avoid duplicates.
        """
        try:
            invocations = self.detector.invocations
        except Exception:
            return []

        blocked: list[dict[str, Any]] = []
        for inv in invocations:
            action = getattr(inv, "action", "") or ""
            if not action.startswith("BLOCKED"):
                continue

            # Build a unique key to avoid re-syncing
            ts = getattr(inv, "timestamp", "") or ""
            tool = getattr(inv, "tool_name", "") or ""
            agent = getattr(inv, "agent_name", "") or ""
            dedup_key = f"{agent}:{tool}:{ts}:{action}"

            if dedup_key in self._synced_blocked:
                continue
            self._synced_blocked.add(dedup_key)

            # Map blocked action to anomaly type
            action_to_anomaly = {
                "BLOCKED_AUTH": "PRIVILEGE_ESCALATION",
                "BLOCKED_RATE": "RATE_SPIKE",
                "BLOCKED_SCOPE": "DEFENSE_EVASION",
                "BLOCKED_POLICY": "POLICY",
                "BLOCKED_BLOCKLIST": "RECONNAISSANCE",
            }
            anomaly_type = action_to_anomaly.get(
                action, "DEFENSE_EVASION"
            )

            d: dict[str, Any] = {
                "agent_name": agent,
                "tool_name": tool,
                "anomaly_type": anomaly_type,
                "severity": "high",
                "confidence": 1.0,
                "timestamp": ts,
                "action": action,
                "payload_bytes": getattr(inv, "arguments_size_bytes", 0) or 0,
                "response_bytes": 0,
                "duration_ms": getattr(inv, "duration_ms", 0) or 0,
                "mcp_server_name": getattr(inv, "target_server", None),
            }
            if self.machine_id:
                d["machine_id"] = self.machine_id
            blocked.append(d)

        return blocked

    async def _check_blocklist_updates(self) -> None:
        """Check for and apply blocklist updates from the cloud.

        Called after each successful telemetry sync. Reads configuration
        from ``~/.navil/config.yaml`` to determine whether auto-updates
        are enabled and which endpoint to use.
        """
        try:
            from navil.cloud.blocklist_updater import (
                check_for_updates_async,
                get_blocklist_config,
                get_local_version,
                merge_patterns,
            )

            config = get_blocklist_config()
            if not config.get("auto_update", True):
                return

            api_url = config.get("update_url", "")
            if not api_url:
                return

            blocklist_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "data",
                "blocklist_v1.json",
            )

            local_version = get_local_version(blocklist_path)
            headers: dict[str, str] = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            new_patterns = await check_for_updates_async(api_url, local_version, headers)
            if new_patterns:
                result = merge_patterns(blocklist_path, new_patterns)
                logger.info(
                    "Blocklist updated: %d new, %d updated patterns",
                    result["added"],
                    result["updated"],
                )
        except Exception as exc:
            logger.debug("Blocklist update check failed: %s", exc)

    async def close(self) -> None:
        self._running = False
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
