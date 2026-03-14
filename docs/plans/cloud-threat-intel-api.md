# Cloud Threat Intelligence API — Backend Build Prompt

## Context

Navil is an open-source MCP security gateway. The OSS repo has two client-side components that need a cloud backend:

**1. Outbound (Give):** `CloudSyncWorker` (`navil/cloud/telemetry_sync.py`) periodically POSTs sanitized anomaly alerts to `POST /v1/telemetry/sync`. Alerts are stripped of all PII via `sanitize_alert()` — only HMAC-anonymized agent IDs, tool names, anomaly types, severity, and numeric metrics survive. Auth: `Authorization: Bearer {NAVIL_API_KEY}`.

**2. Inbound (Get):** `ThreatIntelConsumer` (`navil/threat_intel.py`) listens on Redis pub/sub channel `navil:threat_intel:inbound` for `ThreatIntelEntry` objects with two landing zones:
- `entry_type="blocklist"` → HSET `blocked=1` on agent threshold key (Rust proxy blocks in O(1))
- `entry_type="pattern"` → `PatternStore.add_community_pattern()` (anomaly detector confidence boost)

**Give-to-Get enforcement (already implemented client-side):**
- Community mode (no API key): must share to receive. If `NAVIL_DISABLE_CLOUD_SYNC=true`, the consumer refuses to start.
- Paid mode (`NAVIL_API_KEY` set): always receives intel regardless of sync setting ("privacy premium").

**PatternStore format** — each pattern is a `LearnedPattern`:
```python
{
    "pattern_id": "community_exfil_001",
    "anomaly_type": "DATA_EXFILTRATION",  # one of 11 SAFE-MCP types
    "description": "Bulk read followed by external upload",
    "features": {
        "tool_sequence": ["read_all", "upload"],
        "avg_data_volume": 50000,
        "tool_count": 2
    },
    "created_at": "2026-01-01T00:00:00+00:00",
    "match_count": 0,
    "confidence_boost": 0.3,
    "source": "community"
}
```

The 11 SAFE-MCP anomaly types: `RECONNAISSANCE`, `PERSISTENCE`, `DEFENSE_EVASION`, `LATERAL_MOVEMENT`, `COMMAND_AND_CONTROL`, `SUPPLY_CHAIN`, `RUG_PULL`, `DATA_EXFILTRATION`, `PRIVILEGE_ESCALATION`, `RATE_SPIKE`, `POLICY`.

## What to Build

A FastAPI service that acts as the cloud-side hub for the Give-to-Get threat intelligence exchange. It has three jobs:

### Job 1: Ingest — Receive sanitized alerts from deployments

The `POST /v1/telemetry/sync` endpoint already exists conceptually (the client POSTs to it). Build it:

- Validate the API key from `Authorization: Bearer` header
- Accept `{"events": [...]}` where each event has only the allowlisted fields (`agent_id`, `tool_name`, `anomaly_type`, `severity`, `confidence`, `statistical_deviation`, `payload_bytes`, `response_bytes`, `duration_ms`, `timestamp`, `action`)
- **Defence-in-depth:** Server-side re-validation — reject any event containing banned fields (`agent_name`, `description`, `evidence`, `recommended_action`, `target_server`, `location`, `arguments`, `params`, `raw`, `content`, `prompt`, `ip_address`, `email`)
- Store raw events in the `events` table (already modeled in `navil/cloud/models.py`)
- Track last sync timestamp per API key for Give-to-Get enforcement
- Return `{"accepted": N, "rejected": M}`

### Job 2: Aggregate — Extract patterns from cross-deployment alert clusters

Background job (APScheduler or similar) that runs periodically:

- Query recent alerts across all deployments
- Cluster by `(anomaly_type, tool_name)` tuples
- When a cluster reaches a **quorum threshold** (e.g., 3+ distinct deployments reporting the same anomaly type + tool combination within 24h), auto-generate a `ThreatPattern`:
  - `pattern_id`: deterministic hash of the cluster key
  - `anomaly_type`: from the cluster
  - `features.tool_sequence`: extracted from the cluster's tool names
  - `features.avg_data_volume`: mean of `payload_bytes` across the cluster
  - `confidence_boost`: scaled by cluster size (more reporters = higher confidence)
  - `source`: `"community"`
- Deduplicate: if a pattern with the same `pattern_id` already exists, update `match_count` and recalculate `confidence_boost` — don't create duplicates
- The 33 seed patterns (previously in `navil/data/seed_patterns.json`) should be loaded into this table as the initial dataset with `source="seed"`

### Job 3: Serve — Deliver patterns to subscribers

`GET /v1/threat-intel/patterns`

- Auth: `Authorization: Bearer {NAVIL_API_KEY}`
- **Give-to-Get enforcement (server-side):**
  - Check when this API key last synced (from Job 1 tracking)
  - If `last_sync_at` is NULL or older than 7 days → return `403` with message: `"Community tier requires active threat sharing. Last sync: never. POST to /v1/telemetry/sync to contribute."`
  - Paid keys (flagged in API key table) bypass this check
- Query params:
  - `?since=<ISO timestamp>` — only return patterns created/updated after this time (for incremental sync)
  - `?anomaly_type=<type>` — filter by anomaly type
  - `?min_confidence=<float>` — filter by minimum confidence_boost
- Response: `{"patterns": [...], "total": N, "as_of": "<ISO timestamp>"}`
  - Each pattern in `LearnedPattern` format (see above) so the client can directly construct `LearnedPattern(**p)`
- Cap response at 500 patterns per request (paginate with `?offset=`)

### OSS Client Integration Point

After the backend is live, the OSS client needs a lightweight `ThreatIntelFetcher` that:
1. On proxy startup, calls `GET /v1/threat-intel/patterns` to seed the local `PatternStore`
2. Periodically re-fetches (e.g., every hour) with `?since=` for incremental updates
3. Publishes fetched patterns to the `navil:threat_intel:inbound` Redis pub/sub channel so the existing `ThreatIntelConsumer` picks them up
4. This is the only new OSS-side code needed — everything else is already wired.

## Database Models Needed

Add to `navil/cloud/models.py`:

```
ThreatPattern
  - id (PK)
  - pattern_id (unique, varchar 256) — deterministic hash
  - anomaly_type (varchar 128, indexed)
  - description (text)
  - features (text, JSON)
  - confidence_boost (float)
  - match_count (int, default 0) — how many deployments have matched
  - source (varchar 32) — "seed", "community", "curated"
  - quorum_count (int) — number of distinct deployments that contributed
  - created_at (datetime)
  - updated_at (datetime)

PatternContribution
  - id (PK)
  - pattern_id (FK → ThreatPattern)
  - api_key_id (FK → ApiKey)
  - contributed_at (datetime)
  (tracks which deployments contributed to which patterns — for attribution without deanonymization)
```

Extend `ApiKey` with:
- `last_sync_at` (datetime, nullable) — last time this key POSTed to /v1/telemetry/sync
- `tier` (varchar 16, default "community") — "community" or "paid"

## Non-Functional Requirements

- **Privacy:** The cloud NEVER stores raw agent names, prompts, or tool arguments. Only the allowlisted fields. Server-side re-validation is mandatory even though the client sanitizes.
- **Rate limiting:** 100 req/min per API key on ingest, 10 req/min on pattern fetch.
- **Latency:** Pattern fetch must respond in <200ms (it's called on proxy startup).
- **Idempotency:** Re-POSTing the same sync batch should not create duplicate events (use `(api_key_id, timestamp, agent_id, tool_name)` as a natural dedup key).
