# Cloud Threat Intelligence API — Backend Build Prompt

## Context

Navil is an open-source MCP security gateway. The OSS repo (`navilai/navil`) has three client-side components that talk to this cloud backend:

### 1. Outbound (Give): `CloudSyncWorker`

**File:** `navil/cloud/telemetry_sync.py`

Periodically POSTs sanitized anomaly alerts to `POST /v1/telemetry/sync`.

- Auth: `Authorization: Bearer {NAVIL_API_KEY}`
- Alerts are stripped of all PII via `sanitize_alert()` before transmission
- Each event includes a **deterministic `event_uuid`** (UUID5 derived from `agent_id:tool_name:timestamp:anomaly_type`) — the backend MUST use this as the idempotency/dedup key
- Events optionally include `tool_sequence_hash` (SHA-256 of the tool execution chain) — the backend uses this for higher-fidelity pattern clustering

**Allowlisted fields per event:**
```
agent_id, tool_name, anomaly_type, severity, confidence,
statistical_deviation, payload_bytes, response_bytes,
duration_ms, timestamp, action, event_uuid, tool_sequence_hash
```

**Banned fields (reject if present — defence-in-depth):**
```
agent_name, description, evidence, recommended_action,
target_server, location, arguments, arguments_hash,
params, raw, content, prompt, ip_address, email
```

### 2. Inbound (Get): `ThreatIntelFetcher`

**File:** `navil/cloud/threat_intel_fetcher.py` (already built in OSS)

Polls `GET /v1/threat-intel/patterns` from this backend and publishes patterns to local Redis pubsub channel `navil:threat_intel:inbound`.

- Auth: `Authorization: Bearer {NAVIL_API_KEY}`
- Initial fetch on proxy startup (seeds the local PatternStore)
- Incremental sync via `?since=<ISO timestamp>` using the `as_of` cursor from previous response
- Also accepts `?limit=500` (default page size)
- On 403, logs warning and retries next interval (Give-to-Get enforcement)
- Publishes each pattern as a `ThreatIntelEntry` with `entry_type="pattern"` and `source="navil-cloud"`

### 3. Inbound (Get): `ThreatIntelConsumer`

**File:** `navil/threat_intel.py`

Listens on Redis pubsub channel `navil:threat_intel:inbound` for `ThreatIntelEntry` objects. Two landing zones:
- `entry_type="blocklist"` → HSET `blocked=1` on agent threshold key (Rust proxy blocks in O(1))
- `entry_type="pattern"` → `PatternStore.add_community_pattern()` (anomaly detector confidence boost)

### Give-to-Get enforcement (client-side, already implemented)

- Community mode (no API key): must share to receive. If `NAVIL_DISABLE_CLOUD_SYNC=true`, the consumer refuses to start.
- Paid mode (`NAVIL_API_KEY` set): always receives intel regardless of sync setting ("privacy premium").

### PatternStore format

Each pattern is a `LearnedPattern` — the backend response MUST use this exact schema so the client can construct `LearnedPattern(**p)` directly:

```json
{
    "pattern_id": "community_exfil_001",
    "anomaly_type": "DATA_EXFILTRATION",
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

A FastAPI service that acts as the cloud-side hub for the Give-to-Get threat intelligence exchange. Three jobs:

### Job 1: Ingest — Receive sanitized alerts from deployments

`POST /v1/telemetry/sync`

- Validate the API key from `Authorization: Bearer` header
- Accept `{"events": [...]}` where each event has only the allowlisted fields (see above)
- **Defence-in-depth:** Server-side re-validation — reject any event containing banned fields (see above)
- **Deduplication:** Use `event_uuid` as the primary dedup key — `INSERT ON CONFLICT (event_uuid) DO NOTHING`. The `event_uuid` is deterministic (same alert always produces the same UUID), so re-POSTing is safe.
- **Pattern clustering hint:** When `tool_sequence_hash` is present, store it — the aggregation job uses it for grouping events that share the same tool execution chain
- Track `last_sync_at` timestamp per API key for Give-to-Get enforcement
- Return `{"accepted": N, "rejected": M}`

### Job 2: Aggregate — Extract patterns from cross-deployment alert clusters

Background job (APScheduler or similar) that runs every 10 minutes:

- Query recent sync events across all deployments
- **Primary clustering:** Group by `(anomaly_type, tool_sequence_hash)` when `tool_sequence_hash` is available — this gives exact tool-chain matches across deployments
- **Fallback clustering:** Group by `(anomaly_type, tool_name)` when no hash is available
- When a cluster reaches a **quorum threshold** (3+ distinct API keys reporting the same cluster within 24h), auto-generate a `ThreatPattern`:
  - `pattern_id`: deterministic hash of the cluster key (so re-runs don't create duplicates)
  - `anomaly_type`: from the cluster
  - `features.tool_sequence`: extracted from the cluster's tool names
  - `features.avg_data_volume`: mean of `payload_bytes` across the cluster
  - `confidence_boost`: scaled by cluster size (more reporters = higher confidence, cap at 0.5)
  - `source`: `"community"`
- Deduplicate: if a pattern with the same `pattern_id` already exists, update `match_count` and recalculate `confidence_boost` — don't create duplicates
- **Seed data:** Load the 33 seed patterns (previously shipped in `navil/data/seed_patterns.json` — now removed from OSS) into this table as the initial dataset with `source="seed"`. These cover all 11 SAFE-MCP attack types and provide baseline threat intelligence before any deployment has contributed data. The seed patterns JSON is available in the OSS repo's git history at commit `e96f7c5`.

### Job 3: Serve — Deliver patterns to subscribers

`GET /v1/threat-intel/patterns`

- Auth: `Authorization: Bearer {NAVIL_API_KEY}`
- **Give-to-Get enforcement (server-side):**
  - Check when this API key last synced (from Job 1 tracking)
  - If `last_sync_at` is NULL or older than 7 days → return `403` with body:
    ```json
    {"detail": "Community tier requires active threat sharing. Last sync: never. POST to /v1/telemetry/sync to contribute."}
    ```
  - Paid keys (`tier="paid"` in API key table) bypass this check
- Query params:
  - `?since=<ISO timestamp>` — only return patterns created/updated after this time (the OSS `ThreatIntelFetcher` sends this as the `as_of` cursor from the previous response)
  - `?anomaly_type=<type>` — filter by anomaly type
  - `?min_confidence=<float>` — filter by minimum confidence_boost
  - `?limit=<int>` — max patterns per response (default 500)
  - `?offset=<int>` — pagination offset
- Response format (must match exactly — the OSS client parses this):
  ```json
  {
      "patterns": [{"pattern_id": "...", "anomaly_type": "...", ...}],
      "total": 142,
      "as_of": "2026-03-15T12:00:00+00:00"
  }
  ```
  - Each pattern in `LearnedPattern` format (see above)
  - `as_of` is the server timestamp of this response — the client stores it and sends it as `?since=` on the next request

## Database Models

### New tables

```sql
CREATE TABLE threat_patterns (
    id SERIAL PRIMARY KEY,
    pattern_id VARCHAR(256) UNIQUE NOT NULL,
    anomaly_type VARCHAR(128) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    features TEXT NOT NULL DEFAULT '{}',           -- JSON
    confidence_boost FLOAT NOT NULL DEFAULT 0.2,
    match_count INT NOT NULL DEFAULT 0,
    source VARCHAR(32) NOT NULL DEFAULT 'community',  -- "seed", "community", "curated"
    quorum_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_threat_patterns_anomaly ON threat_patterns (anomaly_type);
CREATE INDEX ix_threat_patterns_updated ON threat_patterns (updated_at);

CREATE TABLE sync_events (
    id SERIAL PRIMARY KEY,
    event_uuid VARCHAR(36) UNIQUE NOT NULL,        -- dedup key from client
    api_key_id INT NOT NULL REFERENCES api_keys(id),
    agent_id VARCHAR(64) NOT NULL,                 -- HMAC-anonymized
    tool_name VARCHAR(256),
    anomaly_type VARCHAR(128),
    severity VARCHAR(16),
    confidence FLOAT,
    statistical_deviation FLOAT,
    payload_bytes INT,
    response_bytes INT,
    duration_ms INT,
    timestamp VARCHAR(64),
    action VARCHAR(256),
    tool_sequence_hash VARCHAR(64),                -- optional SHA-256
    received_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_sync_events_api_key ON sync_events (api_key_id);
CREATE INDEX ix_sync_events_anomaly_tool ON sync_events (anomaly_type, tool_name);
CREATE INDEX ix_sync_events_seq_hash ON sync_events (tool_sequence_hash) WHERE tool_sequence_hash IS NOT NULL;
CREATE INDEX ix_sync_events_received ON sync_events (received_at);

CREATE TABLE pattern_contributions (
    id SERIAL PRIMARY KEY,
    pattern_id INT NOT NULL REFERENCES threat_patterns(id),
    api_key_id INT NOT NULL REFERENCES api_keys(id),
    contributed_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Extend existing `api_keys` table

```sql
ALTER TABLE api_keys ADD COLUMN last_sync_at TIMESTAMP;
ALTER TABLE api_keys ADD COLUMN tier VARCHAR(16) NOT NULL DEFAULT 'community';
```

## Data Flow (Complete Loop)

```
OSS Deployment
├── Anomaly detected by BehavioralAnomalyDetector
├── CloudSyncWorker.sanitize_alert()
│   ├── Strips PII (HMAC agent names, drop descriptions/evidence)
│   ├── Generates deterministic event_uuid (UUID5)
│   └── Hashes tool_sequence if available (SHA-256)
├── POST /v1/telemetry/sync  ─────────────────────────►  Cloud Backend
│                                                         ├── Validate API key
│                                                         ├── Reject banned fields
│                                                         ├── INSERT ON CONFLICT (event_uuid) DO NOTHING
│                                                         └── Update api_keys.last_sync_at
│
│   (every 10 min)                                        Pattern Aggregator
│                                                         ├── Cluster by (anomaly_type, tool_sequence_hash)
│                                                         ├── Quorum ≥ 3 deployments → create ThreatPattern
│                                                         └── Dedup by pattern_id
│
├── ThreatIntelFetcher (every hour + on startup)
│   GET /v1/threat-intel/patterns?since=<cursor>  ◄──────  Cloud Backend
│                                                         ├── Check Give-to-Get (last_sync_at < 7d ago?)
│                                                         ├── Query threat_patterns WHERE updated_at > since
│                                                         └── Return LearnedPattern JSON + as_of cursor
│
├── redis.publish("navil:threat_intel:inbound", entry)
├── ThreatIntelConsumer.apply_entry()
└── PatternStore.add_community_pattern() → confidence boost
```

## Non-Functional Requirements

- **Privacy:** The cloud NEVER stores raw agent names, prompts, or tool arguments. Only the allowlisted fields. Server-side re-validation is mandatory even though the client sanitizes.
- **Rate limiting:** 100 req/min per API key on ingest, 10 req/min on pattern fetch.
- **Latency:** Pattern fetch must respond in <200ms (it's called on proxy startup).
- **Idempotency:** `event_uuid` is the dedup key. `INSERT ON CONFLICT (event_uuid) DO NOTHING`.
- **Seed data:** The 33 seed patterns must be loaded on first deploy. They are the baseline threat intelligence that makes the system useful before any deployment has contributed data.

## Environment Variables (Backend)

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | required | PostgreSQL connection string |
| `AGGREGATION_INTERVAL_SECONDS` | `600` | How often the pattern aggregator runs |
| `QUORUM_THRESHOLD` | `3` | Minimum distinct API keys for pattern creation |
| `QUORUM_WINDOW_HOURS` | `24` | Time window for quorum counting |
| `GIVE_TO_GET_MAX_STALENESS_DAYS` | `7` | Max days since last sync before 403 |
