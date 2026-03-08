# Architecture

Navil is a **Rust/Python hybrid** security gateway for the Model Context Protocol (MCP). The system follows an open-core SaaS model: a high-performance Rust data plane handles live traffic, while a Python control plane runs heavy ML detection, LLM analysis, and fleet management.

## System Overview

```
                         Agents (Claude, GPT, custom)
                                    |
                                    v
                    +-------------------------------+
                    |     Rust Data Plane (Axum)    |   Port 8080
                    |  O(1) threshold gate + HMAC   |
                    |  JSON sanitization + depth    |
                    |  Rate limiting (Redis INCR)   |
                    +---------|----------|----------+
                     BLOCKED  |          | FORWARDED
                     (429)    |          v
                              |    MCP Server(s)
                              |
              LPUSH telemetry |
                              v
                    +-------------------+
                    |      Redis        |   Port 6379
                    |  Threshold hashes |
                    |  Rate counters    |
                    |  Telemetry queue  |
                    +---------|--------+
                              |
                    BRPOP     |     HMGET/HSET
                              v
                    +-------------------------------+
                    |   Python Control Plane        |   Port 8484
                    |  TelemetryWorker (consumer)   |
                    |  BehavioralAnomalyDetector     |
                    |  12 statistical detectors      |
                    |  Adaptive EMA baselines        |
                    |  LLM analysis (SSE streaming) |
                    |  Cloud dashboard (React)      |
                    +-------------------------------+
                              |
                     HMAC-SHA256 anonymized
                              v
                    +-------------------+
                    |  Navil Cloud API  |   (optional)
                    |  Threat intel     |
                    |  Fleet telemetry  |
                    +-------------------+
```

## Data Plane: Rust Proxy

**Location:** `navil-proxy/src/main.rs`
**Stack:** Axum 0.8, Reqwest 0.12, Tokio, Redis 0.27, HMAC-SHA256

The Rust proxy sits in front of MCP servers and processes every JSON-RPC request on the hot path. It is designed for sub-millisecond overhead.

### Request Flow

1. **Sanitize** -- Reject payloads over 5 MB, parse JSON, enforce depth limit of 10 levels, re-serialize compact (strips whitespace padding attacks).
2. **HMAC verify** -- If `NAVIL_HMAC_SECRET` is set, validate `X-Navil-Signature` header using constant-time HMAC-SHA256.
3. **Agent identity** -- Read `X-Agent-Name` header.
4. **O(1) threshold check** (only for `tools/call`) -- Single Redis `HMGET` reads three pre-computed fields from `navil:agent:{name}:thresholds`:

   | Field | Default | Meaning |
   |-------|---------|---------|
   | `max_payload_bytes` | 10 MB | Hard payload cap |
   | `rate_limit_per_min` | 120 | Per-agent rate limit |
   | `blocked` | false | Kill-switch set on CRITICAL alerts |

   Rate limiting uses minute-bucketed `INCR` + `EXPIRE(120s)` counters.

5. **Forward** -- Proxy the request to the upstream MCP server via Reqwest, preserving `mcp-session-id` headers.
6. **Telemetry** -- Fire-and-forget `LPUSH` to `navil:telemetry:queue` with request metadata (agent, tool, duration, bytes, action). Never blocks the response.

### Fail-Open Policy

If Redis is unavailable, the proxy uses hardcoded defaults and allows traffic through. Telemetry failures are logged as warnings but never block requests.

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NAVIL_TARGET_URL` | `http://localhost:3000` | Upstream MCP server |
| `NAVIL_REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection |
| `NAVIL_HMAC_SECRET` | *(none)* | HMAC signing key (optional) |
| `NAVIL_PORT` | `8080` | Proxy listen port |
| `RUST_LOG` | `navil_proxy=info` | Tracing log level |

## Control Plane: Python

**Location:** `navil/` (core), `navil/cloud/` (API + dashboard)
**Stack:** FastAPI, httpx, orjson, Redis (async), React

The Python side handles everything too expensive for the hot path: statistical anomaly detection, ML baselines, LLM analysis, and the management dashboard.

### TelemetryWorker (Redis Bridge)

**Location:** `navil/telemetry_worker.py`

The worker is a long-running async loop that bridges the Rust data plane to the Python detection pipeline:

```
Redis queue (BRPOP) --> parse JSON event --> detector.record_invocation_async()
                                                |
                                                +--> Run 12 anomaly detectors
                                                +--> Update adaptive EMA baselines
                                                +--> Recompute thresholds
                                                +--> HSET back to Redis
```

This creates a feedback loop: the Rust proxy reads thresholds that the Python detectors continuously refine based on observed behavior.

### BehavioralAnomalyDetector

**Location:** `navil/anomaly_detector.py`

The detector maintains per-agent statistical baselines and runs 12 detection methods on every invocation:

| Detector | Tactic | Severity | Trigger |
|----------|--------|----------|---------|
| Reconnaissance | `tools/list` probing | MEDIUM | >5 list calls in 10 min |
| Persistence | Bot-like reconnection | HIGH | Regular intervals (std_dev < 3s) |
| Defense Evasion | Encoded payloads | HIGH | Arguments > 5 KB |
| Lateral Movement | Cross-server chaining | HIGH | >3 distinct servers in 5 min |
| C2 Beaconing | Command & control | CRITICAL | Regular timing + small responses |
| Supply Chain | Unregistered tools | CRITICAL | Tool not in server's `tools/list` |
| Rug Pull | Sudden behavior shift | HIGH | >3 new tools not in baseline |
| Data Exfiltration | Volume spike | CRITICAL | >5x baseline data volume |
| Privilege Escalation | Sensitive tool access | CRITICAL | First-time admin tool use |
| Rate Spike | Call burst | MEDIUM | >3x baseline rate |
| Geographic Anomaly | Location shift | MEDIUM | New location for agent |
| Time Anomaly | Off-hours access | LOW | Access outside normal window |

#### Two-Phase Detection

**Phase 1 -- Hot path (O(1), in proxy):**
`check_fast()` reads pre-computed thresholds from Redis. Three integer comparisons: blocked flag, payload size, rate count. Microsecond latency.

**Phase 2 -- Background (off hot path, in worker):**
`record_invocation_async()` runs the full detection suite, updates adaptive EMA baselines, recomputes thresholds, and syncs them back to Redis for the next Phase 1 check.

### Adaptive Baselines

**Location:** `navil/adaptive/`

Each agent gets an `AgentAdaptiveBaseline` that tracks four exponential moving averages (updated in O(1) per invocation):

- **Duration EMA** (alpha=0.1) -- Tool execution time
- **Data volume EMA** (alpha=0.1) -- Bytes per call
- **Rate EMA** (alpha=0.05) -- Invocation frequency (slower adaptation)
- **Success rate EMA** (alpha=0.1) -- Success/failure ratio

Thresholds self-tune via operator feedback:

```
Operator marks alert as false positive
  --> FeedbackLoop.submit_feedback(verdict="dismissed")
  --> compute_adjustments() (needs >= 5 entries)
  --> If FP rate > 50%: loosen thresholds
  --> If FP rate < 20% and TP rate > 50%: tighten thresholds
  --> apply_adjustments_to_baseline()
```

### SSE Streaming + LLM Cache

**Location:** `navil/api/local/routes.py`, `navil/llm/cache.py`

Five LLM endpoints stream responses via Server-Sent Events instead of waiting for full completion:

- `POST /llm/analyze-config`
- `POST /llm/explain-anomaly`
- `POST /llm/generate-policy`
- `POST /llm/refine-policy`
- `POST /llm/suggest-remediation`

Each endpoint checks a SHA-256-keyed LRU cache first. Cache hits return instantly as SSE with `"cached": true`. Cache misses stream chunks from the LLM provider and store the result for future deduplication.

The cache is hybrid: async Redis with TTL expiry for distributed deployments, in-memory `OrderedDict` LRU (max 256 entries, 1-hour TTL) as fallback.

### Cold-Start Seeding

**Location:** `navil/seed.py`

The `navil seed-database` command solves the ML cold-start problem by generating synthetic baseline data:

- Runs 10 SAFE-MCP attack scenarios (all except `policy_bypass`)
- Each scenario runs N times (default 1,000) with **Gaussian fuzzing** on payload sizes, durations, response sizes, and call rates
- Fires up a background mock MCP server for realism
- Feeds data through the full detection pipeline to build statistical baselines

## Redis Key Structure

```
navil:agent:{name}:thresholds    HASH   max_payload_bytes, rate_limit_per_min, blocked
navil:agent:{name}:rate:{bucket} STRING minute-bucketed counter (TTL 120s)
navil:telemetry:queue            LIST   Rust-->Python telemetry events (LPUSH/BRPOP)
navil:llm:cache:{sha256}         STRING Cached LLM responses (TTL 3600s)
```

## Zero-Knowledge Telemetry

When cloud sync is enabled, Navil enforces strict privacy guarantees at the transmission boundary. **No raw agent identities, tool arguments, file paths, or infrastructure topology ever leave the local deployment.**

### Anonymization: HMAC-SHA256

Every agent name is replaced with a one-way HMAC-SHA256 hash before transmission:

```python
agent_id = hmac.new(deployment_secret, agent_name.encode(), sha256).hexdigest()
```

- **One-way:** Cannot reverse to recover the original agent name
- **Deterministic within deployment:** Same agent always maps to the same ID (for correlation)
- **Isolated across deployments:** Different secrets produce different IDs (no cross-org linking)
- **Per-install secret:** Generated with `os.urandom(32)` or provided by the operator

### Strict Allowlist

Only these fields can leave the deployment:

```
agent_id              (HMAC-anonymized)
tool_name
anomaly_type
severity
confidence
statistical_deviation
payload_bytes
response_bytes
duration_ms
timestamp
action
```

### Banned Fields

These fields are **actively blocked** from transmission with a runtime `ValueError` if any leak through:

```
agent_name            (raw identity)
description           (may contain file paths, prompts)
evidence              (raw tool arguments, results)
recommended_action
target_server         (infrastructure topology)
location
arguments_hash, arguments, params, raw, content, prompt
ip_address, email
```

### Defense in Depth

The sanitization pipeline applies four layers:

1. **Anonymize** -- Replace `agent_name` with HMAC hash
2. **Allowlist copy** -- Only copy fields present in `ALLOWED_FIELDS`
3. **Banned field check** -- Raise `ValueError` if any banned field leaked
4. **Final gate** -- Drop anything not explicitly in the allowlist

### Opt-Out

Cloud telemetry sync is entirely optional:

```bash
NAVIL_DISABLE_CLOUD_SYNC=true    # Environment variable
```

Or programmatically: `CloudSyncWorker(enabled=False)`

When disabled, all anomaly detection and threshold computation still runs locally. Only the outbound sync loop is skipped.

## License Boundaries

| Component | License | Directory |
|-----------|---------|-----------|
| Core detectors, proxy, CLI, adaptive ML | Apache 2.0 | `navil/`, `navil/adaptive/`, `navil-proxy/` |
| Cloud dashboard, LLM features, API server | BSL 1.1 | `navil/api/local/`, `navil/llm/`, `dashboard/` |
