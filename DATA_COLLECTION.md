# Navil Data Collection & Privacy

This document explains exactly what data the Navil gateway collects, what leaves your machine, and how to opt out. Written for developers who want full transparency — no legalese.

## TL;DR

- Navil **never** sends raw prompts, tool arguments, file paths, server URLs, agent names, IP addresses, or email addresses to the cloud.
- Cloud sync sends only anonymized metadata: anomaly type, severity, confidence, tool name, timing, and byte counts.
- Agent identities are one-way HMAC-SHA256 hashed — irreversible, unique per deployment.
- Opt out entirely: `NAVIL_DISABLE_CLOUD_SYNC=true`.
- Audit what's sent: inspect [`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py).

## What Stays Local (Never Leaves Your Machine)

| Data | Where It Lives | Retention |
|------|---------------|-----------|
| MCP request/response payloads | In-memory only (proxy hot path) | Discarded after forwarding |
| Tool arguments & results | In-memory (anomaly detection) | Discarded after analysis |
| Agent names | Local Redis | Session duration |
| File paths, prompts, raw content | Never stored | N/A |
| Your MCP server URLs | Local config only | Until you change them |
| Anomaly detection baselines (EMA) | Local Redis | Persistent |
| Learned behavior patterns | Local Redis / PatternStore | Persistent |

## What Gets Sent to Navil Cloud (When Sync Is Enabled)

The `CloudSyncWorker` ([`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py)) runs every 60 seconds and sends **only** fields on an explicit allowlist. Every outgoing payload is validated at runtime — if a banned field leaks through, a `ValueError` is raised and the sync aborts.

### Allowlisted Fields

```
agent_id              → HMAC-SHA256 hash (NOT the agent name)
tool_name             → e.g. "read_file", "query_db"
anomaly_type          → e.g. "payload_size_spike", "rapid_fire"
severity              → CRITICAL / HIGH / MEDIUM / LOW / INFO
confidence            → 0.0 – 1.0
statistical_deviation → how far from the EMA baseline
payload_bytes         → request size (number only)
response_bytes        → response size (number only)
duration_ms           → call duration
timestamp             → ISO 8601 UTC
action                → "forwarded" or "blocked"
event_uuid            → deterministic UUID5 for dedup
tool_sequence_hash    → SHA-256 of the tool call sequence
```

### Banned Fields (Runtime Enforced)

These fields are **explicitly blocked** with a runtime `ValueError` check:

```
agent_name, description, evidence, recommended_action,
target_server, location, arguments_hash, arguments,
params, raw, content, prompt, ip_address, email
```

### Sanitization Process

1. **Agent name → HMAC-SHA256** using a per-deployment secret (auto-generated on first run). Same agent produces the same hash within your deployment but different hashes across deployments. Cannot be reversed.
2. **Numeric metadata copied** — severity, confidence, timing, byte counts.
3. **Tool sequences hashed** — the order of tool calls is SHA-256 hashed for pattern matching without revealing the actual sequence.
4. **Event UUID generated** — deterministic UUID5 for cloud-side deduplication.
5. **Banned field check** — final validation that no prohibited field made it through.

## What the Cloud Backend Stores

When your data reaches `api.navil.ai`, additional privacy measures apply:

- **IP addresses** are SHA-256 hashed (truncated to 16 chars) before writing to the database. Raw IPs are never stored.
- **Telemetry events** are auto-deleted after **30 days**.
- **Sync events** (threat intelligence) are auto-deleted after **7 days**.
- **No email addresses** are included in telemetry. The proxy strips `human_email` from all telemetry events before they're generated.

## Proxy Header Injection

When the Navil proxy forwards requests to MCP servers, it adds identity headers for audit trails:

| Header | Value | Purpose |
|--------|-------|---------|
| `x-agent-name` | Raw agent name | MCP server identifies the calling agent |
| `x-human-identity` | OIDC `sub` claim | Pseudonymous human audit trail |
| `x-delegation-depth` | Number | Depth of delegation chain |

**Not forwarded:** `x-human-email` — email addresses are never sent to upstream MCP servers.

## How to Opt Out

```bash
# Disable cloud sync entirely (no data leaves your machine)
export NAVIL_DISABLE_CLOUD_SYNC=true

# Or disable in your MCP config
{
  "env": {
    "NAVIL_DISABLE_CLOUD_SYNC": "true"
  }
}
```

With cloud sync disabled:
- All 12 anomaly detectors still run locally.
- The adaptive EMA baselines still learn from your traffic.
- You lose access to the global threat blocklist (community feed).
- Paid tier (`NAVIL_API_KEY`) users can disable sync and still receive threat intel.

## How to Audit

1. **Read the code:** [`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py) — the `ALLOWED_FIELDS` frozenset and `BANNED_FIELDS` frozenset are the canonical source of truth.
2. **Inspect outgoing payloads:** Set `NAVIL_LOG_LEVEL=DEBUG` and look for `CloudSyncWorker` log entries.
3. **Network inspection:** The only outbound endpoint is `POST https://api.navil.ai/v1/telemetry/sync`. No other cloud calls are made except `GET /v1/threat-intel/patterns` (receiving blocklist updates).

## Community Tier: Give-to-Get

Community tier users contribute anonymized threat data in exchange for access to the global blocklist. This is the default behavior. If you don't want to contribute, you have two options:

1. **Disable cloud sync** (`NAVIL_DISABLE_CLOUD_SYNC=true`) — you lose blocklist access.
2. **Upgrade to Pro+ ($49/mo)** — you get blocklist access without contributing ("privacy premium").

## Questions?

Open an issue or email privacy@navil.dev.
