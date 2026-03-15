# Proxy Interface Specification

> **Version:** 1.0.0
> **Status:** Normative
> **Audience:** Python proxy team, Rust proxy team, QA

Both the Python proxy (`navil/proxy.py`) and the Rust proxy (`navil-proxy/src/main.rs`) MUST implement this contract for the Navil identity system. Any deviation between the two implementations is a bug.

---

## 1. Transport

| Property | Value |
|---|---|
| Protocol | HTTP/1.1 (minimum) |
| Endpoint | `POST /mcp` |
| Content-Type (request) | `application/json` |
| Content-Type (response) | `application/json` |
| Accept (forwarded) | `application/json, text/event-stream` |
| Health endpoint | `GET /health` |

The proxy is a reverse proxy: it receives JSON-RPC 2.0 requests from agents, applies security checks, and forwards valid requests to the upstream MCP server.

```
Agent --> POST /mcp --> Navil Proxy --> upstream MCP Server
```

---

## 2. Authentication Flow

```
Request arrives at POST /mcp
  |
  +-- Has Authorization: Bearer <JWT>?
  |     |
  |     +-- Yes --> JWT validation path (Section 3)
  |     |             |
  |     |             +-- Valid   --> extract identity from JWT claims
  |     |             +-- Invalid --> reject with -32003 (NEVER fall back to HMAC or X-Agent-Name)
  |     |
  |     +-- No --> Has x-navil-signature header?
  |           |
  |           +-- Yes --> HMAC validation path (Section 4)
  |           |             |
  |           |             +-- Valid   --> extract identity from x-agent-name header
  |           |             +-- Invalid --> reject with -32003
  |           |
  |           +-- No --> Is HMAC secret configured?
  |                 |
  |                 +-- Yes --> reject with -32003 ("Missing HMAC signature")
  |                 +-- No  --> allow as anonymous (agent_name = "anonymous")
```

**Critical rule:** If a `Bearer` token is present in the `Authorization` header but fails validation, the proxy MUST reject the request. It MUST NOT fall back to `x-agent-name` or HMAC. This prevents authentication bypass attacks.

---

## 3. JWT Validation Path

### 3.1 JWT Claims Schema

The JWT payload MUST contain these claims:

| Claim | Type | Required | Description |
|---|---|---|---|
| `token_id` | string | Yes | Credential identifier. Format: `cred_{64_hex_chars}` |
| `agent_name` | string | Yes | Name of the presenting agent |
| `scope` | string | Yes | Space-separated permission tokens (see Section 5) |
| `human_context` | object or null | No | Human identity context from OIDC (see below) |
| `delegation_chain` | string[] | No | Ordered list of ancestor credential IDs, root-first |
| `parent_credential_id` | string or null | No | Immediate parent credential ID |
| `iat` | string | Yes | Issued-at timestamp, ISO 8601 (e.g., `"2026-03-15T10:30:00+00:00"`) |
| `exp` | string | Yes | Expiry timestamp, ISO 8601 (e.g., `"2026-03-15T11:30:00+00:00"`) |

### 3.2 `human_context` Object

When present, `human_context` MUST contain:

| Field | Type | Description |
|---|---|---|
| `sub` | string | Human subject identifier from OIDC provider |
| `email` | string | Human email address |
| `roles` | string[] | Roles assigned to the human |

### 3.3 Example JWT Payload

```json
{
  "token_id": "cred_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "agent_name": "deploy-bot",
  "scope": "read:tools write:logs",
  "human_context": {
    "sub": "google-oauth2|108234567890",
    "email": "alice@example.com",
    "roles": ["engineer", "on-call"]
  },
  "delegation_chain": [
    "cred_0000000000000000000000000000000000000000000000000000000000000001",
    "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ],
  "parent_credential_id": "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "iat": "2026-03-15T10:30:00+00:00",
  "exp": "2026-03-15T11:30:00+00:00"
}
```

### 3.4 JWT Signature Verification

- Algorithm: `HS256` (HMAC-SHA256)
- The signing key is the `secret_key` from the credential manager
- Reject any token using an algorithm other than `HS256`

### 3.5 JWT Validation Steps

In order:

1. Decode the JWT header. Verify `alg` is `HS256`.
2. Verify the signature using the shared `secret_key`.
3. Parse the claims payload.
4. Check `exp`: if the current time >= `exp`, reject with -32003 ("Token has expired").
5. Check `token_id`: look up credential status (see Section 6 for Redis path). If status is `REVOKED`, reject with -32003 ("Credential has been revoked").
6. If `delegation_chain` is present, perform delegation chain verification (Section 6).
7. Extract `agent_name` from claims for use in downstream processing.

---

## 4. HMAC Validation Path (Legacy)

When no `Authorization: Bearer` header is present, and the request includes an `x-navil-signature` header:

1. Read the HMAC secret from configuration (`NAVIL_HMAC_SECRET` env var or constructor parameter).
2. Compute `HMAC-SHA256(secret, compact_request_body)`.
3. Compare the computed MAC against the `x-navil-signature` header value using constant-time comparison.
4. The signature value MAY be prefixed with `sha256=`. Strip this prefix before hex-decoding.
5. If verification succeeds, extract `agent_name` from the `x-agent-name` header.
6. If verification fails, reject with -32003 ("Invalid HMAC signature").

**Note:** HMAC-authenticated requests have no `human_context`. They MUST NOT receive `X-Human-Identity` or `X-Human-Email` headers when forwarded.

---

## 5. Scope Grammar

### 5.1 Format

Scopes are space-separated tokens. Each token follows the pattern `action:resource`.

```
"read:tools write:logs admin:policy"
```

### 5.2 Rules

- **Delimiter:** single ASCII space (U+0020)
- **Token format:** lowercase alphanumeric characters and colons only (regex: `[a-z0-9:]+`)
- **No wildcards:** there is no `*` or glob support
- **No hierarchy:** `read:tools` does not imply `read:tools:dangerous`; tokens are matched exactly
- **Flat set:** order does not matter; `"write:logs read:tools"` equals `"read:tools write:logs"`
- **Empty scope:** the empty string `""` is valid and is a subset of every scope

### 5.3 Subset Check

A child scope is valid if and only if every token in the child scope appears in the parent scope:

```
set(child_scope.split(" ")) <= set(parent_scope.split(" "))
```

Examples:

| Parent Scope | Child Scope | Valid? |
|---|---|---|
| `"read:tools write:logs"` | `"read:tools"` | Yes |
| `"read:tools write:logs"` | `"read:tools write:logs"` | Yes |
| `"read:tools write:logs"` | `""` | Yes |
| `"read:tools"` | `"read:tools write:logs"` | **No** |
| `"read:tools"` | `"write:logs"` | **No** |

---

## 6. Delegation Chain Verification

When a JWT contains a `delegation_chain` array, the proxy MUST verify that every ancestor credential in the chain is still active.

### 6.1 Chain Depth Limit

If `delegation_chain.length > 10`, reject immediately with -32003 ("Delegation chain too deep"). This is a hard cap.

### 6.2 Batch Status Lookup via Redis

Collect all credential IDs from `delegation_chain` and issue a single `MGET` command:

```
MGET navil:cred:{id1}:status navil:cred:{id2}:status navil:cred:{id3}:status
```

**Example command:**

```
MGET navil:cred:cred_0000000000000000000000000000000000000000000000000000000000000001:status navil:cred:cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:status
```

**Expected response (all active):**

```
1) "ACTIVE"
2) "ACTIVE"
```

**Expected response (ancestor revoked):**

```
1) "ACTIVE"
2) "REVOKED"
```

### 6.3 Verification Rules

1. For each credential ID in `delegation_chain`, read the corresponding status from the `MGET` result.
2. If ANY status is not `"ACTIVE"` (i.e., `"REVOKED"`, `"EXPIRED"`, `"INACTIVE"`, or `nil`/missing), reject the request with -32003 ("Ancestor credential {id} is not active").
3. A `nil` (key not found) response for a credential ID MUST be treated as not active -- reject.

### 6.4 Scope Enforcement

The presenting credential's `scope` claim (from the JWT) is the effective scope. Delegation already narrows the scope at issuance time, so the proxy does not need to re-intersect scopes across the chain. It simply uses the `scope` value from the JWT claims as-is.

### 6.5 Redis Failure Behavior

If the Redis `MGET` command fails (connection error, timeout), the proxy SHOULD reject the request with -32003 rather than failing open. Delegation chain verification is a security-critical path and MUST NOT be skipped.

This differs from the rate-limit Redis path, which fails open.

---

## 7. Request Sanitization

Both proxies MUST apply these checks before any authentication or forwarding:

| Check | Limit | Error Code | Error Message Pattern |
|---|---|---|---|
| Payload size | 5,242,880 bytes (5 MB) | -32700 | `"Payload too large: {n} bytes (limit 5242880 bytes)"` |
| JSON parse | Valid JSON | -32700 | `"Invalid JSON: {details}"` |
| Nesting depth | 10 levels | -32700 | `"JSON nesting depth {n} exceeds limit 10"` |

After parsing, the proxy MUST re-serialize the JSON compactly (strip whitespace padding) before forwarding. HMAC signatures are computed over the **compact** body.

---

## 8. Header Injection

When forwarding a request to the upstream MCP server, the proxy MUST inject the following headers. These headers allow the upstream server to make identity-aware decisions without parsing JWTs itself.

### 8.1 Headers from JWT-Authenticated Requests

| Header | Value | Condition |
|---|---|---|
| `X-Agent-Name` | `{agent_name}` from JWT claims | Always (JWT path) |
| `X-Human-Identity` | `{human_context.sub}` | Only if `human_context` is present and not null |
| `X-Human-Email` | `{human_context.email}` | Only if `human_context` is present and not null |
| `X-Delegation-Depth` | `{len(delegation_chain)}` as decimal string | Always; `"0"` if no delegation chain |

### 8.2 Headers from HMAC-Authenticated Requests

| Header | Value | Condition |
|---|---|---|
| `X-Agent-Name` | Value from `x-agent-name` request header | Always (HMAC path) |

HMAC-authenticated requests MUST NOT have `X-Human-Identity`, `X-Human-Email`, or `X-Delegation-Depth` headers injected.

### 8.3 Headers from Anonymous Requests

| Header | Value |
|---|---|
| `X-Agent-Name` | `"anonymous"` |

### 8.4 Header Forwarding

- Strip hop-by-hop headers (`host`, `connection`, `transfer-encoding`) before forwarding.
- Set `Content-Type: application/json` on the forwarded request.
- Set `Accept: application/json, text/event-stream` on the forwarded request.
- Forward the `mcp-session-id` header from the upstream response back to the client.

---

## 9. Error Codes (JSON-RPC 2.0)

All error responses MUST use this JSON-RPC 2.0 envelope:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": <int>,
    "message": "<string>"
  },
  "id": <request_id_or_null>
}
```

### 9.1 Error Code Table

| Code | Category | When Used |
|---|---|---|
| -32003 | Authentication failure | Invalid JWT signature, expired JWT, revoked credential, revoked ancestor in delegation chain, invalid HMAC signature, missing HMAC signature when secret is configured |
| -32002 | Authorization failure | Scope insufficient for requested operation, rate limit exceeded, agent blocked by threshold, anomaly detector block |
| -32700 | Parse error | Payload too large, invalid JSON, JSON nesting too deep |
| -32001 | Policy violation | Blocked by policy engine (tool/action denied) |
| -32603 | Internal error | Upstream server returned non-JSON, upstream connection failure |

### 9.2 HTTP Status Codes

| Scenario | HTTP Status |
|---|---|
| Payload too large (pre-body-read, Content-Length check) | 413 |
| Authentication failure (HMAC/JWT) | 401 |
| Rate limit / threshold block | 429 |
| Upstream failure | 502 |
| All other JSON-RPC errors | 200 (error is in the JSON-RPC body) |

---

## 10. Telemetry

Every tool call (both forwarded and blocked) MUST emit a telemetry event to the Redis telemetry queue.

### 10.1 Telemetry Queue

```
Key:    navil:telemetry:queue
Op:     LPUSH
Format: JSON string
```

### 10.2 Telemetry Event Schema

```json
{
  "agent_name": "deploy-bot",
  "tool_name": "run_command",
  "method": "tools/call",
  "action": "FORWARDED",
  "payload_bytes": 1234,
  "response_bytes": 5678,
  "duration_ms": 42,
  "timestamp": "2026-03-15T10:30:00+00:00",
  "target_server": "http://localhost:3000"
}
```

### 10.3 Required Fields

| Field | Type | Description |
|---|---|---|
| `agent_name` | string | From JWT `agent_name` claim, `x-agent-name` header, or `"anonymous"` |
| `tool_name` | string | From JSON-RPC `params.name`; `""` if not a tools/call; `"__tools_list__"` for tools/list |
| `method` | string | JSON-RPC method (e.g., `"tools/call"`, `"tools/list"`) |
| `action` | string | One of the action values below |
| `payload_bytes` | int | Size of the compact request body in bytes |
| `response_bytes` | int | Size of upstream response body in bytes (0 if blocked before forwarding) |
| `duration_ms` | int | Wall-clock time from request receipt to response send |
| `timestamp` | string | ISO 8601 UTC timestamp of the event |
| `target_server` | string | Upstream MCP server URL |

### 10.4 Extended Fields (Python proxy, optional for Rust)

| Field | Type | Description |
|---|---|---|
| `arguments_hash` | string | SHA-256 hex digest of the sorted JSON-serialized arguments |
| `arguments_size_bytes` | int | Byte length of the serialized arguments |
| `is_list_tools` | bool | `true` for tools/list calls |

### 10.5 Identity-Enriched Fields (new, for JWT-authenticated requests)

When the request was authenticated via JWT, the telemetry event SHOULD also include:

| Field | Type | Description |
|---|---|---|
| `human_email` | string or null | From `human_context.email`, if present |
| `delegation_depth` | int | `len(delegation_chain)`, or `0` |

### 10.6 Action Values

| Value | Meaning |
|---|---|
| `FORWARDED` | Request was forwarded to upstream and response returned |
| `BLOCKED_AUTH` | Blocked due to authentication failure (bad JWT, bad HMAC) |
| `BLOCKED_SCOPE` | Blocked due to insufficient scope |
| `BLOCKED_RATE` | Blocked due to rate limit |
| `BLOCKED_THRESHOLD` | Blocked due to agent payload threshold |
| `BLOCKED_AGENT` | Blocked because agent is explicitly blocked |

### 10.7 Telemetry Delivery

- Telemetry emission MUST NOT block the response path. Use background tasks / spawn.
- Telemetry failures MUST be logged but MUST NOT cause request failure.
- Telemetry is best-effort; dropped events are acceptable.

---

## 11. Redis Key Namespace

Summary of all Redis keys used by the proxy:

| Key Pattern | Type | Description |
|---|---|---|
| `navil:cred:{credential_id}:status` | string | Credential status: `"ACTIVE"`, `"REVOKED"`, `"EXPIRED"`, `"INACTIVE"` |
| `navil:agent:{agent_name}:thresholds` | hash | Fields: `max_payload_bytes`, `rate_limit_per_min`, `blocked` |
| `navil:agent:{agent_name}:rate:{bucket}` | integer | Request count for minute bucket (120s TTL, INCR) |
| `navil:telemetry:queue` | list | Telemetry event queue (LPUSH by proxy, BRPOP by worker) |

---

## 12. Rate Limiting

### 12.1 Bucket Calculation

```
bucket = floor(unix_epoch_seconds / 60)
```

### 12.2 Redis Commands

```
INCR  navil:agent:{agent_name}:rate:{bucket}
EXPIRE navil:agent:{agent_name}:rate:{bucket} 120
```

These two commands MUST be sent as an atomic pipeline.

### 12.3 Enforcement

If the `INCR` result exceeds `rate_limit_per_min` from the agent's thresholds, reject with -32002.

### 12.4 Failure Mode

Rate limiting fails **open**: if Redis is unreachable, allow the request through. Log a warning.

---

## 13. Backward Compatibility

### 13.1 Coexistence

Both authentication methods (JWT and HMAC) MUST coexist in a single proxy instance:

- JWT: for identity-aware clients that present `Authorization: Bearer <JWT>`
- HMAC: for existing clients that present `x-navil-signature` + `x-agent-name`
- Anonymous: when no HMAC secret is configured and neither auth method is used

### 13.2 No Cross-Contamination

- A request with a `Bearer` token MUST NEVER fall through to HMAC validation, even if the JWT is invalid.
- A request with an `x-navil-signature` MUST NEVER be treated as a JWT request.
- HMAC-authenticated requests MUST NOT receive human identity headers (`X-Human-Identity`, `X-Human-Email`).

### 13.3 Configuration

| Env Variable | Purpose | Default |
|---|---|---|
| `NAVIL_HMAC_SECRET` | Shared secret for HMAC verification | None (HMAC disabled) |
| `NAVIL_TARGET_URL` | Upstream MCP server URL | `http://localhost:3000` |
| `NAVIL_REDIS_URL` | Redis connection string | `redis://127.0.0.1:6379` |
| `NAVIL_PORT` | Proxy listen port | `8080` (Rust), constructor-defined (Python) |

---

## 14. Upstream Response Handling

### 14.1 Content-Type Dispatch

| Upstream Content-Type | Handling |
|---|---|
| `application/json` | Parse JSON, return as JSON-RPC response |
| `text/event-stream` | Parse SSE: extract JSON from `data: {...}` lines, return first valid JSON-RPC object |
| Other / unparseable | Return JSON-RPC error -32603 ("Upstream returned non-JSON") |

### 14.2 Response Headers

Forward `mcp-session-id` from the upstream response to the client. Strip all other upstream response headers.

---

## 15. Implementation Checklist

Both proxy implementations MUST pass identical integration tests covering:

- [ ] JWT authentication: valid token accepted, identity extracted from claims
- [ ] JWT authentication: expired token rejected with -32003
- [ ] JWT authentication: revoked credential rejected with -32003
- [ ] JWT authentication: invalid signature rejected with -32003
- [ ] JWT authentication: failed JWT does NOT fall back to x-agent-name
- [ ] HMAC authentication: valid signature accepted
- [ ] HMAC authentication: invalid signature rejected with -32003
- [ ] HMAC authentication: missing signature rejected when secret configured
- [ ] Anonymous access: allowed when no HMAC secret configured
- [ ] Delegation chain: all ancestors ACTIVE -- request allowed
- [ ] Delegation chain: one ancestor REVOKED -- request rejected with -32003
- [ ] Delegation chain: missing Redis key -- request rejected with -32003
- [ ] Delegation chain: depth > 10 -- request rejected with -32003
- [ ] Scope subset check: valid subset passes
- [ ] Scope subset check: superset scope rejected with -32002
- [ ] Header injection: X-Human-Identity present for JWT with human_context
- [ ] Header injection: X-Human-Identity absent for HMAC requests
- [ ] Header injection: X-Delegation-Depth correct
- [ ] Payload size limit: > 5 MB rejected with -32700
- [ ] JSON depth limit: depth > 10 rejected with -32700
- [ ] Rate limiting: exceeding limit returns -32002
- [ ] Telemetry: FORWARDED event emitted on success
- [ ] Telemetry: BLOCKED_AUTH event emitted on auth failure
- [ ] Telemetry: human_email and delegation_depth present for JWT requests
