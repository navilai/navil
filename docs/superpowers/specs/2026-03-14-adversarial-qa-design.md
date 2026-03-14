# Adversarial QA Test Suite — Design Spec

**Date:** 2026-03-14
**Author:** QA (adversarial)
**Target:** Navil MCP Security Gateway

---

## Goal

Build a comprehensive adversarial test suite that attempts to break every security control in Navil — both the fixes applied in the 2026-03-14 security hardening pass and the broader security surface not yet addressed. The suite acts as a living red-team document: tests that pass (i.e., attacks that succeed) become bug reports.

---

## Approach

**Hybrid Layer 1 + Layer 2:**

- **Layer 1 (unit):** Instantiate Python classes directly and call methods with malicious inputs. Fast, surgical, no HTTP overhead.
- **Layer 2 (ASGI):** Use `httpx.AsyncClient` + `ASGITransport` to send real HTTP requests through the full FastAPI stack (middleware, routing, serialization). Required for testing CORS headers, security headers, and content-length handling.

**Single file:** `tests/test_adversarial.py`

**Stance:** Every test that passes represents a finding. Tests are written to EXPECT the attack to fail (i.e., the security control holds). If a test fails in pytest, the security control has been bypassed and must be treated as a bug.

---

## File Structure

```
tests/
  test_adversarial.py       # All adversarial tests (new)
```

No new production files. No changes to existing source files unless a finding requires a fix (handled separately).

---

## Critical Pre-Implementation Finding (Verify First)

**JWT verification is broken in the proxy hot path.**

`CredentialManager.issue_credential()` stores `iat` and `exp` as ISO 8601 strings (e.g. `"2026-03-14T09:00:00+00:00"`). However, `jwt.decode()` requires these claims to be Unix integer timestamps. As a result, `verify_credential()` raises `DecodeError: Issued At claim (iat) must be an integer` for every token the system issues.

In `extract_agent_name()`, this error is swallowed by `except Exception: pass`, and the code falls through to the `hmac.compare_digest` loop — authenticating via raw plaintext token equality rather than JWT signature verification. **Token expiry is never enforced** in the proxy hot path.

This must be verified at the start of `TestJWTSecurity` and documented as a High severity finding.

Consequence for JWT tests: all tests requiring JWT verification must use hand-crafted tokens with **integer** `iat`/`exp` claims (not `issue_credential()`), and the `token_id` must be inserted manually into `cm.credentials`.

---

## Test Classes

### 1. `TestAuthBypass` — Layer 1

Targets `MCPSecurityProxy.extract_agent_name()`.

Setup: construct `MCPSecurityProxy` with `require_auth=True` or `require_auth=False` as needed. Use a real `CredentialManager`.

| Test | Input | Expected |
|------|-------|----------|
| `test_empty_bearer_token` | `Authorization: Bearer ` (trailing space, empty token after split) | `None` |
| `test_lowercase_bearer_not_matched` | `Authorization: bearer TOKEN` | Falls to x-agent-name path (Bearer check is case-sensitive); with `require_auth=False` returns x-agent-name or None |
| `test_bearer_failure_xagentname_blocked` | Bad Bearer + `X-Agent-Name: admin`, `require_auth=True` | `None` (regression guard on fixed bypass) |
| `test_bearer_failure_xagentname_blocked_auth_false` | Bad Bearer + `X-Agent-Name: admin`, `require_auth=False` | `None` (Bearer was attempted, must not fall through) |
| `test_require_auth_blocks_xagentname_only` | `X-Agent-Name: admin`, `require_auth=True` | `None` |
| `test_require_auth_blocks_no_header` | No headers, `require_auth=True` | `None` |
| `test_forged_xagentname_no_filter` | `X-Agent-Name: ../../admin`, `require_auth=False` | Returns raw string verbatim — **finding: no validation** |
| `test_very_long_bearer_token` | 1MB Bearer token string | `None`, no crash |
| `test_bearer_whitespace_only` | `Authorization: Bearer    ` (all spaces) | `None` |

Note: `test_multiple_auth_headers` is omitted — Python `dict` cannot have duplicate keys; this scenario only exists at the HTTP layer and is covered by ASGI tests.

---

### 2. `TestJWTSecurity` — Layer 1

Targets `CredentialManager.verify_credential()` directly (not via proxy).

**Setup note:** All test tokens must be crafted with **integer** `iat`/`exp` Unix timestamps and manually inserted into `cm.credentials` where `token_id` lookup is needed. Do NOT use `cm.issue_credential()` — it produces ISO-format claims that always fail `jwt.decode()`.

```python
import time, jwt

def _make_token(secret: str, payload_overrides: dict) -> str:
    base = {"token_id": "cred_test", "agent_name": "test-agent",
            "scope": "*", "iat": int(time.time()), "exp": int(time.time()) + 3600}
    return jwt.encode({**base, **payload_overrides}, secret, algorithm="HS256")
```

| Test | Input | Expected |
|------|-------|----------|
| `test_verify_broken_for_issued_tokens` | Token from `cm.issue_credential()` | Raises `DecodeError` — **High finding: expiry not enforced** |
| `test_alg_none_rejected` | Hand-crafted token, `alg: none` | `InvalidTokenError` / `DecodeError` |
| `test_tampered_payload_rejected` | Valid token, payload base64-decoded and agent_name flipped, re-encoded | `InvalidTokenError` |
| `test_expired_token_rejected` | `exp: int(time.time()) - 1` | `InvalidTokenError` |
| `test_missing_exp_accepted` | No `exp` field | Accepted (eternal token) — **finding: no expiry enforced** |
| `test_revoked_token_rejected` | Valid token with `token_id` manually set to REVOKED in `cm.credentials` | `InvalidTokenError` |
| `test_wrong_secret_rejected` | Token signed with different secret | `InvalidTokenError` |
| `test_rs256_confusion_rejected` | JWT with `alg: RS256` header | `InvalidAlgorithmError` (blocked by `algorithms=["HS256"]`) |
| `test_empty_string_token` | `""` | `InvalidTokenError` |

---

### 3. `TestRateLimitBypass` — Layer 1

Targets `PolicyEngine._check_rate_limit()`.

**Setup note:** All tests that require a specific rate limit (e.g. 5) must construct `PolicyEngine` with a custom policy dict, because the default policy uses `rate_limit_per_hour: 1000` for unknown agents. Use:

```python
engine = PolicyEngine()
engine.policy = {
    "agents": {
        "test-agent": {"allowed_tools": ["*"], "rate_limit_per_hour": 5}
    }
}
```

**Boundary clarification:** With `rate_limit=5`, calls 1–5 return `True` (counter increments 0→4); call 6 returns `False` (count=5 ≥ limit=5). The `rate_limit`-th call is the last allowed one.

| Test | Input | Expected |
|------|-------|----------|
| `test_concurrent_limit_holds` | 20 threads, `rate_limit=5` | `allowed_count <= 5` |
| `test_key_collision_different_agents` | `agent="a:b"` + `tool="c"` vs `agent="a"` + `tool="b:c"` | Both produce key `"a:b:c"` — **Medium finding: shared bucket** |
| `test_limit_exact_boundary` | Exactly 5 calls → all allowed; 6th call → rejected | Call 5 returns `True`, call 6 returns `False` |
| `test_limit_resets_after_hour` | Hit limit, manually set `reset_at` to 3601s ago, call again | Allowed (counter reset) |

---

### 4. `TestInputValidation` — Layer 1

Targets Pydantic request models in `navil/api/local/routes.py`.

| Test | Model | Input | Expected |
|------|-------|-------|----------|
| `test_agent_name_at_max_length` | `PolicyCheckRequest` | `"a" * 256` | Valid |
| `test_agent_name_over_max_length` | `PolicyCheckRequest` | `"a" * 257` | `ValidationError` |
| `test_unicode_emoji_at_char_limit` | `PolicyCheckRequest` | `"𝕳" * 256` (256 chars, 1024 bytes) | Valid — Pydantic counts chars not bytes |
| `test_null_byte_in_agent_name` | `PolicyCheckRequest` | `"hello\x00world"` | **Predicted finding: passes Pydantic** |
| `test_newline_in_agent_name` | `PolicyCheckRequest` | `"hello\nworld"` | **Predicted finding: passes Pydantic** |
| `test_negative_ttl_rejected` | `CredentialIssueRequest` | `ttl_seconds=-1` | `ValidationError` |
| `test_zero_ttl_rejected` | `CredentialIssueRequest` | `ttl_seconds=0` | `ValidationError` |
| `test_confidence_over_one` | `AutoRemediateRequest` | `confidence_threshold=1.5` | `ValidationError` |
| `test_confidence_negative` | `AutoRemediateRequest` | `confidence_threshold=-0.1` | `ValidationError` |
| `test_empty_agent_name` | `PolicyCheckRequest` | `""` | `ValidationError` |
| `test_scope_at_max_length` | `CredentialIssueRequest` | `"s" * 512` | Valid |
| `test_scope_over_max_length` | `CredentialIssueRequest` | `"s" * 513` | `ValidationError` |

---

### 5. `TestJSONRPCAbuse` — Layer 1

Targets `MCPSecurityProxy.sanitize_request()`, `parse_jsonrpc()`, `handle_jsonrpc()`.

**Setup note:** Tests calling `handle_jsonrpc` that result in `method` not being `"tools/call"` or `"tools/list"` will reach `self._forward()`, which asserts `self.http_client is not None`. Set `proxy.http_client = AsyncMock(return_value=(...))` for those tests.

| Test | Input | Expected |
|------|-------|----------|
| `test_null_method_graceful` | `{"jsonrpc":"2.0","method":null,"id":1}` | `parse_jsonrpc` returns `method=None`; hits the `else` branch in `handle_jsonrpc`; `_forward()` is called (mock it); response returned without crash |
| `test_non_string_method_graceful` | `{"jsonrpc":"2.0","method":{"k":"v"},"id":1}` | Same as above — `method` is not `"tools/call"` or `"tools/list"`, forwarded via mocked `_forward()`, no crash |
| `test_payload_at_size_limit` | Body exactly `MAX_PAYLOAD_BYTES` bytes | Accepted by `sanitize_request` |
| `test_payload_over_size_limit` | Body `MAX_PAYLOAD_BYTES + 1` bytes | Raises `ValueError` / returns -32700 |
| `test_json_depth_at_limit` | Nesting depth exactly 10 | Accepted |
| `test_json_depth_over_limit` | Nesting depth 11 | Raises `ValueError` / returns -32700 |
| `test_sql_injection_in_tool_name` | `params.name: "'; DROP TABLE agents; --"` | Reaches policy check unchanged — document (proxy does not sanitize) |
| `test_path_traversal_in_tool_params` | `params.arguments.path: "../../etc/passwd"` | Forwarded to upstream — document (proxy does not sanitize params) |
| `test_huge_request_id_blocked` | `id: "x" * MAX_PAYLOAD_BYTES` | Blocked by payload size limit |
| `test_batch_request_rejected` | JSON array `[{"jsonrpc":"2.0",...}]` | `ValueError` from `parse_jsonrpc` ("must be an object") |

---

### 6. `TestPathTraversal` — Layer 2 (ASGI)

Targets `serve_frontend()` in `navil/api/local/app.py`.

**Setup note:** `DASHBOARD_DIR` and the route registration are module-level. Use `monkeypatch.setattr(navil.api.local.app, "DASHBOARD_DIR", tmp_path)` before calling `create_app()` inside each test. Create a real `index.html` and a test file inside `tmp_path` so normal serving can be verified.

```python
@pytest.fixture
def dashboard_app(tmp_path, monkeypatch):
    (tmp_path / "index.html").write_text("<html>index</html>")
    (tmp_path / "style.css").write_text("body{}")
    import navil.api.local.app as app_module
    monkeypatch.setattr(app_module, "DASHBOARD_DIR", tmp_path)
    return app_module.create_app(with_demo=False)
```

| Test | Path requested | Expected |
|------|----------------|----------|
| `test_dotdot_slash_blocked` | `../../etc/passwd` | 200 with index.html content (not the file) |
| `test_valid_file_served` | `style.css` | 200 with CSS content |
| `test_nonexistent_file_spa_fallback` | `some/unknown/route` | 200 with index.html |
| `test_symlink_outside_root_blocked` | Create `tmp_path/evil -> /etc`, request `evil/passwd` | 200 with index.html content |
| `test_double_dot_in_middle_blocked` | `assets/../../etc/passwd` | 200 with index.html |

Note: URL-encoded traversal (`%2e%2e%2f`) is decoded by FastAPI before reaching the handler — `Path.resolve()` handles the resulting `../` correctly. Null bytes in URL paths are rejected by the HTTP layer before reaching Python.

---

### 7. `TestCORSBehavior` — Layer 2 (ASGI)

Targets `CORSMiddleware` configuration.

**Setup note:** `_allow_origins` and `_allow_credentials` are module-level variables set at import time. Use `monkeypatch.setattr` on the module attributes directly, then call `create_app()` within the test:

```python
import navil.api.local.app as app_module

def test_something(monkeypatch):
    monkeypatch.setattr(app_module, "_allow_origins", ["*"])
    monkeypatch.setattr(app_module, "_allow_credentials", False)
    app = app_module.create_app(with_demo=False)
    # use httpx.AsyncClient + ASGITransport
```

| Test | `_allow_origins` | `_allow_credentials` | Request | Expected |
|------|-----------------|---------------------|---------|----------|
| `test_wildcard_no_credentials_in_response` | `["*"]` | `False` | GET with `Origin: http://evil.com` | No `Access-Control-Allow-Credentials: true` header |
| `test_explicit_origin_sends_credentials` | `["http://localhost:8484"]` | `True` | GET with matching Origin | `Access-Control-Allow-Credentials: true` present |
| `test_explicit_origin_wrong_origin_blocked` | `["http://localhost:8484"]` | `True` | GET with `Origin: http://evil.com` | No CORS headers (origin not allowed) |
| `test_space_only_origin_env_edge_case` | `[]` (parsed from `" "`) | `True` | GET with any Origin | No CORS headers (empty origins list blocks all) — document as edge case |

---

### 8. `TestNewVulnerabilities` — Both Layers

Novel attack surfaces not covered by any of the 6 hardening fixes.

| Test | Layer | Description | Predicted result |
|------|-------|-------------|-----------------|
| `test_xagentname_no_length_limit` | 1 | `X-Agent-Name: "a" * 10_000`, `require_auth=False` | Accepted, stored in traffic log — **Low finding** |
| `test_xagentname_newline_injection` | 1 | `X-Agent-Name: "admin\nX-Injected: yes"`, `require_auth=False` | Returns raw string — **Low finding: log injection** |
| `test_jwt_expiry_not_enforced_via_hmac_path` | 1 | Issue credential normally (ISO exp), call `extract_agent_name` with that token — verify_credential fails, hmac path accepts it even if conceptually expired. Distinct from `TestJWTSecurity` (which calls `verify_credential` directly); this tests the **proxy's actual auth flow** end-to-end. | Token accepted despite broken expiry — **High finding** |
| `test_anonymous_identity_spoofable` | 1 | `require_auth=False`, no headers → `agent_name="anonymous"`; also send `X-Agent-Name: anonymous` → same result | Documents identity model ambiguity |

---

## Predicted Findings (Severity Table)

| Severity | Finding | Location |
|----------|---------|----------|
| **High** | `issue_credential()` encodes `iat`/`exp` as ISO strings; `verify_credential()` always raises `DecodeError`; proxy falls back to plaintext token comparison; **token expiry never enforced** | `credential_manager.py:issue_credential`, `verify_credential` |
| **High** | JWT with no `exp` claim is accepted by `verify_credential()` as an eternal token | `credential_manager.py:verify_credential` |
| **Medium** | Rate limit key collision: agent names or tool names containing `:` can share buckets across agents | `policy_engine.py:_check_rate_limit` |
| **Low** | Null bytes (`\x00`) and newlines (`\n`) pass Pydantic `str` field validation | `routes.py` models |
| **Low** | `X-Agent-Name` header has no length or character constraint when `require_auth=False`; stored verbatim in traffic log | `proxy.py:extract_agent_name`, `_log_traffic` |
| **Info** | SQL injection and path traversal strings in JSON-RPC params are forwarded to upstream unchanged (proxy does not sanitize params by design, but worth documenting) | `proxy.py:handle_jsonrpc` |

---

## Success Criteria

1. All existing 388 tests continue to pass.
2. Adversarial tests are written to expect security controls to hold — a pytest **failure** = a confirmed finding.
3. Each predicted finding either confirms the bug (test fails) or disproves it (test passes unexpectedly).
4. No crashes or unhandled exceptions on any input — the proxy must degrade gracefully.
5. Suite runs in under 30 seconds (no real network I/O, no `sleep`).
6. Every test has a one-line comment explaining what security property it validates.

---

## Out of Scope

- Actual network penetration (no external services)
- Fuzzing (random input generation)
- Memory/CPU profiling
- Supply chain / dependency auditing
- Fixes for any findings discovered (handled in a separate hardening pass)
