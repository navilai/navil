# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all security audit findings (Critical → Low) without breaking existing tests or functionality.

**Architecture:** Surgical edits to 4 files (`app.py`, `proxy.py`, `policy_engine.py`, `credential_manager.py`) plus one model file (`routes.py`). Each task is independently testable. No new files needed.

**Tech Stack:** Python 3.10+, FastAPI, PyJWT, Pydantic v2, threading

---

## Pre-flight

Before starting, confirm the baseline test suite passes:

```bash
cd /Users/clawbot/claude/navil
pytest tests/test_proxy.py tests/test_credential_manager.py tests/test_policy_engine.py -v
```

Expected: All green. Do not proceed if any test is already failing — investigate first.

---

## Chunk 1: CORS + Path Traversal (app.py)

### Task 1: Fix CORS — disable credentials with wildcard origin

**Files:**
- Modify: `navil/api/local/app.py:175-181`

**Context:** `allow_credentials=True` + `allow_origins=["*"]` is an invalid CORS config (browsers block it per the spec). When `ALLOWED_ORIGINS` is not set (local dev), there's no legitimate cross-origin caller, so credentials are safe to disable in that mode.

- [ ] **Step 1: Read the current CORS block**

  Open `navil/api/local/app.py` lines 30-35 and 172-181 to confirm exact code before editing.

- [ ] **Step 2: Add `_allow_credentials` variable**

  After line 35, add:
  ```python
  # Credentials only allowed when origins are explicitly restricted (not wildcard)
  _allow_credentials: bool = bool(_origins_env)
  ```

- [ ] **Step 3: Update CORSMiddleware call**

  Replace:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=_allow_origins,
      allow_credentials=True,
      allow_methods=["*"],
      allow_headers=["*"],
  )
  ```
  With:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=_allow_origins,
      allow_credentials=_allow_credentials,
      allow_methods=["*"],
      allow_headers=["*"],
  )
  ```

- [ ] **Step 4: Verify no test uses credentials CORS**

  Run: `grep -r "allow_credentials\|CORSMiddleware" tests/` — should return nothing. This change affects only browser behavior, not the API itself; no test changes needed.

- [ ] **Step 5: Commit**

  ```bash
  git add navil/api/local/app.py
  git commit -m "fix: disable CORS credentials when using wildcard origin"
  ```

---

### Task 2: Fix path traversal in frontend static file serving

**Files:**
- Modify: `navil/api/local/app.py:189-199`

**Context:** `DASHBOARD_DIR / path` can be tricked by symlinks outside `DASHBOARD_DIR`. Adding `.resolve()` + `is_relative_to()` closes this.

- [ ] **Step 1: Write a unit test for path traversal**

  Add to `tests/test_proxy.py` (or a new `tests/test_app.py` — use existing `test_proxy.py` for simplicity, adding a standalone function):

  Actually, this endpoint is only active when `DASHBOARD_DIR.exists()`. The test would need a real filesystem. Skip a pytest unit test here; instead verify by code review that the logic is correct (belt-and-suspenders for a dashboard-only route).

- [ ] **Step 2: Apply the path validation fix**

  Replace the `serve_frontend` function body (lines 190-199) with:

  ```python
  @app.get("/{path:path}")
  def serve_frontend(path: str) -> FileResponse:
      """Serve the React SPA — all non-API routes go to index.html."""
      _dashboard_root = DASHBOARD_DIR.resolve()
      file_path = (DASHBOARD_DIR / path).resolve()
      # Reject path traversal attempts
      if not file_path.is_relative_to(_dashboard_root):
          return FileResponse(
              str(DASHBOARD_DIR / "index.html"),
              headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
          )
      if file_path.exists() and file_path.is_file():
          return FileResponse(str(file_path))
      # SPA fallback
      return FileResponse(
          str(DASHBOARD_DIR / "index.html"),
          headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
      )
  ```

- [ ] **Step 3: Run existing tests to confirm nothing is broken**

  ```bash
  pytest tests/ -x -q 2>&1 | tail -20
  ```
  Expected: same pass count as baseline.

- [ ] **Step 4: Commit**

  ```bash
  git add navil/api/local/app.py
  git commit -m "fix: prevent path traversal in frontend static file serving"
  ```

---

## Chunk 2: Auth Bypass + Timing Attack (proxy.py)

### Task 3: Fix auth bypass via `X-Agent-Name` fallback and timing attack

**Files:**
- Modify: `navil/proxy.py:174-198`
- Modify: `navil/proxy.py` (add `import hmac` at top)
- Modify: `tests/test_proxy.py:105-121` (update existing `TestIdentity` tests)

**Context:**
- **Bug 1:** If a Bearer token is provided but fails JWT verification, the code currently falls through to read `X-Agent-Name` — an untrusted header. Attacker sends `Authorization: Bearer invalid` + `X-Agent-Name: admin` to impersonate any agent.
- **Bug 2:** `cred.token == token` is not constant-time — allows timing oracle attacks.
- **Safe behavior:** `X-Agent-Name` is only a valid identity signal when `require_auth=False` AND no Bearer token was attempted.

- [ ] **Step 1: Write failing tests for the security fixes**

  In `tests/test_proxy.py`, add to the `TestIdentity` class:

  ```python
  def test_bearer_failure_does_not_fall_through_to_x_agent_name(
      self,
      proxy: MCPSecurityProxy,
  ) -> None:
      """If Bearer token fails, x-agent-name must NOT be used as fallback."""
      headers = {
          "authorization": "Bearer invalid_token",
          "x-agent-name": "attacker",
      }
      name = proxy.extract_agent_name(headers)
      assert name is None, "Fallthrough from failed Bearer to X-Agent-Name is an auth bypass"

  def test_x_agent_name_not_honored_when_require_auth_true(
      self,
      detector: BehavioralAnomalyDetector,
      cred_manager: CredentialManager,
  ) -> None:
      """When require_auth=True, X-Agent-Name alone must not authenticate."""
      strict_proxy = MCPSecurityProxy(
          target_url="http://localhost:3000",
          policy_engine=PolicyEngine(),
          anomaly_detector=detector,
          credential_manager=cred_manager,
          require_auth=True,
      )
      name = strict_proxy.extract_agent_name({"x-agent-name": "legit-agent"})
      assert name is None
  ```

- [ ] **Step 2: Run tests to confirm they fail**

  ```bash
  pytest tests/test_proxy.py::TestIdentity -v
  ```
  Expected: `test_bearer_failure_does_not_fall_through_to_x_agent_name` FAILS.

- [ ] **Step 3: Add `import hmac` at the top of `navil/proxy.py`**

  After line 19 (`import hashlib`), add:
  ```python
  import hmac
  ```

- [ ] **Step 4: Rewrite `extract_agent_name`**

  Replace lines 174-198 with:

  ```python
  def extract_agent_name(self, headers: dict[str, str]) -> str | None:
      """Extract agent identity from request headers.

      Checks Authorization header (Bearer JWT) first. If a Bearer token is
      present but fails verification, returns None — never falls back to
      X-Agent-Name to prevent auth bypass.

      X-Agent-Name is only honoured when no Bearer token was attempted and
      require_auth is False.
      """
      auth = headers.get("authorization", "")
      if auth.startswith("Bearer "):
          token = auth[7:]
          # Try JWT verification first
          try:
              payload = self.credential_manager.verify_credential(token)
              if payload and "agent_name" in payload:
                  return payload["agent_name"]
          except Exception:
              pass
          # Fallback: match token against stored credentials (constant-time)
          if hasattr(self.credential_manager, "credentials"):
              for cred in self.credential_manager.credentials.values():
                  status = cred.status
                  status_str = status.value if hasattr(status, "value") else str(status)
                  try:
                      token_match = hmac.compare_digest(
                          cred.token.encode(), token.encode()
                      )
                  except Exception:
                      token_match = False
                  if token_match and status_str == "ACTIVE":
                      return cred.agent_name
          # Bearer was attempted but failed — do NOT fall through
          return None

      # No Bearer token: only honour X-Agent-Name when auth is not required
      if not self.require_auth:
          return headers.get("x-agent-name")
      return None
  ```

- [ ] **Step 5: Update the existing `test_x_agent_name_header` test**

  The existing test uses the `proxy` fixture which has `require_auth=False`, so it still passes.
  The existing `test_no_identity` test sends `{}` with `require_auth=False` proxy — still returns None. No change needed.

- [ ] **Step 6: Run all identity + auth tests**

  ```bash
  pytest tests/test_proxy.py -v
  ```
  Expected: All green.

- [ ] **Step 7: Commit**

  ```bash
  git add navil/proxy.py tests/test_proxy.py
  git commit -m "fix: prevent auth bypass via X-Agent-Name fallback; use constant-time token comparison"
  ```

---

## Chunk 3: Rate Limit Race Condition (policy_engine.py)

### Task 4: Make rate limiting atomic with a threading lock

**Files:**
- Modify: `navil/policy_engine.py` (add `import threading`, update `__init__`, update `_check_rate_limit`)
- Modify: `tests/test_policy_engine.py` (add concurrency test)

**Context:** `_check_rate_limit` reads then increments a counter in two non-atomic steps. In a concurrent ASGI context, two requests can both pass the check before either increments. A `threading.Lock` makes the check-and-increment atomic.

- [ ] **Step 1: Write a failing concurrent test**

  Add to `tests/test_policy_engine.py`:

  ```python
  import threading

  def test_rate_limit_atomic_under_concurrent_calls() -> None:
      """Rate limit must not be exceeded under concurrent access."""
      import yaml
      policy_yaml = """
  agents:
    concurrent-agent:
      allowed_tools: ["*"]
      rate_limit_per_hour: 5
  """
      import tempfile, os
      with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
          f.write(policy_yaml)
          policy_file = f.name
      try:
          engine = PolicyEngine(policy_file=policy_file)
          results = []

          def check():
              decision = engine.check_tool_call("concurrent-agent", "any_tool", "tools/call")
              # decision is a tuple (allowed: bool, reason: str) or PolicyEvaluationResult
              if hasattr(decision, "decision"):
                  results.append(decision.decision.value == "ALLOW")
              else:
                  results.append(decision[0])

          threads = [threading.Thread(target=check) for _ in range(20)]
          for t in threads:
              t.start()
          for t in threads:
              t.join()

          allowed_count = sum(results)
          assert allowed_count <= 5, f"Rate limit exceeded: {allowed_count} allowed (limit 5)"
      finally:
          os.unlink(policy_file)
  ```

- [ ] **Step 2: Run test to confirm it fails (or is flaky)**

  ```bash
  pytest tests/test_policy_engine.py::test_rate_limit_atomic_under_concurrent_calls -v
  ```
  May pass by luck in single runs; that's OK — the fix is still correct.

- [ ] **Step 3: Add `import threading` to `navil/policy_engine.py`**

  After the existing imports (around line 14), add:
  ```python
  import threading
  ```

- [ ] **Step 4: Add lock to `PolicyEngine.__init__`**

  In `__init__` (around line 68, after `self.rate_limits: dict[str, dict[str, int]] = {}`), add:
  ```python
  self._rate_limit_lock = threading.Lock()
  ```

- [ ] **Step 5: Wrap `_check_rate_limit` body in the lock**

  Replace the body of `_check_rate_limit` (lines 223-248) with:

  ```python
  def _check_rate_limit(self, agent_name: str, tool_name: str) -> bool:
      """Check if rate limit is exceeded (thread-safe)."""
      agents = self.policy.get("agents", {})
      agent_policy = agents.get(agent_name, {})
      rate_limit = agent_policy.get("rate_limit_per_hour", 1000)

      key = f"{agent_name}:{tool_name}"
      current_time = int(time.time())

      with self._rate_limit_lock:
          if key not in self.rate_limits:
              self.rate_limits[key] = {"count": 0, "reset_at": current_time}

          limit_data = self.rate_limits[key]

          # Reset if hour has passed
          if current_time - limit_data["reset_at"] > 3600:
              limit_data["count"] = 0
              limit_data["reset_at"] = current_time

          # Atomic check-and-increment
          if limit_data["count"] >= rate_limit:
              return False

          limit_data["count"] += 1
          return True
  ```

- [ ] **Step 6: Run all policy engine tests**

  ```bash
  pytest tests/test_policy_engine.py -v
  ```
  Expected: All green.

- [ ] **Step 7: Commit**

  ```bash
  git add navil/policy_engine.py tests/test_policy_engine.py
  git commit -m "fix: make rate limit check-and-increment atomic with threading.Lock"
  ```

---

## Chunk 4: Credential Manager Hardening (credential_manager.py)

### Task 5a: Increase JWT secret minimum entropy

**Files:**
- Modify: `navil/credential_manager.py:88`

**Context:** `secrets.token_urlsafe(32)` produces ~32 bytes of entropy. JWT HS256 recommends at least 256 bits (32 bytes). We upgrade to 64 bytes (512 bits) to be safe. This only affects newly created `CredentialManager` instances with no explicit `secret_key`; passing an explicit key is unchanged.

- [ ] **Step 1: Write a test that asserts the generated secret has sufficient length**

  Add to `tests/test_credential_manager.py`:

  ```python
  import base64

  def test_default_secret_key_has_sufficient_entropy() -> None:
      """Auto-generated secret key must have at least 64 bytes of entropy."""
      cm = CredentialManager()
      # token_urlsafe uses URL-safe base64; decode to get raw bytes
      # Length of urlsafe_b64 string with n bytes: ceil(n * 4 / 3)
      # 64 bytes → at least 86 chars
      assert len(cm.secret_key) >= 86, (
          f"Secret key too short: {len(cm.secret_key)} chars (need ≥86 for 64 bytes)"
      )
  ```

- [ ] **Step 2: Run test to confirm it fails**

  ```bash
  pytest tests/test_credential_manager.py::test_default_secret_key_has_sufficient_entropy -v
  ```
  Expected: FAIL (32-byte key produces ~43 chars).

- [ ] **Step 3: Update the secret_key default**

  In `navil/credential_manager.py` line 88, change:
  ```python
  self.secret_key = secret_key or secrets.token_urlsafe(32)
  ```
  To:
  ```python
  self.secret_key = secret_key or secrets.token_urlsafe(64)
  ```

- [ ] **Step 4: Run test + full credential manager suite**

  ```bash
  pytest tests/test_credential_manager.py -v
  ```
  Expected: All green.

---

### Task 5b: Increase token ID entropy

**Files:**
- Modify: `navil/credential_manager.py:448`

**Context:** `token_hex(12)` = 96 bits. Upgrade to `token_hex(32)` = 256 bits to future-proof at scale.

- [ ] **Step 1: Update `_generate_token_id`**

  In line 448, change:
  ```python
  return f"cred_{secrets.token_hex(12)}"
  ```
  To:
  ```python
  return f"cred_{secrets.token_hex(32)}"
  ```

- [ ] **Step 2: Run tests**

  ```bash
  pytest tests/test_credential_manager.py -v
  ```
  Expected: All green (tests only check `token_id.startswith("cred_")`, not length).

- [ ] **Step 3: Commit both 5a and 5b together**

  ```bash
  git add navil/credential_manager.py tests/test_credential_manager.py
  git commit -m "fix: increase JWT secret entropy to 64 bytes and token ID to 256 bits"
  ```

---

## Chunk 5: Input Validation on API Models (routes.py)

### Task 6: Add Pydantic field constraints to prevent ReDoS and oversized inputs

**Files:**
- Modify: `navil/api/local/routes.py:185-244` (model definitions)

**Context:** `agent_name`, `tool_name`, `action` fields have no length or character constraints. A 1MB agent_name could cause ReDoS in policy pattern matching. Adding `Field(max_length=...)` is safe and backward-compatible — valid inputs are well within these limits.

**Important:** Do NOT add `pattern=` regex constraints — FastAPI/Pydantic emit a 422 for constraint violations, which is correct behavior, but overly-strict patterns could break legitimate callers. `max_length` alone is safe.

- [ ] **Step 1: Add `Field` import to routes.py**

  In the Pydantic import line (around line 18), change:
  ```python
  from pydantic import BaseModel
  ```
  To:
  ```python
  from pydantic import BaseModel, Field
  ```

- [ ] **Step 2: Write a test for oversized input rejection**

  Add to `tests/test_proxy.py` (or create `tests/test_routes_validation.py`):

  ```python
  # tests/test_routes_validation.py
  from navil.api.local.routes import PolicyCheckRequest, InvocationRequest, CredentialIssueRequest
  import pytest
  from pydantic import ValidationError

  def test_policy_check_request_rejects_oversized_agent_name() -> None:
      with pytest.raises(ValidationError):
          PolicyCheckRequest(agent_name="a" * 300, tool_name="read", action="tools/call")

  def test_policy_check_request_rejects_oversized_tool_name() -> None:
      with pytest.raises(ValidationError):
          PolicyCheckRequest(agent_name="agent", tool_name="t" * 300, action="tools/call")

  def test_policy_check_request_accepts_valid_input() -> None:
      req = PolicyCheckRequest(agent_name="my-agent", tool_name="read_file", action="tools/call")
      assert req.agent_name == "my-agent"

  def test_invocation_request_rejects_oversized_fields() -> None:
      with pytest.raises(ValidationError):
          InvocationRequest(
              agent_name="a" * 300,
              tool_name="t",
              action="tools/call",
              duration_ms=100,
          )

  def test_credential_issue_request_rejects_oversized_scope() -> None:
      with pytest.raises(ValidationError):
          CredentialIssueRequest(agent_name="agent", scope="s" * 600)
  ```

- [ ] **Step 3: Run tests to confirm they fail**

  ```bash
  pytest tests/test_routes_validation.py -v
  ```
  Expected: All FAIL (no constraints yet).

- [ ] **Step 4: Update model definitions in `routes.py`**

  Replace the model blocks (lines 185-244) with:

  ```python
  class ScanRequest(BaseModel):
      config: dict[str, Any]


  class InvocationRequest(BaseModel):
      agent_name: str = Field(..., min_length=1, max_length=256)
      tool_name: str = Field(..., min_length=1, max_length=256)
      action: str = Field(..., min_length=1, max_length=128)
      duration_ms: int
      data_accessed_bytes: int = 0
      success: bool = True


  class CredentialIssueRequest(BaseModel):
      agent_name: str = Field(..., min_length=1, max_length=256)
      scope: str = Field(..., min_length=1, max_length=512)
      ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 365)


  class PolicyCheckRequest(BaseModel):
      agent_name: str = Field(..., min_length=1, max_length=256)
      tool_name: str = Field(..., min_length=1, max_length=256)
      action: str = Field(..., min_length=1, max_length=128)


  class FeedbackRequest(BaseModel):
      alert_timestamp: str = Field(..., max_length=64)
      anomaly_type: str = Field(..., max_length=128)
      agent_name: str = Field(..., min_length=1, max_length=256)
      verdict: str = Field(..., max_length=64)
      operator_notes: str = Field(default="", max_length=2048)


  class ExplainAnomalyRequest(BaseModel):
      anomaly_data: dict[str, Any]


  class AnalyzeConfigRequest(BaseModel):
      config: dict[str, Any]


  class GeneratePolicyRequest(BaseModel):
      description: str = Field(..., min_length=1, max_length=4096)


  class RefinePolicyRequest(BaseModel):
      existing_policy: dict[str, Any]
      instruction: str = Field(..., min_length=1, max_length=4096)


  class ApplyActionRequest(BaseModel):
      action: dict[str, Any]


  class AutoRemediateRequest(BaseModel):
      confidence_threshold: float = Field(default=0.9, ge=0.0, le=1.0)


  class LLMConfigRequest(BaseModel):
      provider: str = Field(..., max_length=64)
      api_key: str = Field(..., max_length=512)
      base_url: str = Field(default="", max_length=512)
      model: str = Field(default="", max_length=128)
  ```

- [ ] **Step 5: Run validation tests**

  ```bash
  pytest tests/test_routes_validation.py -v
  ```
  Expected: All green.

- [ ] **Step 6: Run full test suite**

  ```bash
  pytest tests/ -x -q 2>&1 | tail -30
  ```
  Expected: Same pass count as baseline (no regressions).

- [ ] **Step 7: Commit**

  ```bash
  git add navil/api/local/routes.py tests/test_routes_validation.py
  git commit -m "fix: add Pydantic field length constraints to prevent oversized input"
  ```

---

## Final Verification

- [ ] **Run full test suite one last time**

  ```bash
  pytest tests/ -v 2>&1 | tail -40
  ```

- [ ] **Run linter**

  ```bash
  ruff check navil/
  ```
  Fix any issues before declaring done.

- [ ] **Run type checker**

  ```bash
  mypy navil
  ```
  Fix any new type errors introduced by the changes.

---

## Summary of Changes

| File | What changed |
|------|-------------|
| `navil/api/local/app.py` | CORS credentials disabled for wildcard origin; path traversal guard added |
| `navil/proxy.py` | Auth bypass via `X-Agent-Name` fallback closed; constant-time token comparison |
| `navil/policy_engine.py` | Rate limit counter made atomic with `threading.Lock` |
| `navil/credential_manager.py` | JWT secret upgraded to 64 bytes; token ID to 256 bits |
| `navil/api/local/routes.py` | Pydantic `Field` length constraints on all API request models |
| `tests/test_proxy.py` | Two new identity security tests |
| `tests/test_credential_manager.py` | One new entropy assertion test |
| `tests/test_policy_engine.py` | One new concurrency test |
| `tests/test_routes_validation.py` | New file — validation boundary tests |
