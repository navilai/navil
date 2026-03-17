<p align="center">
  <h1 align="center">Navil</h1>
  <p align="center">
    <strong>The security gateway for AI agents.</strong>
    <br />
    Protect your MCP servers from prompt injection, data exfiltration, and autonomous drift — with sub-millisecond overhead.
  </p>
</p>

<p align="center">
  <a href="https://github.com/ivanlkf/navil/actions/workflows/ci.yml"><img src="https://github.com/ivanlkf/navil/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0" /></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#openclaw-integration">OpenClaw</a> &bull;
  <a href="#performance">Performance</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#cicd-integration">CI/CD</a> &bull;
  <a href="#dashboard">Dashboard</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Why Navil?

[MCP](https://modelcontextprotocol.io/) is becoming the standard for connecting AI agents to tools — but it has **no native permissions model**. Real attacks have already been demonstrated:

- A malicious MCP server **exfiltrated an entire WhatsApp history** by poisoning tool definitions
- Prompt injection via a GitHub issue made the official GitHub MCP server **leak private repo data**
- MCP tool definitions can **mutate after installation** — a safe tool on day 1 becomes a backdoor by day 7

Navil sits between your MCP clients and servers as a security proxy. It monitors, detects, and enforces — so your agents stay within bounds.

> Developed by **[Pantheon Lab Pte Ltd](https://github.com/ivanlkf/navil)**.

## Getting Started

```bash
pip install navil
navil init
```

`navil init` walks you through setup: paste your API key from the [Navil Cloud dashboard](https://dashboard.navil.ai) and Navil writes a local config at `~/.navil/config.toml`. The dashboard provides billing management, real-time analytics, and fleet-wide threat intelligence.

Next, integrate Navil with your IDE or tool of choice:

- **[Claude Desktop](docs/guides/claude-desktop.md)** -- wrap MCP servers in your Claude Desktop config
- **[Cursor IDE](docs/guides/cursor.md)** -- wrap MCP servers in `~/.cursor/mcp.json`
- **[Continue.dev (VS Code)](docs/guides/continue-dev.md)** -- wrap MCP servers in `.continue/config.json`

Or, if you already know your config file path:

```bash
navil wrap mcp_config.json
# Works with Claude Desktop, Cursor, Continue.dev, or any MCP config
```

Each guide takes under 5 minutes and ends with dashboard verification.

## Quick Start

```bash
pip install navil

# Scan an MCP server config for vulnerabilities
navil scan config.json

# Run all 11 SAFE-MCP penetration tests
navil pentest

# Start the security proxy
navil proxy start --target http://localhost:3000
```

That's it. Your agents now connect through Navil instead of directly to the MCP server.

## OpenClaw Integration

Using [OpenClaw](https://openclaw.ai)? Secure **every** MCP server in your config with one command:

```bash
pip install navil
navil wrap openclaw.json
```

That's it. Navil backs up your original config, then wraps every MCP server with `navil shim` so all tool calls are monitored, policy-checked, and anomaly-detected — with [<3 µs overhead per message](#performance).

Why this matters: OpenClaw's skill registry has had [824+ malicious skills](https://blog.cyberdesserts.com/openclaw-malicious-skills-security/) identified, and [135,000+ instances](https://www.darkreading.com/application-security/critical-openclaw-vulnerability-ai-agent-risks) are exposed to the public internet.

### What `navil wrap` does

```
Before:                              After:
┌─────────────────────┐              ┌─────────────────────┐
│  "filesystem": {    │              │  "filesystem": {    │
│    "command": "npx", │   navil     │    "command":"navil",│
│    "args": [...]    │ ──wrap──►   │    "args": ["shim", │
│  }                  │              │      "--cmd","npx …"]│
└─────────────────────┘              └─────────────────────┘
```

Every server gets its own agent identity for per-server policy and telemetry. Your env vars, cwd, and other config keys pass through untouched.

### Options

```bash
# Wrap only specific servers
navil wrap openclaw.json --only filesystem,github

# Attach a policy file to all servers
navil wrap openclaw.json --policy policy.yaml

# Preview changes without modifying anything
navil wrap openclaw.json --dry-run

# Undo: restore your original config
navil wrap openclaw.json --undo
```

### Works with Claude Desktop too

```bash
navil wrap ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Scan before you wrap

```bash
# Audit your MCP configs for vulnerabilities (0–100 score)
navil scan openclaw.json
```

### HTTP transport (production deployments)

For OpenClaw instances using MCP over Streamable HTTP, use Navil's HTTP proxy:

```bash
navil proxy start --target http://your-mcp-server:3000 --no-auth
```

Then point your OpenClaw MCP server URL at `http://localhost:9090/mcp` instead of the real server.

## Performance

Navil's security pipeline adds **negligible overhead** to real workloads. We benchmarked the stdio shim against a mock MCP server to isolate the cost of security checks from network/tool latency.

### Per-message overhead

| Component | Mean | p50 | p99 |
|-----------|------|-----|-----|
| Full security check (sanitize + parse + policy + anomaly) | **2.7 µs** | 2.4 µs | 6.1 µs |
| `orjson` parse | 0.9 µs | 0.8 µs | 2.0 µs |
| Policy engine lookup | 0.5 µs | 0.4 µs | 1.2 µs |
| Anomaly gate scan | 0.3 µs | 0.3 µs | 0.8 µs |

### Total session wall-clock

| Session size | Direct | With Navil | Overhead |
|--------------|--------|------------|----------|
| Light (5 tool calls) | 11.5 ms | 12.0 ms | **+0.5 ms** (4.4%) |
| Medium (50 tool calls) | 12.8 ms | 14.2 ms | **+1.4 ms** (10.8%) |
| Heavy (500 tool calls) | 28.0 ms | 40.3 ms | **+12.3 ms** |

> **Context:** These benchmarks use a mock server that responds in ~40 µs. Real MCP tools take 1–5,000 ms (file reads, API calls, LLM inference). On any real workload, Navil's overhead is **< 0.1%** of total session time.

Run the benchmarks yourself:

```bash
python bench_shim_latency.py    # Per-message breakdown
python bench_total_latency.py   # Full session wall-clock
```

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="Navil Dashboard — Fleet overview showing agent count, active alerts, invocations, credential status, agent health grid, and recent policy decisions" width="800" />
</p>

## Features

### Rust Data Plane
Axum-based reverse proxy with HMAC-SHA256 verification, JSON depth limiting, O(1) Redis threshold checks, and minute-bucketed rate limiting. Sub-millisecond overhead per request.

### Behavioral Anomaly Detection
12 statistical detectors with adaptive EMA baselines, operator feedback loops, and learned pattern matching. Runs off the hot path via Redis-bridged telemetry — security analysis never blocks your agents.

### Configuration Scanning
Detect plaintext credentials, over-privileged permissions, missing authentication, unverified sources, and malicious patterns. Produces a 0–100 security score.

### Policy Enforcement
YAML-driven tool/action allow-lists, per-agent rate limiting, data-sensitivity gates, and suspicious-pattern detection.

### Penetration Testing
11 SAFE-MCP attack simulations that validate your detectors actually catch threats. No real network traffic generated.

### LLM-Powered Analysis
AI-powered config analysis, anomaly explanation, policy generation, and self-healing. Bring your own key — supports Anthropic, OpenAI, Gemini, and Ollama (fully local).

### Analytics *(Navil Cloud)*
Per-agent trust scores with behavioral profiling and anomaly trend analysis. Continuously scores every agent over time and surfaces risk trends before they become incidents.

### Identity System
OIDC token exchange converts external identity tokens into Navil credentials with human context attached (`navil credential exchange`). Delegation chains let parent credentials mint narrower child credentials for sub-agents (`navil credential delegate`), with full chain visualization (`navil credential chain <id>`) and cascade revocation that invalidates an entire delegation tree in one call (`navil credential revoke --cascade`). The proxy forwards `X-Human-Identity` and `X-Human-Email` headers to upstream MCP servers so tools can attribute actions back to a real person.

### Credential Lifecycle
Issue, rotate, and revoke JWT tokens with JIT provisioning, configurable TTL, usage tracking, and immutable audit logs. Hardened with a global active-credential cap (500), auto-purge of expired credentials, thread-safe rotation (no TOCTOU races), and bearer-token auth on all credential endpoints (set `NAVIL_DASHBOARD_TOKEN`).

### Threat Intelligence & Blocklist Engine
Community-sourced threat intel via the [Give-to-Get initiative](#the-navil-give-to-get-initiative), backed by a local blocklist engine for pattern matching. Manage blocklists with `navil blocklist update`, `navil blocklist status`, `navil blocklist load`, and `navil blocklist search`. Ships with 28 curated patterns in `blocklist_v1.json`. The public attack catalog (`public_attacks.yaml`) contains 32 cataloged attack patterns across 10 categories, expanded to 200+ parameterized variants via the `AttackVariantGenerator` for comprehensive ML baseline training with `navil seed-database --full`.

### Honeypot & Canary Kit
Deploy decoy MCP servers to detect and study attackers in the wild. The MCP Canary Kit (`python -m navil.canary --profile dev-tools --port 8080`) ships with 3 profiles: `dev-tools`, `cloud-creds`, and `db-admin`. A built-in `SignatureExtractor` analyzes collected honeypot interactions and auto-generates blocklist entries from observed tool names, call sequences, and argument patterns. Production deployment uses Docker Compose with isolated networking — honeypot containers have no internet access, read-only filesystems, and resource limits (`docker compose -f docker-compose.honeypot.yaml up -d`).

### Registry Scanning
Discover and audit MCP servers at scale. `navil crawl registries` discovers servers from npm, PyPI, and awesome-mcp-servers lists. `navil scan-batch` bulk-scans crawl results and outputs JSONL. `navil report-mcp` generates a State of MCP security report from batch scan data.

### State of MCP Security Report
We scanned **1,000 public MCP servers** from awesome-mcp-servers, npm, and PyPI using `navil crawl registries` and `navil scan-batch`. Key findings:

| Metric | Value |
|--------|-------|
| Servers scanned | 1,000 |
| Average security score | 61.7 / 100 |
| Missing authentication | 100% |
| Unverified sources | 100% |
| Unverified GitHub repos | 98.2% |

The most common vulnerability is **AUTH-MISSING** (every server), followed by **SRC-UNVERIFIED** and **SUPPLY-GH-UNVERIFIED**. No server scored above 80. The full report is at [`state_of_mcp_security_v3.md`](state_of_mcp_security_v3.md). Generate your own with `navil report-mcp scan_results.jsonl`.

### Zero-Knowledge Telemetry
Cloud sync anonymizes all agent identities with HMAC-SHA256, enforces a strict field allowlist, and actively blocks banned fields. Raw data never leaves your deployment. Fully opt-out with `NAVIL_DISABLE_CLOUD_SYNC=true`. See [Privacy Guarantees](#zero-knowledge-telemetry-details) and [DATA_COLLECTION.md](DATA_COLLECTION.md) for the full breakdown of exactly what data goes where.

## Architecture

```
  Agents ──> [ Rust Proxy :8080 ] ──> MCP Servers
                    |
              Redis :6379  (thresholds, rate counters, telemetry queue)
                    |
             [ Python Workers :8484 ]  (ML detectors, LLM analysis, dashboard)
                    |
              (optional) Navil Cloud  (anonymized threat intel)
```

The Rust proxy handles the hot path: sanitization, HMAC auth, O(1) threshold gates, and rate limiting. It publishes telemetry to a Redis queue. Python workers consume events, run the full anomaly detection suite, recompute thresholds, and sync them back to Redis for the proxy to read.

For the full system design, see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Dashboard

Navil ships with a full-featured 12-page security dashboard for visualizing and managing your MCP fleet.

<table>
<tr>
<td width="50%">

**Dashboard** — Fleet overview: agent count, active alerts, invocations, credential status, agent health grid, and recent policy decisions at a glance.

<img src="docs/screenshots/dashboard.png" alt="Dashboard — fleet overview with stats and agent health" />

</td>
<td width="50%">

**Gateway** — Configure and start the MCP Security Proxy. Intercepts agent-to-tool traffic in real time, enforcing policies and blocking anomalies.

<img src="docs/screenshots/gateway.png" alt="Gateway — proxy configuration and start" />

</td>
</tr>
<tr>
<td width="50%">

**Penetration Testing** — Run all 11 SAFE-MCP attack scenarios (reconnaissance, supply chain, c2 beaconing, rug pull, and more) and see which threats your detectors catch.

<img src="docs/screenshots/pentest.png" alt="Pentest — 11/11 attacks detected" />

</td>
<td width="50%">

**Config Scanner** — Paste any MCP server config and get a 0–100 security score with CRITICAL/HIGH findings and actionable remediation steps.

<img src="docs/screenshots/scanner.png" alt="Config Scanner — vulnerability scan results" />

</td>
</tr>
<tr>
<td width="50%">

**Self-Healing AI** — Analyze threats and apply AI-generated remediation actions (credential rotation, policy updates, alert escalation) with confidence scores.

<img src="docs/screenshots/self-healing.png" alt="Self-Healing — AI remediation actions with confidence scores" />

</td>
<td width="50%">

**Alerts** — Real-time anomaly alerts with CRITICAL / HIGH / MEDIUM / LOW severity filtering across your agent fleet.

<img src="docs/screenshots/alerts.png" alt="Alerts — anomaly detection alerts with severity filters" />

</td>
</tr>
<tr>
<td width="50%">

**Policy Engine** — Check permissions for any agent/tool/action pair, review the live decision log, and generate YAML policies from natural language.

<img src="docs/screenshots/policy.png" alt="Policy — permission check form, decision log, AI policy generation" />

</td>
<td width="50%">

**Analytics** *(Navil Cloud)* — Per-agent trust scores with behavioral profiling and anomaly trend analysis. Surfaces drift before it becomes an incident.

<img src="docs/screenshots/analytics.png" alt="Analytics — Navil Cloud agent risk scoring upsell" />

</td>
</tr>
</table>

<details>
<summary>More screenshots</summary>

| Page | Screenshot |
|------|-----------|
| Agents | <img src="docs/screenshots/agents.png" alt="Agents — fleet table with observations, alerts, and tool usage" width="600" /> |
| Credentials | <img src="docs/screenshots/credentials.png" alt="Credentials — issue and revoke JWT tokens" width="600" /> |
| Settings | <img src="docs/screenshots/settings.png" alt="Settings — subscription tier, LLM config, authentication" width="600" /> |

</details>

## Installation

### Prerequisites

| Component | Required | Version |
|-----------|----------|---------|
| Python | Yes | 3.10+ |
| Redis | Yes (for proxy mode) | 5.0+ |
| Rust | Optional (for Rust proxy) | stable |
| Node.js | Optional (for dashboard dev) | 20+ |

### Install from PyPI

```bash
pip install navil
```

With optional features:

```bash
pip install navil[llm]         # + AI-powered analysis (Anthropic, OpenAI, Gemini)
pip install navil[cloud]       # + Cloud dashboard (FastAPI + React)
pip install navil[all]         # Everything
```

### Install from source

```bash
git clone https://github.com/ivanlkf/navil.git
cd navil
pip install -e ".[dev]"
```

### Rust proxy (optional, for high-throughput deployments)

```bash
cd navil-proxy
cargo build --release
```

The compiled binary is at `navil-proxy/target/release/navil-proxy`.

## Full Setup Guide

### 1. Start Redis

```bash
# macOS
brew install redis && redis-server

# Docker
docker run -d -p 6379:6379 redis:7-alpine

# Linux
sudo apt install redis-server && sudo systemctl start redis
```

### 2. Start the Rust proxy (data plane)

```bash
cd navil-proxy

# Point at your MCP server and Redis
NAVIL_TARGET_URL=http://localhost:3000 \
NAVIL_REDIS_URL=redis://127.0.0.1:6379 \
NAVIL_PORT=8080 \
cargo run --release
```

Your agents now connect to `http://localhost:8080/mcp` instead of directly to the MCP server.

Optional: enable HMAC request signing:

```bash
NAVIL_HMAC_SECRET=your-secret-key cargo run --release
```

### 3. Start the Python control plane (dashboard + ML workers)

```bash
pip install navil[cloud]
navil cloud serve    # Opens at http://localhost:8484
```

The Python control plane automatically connects to Redis, consumes telemetry from the Rust proxy, runs anomaly detection, and serves the dashboard.

### 4. Seed ML baselines (recommended before first deployment)

```bash
navil seed-database                  # 10 scenarios x 1,000 iterations
navil seed-database --full           # All 32+ scenarios with 200+ parameterized variants
navil seed-database -n 5000          # More iterations for tighter baselines
navil seed-database --json           # Machine-readable output
navil seed-database --export out.json  # Export scenario definitions
```

This populates the `BehavioralAnomalyDetector` with synthetic attack data so the statistical thresholds (mean + 5*std_dev) have historical baselines from day one. The `--full` flag includes parameterized variants from the public attack catalog (`public_attacks.yaml`) for comprehensive coverage across all 10 attack categories.

### Python-only mode (no Rust proxy)

If you don't need the Rust data plane, the Python proxy works standalone:

```bash
navil proxy start --target http://localhost:3000
```

### AI-powered analysis (BYOK)

```bash
# Uses ANTHROPIC_API_KEY env var automatically
navil llm analyze-config config.json

# Or specify provider explicitly
navil llm generate-policy "only allow read access to logs" --provider gemini
navil llm explain-anomaly '{"type": "rate_spike", "agent": "bot-1"}' --provider openai
```

Ollama is also supported for fully local, offline AI analysis:

```bash
navil cloud serve
# Then configure in Settings: provider=openai, base_url=http://localhost:11434/v1, model=llama3.2
```

### Issue a short-lived credential

```bash
navil credential issue --agent my-agent --scope "read:tools" --ttl 3600
```

### OIDC token exchange (identity-linked credentials)

```bash
# Exchange an OIDC token for a Navil credential with human context
navil credential exchange --oidc-token "$OIDC_JWT" --agent my-agent --scope "read:tools"

# Delegate a credential to a sub-agent with narrowed scope
navil credential delegate --parent cred_abc123 --agent sub-agent --scope "read:logs" --ttl 1800

# Visualize the full delegation chain
navil credential chain cred_xyz789

# Revoke a credential and all its descendants
navil credential revoke --token-id cred_abc123 --cascade
```

### Manage threat blocklists

```bash
# Fetch latest blocklist from Navil Cloud
navil blocklist update

# Check blocklist status
navil blocklist status

# Search for patterns matching a keyword
navil blocklist search "exfiltration"

# Load a custom blocklist from file
navil blocklist load custom_blocklist.json
```

### Deploy a honeypot canary

```bash
# Start a canary MCP server with the dev-tools profile
python -m navil.canary --profile dev-tools --port 8080

# Or use cloud-creds or db-admin profiles
python -m navil.canary --profile cloud-creds --port 8081 --contribute

# Production deployment with Docker (isolated network, no internet for honeypots)
docker compose -f docker-compose.honeypot.yaml up -d
```

### Check a policy decision

```bash
navil policy check --tool file_system --agent my-agent --action read
```

## CI/CD Integration

### GitHub Actions

Add SARIF-based security scanning to any repository that uses MCP servers:

```yaml
name: Navil MCP Security Scan
on:
  push:
    paths: ["**.mcp.json", ".mcp.json"]
  pull_request:
    paths: ["**.mcp.json", ".mcp.json"]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/navil-scan
        with:
          config: .mcp.json
          fail-on-score-below: "60"
          format: sarif
```

Scan results appear in the GitHub **Security** tab under **Code scanning alerts**.

You can also use the `--format` flag directly:

```bash
# SARIF output (for CI integration)
navil scan config.json --format sarif --output results.sarif

# JSON output (for programmatic consumption)
navil scan config.json --format json

# Human-readable text (default)
navil scan config.json
```

### GitLab CI

```yaml
navil-scan:
  image: python:3.12-slim
  script:
    - pip install navil
    - navil scan .mcp.json --format sarif --output gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
  rules:
    - changes:
        - "**.mcp.json"
        - ".mcp.json"
```

### Viewing Results in GitHub Security Tab

1. The GitHub Action uploads SARIF output via `github/codeql-action/upload-sarif`.
2. Navigate to your repository's **Security** tab > **Code scanning alerts**.
3. Each Navil finding appears as a code scanning alert with severity, description, and remediation steps.

## Commands

| Command | Description |
|---------|-------------|
| `navil scan <config>` | Scan MCP config for vulnerabilities (0-100 score) |
| `navil scan --format sarif` | Output scan results in SARIF v2.1.0 format |
| `navil scan-batch <dir>` | Batch-scan crawl results directory, output JSONL |
| `navil crawl registries` | Discover MCP servers from npm, PyPI, and awesome-mcp-servers |
| `navil report-mcp <jsonl>` | Generate State of MCP security report from batch scan results |
| `navil pentest` | Run SAFE-MCP penetration tests (11 attack scenarios) |
| `navil proxy start` | Start Python MCP security proxy |
| `navil proxy stop` | Stop the running proxy |
| `navil cloud serve` | Launch Navil Cloud dashboard |
| `navil seed-database` | Populate ML baselines with synthetic attack data |
| `navil seed-database --full` | Run all 32+ scenarios with 200+ parameterized variants |
| `navil seed-database --export` | Export all scenario definitions to JSON |
| `navil credential issue` | Issue a new JWT credential |
| `navil credential revoke` | Revoke an active credential |
| `navil credential revoke --cascade` | Cascade-revoke credential and all descendants |
| `navil credential list` | List credentials with filters |
| `navil credential exchange` | Exchange an OIDC token for a Navil credential |
| `navil credential delegate` | Delegate credential to a child agent with narrowed scope |
| `navil credential chain <id>` | Display full delegation chain for a credential |
| `navil blocklist update` | Fetch and merge latest threat blocklist |
| `navil blocklist status` | Show blocklist version, pattern count, and stats |
| `navil blocklist load <file>` | Load blocklist from a local JSON file |
| `navil blocklist search <pattern>` | Search for matching blocklist entries |
| `navil policy check` | Evaluate a tool call against policy |
| `navil wrap <config>` | One-command setup: wrap all MCP servers in a config with navil shim |
| `navil shim` | Wrap a single stdio MCP server with security checks |
| `navil monitor start` | Start anomaly monitoring mode |
| `navil report` | Generate security report |
| `navil feedback submit` | Submit operator feedback on an anomaly alert |
| `navil llm analyze-config` | AI-powered config analysis |
| `navil llm explain-anomaly` | AI-powered anomaly explanation |
| `navil llm generate-policy` | Generate policy from natural language |
| `navil llm suggest-healing` | AI-powered remediation suggestions |

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NAVIL_TARGET_URL` | `http://localhost:3000` | Upstream MCP server (Rust proxy) |
| `NAVIL_REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection (Rust proxy) |
| `NAVIL_HMAC_SECRET` | *(none)* | HMAC signing key for request auth |
| `NAVIL_PORT` | `8080` | Rust proxy listen port |
| `NAVIL_DISABLE_CLOUD_SYNC` | `false` | Disable cloud telemetry sync |
| `NAVIL_API_KEY` | *(none)* | Navil Cloud API key (paid mode) |
| `NAVIL_INTEL_SYNC_INTERVAL` | `3600` | Seconds between outbound cloud sync cycles |
| `NAVIL_INTEL_FETCH_INTERVAL` | `3600` | Seconds between inbound pattern fetch cycles |
| `NAVIL_DEPLOYMENT_SECRET` | *(auto-generated)* | Secret for HMAC agent anonymization |
| `NAVIL_CLOUD_URL` | `https://api.navil.ai` | Navil Cloud API base URL |
| `NAVIL_DASHBOARD_TOKEN` | *(none)* | Bearer token for credential endpoints (unset = open in dev) |
| `ANTHROPIC_API_KEY` | *(none)* | Anthropic API key for LLM features |
| `OPENAI_API_KEY` | *(none)* | OpenAI API key for LLM features |
| `GEMINI_API_KEY` | *(none)* | Google Gemini API key for LLM features |
| `ALLOWED_ORIGINS` | `*` | CORS origins for dashboard API |

## Zero-Knowledge Telemetry Details

When cloud sync is enabled, Navil enforces strict privacy guarantees at the transmission boundary:

- **Agent identities** are replaced with one-way HMAC-SHA256 hashes using a per-deployment secret. Cannot be reversed.
- **Only numeric aggregates and categorical labels** leave the deployment (severity, confidence, duration, bytes, anomaly type).
- **Raw data is actively blocked** — agent names, tool arguments, evidence, file paths, server URLs, IP addresses, emails, and prompts are stripped. A runtime check raises `ValueError` if any banned field leaks through.
- **No PII is forwarded to MCP servers** — the proxy injects only a pseudonymous `x-human-identity` (OIDC `sub` claim) for audit trails. Email addresses are never forwarded upstream.
- **IP addresses are never stored raw** — the cloud backend pseudonymizes all IP addresses via truncated SHA-256 before writing to the database.
- **Fully opt-out** with `NAVIL_DISABLE_CLOUD_SYNC=true`.

### Exactly What Data Leaves Your Machine

When cloud sync sends data to Navil Cloud, the payload is validated against an **explicit allowlist** ([`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py)). Only these fields are permitted:

| Field | Example | Purpose |
|-------|---------|---------|
| `agent_id` | `a3f8c1...` (HMAC hash) | Anonymized agent identifier |
| `tool_name` | `read_file` | Which MCP tool was invoked |
| `anomaly_type` | `payload_size_spike` | Type of anomaly detected |
| `severity` | `HIGH` | Alert severity level |
| `confidence` | `0.92` | Detection confidence score |
| `statistical_deviation` | `3.7` | How far from the EMA baseline |
| `payload_bytes` | `4096` | Request size (numeric only) |
| `response_bytes` | `1024` | Response size (numeric only) |
| `duration_ms` | `150` | Call duration |
| `timestamp` | `2026-03-15T10:30:00Z` | When the event occurred |
| `action` | `blocked` | What Navil did (forwarded/blocked) |
| `event_uuid` | `550e8400-...` | Deterministic dedup key |
| `tool_sequence_hash` | `b2a1f3...` (SHA-256) | Hash of tool call sequence |

**Explicitly banned** (runtime `ValueError` if any leak through): `agent_name`, `description`, `evidence`, `recommended_action`, `target_server`, `location`, `arguments_hash`, `arguments`, `params`, `raw`, `content`, `prompt`, `ip_address`, `email`.

### Data Retention (Cloud Backend)

| Data Type | Retention | Deletion |
|-----------|-----------|----------|
| Telemetry events | 30 days (auto-deleted) | Or on-demand via data erasure |
| Sync events (threat intel) | 7 days (auto-deleted) | Or on-demand via data erasure |
| Account data | Duration of subscription | Immediate on erasure request |
| IP addresses | Never stored raw | SHA-256 pseudonymized at ingest |

See [ARCHITECTURE.md](ARCHITECTURE.md#zero-knowledge-telemetry) for the full field allowlist/blocklist.

## The Navil "Give-to-Get" Initiative

Navil operates on a **Mutual Defense** model. AI threats evolve in minutes, not months. A prompt injection discovered on one machine should protect every other machine within seconds.

### How It Works

**The Give:** Your local Navil instance detects a new attack pattern and sends a sanitized metadata snippet — anomaly type, severity, confidence score, tool name, and timing — to the central hub. Agent identities are HMAC-anonymized. Raw data never leaves your machine. You can audit exactly what is sent by inspecting [`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py).

**The Get:** In exchange, your instance receives real-time updates from the **Global Threat Blocklist** — a curated feed of malicious patterns discovered by thousands of other Navil nodes. The built-in `ThreatIntelFetcher` polls `GET /v1/threat-intel/patterns` on startup and periodically thereafter, publishing patterns to the local `PatternStore` for confidence-boosted anomaly detection.

### Privacy-First Architecture

1. **Local Sanitization** — All telemetry is stripped of PII, secrets, and raw prompt content on your machine before it ever reaches our servers.
2. **No Raw Data** — We never see your AI's conversations. We only see the *shape* of the attack (anomaly type, severity, timing, tool name).
3. **Deterministic Deduplication** — Each sync event carries a UUID5 `event_uuid` so the cloud can deduplicate without storing raw identifiers.
4. **Full Transparency** — You can audit exactly what is being sent by inspecting [`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py).

### Tiered Participation

| Tier | Price | Telemetry Sharing | Blocklist Access |
|------|-------|-------------------|------------------|
| **Community (OSS)** | $0/mo | Required (anonymized) | Full access (48h delay) |
| **Dark Site (OSS)** | $0/mo | Disabled | No global updates (local-only) |
| **Pro** | $49/mo | Optional (privacy premium) | Real-time + verified feed |
| **Growth** | $99/mo | Optional | Real-time + 5 custom rules |
| **Team** | $249/mo | Optional | Real-time + unlimited rules |
| **Enterprise** | Custom | Optional | Real-time + dedicated feed |

**For enterprises** whose security policy prohibits outbound telemetry: provide a valid `NAVIL_API_KEY` to receive threat intelligence without sharing your own signals. Visit [navil.ai](https://navil.ai) to get a key.

```bash
# Community mode (default): share and receive
navil cloud serve

# Paid mode: receive without sharing
NAVIL_API_KEY=nvl_your_key NAVIL_DISABLE_CLOUD_SYNC=true navil cloud serve
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (946 tests)
pytest

# Lint
ruff check .

# Type check
mypy navil

# Build Rust proxy
cd navil-proxy && cargo build --release

# Dashboard (requires Node.js 20+)
cd dashboard && npm install && npm run dev
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and how to submit changes.

## Security

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## License

Navil uses a dual-license model:

| Component | License |
|-----------|---------|
| Core CLI, anomaly detection, proxy, adaptive ML, Rust data plane (`navil/`, `navil/adaptive/`, `navil-proxy/`) | [Apache 2.0](LICENSE) |
| Cloud dashboard, LLM features, API server (`navil/cloud/`, `navil/llm/`, `dashboard/`) | [Business Source License 1.1](LICENSE.cloud) |

**Apache 2.0** — free to use, modify, and redistribute for any purpose.

**BSL 1.1** — free for internal use and self-hosting. You may not offer the Licensed Work as a competing hosted service. Each release converts to Apache 2.0 four years after its publication date.

Commercial licensing enquiries: https://github.com/ivanlkf/navil/issues
