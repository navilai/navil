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

### Credential Lifecycle
Issue, rotate, and revoke JWT tokens with JIT provisioning, configurable TTL, usage tracking, and immutable audit logs.

### Zero-Knowledge Telemetry
Cloud sync anonymizes all agent identities with HMAC-SHA256, enforces a strict field allowlist, and actively blocks banned fields. Raw data never leaves your deployment. Fully opt-out with `NAVIL_DISABLE_CLOUD_SYNC=true`. See [Privacy Guarantees](#zero-knowledge-telemetry-details).

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
navil seed-database -n 5000          # More iterations for tighter baselines
navil seed-database --json           # Machine-readable output
```

This populates the `BehavioralAnomalyDetector` with synthetic attack data so the statistical thresholds (mean + 5*std_dev) have historical baselines from day one.

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

### Check a policy decision

```bash
navil policy check --tool file_system --agent my-agent --action read
```

## Commands

| Command | Description |
|---------|-------------|
| `navil scan <config>` | Scan MCP config for vulnerabilities (0-100 score) |
| `navil pentest` | Run SAFE-MCP penetration tests (11 attack scenarios) |
| `navil proxy start` | Start Python MCP security proxy |
| `navil proxy stop` | Stop the running proxy |
| `navil cloud serve` | Launch Navil Cloud dashboard |
| `navil seed-database` | Populate ML baselines with synthetic attack data |
| `navil credential issue` | Issue a new JWT credential |
| `navil credential revoke` | Revoke an active credential |
| `navil credential list` | List credentials with filters |
| `navil policy check` | Evaluate a tool call against policy |
| `navil wrap <config>` | One-command setup: wrap all MCP servers in a config with navil shim |
| `navil shim` | Wrap a single stdio MCP server with security checks |
| `navil monitor start` | Start anomaly monitoring mode |
| `navil report` | Generate security report |
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
| `NAVIL_INTEL_SYNC_INTERVAL` | `3600` | Seconds between cloud sync cycles |
| `NAVIL_DEPLOYMENT_SECRET` | *(auto-generated)* | Secret for HMAC agent anonymization |
| `ANTHROPIC_API_KEY` | *(none)* | Anthropic API key for LLM features |
| `OPENAI_API_KEY` | *(none)* | OpenAI API key for LLM features |
| `GEMINI_API_KEY` | *(none)* | Google Gemini API key for LLM features |
| `ALLOWED_ORIGINS` | `*` | CORS origins for dashboard API |

## Zero-Knowledge Telemetry Details

When cloud sync is enabled, Navil enforces strict privacy guarantees at the transmission boundary:

- **Agent identities** are replaced with one-way HMAC-SHA256 hashes using a per-deployment secret. Cannot be reversed.
- **Only numeric aggregates and categorical labels** leave the deployment (severity, confidence, duration, bytes, anomaly type).
- **Raw data is actively blocked** — agent names, tool arguments, evidence, file paths, server URLs, IP addresses, and prompts are stripped. A runtime check raises `ValueError` if any banned field leaks through.
- **Fully opt-out** with `NAVIL_DISABLE_CLOUD_SYNC=true`.

See [ARCHITECTURE.md](ARCHITECTURE.md#zero-knowledge-telemetry) for the full field allowlist/blocklist.

## The Navil "Give-to-Get" Initiative

Navil operates on a **Mutual Defense** model. AI threats evolve in minutes, not months. A prompt injection discovered on one machine should protect every other machine within seconds.

### How It Works

**The Give:** Your local Navil instance detects a new attack pattern and sends a sanitized metadata snippet — anomaly type, severity, confidence score, tool name, and timing — to the central hub. Agent identities are HMAC-anonymized. Raw data never leaves your machine. You can audit exactly what is sent by inspecting [`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py).

**The Get:** In exchange, your instance receives real-time updates from the **Global Threat Blocklist** — a curated feed of malicious patterns discovered by thousands of other Navil nodes, applied instantly to your local detectors and Rust proxy.

### Privacy-First Architecture

1. **Local Sanitization** — All telemetry is stripped of PII, secrets, and raw prompt content on your machine before it ever reaches our servers.
2. **No Raw Data** — We never see your AI's conversations. We only see the *shape* of the attack (anomaly type, severity, timing, tool name).
3. **Full Transparency** — You can audit exactly what is being sent by inspecting [`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py).

### Tiered Participation

| Tier | Telemetry Sharing | Global Blocklist Access |
|------|-------------------|------------------------|
| **Community (OSS)** | Required (default) | Full access (crowdsourced feed) |
| **Dark Site (OSS)** | Disabled | No global updates (local-only protection) |
| **Pro / Team (Paid)** | Optional ("privacy premium") | Premium access (real-time + verified feed) |

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

# Run tests (473 tests)
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
