# Navil

[![CI](https://github.com/ivanlkf/navil/actions/workflows/ci.yml/badge.svg)](https://github.com/ivanlkf/navil/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

High-performance Rust/Python security gateway for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. A Rust data plane handles live traffic with sub-millisecond O(1) threshold checks, while a Python control plane runs 12 statistical anomaly detectors, adaptive ML baselines, and LLM-powered analysis.

> Developed by **[Pantheon Lab Limited](https://pantheonlab.ai)**.

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="Navil Dashboard — Fleet overview with agent health, alerts, credential status, and policy decisions" width="800" />
</p>

## Features

- **Rust Data Plane** — Axum-based reverse proxy with HMAC-SHA256 verification, JSON depth limiting, O(1) Redis threshold checks, and minute-bucketed rate limiting. Sub-millisecond overhead per request.
- **Python Control Plane** — 12 statistical behavioral detectors with adaptive EMA baselines, operator feedback loops, and learned pattern matching. Runs off the hot path via Redis-bridged telemetry.
- **Zero-Knowledge Telemetry** — Cloud sync anonymizes all agent identities with HMAC-SHA256, enforces a strict field allowlist, and actively blocks banned fields. Raw data never leaves your deployment. Fully opt-out. See [Privacy Guarantees](#zero-knowledge-telemetry).
- **Configuration Scanning** — Detect plaintext credentials, over-privileged permissions, missing authentication, unverified sources, and malicious patterns. Produces a 0-100 security score.
- **Credential Lifecycle** — Issue, rotate, and revoke JWT tokens with JIT provisioning, configurable TTL, usage tracking, and immutable audit logs.
- **Policy Enforcement** — YAML-driven tool/action allow-lists, per-agent rate limiting, data-sensitivity gates, and suspicious-pattern detection.
- **Penetration Testing** — 11 SAFE-MCP attack simulations that validate your detectors actually catch threats. No real network traffic generated.
- **LLM Analysis** — AI-powered config analysis, anomaly explanation, policy generation, and self-healing with SSE streaming. Bring your own key (Anthropic, OpenAI, Gemini, Ollama).
- **Cloud Dashboard** — React-based fleet monitoring dashboard with alerting, gateway traffic visualization, credential management, and pentest UI.

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

Navil ships with a full-featured security dashboard for visualizing and managing your MCP fleet.

<table>
<tr>
<td width="50%">

**Penetration Testing** — Run all 11 SAFE-MCP attack scenarios and see which threats your detectors catch.

<img src="docs/screenshots/pentest.png" alt="Pentest — 11/11 attacks detected" />

</td>
<td width="50%">

**Config Scanner** — Paste any MCP server config and get a security score with actionable findings.

<img src="docs/screenshots/scanner.png" alt="Scanner — vulnerability scan results" />

</td>
</tr>
<tr>
<td width="50%">

**Self-Healing AI** — LLM-powered threat analysis with one-click remediation actions.

<img src="docs/screenshots/self-healing.png" alt="Self-Healing — AI remediation suggestions" />

</td>
<td width="50%">

**Alerts** — Real-time anomaly alerts with severity filtering across your agent fleet.

<img src="docs/screenshots/alerts.png" alt="Alerts — anomaly detection alerts" />

</td>
</tr>
<tr>
<td width="50%">

**Policy Engine** — Check permissions, review decisions, and generate YAML policies with AI.

<img src="docs/screenshots/policy.png" alt="Policy — permission checks and AI generation" />

</td>
<td width="50%">

**Gateway** — MCP security proxy with real-time traffic monitoring and interception.

<img src="docs/screenshots/gateway.png" alt="Gateway — proxy configuration" />

</td>
</tr>
</table>

<details>
<summary>More screenshots</summary>

| Page | Screenshot |
|------|-----------|
| Agents | <img src="docs/screenshots/agents.png" alt="Agents" width="600" /> |
| Credentials | <img src="docs/screenshots/credentials.png" alt="Credentials" width="600" /> |
| Analytics | <img src="docs/screenshots/analytics.png" alt="Analytics" width="600" /> |
| Settings | <img src="docs/screenshots/settings.png" alt="Settings" width="600" /> |

</details>

## Installation

### Prerequisites

| Component | Required | Version |
|-----------|----------|---------|
| Python | Yes | 3.10+ |
| Redis | Yes (for proxy mode) | 5.0+ |
| Rust | Optional (for Rust proxy) | stable |
| Node.js | Optional (for dashboard dev) | 20+ |

### Python packages

```bash
pip install navil
```

With optional features:

```bash
pip install navil[llm]         # + AI-powered analysis (Anthropic, OpenAI, Gemini)
pip install navil[cloud]       # + Cloud dashboard (FastAPI + React)
pip install navil[all]         # Everything
```

Or from source:

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

## Quick Start

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

### Scan an MCP configuration

```bash
navil scan config.json
```

### Run penetration tests

```bash
navil pentest                               # All 11 SAFE-MCP attack simulations
navil pentest --scenario reconnaissance     # Single scenario
navil pentest --json -o report.json         # JSON output for CI
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

## Zero-Knowledge Telemetry

When cloud sync is enabled, Navil enforces strict privacy guarantees at the transmission boundary:

- **Agent identities** are replaced with one-way HMAC-SHA256 hashes using a per-deployment secret. Cannot be reversed.
- **Only numeric aggregates and categorical labels** leave the deployment (severity, confidence, duration, bytes, anomaly type).
- **Raw data is actively blocked** -- agent names, tool arguments, evidence, file paths, server URLs, IP addresses, and prompts are stripped. A runtime check raises `ValueError` if any banned field leaks through.
- **Fully opt-out** with `NAVIL_DISABLE_CLOUD_SYNC=true`.

See [ARCHITECTURE.md](ARCHITECTURE.md#zero-knowledge-telemetry) for the full field allowlist/blocklist.

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
| `ANTHROPIC_API_KEY` | *(none)* | Anthropic API key for LLM features |
| `OPENAI_API_KEY` | *(none)* | OpenAI API key for LLM features |
| `GEMINI_API_KEY` | *(none)* | Google Gemini API key for LLM features |
| `ALLOWED_ORIGINS` | `*` | CORS origins for dashboard API |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (324 tests)
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

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and how to submit changes.

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

Commercial licensing enquiries: info@pantheonlab.ai
