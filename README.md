<p align="center">
  <h1 align="center">Navil</h1>
  <p align="center">
    <strong>The open-source agent governance middleware.</strong>
    <br />
    Observability, policy enforcement, and threat intelligence for AI agent tool calls -- whether your agents use MCP, CLI, or both.
  </p>
</p>

<p align="center">
  <a href="https://github.com/navilai/navil/actions/workflows/ci.yml"><img src="https://github.com/navilai/navil/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0" /></a>
</p>

<p align="center">
  <a href="https://navil.ai/radar"><img src="https://navil-cloud-api.onrender.com/v1/badge/events_7d.svg" alt="Threats Detected" /></a>
  <a href="https://navil.ai/radar"><img src="https://navil-cloud-api.onrender.com/v1/badge/machines.svg" alt="Active Machines" /></a>
  <a href="https://navil.ai/radar"><img src="https://navil-cloud-api.onrender.com/v1/badge/patterns.svg" alt="Blocklist" /></a>
  <a href="https://navil.ai/radar"><img src="https://navil-cloud-api.onrender.com/v1/badge/blocked.svg" alt="Detection Rate" /></a>
</p>

```bash
pip install navil
navil wrap ~/.cursor/mcp.json    # or claude_desktop_config.json, openclaw.json
```

<p align="center">
  <a href="#the-openclaw-security-crisis">OpenClaw Crisis</a> &bull;
  <a href="#getting-started">Getting Started</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#community-threat-network">Threat Network</a> &bull;
  <a href="#works-with">Works With</a> &bull;
  <a href="#cicd-integration">CI/CD</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#performance">Performance</a> &bull;
  <a href="#cloud-dashboard">Cloud</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#installation">Installation</a>
</p>

---

## Why Runtime Monitoring, Not Just Scanning

Static scanning of MCP packages finds real issues -- but only 1.7% of them. We scanned 4,401 MCP packages and found 77 with actual code-level vulnerabilities. The packages themselves are mostly fine.

**The real threats are dynamic.** An MCP server can have perfectly clean source code and still be weaponized at runtime:

| Threat | Static scan catches it? | Runtime proxy catches it? |
|--------|:-----------------------:|:------------------------:|
| Code vulnerabilities in packages | Yes (1.7% found) | -- |
| Prompt injection via tool calls | No | **Yes** |
| Tool poisoning (malicious descriptions) | No | **Yes** |
| Data exfiltration via tool responses | No | **Yes** |
| Rug pull (server changes post-install) | No | **Yes** |
| Credential exposure through tool calls | No | **Yes** |
| Privilege escalation via tool chaining | No | **Yes** |

Static scanning catches 1.7%. Runtime monitoring catches the other 98.3%. That's why Navil is a proxy, not just a scanner. The scanner is a nice-to-have. The proxy is the product.

**Meanwhile, the MCP protocol itself has real problems:** 8+ CVEs in 6 weeks (allowlist bypass, wrapper bypass, exec approval bypass, path traversal, memory bomb, token theft). 42,665+ instances exposed to the public internet with no authentication.

Navil fixes this in one command:

```bash
pip install navil
navil wrap your_mcp_config.json
```

Every MCP server in your config is now behind a security proxy that monitors tool calls, enforces policies, detects anomalies, and blocks known attack patterns -- with [<3 us overhead per message](#performance). Your original config is backed up automatically.

This works for any MCP client, not just OpenClaw. But if you're running OpenClaw, you need this today.

## Getting Started

Two lines. No API key. No signup.

```bash
pip install navil
navil wrap ~/.cursor/mcp.json   # or claude_desktop_config.json, openclaw.json
```

That's it. Every MCP server in your config is now wrapped with `navil shim`, which intercepts all tool calls and runs them through the security pipeline before forwarding.

**Already have Navil? Upgrade to the latest:**

```bash
pip install navil --upgrade
```

**Want fleet analytics and real-time threat intel?** Connect to the cloud in one command:

```bash
navil cloud login    # OAuth device flow -- opens browser, no API key to paste
```

This connects your local instance to [navil.ai](https://navil.ai) for dashboards, per-agent trust scores, and real-time access to the community threat network. The free tier works without it.

## Who Is Navil For

| Buyer | Problem | What Navil Does |
|-------|---------|-----------------|
| **Platform teams** deploying MCP servers for internal dev tooling | No visibility into what agents are doing across the fleet | Centralized observability + policy enforcement across all agents |
| **SaaS companies** building MCP integrations for customers | Multi-tenant auth and credential lifecycle are table stakes | JWT credential management, per-tenant scoping, audit trails |
| **Regulated industries** (finance, healthcare, government) | Audit trails and access controls aren't optional | Complete audit log, per-tool policy enforcement, anomaly alerting |
| **Solo developers** using Claude/Cursor/OpenClaw | Runtime threats invisible to static scanning, no auth on MCP servers | One-command security proxy with community threat intel |

Navil works for solo developers (free, OSS, no account needed). But the architecture is built for teams and enterprises who need governance, not just scanning.

## How It Works

Bloomberg built auth, rate limiting, and AI guardrails internally to make MCP safe for enterprise. Block built Goose, an MCP-compatible agent with governance middleware. Most organizations can't build this in-house. Navil is the open-source version.

```
                    Agent Governance Layer

  AI Agents ------> [ Navil ] ------> Tools (MCP, CLI, API)
                       |
                       |  Observability: every tool call logged
                       |  Policy: least-privilege enforcement
                       |  Detection: anomaly + threat matching
                       |  Sharing: community threat intelligence
                       v
              Community Threat Network

  Using Navil IS contributing to global security.
  Every anomaly detected locally is anonymized and shared.
  Every shared pattern makes every other node smarter.
```

MCP has real problems -- context bloat, no auth, no observability. The "MCP is dead" crowd is right about the problems, wrong about the solution. The answer isn't to abandon the protocol. It's to fix the operational layer. That's what Navil does.

### The Token Cost Problem

MCP servers expose ALL tools to ALL agents. GitHub MCP alone dumps 90+ tool schemas consuming 50,000+ tokens before the model even starts thinking. At scale -- 2,500 API endpoints via MCP -- that's 244,000 tokens just for tool definitions, exceeding most model context limits.

This isn't just a performance problem. It's a cost problem. Every wasted token is money spent on inference that adds zero value. And it's a security problem -- exposing tools an agent doesn't need violates least privilege.

Navil's policy engine fixes both:

```yaml
# ~/.navil/policy.yaml — only expose what the agent needs
scopes:
  code-review:
    allow: [get_pull_request, list_files, create_review_comment]
  deploy:
    allow: [create_deployment, get_deployment_status]
  default:
    allow: "*"   # backward compatible
```

A code review agent sees 3 tools instead of 90. That's a **94% reduction in schema tokens** -- cheaper inference, faster responses, and a smaller attack surface. Security and cost optimization from the same configuration.

### What `navil wrap` does

```
Before:                              After:
+---------------------+              +---------------------+
|  "filesystem": {    |              |  "filesystem": {    |
|    "command": "npx", |   navil     |    "command":"navil",|
|    "args": [...]    | --wrap-->   |    "args": ["shim", |
|  }                  |              |      "--cmd","npx ..."|
+---------------------+              +---------------------+
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

## Community Threat Network

AI threats evolve in minutes, not months. A prompt injection discovered on one machine should protect every other machine within seconds. Navil makes this automatic.

**The Give:** Your local Navil instance detects a new attack pattern and sends a sanitized metadata snippet -- anomaly type, severity, confidence score, tool name, and timing -- to the central hub. Agent identities are HMAC-anonymized. Raw data never leaves your machine. You can audit exactly what is sent by inspecting [`navil/cloud/telemetry_sync.py`](navil/cloud/telemetry_sync.py).

**The Get:** In exchange, your instance receives updates from the Global Threat Blocklist -- a curated feed of malicious patterns discovered by thousands of other Navil nodes. The built-in `ThreatIntelFetcher` polls `GET /v1/threat-intel/patterns` on startup and periodically thereafter.

**Privacy guarantees:** Only numeric aggregates and categorical labels leave your machine. Agent identities are one-way HMAC-SHA256 hashed. A runtime check raises `ValueError` if any banned field leaks through. Full opt-out with `NAVIL_DISABLE_CLOUD_SYNC=true`. See [DATA_COLLECTION.md](DATA_COLLECTION.md).

### Tiered Access

| Tier | Price | Sharing | Blocklist Access | Limits |
|------|-------|---------|------------------|--------|
| **Community (OSS)** | $0/mo | Required (anonymized) | Full access, 48h delay | 25 agents · 25 keys · 60 req/min |
| **Pro** | $59/mo | Optional | Real-time + verified feed | 50 agents · 50 keys · 1,000 req/min |
| **Growth** | $129/mo | Optional | Real-time + OIDC + 5 custom rules | 100 agents · 100 keys · 5,000 req/min |
| **Team** | $299/mo | Optional | Real-time + full OIDC + unlimited rules | 250 agents · 500 keys · 10,000 req/min |
| **Enterprise** | Custom | Optional | Real-time + dedicated feed + on-prem | 10,000 agents · 10,000 keys · 100,000 req/min |

```bash
# Community mode (default): share and receive
navil wrap config.json

# Paid mode: receive without sharing
NAVIL_API_KEY=navil_live_your_key NAVIL_DISABLE_CLOUD_SYNC=true navil wrap config.json
```

## Works With

| Client | Config Path | Command |
|--------|------------|---------|
| **Claude Desktop** | `~/Library/Application Support/Claude/claude_desktop_config.json` | `navil wrap ~/Library/Application\ Support/Claude/claude_desktop_config.json` |
| **Cursor** | `~/.cursor/mcp.json` | `navil wrap ~/.cursor/mcp.json` |
| **Continue.dev** | `.continue/config.json` | `navil wrap .continue/config.json` |
| **OpenClaw** | `openclaw.json` | `navil wrap openclaw.json` |

Any tool that uses MCP config files works. Navil reads the config, wraps each server entry, and writes it back.

For OpenClaw instances using MCP over Streamable HTTP (production deployments), use the HTTP proxy:

```bash
navil proxy start --target http://your-mcp-server:3000 --no-auth
# Point your OpenClaw MCP server URL at http://localhost:9090/mcp
```

## OpenClaw Skills

Install Navil directly from ClawHub — or just tell your OpenClaw agent "secure my setup."

| Skill | What It Does | Install |
|-------|-------------|---------|
| **navil-shield** | Always-on runtime security proxy | `clawhub install ivanpantheon/navil-shield` |
| **navil-audit** | Deep security audit with penetration testing | `clawhub install ivanpantheon/navil-audit` |
| **navil-policy** | Token cost optimization via tool scoping | `clawhub install ivanpantheon/navil-policy` |

Or paste any of these ClawHub links into your OpenClaw chat — the agent handles setup automatically.

## CI/CD Integration

824 malicious skills in the OpenClaw registry. 100% of public MCP servers missing authentication. Don't let bad configs reach production.

### GitHub Actions

```yaml
name: MCP Security Scan
on:
  pull_request:
    paths: ["**.mcp.json", ".mcp.json", "openclaw.json"]

jobs:
  navil-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: navil/scan-action@v1
        with:
          config: mcp_config.json
          fail-on: critical

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif
```

Scan results appear in the GitHub **Security** tab under **Code scanning alerts**. Every PR that touches an MCP config gets scanned automatically. Critical findings block the merge.

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

### CLI scan formats

```bash
navil scan config.json                          # Human-readable (default)
navil scan config.json --format sarif           # SARIF v2.1.0 for CI
navil scan config.json --format json            # JSON for scripting
navil scan config.json --format sarif --output results.sarif
```

## Features

### Rust Data Plane
Axum-based reverse proxy with HMAC-SHA256 verification, JSON depth limiting, O(1) Redis threshold checks, and minute-bucketed rate limiting. Sub-millisecond overhead per request.

### Behavioral Anomaly Detection
11 statistical detectors with adaptive EMA baselines, operator feedback loops, and learned pattern matching. Runs off the hot path via Redis-bridged telemetry -- security analysis never blocks your agents.

### Configuration Scanning
Detect plaintext credentials, over-privileged permissions, missing authentication, unverified sources, and malicious patterns. Produces a 0-100 security score.

### Policy Enforcement
YAML-driven tool/action allow-lists, per-agent rate limiting, data-sensitivity gates, and suspicious-pattern detection.

### Penetration Testing
11 SAFE-MCP attack simulations that validate your detectors actually catch threats. No real network traffic generated.

### LLM-Powered Analysis
AI-powered config analysis, anomaly explanation, policy generation, and self-healing. Bring your own key -- supports Anthropic, OpenAI, Gemini, and Ollama (fully local).

### Identity System
OIDC token exchange converts external identity tokens into Navil credentials with human context attached. Delegation chains let parent credentials mint narrower child credentials for sub-agents, with full chain visualization and cascade revocation that invalidates an entire delegation tree in one call.

### Credential Lifecycle
Issue, rotate, and revoke JWT tokens with JIT provisioning, configurable TTL, usage tracking, and immutable audit logs. Hardened with a global active-credential cap (500), auto-purge of expired credentials, and thread-safe rotation.

### Threat Intelligence & Blocklist Engine
Community-sourced threat intel via the [Give-to-Get initiative](#community-threat-network), backed by a local blocklist engine for pattern matching. Ships with 568 detection patterns across 30 attack categories (v3 blocklist). The Navil-200 attack benchmark validates proxy detection across protocol manipulation, tool shadowing, context smuggling, multi-agent exploits, RAG poisoning, supply chain attacks, privilege escalation, and anti-forensics vectors.

### Honeypot & Canary Kit
Deploy decoy MCP servers to detect and study attackers in the wild. 10 built-in profiles: `dev_tools`, `cloud_creds`, `db_admin`, `openclaw_registry`, `ci_pipeline`, `llm_gateway`, `k8s_dashboard`, `rag_endpoint`, `oauth_server`, and `agent_marketplace`. A built-in `SignatureExtractor` analyzes collected interactions and auto-generates blocklist entries. Production deployment uses Docker Compose with isolated networking.

### Tool Scoping
Context-aware visibility control for MCP tools. Define scopes in `policy.yaml` to restrict which tools each agent *sees* in `tools/list` responses -- separate from policy enforcement (which controls what agents can *call*). Reduces schema token bloat by up to 94%. The Rust proxy reads scope definitions from Redis in O(1) and caches filtered responses with 60s TTL. Ships with community templates for GitHub, filesystem, and kubectl MCP servers.

### AI Policy Builder
Closed-loop policy generation from observed agent behavior. The system watches how agents use tools, detects anomalies, suggests policy rules with confidence scores, and auto-applies safe changes. Three CLI commands: `navil policy auto-generate` (bootstrap from baselines), `navil policy suggest` (review pending rules), and `navil policy rollback` (undo auto-generated changes). Machine-generated rules go to `policy.auto.yaml` -- your `policy.yaml` always takes precedence.

### CLI Wrapping
Extend governance beyond MCP to CLI tools. `navil wrap` creates PATH-prefix shims for `gh`, `kubectl`, `aws`, and other CLI binaries. Each shim logs invocations, checks policy rules, forwards to the real binary, and captures telemetry -- using the same pipeline as MCP events.

### A2A Agent Card
Publish a discoverable agent identity at `/.well-known/agent.json` per the Google A2A spec. Other agents can discover your Navil-protected agent's capabilities, authentication requirements, and governance metadata. Supports agent-to-agent task dispatch via the `/a2a` endpoint.

### Registry Scanning
Discover and audit MCP servers at scale. `navil crawl registries` discovers servers from npm, PyPI, and awesome-mcp-servers lists. `navil scan-batch` bulk-scans crawl results and outputs JSONL.

### Zero-Knowledge Telemetry
Cloud sync anonymizes all agent identities with HMAC-SHA256, enforces a strict field allowlist, and actively blocks banned fields. Raw data never leaves your deployment. Fully opt-out with `NAVIL_DISABLE_CLOUD_SYNC=true`. See [DATA_COLLECTION.md](DATA_COLLECTION.md).

## Performance

Navil's security pipeline adds **negligible overhead** to real workloads. We benchmarked the stdio shim against a mock MCP server to isolate the cost of security checks from network/tool latency.

### Per-message overhead

| Component | Mean | p50 | p99 |
|-----------|------|-----|-----|
| Full security check (sanitize + parse + policy + anomaly) | **2.7 us** | 2.4 us | 6.1 us |
| `orjson` parse | 0.9 us | 0.8 us | 2.0 us |
| Policy engine lookup | 0.5 us | 0.4 us | 1.2 us |
| Anomaly gate scan | 0.3 us | 0.3 us | 0.8 us |

### Total session wall-clock

| Session size | Direct | With Navil | Overhead |
|--------------|--------|------------|----------|
| Light (5 tool calls) | 11.5 ms | 12.0 ms | **+0.5 ms** (4.4%) |
| Medium (50 tool calls) | 12.8 ms | 14.2 ms | **+1.4 ms** (10.8%) |
| Heavy (500 tool calls) | 28.0 ms | 40.3 ms | **+12.3 ms** |

> **Context:** These benchmarks use a mock server that responds in ~40 us. Real MCP tools take 1-5,000 ms (file reads, API calls, LLM inference). On any real workload, Navil's overhead is **< 0.1%** of total session time.

```bash
python bench_shim_latency.py    # Per-message breakdown
python bench_total_latency.py   # Full session wall-clock
```

## Cloud Dashboard

Full-featured security dashboard for visualizing and managing your MCP fleet. Available at [navil.ai](https://navil.ai).

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="Navil Dashboard -- Fleet overview showing agent count, active alerts, invocations, credential status, agent health grid, and recent policy decisions" width="800" />
</p>

<table>
<tr>
<td width="50%">

**Dashboard** -- Fleet overview: agent count, active alerts, invocations, credential status, agent health grid, and recent policy decisions.

<img src="docs/screenshots/dashboard.png" alt="Dashboard -- fleet overview with stats and agent health" />

</td>
<td width="50%">

**Gateway** -- Configure and start the MCP Security Proxy. Intercepts agent-to-tool traffic in real time, enforcing policies and blocking anomalies.

<img src="docs/screenshots/gateway.png" alt="Gateway -- proxy configuration and start" />

</td>
</tr>
<tr>
<td width="50%">

**Penetration Testing** -- Run all 11 SAFE-MCP attack scenarios and see which threats your detectors catch.

<img src="docs/screenshots/pentest.png" alt="Pentest -- 11/11 attacks detected" />

</td>
<td width="50%">

**Config Scanner** -- Paste any MCP server config and get a 0-100 security score with actionable remediation steps.

<img src="docs/screenshots/scanner.png" alt="Config Scanner -- vulnerability scan results" />

</td>
</tr>
<tr>
<td width="50%">

**Self-Healing AI** -- Analyze threats and apply AI-generated remediation actions with confidence scores.

<img src="docs/screenshots/self-healing.png" alt="Self-Healing -- AI remediation actions" />

</td>
<td width="50%">

**Alerts** -- Real-time anomaly alerts with severity filtering across your agent fleet.

<img src="docs/screenshots/alerts.png" alt="Alerts -- anomaly detection alerts with severity filters" />

</td>
</tr>
</table>

<details>
<summary>More screenshots</summary>

| Page | Screenshot |
|------|-----------|
| Policy Engine | <img src="docs/screenshots/policy.png" alt="Policy -- permission check, decision log, AI policy generation" width="600" /> |
| Analytics (Cloud) | <img src="docs/screenshots/analytics.png" alt="Analytics -- agent risk scoring" width="600" /> |
| Agents | <img src="docs/screenshots/agents.png" alt="Agents -- fleet table with observations, alerts, and tool usage" width="600" /> |
| Credentials | <img src="docs/screenshots/credentials.png" alt="Credentials -- issue and revoke JWT tokens" width="600" /> |
| Settings | <img src="docs/screenshots/settings.png" alt="Settings -- subscription tier, LLM config, authentication" width="600" /> |

</details>

## CLI Reference

### Getting Started
| Command | What It Does |
|---------|-------------|
| `navil wrap config.json` | Wrap all MCP servers with security proxy |
| `navil wrap config.json --undo` | Restore original config |
| `navil wrap config.json --dry-run` | Preview without modifying |
| `navil wrap config.json --agent-prefix openclaw` | Custom agent names (e.g. `openclaw-filesystem`) |
| `navil init` | Initialize navil config in current directory |
| `navil init --with-policy` | Initialize with a starter policy.yaml |

> **Tip: Multi-client setups.** If you run multiple AI clients (OpenClaw + NemoClaw + Cursor) on the same machine, use `--agent-prefix` to distinguish them in the dashboard:
> ```bash
> navil wrap ~/.openclaw/config.json --agent-prefix openclaw
> navil wrap ~/.nemoclaw/mcp.json --agent-prefix nemo
> navil wrap ~/.cursor/mcp.json --agent-prefix cursor
> ```
> This gives you per-client visibility: `openclaw-filesystem`, `nemo-github`, `cursor-terminal`.

### Security Analysis
| Command | What It Does |
|---------|-------------|
| `navil scan config.json` | Scan config for vulnerabilities (0-100 score) |
| `navil scan config.json --format sarif` | Output SARIF for CI/CD |
| `navil analyze /path/to/server` | Static analysis of MCP server source code |
| `navil pentest` | Run 11 SAFE-MCP attack simulations |
| `navil test --pool default` | Test coverage against threat pool |
| `navil redteam --generate` | AI-generated novel attack hypotheses |

### Runtime Protection
| Command | What It Does |
|---------|-------------|
| `navil proxy start --target URL` | Start HTTP security proxy |
| `navil monitor start` | Start real-time anomaly monitoring |
| `navil policy check --agent X --tool Y` | Check if a tool call would be allowed |
| `navil policy auto-generate` | Generate policy from observed behavior |
| `navil policy suggest` | Show pending policy suggestions |
| `navil policy rollback` | Undo auto-generated policy changes |

### Identity & Credentials
| Command | What It Does |
|---------|-------------|
| `navil credential issue --agent X --scope Y` | Issue JWT credential |
| `navil credential list` | List all credentials |
| `navil credential revoke --token-id X` | Revoke a credential |
| `navil credential delegate --parent X --child Y` | Delegate to sub-agent |
| `navil a2a card` | Print agent discovery card (A2A spec) |

### Cloud & Fleet
| Command | What It Does |
|---------|-------------|
| `navil cloud login` | Connect to Navil Cloud (OAuth) |
| `navil cloud status` | Show cloud connection status |
| `navil cloud serve` | Start local dashboard + API server |
| `navil report` | Generate security report |

### Threat Intelligence
| Command | What It Does |
|---------|-------------|
| `navil crawl registries` | Discover MCP servers from npm/PyPI |
| `navil crawl threat-scan` | Crawl public threat intel sources |
| `navil scan-batch results/` | Bulk scan crawl results |
| `navil blocklist show` | Show loaded threat patterns |
| `navil honeypot start` | Start honeypot decoy servers |

### Advanced
| Command | What It Does |
|---------|-------------|
| `navil openapi convert spec.yaml` | Convert OpenAPI to MCP server |
| `navil llm analyze` | LLM-powered threat analysis |
| `navil feedback submit --alert-id X` | Submit feedback on alerts |
| `navil seed-database` | Populate with synthetic attack data |
| `navil ml train` | Train ML anomaly detection models |
| `navil adaptive show` | Show adaptive baselines |

## Architecture

```
  Agents --> [ Rust Proxy :8080 ] --> MCP Servers
                    |
              Redis :6379  (thresholds, rate counters, telemetry queue)
                    |
             [ Python Workers :8484 ]  (ML detectors, LLM analysis, dashboard)
                    |
              (optional) Navil Cloud  (anonymized threat intel)
```

The Rust proxy handles the hot path: sanitization, HMAC auth, O(1) threshold gates, and rate limiting. It publishes telemetry to a Redis queue. Python workers consume events, run the full anomaly detection suite, recompute thresholds, and sync them back to Redis for the proxy to read. For the full system design, see [ARCHITECTURE.md](ARCHITECTURE.md).

## State of MCP Security

We scanned **1,000 public MCP servers** from awesome-mcp-servers, npm, and PyPI using `navil crawl registries` and `navil scan-batch`. The results are sobering.

| Metric | Value |
|--------|-------|
| Servers scanned | 1,000 |
| Average security score | 61.7 / 100 |
| Missing authentication | 100% |
| Unverified sources | 100% |
| Unverified GitHub repos | 98.2% |

No server scored above 80. The most common vulnerability is **AUTH-MISSING** (every server), followed by **SRC-UNVERIFIED** and **SUPPLY-GH-UNVERIFIED**. The full report is at [`state_of_mcp_security_v3.md`](state_of_mcp_security_v3.md). Generate your own with `navil report-mcp scan_results.jsonl`.

## Installation

```bash
pip install navil
```

With optional features:

```bash
pip install navil[llm]         # + AI-powered analysis (Anthropic, OpenAI, Gemini)
pip install navil[cloud]       # + Cloud dashboard (FastAPI + React)
pip install navil[all]         # Everything
```

### Prerequisites

| Component | Required | Version |
|-----------|----------|---------|
| Python | Yes | 3.10+ |
| Redis | For proxy mode | 5.0+ |
| Rust | Optional (Rust proxy) | stable |
| Node.js | Optional (dashboard dev) | 20+ |

### From source

```bash
git clone https://github.com/navilai/navil.git
cd navil
pip install -e ".[dev]"
```

### Rust proxy (high-throughput deployments)

```bash
cd navil-proxy && cargo build --release
```

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and how to submit changes.

## Security

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## License

| Component | License |
|-----------|---------|
| Core CLI, anomaly detection, proxy, adaptive ML, Rust data plane | [Apache 2.0](LICENSE) |
| Cloud dashboard, LLM features, API server | [Business Source License 1.1](LICENSE.cloud) |

**Apache 2.0** -- free to use, modify, and redistribute for any purpose.
**BSL 1.1** -- free for internal use and self-hosting. Each release converts to Apache 2.0 four years after publication.

---

<p align="center">
  Built by <a href="https://github.com/navilai/navil"><strong>Pantheon Lab</strong></a>
</p>
