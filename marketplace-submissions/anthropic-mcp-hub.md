# Anthropic MCP Server Directory Submission

**Target:** Anthropic's MCP server directory / hub

---

## Server Metadata

| Field | Value |
|-------|-------|
| **Server name** | navil |
| **Display name** | Navil - MCP Security Proxy |
| **Author** | Pantheon Lab Pte Ltd |
| **License** | Apache 2.0 (core) |
| **GitHub URL** | https://github.com/navilai/navil |
| **Website** | https://navil.ai |
| **Category** | Security / Governance |

## Description

Runtime security proxy for MCP -- intercepts tool calls, enforces policies, detects anomalies, and shares threat intelligence across the community. Wraps any MCP server config in one command with zero code changes. Ships with 568 detection patterns across 36 attack categories, adds <2.7us overhead per message.

## Transport

| Mode | How | Use Case |
|------|-----|----------|
| **stdio** | `navil shim --cmd <original_command> --args <original_args>` | Local MCP clients (Claude Desktop, Cursor, Continue.dev) |
| **HTTP** | `navil proxy start --target http://your-mcp-server:3000` | Production deployments, Streamable HTTP MCP servers |

## Installation

```bash
# Install
pip install navil

# Wrap all MCP servers in your config (stdio mode)
navil wrap claude_desktop_config.json

# Or start an HTTP proxy (for Streamable HTTP servers)
navil proxy start --target http://your-mcp-server:3000
```

No API key required. No signup required. The free Community tier works out of the box.

## Features

- **Runtime Interception** -- Sits between agent and MCP server, inspecting every tool call and response in real time
- **Policy Enforcement** -- YAML-driven allow-lists per agent, per tool, with rate limiting and data-sensitivity gates
- **Anomaly Detection** -- 11 statistical detectors with adaptive baselines and ML-powered pattern matching
- **Threat Intelligence** -- Community-sourced blocklist with 568 patterns across 36 attack categories; anonymized give-to-get model
- **Configuration Scanning** -- Static scan producing a 0-100 security score with actionable remediation
- **Penetration Testing** -- 11 SAFE-MCP attack simulations to validate detector coverage
- **Tool Scoping** -- Restrict which tools each agent sees in `tools/list`, reducing schema token bloat by up to 94%
- **Credential Lifecycle** -- Issue, rotate, and revoke JWT tokens with delegation chains and cascade revocation
- **OIDC Identity** -- Token exchange converts external identity tokens into Navil credentials
- **A2A Agent Card** -- Google A2A-compatible agent discovery at `/.well-known/agent.json`
- **Honeypot Kit** -- 10 decoy MCP server profiles to detect and study attackers
- **CI/CD Integration** -- GitHub Actions and GitLab CI with SARIF output
- **LLM-Powered Analysis** -- AI config review, anomaly explanation, and self-healing (supports Anthropic, OpenAI, Gemini, Ollama)
- **Zero-Knowledge Telemetry** -- HMAC-SHA256 anonymized; raw data never leaves your machine; full opt-out available

## Requirements

| Component | Required | Version |
|-----------|----------|---------|
| Python | Yes | 3.10+ |
| Redis | For proxy mode | 5.0+ |
| Rust | Optional (high-throughput proxy) | stable |

## Compatibility

Works with any MCP client that uses config files:

- Claude Desktop (`claude_desktop_config.json`)
- Cursor (`~/.cursor/mcp.json`)
- Continue.dev (`.continue/config.json`)
- OpenClaw (`openclaw.json`)

## Links

- README: https://github.com/navilai/navil#readme
- Live threat radar: https://navil.ai/radar
- Data collection policy: https://github.com/navilai/navil/blob/main/DATA_COLLECTION.md
- Security policy: https://github.com/navilai/navil/blob/main/SECURITY.md
- Architecture: https://github.com/navilai/navil/blob/main/ARCHITECTURE.md
