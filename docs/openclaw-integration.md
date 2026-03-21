# Securing OpenClaw with Navil

OpenClaw is the largest open MCP skill registry. It's also the biggest attack surface for AI agents — 824+ malicious skills have been cataloged, with 8 critical CVEs discovered in 6 weeks.

This guide shows how to protect your OpenClaw-connected agents with Navil in under 2 minutes.

## The Problem

When your agent connects to OpenClaw skills, it trusts every tool description and every response. A malicious skill can:

- **Poison tool descriptions** to trick your agent into calling it with sensitive data
- **Exfiltrate credentials** by reading environment variables or config files
- **Execute arbitrary commands** through prompt injection in tool responses
- **Change behavior after installation** (rug pull attacks)

Static scanning catches 1.7% of these issues. The other 98.3% only appear at runtime.

## Quick Start

```bash
# Install navil
pip install navil

# Wrap your OpenClaw config — done
navil wrap openclaw.json
```

That's it. Every tool call now passes through Navil's security proxy. No config changes to your agent.

## What Happens After Wrapping

```
Your Agent
    ↓ (tool call)
Navil Shim (transparent proxy)
    ├── Checks call against 368 threat signatures
    ├── Runs anomaly detection (11 attack patterns)
    ├── Enforces policy rules (if configured)
    ├── Logs everything for audit trail
    ↓ (if safe)
OpenClaw MCP Server
    ↓ (response)
Navil Shim
    ├── Scans response for data exfiltration
    ├── Checks for prompt injection in output
    ↓ (if clean)
Your Agent
```

## Before vs After

| Without Navil | With Navil |
|---------------|-----------|
| Agent trusts all tool descriptions blindly | Descriptions checked against injection patterns |
| Credentials exposed via env read tools | Credential access logged and policy-gated |
| No visibility into what tools do | Full audit trail of every call |
| Malicious responses reach agent | Responses scanned for injection/exfil |
| No threat sharing | Your detections protect every Navil user |

## Optional: Cloud Dashboard

Connect to Navil Cloud for real-time monitoring, analytics, and community threat intelligence:

```bash
navil cloud login
```

Opens your browser, sign in, done. Your machine starts contributing to the community threat network and receives patterns from other users in return.

## Optional: Policy Enforcement

Create `policy.yaml` to enforce rules:

```yaml
default_action: allow

rules:
  - tool: "exec_command"
    action: deny
    reason: "Shell execution blocked for OpenClaw skills"

  - tool: "read_file"
    arguments:
      path:
        deny_patterns:
          - "~/.ssh/*"
          - "~/.aws/*"
          - ".env*"
    action: deny
    reason: "Sensitive file access blocked"

  - tool: "*"
    rate_limit: 60/minute
    reason: "Rate limit all tool calls"
```

Apply it:

```bash
navil wrap openclaw.json --policy policy.yaml
```

## CI/CD: Scan OpenClaw Configs in PRs

Add to `.github/workflows/mcp-scan.yml`:

```yaml
name: MCP Security Scan
on:
  pull_request:
    paths: ['openclaw.json', '*.mcp.json']

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ivanlkf/navil/.github/actions/scan@main
        with:
          config: openclaw.json
          fail-on: high
```

## How It Works With OpenClaw

OpenClaw uses standard MCP stdio transport. Navil's `wrap` command modifies your `openclaw.json` to route each server through `navil shim`:

**Before:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

**After:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "navil",
      "args": ["shim", "--cmd", "npx -y @modelcontextprotocol/server-filesystem /tmp"]
    }
  }
}
```

The agent doesn't know Navil is there. The MCP server doesn't know Navil is there. Navil sits in between, watching everything.

## Links

- [Navil GitHub](https://github.com/ivanlkf/navil)
- [Navil Cloud Dashboard](https://navil.ai)
- [Navil Radar (public threat intel)](https://navil.ai/radar)
- [Report an issue](https://github.com/ivanlkf/navil/issues)
