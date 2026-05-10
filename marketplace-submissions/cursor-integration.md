# Securing Cursor's MCP Servers with Navil

*A step-by-step guide for Cursor users who want runtime security for their MCP tool calls.*

---

## The Problem

Cursor connects to MCP servers to give your AI agent access to tools -- filesystem, GitHub, databases, terminal. But every tool call is unmonitored. There is no policy enforcement, no anomaly detection, and no audit trail. If a prompt injection tricks your agent into running `rm -rf /` through the filesystem MCP server, nothing stops it.

Static scanning of MCP configs catches some issues, but only about 1.7% of real-world threats. The rest -- prompt injection via tool calls, data exfiltration through responses, credential exposure, privilege escalation via tool chaining -- only show up at runtime.

Navil fixes this in one command.

## What Navil Does

Navil is an open-source security proxy that sits between Cursor's AI agent and your MCP servers. It intercepts every tool call and response, running them through:

1. **Policy enforcement** -- YAML-driven allow-lists control which tools each agent can call, with rate limiting and data-sensitivity gates
2. **Anomaly detection** -- 11 statistical detectors with adaptive baselines flag unusual behavior patterns
3. **Threat pattern matching** -- 568 detection patterns across 36 attack categories block known exploits
4. **Community threat intel** -- attack patterns found anywhere in the network protect everyone within seconds

All of this adds less than 2.7 microseconds of overhead per message. Your workflow stays fast.

## Step-by-Step Setup

### 1. Install Navil

```bash
pip install navil
```

That is the only dependency. No API key required, no signup, no Docker.

### 2. Wrap your Cursor MCP config

```bash
navil wrap ~/.cursor/mcp.json
```

This reads your Cursor MCP config, wraps every server entry with `navil shim`, and writes it back. Your original config is backed up automatically.

**Before** (in `~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "ghp_..." }
    }
  }
}
```

**After** (navil-wrapped):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "navil",
      "args": ["shim", "--agent-id", "cursor-filesystem", "--cmd", "npx", "--args", "-y @modelcontextprotocol/server-filesystem /home/user/projects"]
    },
    "github": {
      "command": "navil",
      "args": ["shim", "--agent-id", "cursor-github", "--cmd", "npx", "--args", "-y @modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "ghp_..." }
    }
  }
}
```

Each server gets a unique agent identity (`cursor-filesystem`, `cursor-github`) for per-server telemetry and policy. Your environment variables pass through untouched.

### 3. Restart Cursor

Close and reopen Cursor (or reload the window) so it picks up the updated MCP config. Your MCP servers will work exactly as before -- navil is transparent to the agent.

### 4. Verify it is working

```bash
# Check navil is intercepting calls
navil monitor start

# In another terminal, use Cursor normally -- you'll see tool calls flowing through
```

You should see output like:

```
[navil] cursor-filesystem | tools/list | ALLOW | 0.4us
[navil] cursor-github     | get_pull_request | ALLOW | 0.3us
[navil] cursor-filesystem | read_file | ALLOW | 0.5us
```

## Adding a Policy (Optional)

By default, navil allows all tool calls and monitors for anomalies. To add explicit restrictions:

```bash
navil init --with-policy
```

This creates `~/.navil/policy.yaml`. Edit it to restrict what each agent can do:

```yaml
# ~/.navil/policy.yaml
scopes:
  code-review:
    allow: [get_pull_request, list_files, create_review_comment]
  filesystem-readonly:
    allow: [read_file, list_directory, search_files]
    deny: [write_file, delete_file, create_directory]

agents:
  cursor-github:
    scope: code-review
  cursor-filesystem:
    scope: filesystem-readonly
```

This restricts your GitHub MCP to read-only PR review operations and your filesystem MCP to read-only access. Any tool call outside the allow-list is blocked and logged.

## Connecting to Cloud (Optional)

For dashboards, fleet analytics, and real-time threat intel:

```bash
navil cloud login
```

This opens an OAuth flow in your browser. Once connected, visit [navil.ai](https://navil.ai) to see:

- Per-agent trust scores and health status
- Real-time anomaly alerts with severity filtering
- Tool call analytics and usage patterns
- Community threat radar at [navil.ai/radar](https://navil.ai/radar)

The free Community tier works without cloud. Cloud adds visibility and faster threat intel updates.

## Running a Security Scan

Before (or after) wrapping, scan your config for static vulnerabilities:

```bash
navil scan ~/.cursor/mcp.json
```

Example output:

```
Navil Security Scan
====================
Config: /home/user/.cursor/mcp.json
Servers: 2

filesystem ................. Score: 72/100
  [WARN] AUTH-MISSING: No authentication configured
  [WARN] SRC-UNVERIFIED: Package source not pinned to hash

github ..................... Score: 68/100
  [WARN] AUTH-MISSING: No MCP-level authentication
  [WARN] CRED-EXPOSED: Token in plaintext env var
  [INFO] SRC-UNVERIFIED: Package source not pinned

Overall: 70/100
```

## Running Penetration Tests

Validate that your detectors actually catch threats:

```bash
navil pentest
```

This runs 11 SAFE-MCP attack simulations (no real network traffic) and reports which ones your current setup detects.

## Undoing the Wrap

To restore your original Cursor config:

```bash
navil wrap ~/.cursor/mcp.json --undo
```

Your original config was backed up when you first ran `navil wrap`. This command restores it.

## Preview Mode

Not ready to commit? Preview what navil would change without modifying your config:

```bash
navil wrap ~/.cursor/mcp.json --dry-run
```

## Performance

Navil adds negligible overhead. Benchmarks on a mock MCP server:

| Metric | Value |
|--------|-------|
| Per-message security check | 2.7us mean |
| 5 tool calls session overhead | +0.5ms |
| 50 tool calls session overhead | +1.4ms |

Real MCP tools take 1-5,000ms per call (file reads, API calls). Navil's overhead is less than 0.1% of actual session time.

## Further Reading

- **GitHub:** https://github.com/navilai/navil
- **Live threat radar:** https://navil.ai/radar
- **Full CLI reference:** https://github.com/navilai/navil#cli-reference
- **Architecture:** https://github.com/navilai/navil/blob/main/ARCHITECTURE.md
- **Data collection policy:** https://github.com/navilai/navil/blob/main/DATA_COLLECTION.md
