# Using Navil with Cursor IDE

Secure every MCP server in Cursor by routing tool calls through the Navil proxy.

## Prerequisites

- Python 3.10+
- pip
- A Navil account ([sign up](https://dashboard.navil.ai/sign-up))

## 1. Install Navil

```bash
pip install navil
```

## 2. Initialize

```bash
navil init
```

Paste your API key from the [Navil dashboard](https://dashboard.navil.ai) when prompted. This writes a local `~/.navil/config.toml` with your credentials.

## 3. Configure Cursor MCP Settings

Open (or create) your Cursor MCP config file:

```
~/.cursor/mcp.json
```

Wrap each MCP server entry with `navil shim` so all tool calls flow through the security proxy. For example, if your original config looks like this:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]
    }
  }
}
```

Replace it with:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "navil",
      "args": [
        "shim",
        "--cmd", "npx -y @modelcontextprotocol/server-filesystem /home/user/projects"
      ]
    }
  }
}
```

Alternatively, use `navil wrap` to do this automatically:

```bash
navil wrap ~/.cursor/mcp.json
```

## 4. Restart Cursor

Close and reopen Cursor (or reload the window) so it picks up the new MCP config.

## 5. Verify

1. Use any MCP tool in Cursor as usual.
2. Open the [Navil dashboard](https://dashboard.navil.ai).
3. You should see tool-call telemetry, anomaly alerts, and policy decisions appearing in real time.

## What's Next?

- [Full documentation](https://github.com/navilai/navil#readme)
- [Policy engine reference](https://github.com/navilai/navil#policy-enforcement)
- [Anomaly detection details](https://github.com/navilai/navil#behavioral-anomaly-detection)
