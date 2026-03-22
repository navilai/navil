# Using Navil with Claude Desktop

Secure every MCP server in Claude Desktop by routing tool calls through the Navil proxy.

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

Paste your API key from the [Navil dashboard](https://dashboard.navil.ai) when prompted.

## 3. Configure Claude Desktop MCP Settings

Open the Claude Desktop config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Wrap each MCP server with `navil shim`. For example, if your original config is:

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

Or use `navil wrap` to do it automatically:

```bash
navil wrap ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

## 4. Restart Claude Desktop

Quit and reopen Claude Desktop so it loads the updated MCP configuration.

## 5. Verify

1. Start a conversation in Claude Desktop that uses an MCP tool.
2. Open the [Navil dashboard](https://dashboard.navil.ai).
3. Confirm that tool-call telemetry, anomaly alerts, and policy decisions appear.

## What's Next?

- [Full documentation](https://github.com/navilai/navil#readme)
- [Policy engine reference](https://github.com/navilai/navil#policy-enforcement)
- [Anomaly detection details](https://github.com/navilai/navil#behavioral-anomaly-detection)
