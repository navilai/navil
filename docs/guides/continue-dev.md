# Using Navil with Continue.dev (VS Code)

Secure every MCP server in Continue.dev by routing tool calls through the Navil proxy.

## Prerequisites

- Python 3.10+
- pip
- VS Code with the [Continue extension](https://marketplace.visualstudio.com/items?itemName=Continue.continue)
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

## 3. Configure Continue MCP Settings

Open the Continue config file:

```
~/.continue/config.json
```

In the `mcpServers` section, wrap each server with `navil shim`. For example, if your original config has:

```json
{
  "mcpServers": [
    {
      "name": "filesystem",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]
    }
  ]
}
```

Replace it with:

```json
{
  "mcpServers": [
    {
      "name": "filesystem",
      "command": "navil",
      "args": [
        "shim",
        "--cmd", "npx -y @modelcontextprotocol/server-filesystem /home/user/projects"
      ]
    }
  ]
}
```

Or use `navil wrap` to do it automatically:

```bash
navil wrap ~/.continue/config.json
```

## 4. Reload VS Code

Run **Developer: Reload Window** from the VS Code command palette (`Cmd+Shift+P` / `Ctrl+Shift+P`).

## 5. Verify

1. Use any MCP tool through Continue as usual.
2. Open the [Navil dashboard](https://dashboard.navil.ai).
3. Confirm that tool-call telemetry, anomaly alerts, and policy decisions appear.

## What's Next?

- [Full documentation](https://github.com/ivanlkf/navil#readme)
- [Policy engine reference](https://github.com/ivanlkf/navil#policy-enforcement)
- [Anomaly detection details](https://github.com/ivanlkf/navil#behavioral-anomaly-detection)
