# Twitter/X Thread

## Tweet 1 (hook)
We scanned 4,401 MCP servers across npm, PyPI, and registries.

Only 1.7% had actual vulnerabilities.

So MCP is safe, right?

No. We deployed honeypots and the real story is much worse. Thread:

## Tweet 2
Static scanning catches package-level bugs.

But the real threats are invisible until runtime:
- Prompt injection in tool descriptions
- Credential exfiltration through tool calls
- Rug pull attacks (server changes behavior after install)

These pass every scanner.

## Tweet 3
We deployed honeypot MCP servers with tools like "read_env" and "exec_command."

Within hours:
- Automated scanners probing for AWS creds
- Attempts to read SSH keys
- Reverse shell attempts
- Webshell drops

MCP is the new attack surface nobody's watching.

## Tweet 4
So we built Navil — open-source runtime security for AI agents.

Two commands:
```
pip install navil
navil wrap claude_desktop_config.json
```

Transparent proxy. Your agent doesn't know it's there. 11 attack patterns detected. 368 threat signatures. 100% detection rate.

## Tweet 5
The key insight: every Navil proxy contributes to a community threat network.

No account needed. Your proxy shares anonymized detections as a side-effect of use.

More proxies = better protection for everyone.

Like Cloudflare's DNS network, but for AI agent security.

## Tweet 6
Bloomberg and Block built this internally. They needed runtime security for MCP at scale.

Navil is the open-source version.

MIT licensed. Works with Claude Desktop, Cursor, Continue.dev, OpenClaw.

github.com/navilai/navil
navil.ai/radar (live threat data)
