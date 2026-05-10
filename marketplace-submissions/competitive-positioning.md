# Navil Competitive Positioning

Use these talking points when responding to questions on HN, Reddit, or social media.

## Navil vs. the Field

| Feature | Navil | ContextForge | MintMCP | Snyk agent-scan | Docker MCP GW |
|---------|-------|-------------|---------|----------------|---------------|
| Runtime monitoring | Yes | No (routing only) | Yes | No (static only) | No |
| Open source | Apache 2.0 | Apache 2.0 | Proprietary | OSS (scanner) | OSS |
| One-command setup | `navil secure` | Config required | SaaS setup | CLI scan | Docker Compose |
| Offline capable | Yes | No | No | Yes | Yes |
| Community threat intel | Yes (anonymized) | No | No | No | No |
| Pentest mode | Yes (11 attack sims) | No | No | No | No |
| Policy enforcement | YAML-driven | Plugin-based | Dashboard | N/A | N/A |
| Overhead | <3us/message | N/A | Unknown | N/A | ~5ms |

## Key Differentiators (short version)

1. **Runtime, not static.** Most tools scan packages. Navil monitors what happens when agents actually call tools.
2. **One command.** `pip install navil && navil secure` — no accounts, no API keys, no config.
3. **Community threat network.** Every proxy node contributes anonymized detections. More users = better protection.
4. **Research-backed.** Built on scanning 4,401 servers and deploying honeypots. Data, not opinions.

## Common Questions (HN/Reddit Reply Templates)

### "How is this different from just auditing MCP server code?"

Static audits catch 1.7% of threats. We found 77 vulnerable packages out of 4,401 scanned. The real risk is runtime behavior — prompt injection via tool descriptions, credential theft through tool arguments, rug pull attacks where servers change behavior after install. You can't catch these by reading source code.

### "What's the overhead?"

<3 microseconds per message for the Rust proxy layer. The Python detection pipeline runs async — it never blocks tool calls. Total session overhead is <0.1%. We benchmark on every CI run.

### "Why not just use a firewall/WAF?"

MCP traffic is JSON-RPC over stdio (local) or HTTP (remote). A traditional WAF doesn't understand the semantics. Navil understands MCP — it knows what a tool call is, what arguments are expected, what a normal response looks like. It detects behavioral anomalies, not just pattern matches.

### "Is the community threat network anonymous?"

Yes. We hash tool names, server identifiers, and patterns. No raw prompts, file contents, or tool arguments are ever transmitted. The telemetry spec is published in our docs. You can also run fully offline — the threat network is opt-in by default.

### "How does this compare to Snyk's agent-scan?"

Snyk scans MCP server metadata and source for known vulnerabilities — it's a good static analysis tool. Navil complements it by monitoring runtime behavior. Think of Snyk as the package audit, Navil as the runtime firewall. They work together.

### "Does this work with remote MCP servers (HTTP transport)?"

Yes. `navil wrap` handles stdio-based servers (the default for Claude Desktop, Cursor). For HTTP MCP servers, use `navil proxy --upstream https://your-server.com` to create an HTTP reverse proxy with the same detection pipeline.

### "What about false positives?"

0% on our test suite of 11 SAFE-MCP attack patterns. In production, the anomaly detectors use adaptive baselines — they learn what "normal" looks like for each server before flagging deviations. New deployments have a 24-hour learning period with alerts but no blocking.
