# HN Submission

## Title (pick one)
- "We scanned 4,401 MCP servers. 1.7% had vulnerabilities. The real threats are at runtime."
- "Show HN: Navil – Open-source runtime security proxy for MCP/AI agents"
- "The MCP security problem isn't in the packages — it's what happens when agents use them"

## URL
https://navil.ai

## Text (if Show HN)

We built an open-source security proxy for AI agents using MCP (Model Context Protocol).

The problem: we scanned 4,401 MCP servers across npm, PyPI, and registries. Only 1.7% had actual code vulnerabilities. The real threats — prompt injection, credential exfiltration, rug pull attacks — only appear at runtime when agents call tools.

Navil sits transparently between your agent and MCP servers. Two commands:

```
pip install navil
navil wrap claude_desktop_config.json
```

What it does:
- Detects 11 attack patterns (prompt injection, data exfil, privilege escalation, C2, etc.)
- 368 threat signatures, 100% detection rate on our test suite
- Community threat network — every proxy shares anonymized detections
- Zero config — works with Claude Desktop, Cursor, Continue.dev, OpenClaw
- MIT licensed

We also deployed honeypots and within hours had automated scanners probing for credentials and attempting reverse shells.

GitHub: https://github.com/ivanlkf/navil
Live threat radar: https://navil.ai/radar

Built by a small team in Singapore. Happy to answer questions about MCP security, the threat landscape, or the architecture.
