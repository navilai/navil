# PR: Add Navil to awesome-mcp-servers

**Target repo:** https://github.com/punkpeye/awesome-mcp-servers
**Category:** Security

---

## PR Title

Add Navil - Runtime security proxy for MCP servers

## PR Description

### Entry (under "Security" category)

```markdown
- [Navil](https://github.com/navilai/navil) - Runtime security proxy for MCP servers. Intercepts tool calls, enforces policies, detects anomalies, and shares threat intelligence. 568 detection patterns across 36 attack categories. <2.7us overhead.
```

### What is Navil?

Navil is an open-source agent governance middleware that sits between AI agents and MCP servers as a security proxy. It intercepts every tool call, runs it through a pipeline of policy checks, anomaly detection, and threat pattern matching, then forwards the call to the real server. It works with any MCP client (Claude Desktop, Cursor, Continue.dev, OpenClaw) and requires zero code changes -- one command wraps all servers in your config.

Beyond local protection, Navil connects to a community threat network: attack patterns detected on one machine are anonymized and shared to protect every other node. The project ships with 568 detection patterns across 36 attack categories, and adds less than 2.7 microseconds of overhead per message.

### Why it belongs in this list

- It is the only open-source **runtime** security proxy for MCP (most existing tools are static scanners, which catch only ~1.7% of threats)
- Directly addresses documented MCP security gaps: 8+ CVEs in 6 weeks, 100% of public servers missing authentication, 42,665+ instances exposed without auth
- Production-grade: Rust data plane for the hot path, Python workers for ML/anomaly detection, Redis for coordination
- Apache 2.0 licensed (core), actively maintained, CI-passing

### Links

- **GitHub:** https://github.com/navilai/navil
- **Live threat radar:** https://navil.ai/radar
- **Documentation:** https://github.com/navilai/navil#readme
- **State of MCP Security report:** https://github.com/navilai/navil/blob/main/state_of_mcp_security_v3.md
- **Installation:** `pip install navil && navil wrap config.json`

### Checklist

- [x] Project is open source
- [x] Project is related to MCP
- [x] Entry follows the format: `[Name](URL) - Description.`
- [x] Entry is added in alphabetical order within the category
- [x] Description starts with a capital letter and does not end with a period (unless multi-sentence)
