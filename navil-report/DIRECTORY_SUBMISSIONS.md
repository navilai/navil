# AI Directory Submission Copy — Navil

Ready-to-paste entries for each directory. All copy is based strictly on verified facts.

---

## 1. Product Hunt

**Name:** Navil

**Tagline (60 chars max):**
Production governance for AI agents — open source

**Description (260 chars):**
Open-source runtime proxy for MCP servers, CLIs, and APIs your AI agents call. Enforces YAML-defined policies, detects threats (568 patterns, 36 categories), and cuts schema tokens 94% per call. 2.7 µs overhead. Apache 2.0.

**Topics (pick 3):**
- Developer Tools
- Artificial Intelligence
- Security

**Maker Comment (200 words):**

Hey PH — Ivan here, founder of Navil.

The hook: we scanned 400 public MCP packages and found that 75% carry known CVEs in their dependency tree. Anthropic's own MCP SDK has 6 HIGH-severity vulnerabilities that affect 54–68% of the ecosystem. You can generate this report for your own MCP config in seconds with `navil audit-deps`.

But dependency CVEs are only 1.7% of the problem. The real threats are runtime — prompt injection, tool poisoning, data exfiltration, rug pulls. Static scanners miss all of them.

Navil is a security proxy that sits in front of every MCP server, CLI tool, and API your AI agents call. One command wraps your entire setup:

```
pip install navil && navil secure
```

No API key. No signup. Works fully offline. It auto-discovers your Cursor, Claude Desktop, and other MCP configs, wraps every server, and shows you a before/after coverage score in under 60 seconds.

The threat detection engine ships with 568 patterns across 36 attack categories, contributed by the community. Every detection you make (anonymized) strengthens every other node.

Core is Apache 2.0. Free tier is fully functional. No catch.

Would love your feedback — especially from teams already running MCP in production.

---

**First founder comment (standard PH launch practice):**

Hey everyone — wanted to share a bit more context on why we built this.

We run a lot of AI agents internally, and six months ago we started noticing something uncomfortable: we had zero visibility into what those agents were actually doing when they called tools. MCP makes it trivially easy to give an agent access to your filesystem, GitHub, database, and kubectl — but there's no auth, no audit log, and no way to enforce least-privilege.

So we built Navil. It's a security proxy that intercepts every agent-to-tool call, enforces YAML policies, runs 568 threat detection patterns, and logs everything. The architecture is a Rust proxy on the hot path (2.7 µs overhead) with Python workers handling the ML anomaly detection off-path.

The free tier is genuinely free — open source, works offline, no account needed. The paid tiers add real-time threat intel from the community network and fleet dashboards.

One thing we're proud of: the community threat network. When your local Navil instance detects an attack, it anonymizes and shares the pattern. Every other node gets smarter. This is the model we think should exist for AI security.

Try it: `pip install navil && navil secure`. Takes under 60 seconds. Happy to answer any questions here.

---

## 2. There's An AI For That (theresanaiforthat.com)

**Name:** Navil

**Description (1 sentence):**
Navil is an open-source runtime security proxy that sits in front of every MCP server, CLI, and API your AI agents call, enforcing YAML-defined policies and detecting threats with 568 patterns across 36 attack categories.

**Category:** AI Security

**URL:** https://navil.ai

---

## 3. AI ToolKit (aitoolkit.com)

**Name:** Navil

**Short Description:**
Open-source production governance and security proxy for AI agents.

**Long Description:**
Navil is a runtime security proxy that intercepts every tool call your AI agents make — to MCP servers, CLIs, and APIs — and enforces policy before the call goes through. Install with `pip install navil && navil secure`. It auto-discovers your MCP configs (Cursor, Claude Desktop, Continue.dev), wraps every server with a security shim, and shows you a before/after threat coverage score in under 60 seconds.

The threat detection engine ships with 568 patterns across 36 attack categories covering prompt injection, tool poisoning, data exfiltration, credential exposure, privilege escalation, and more. Static scanners catch 1.7% of MCP threats; Navil's runtime proxy catches the other 98.3%.

Additional capabilities: YAML policy enforcement with per-agent tool scoping (94% reduction in schema tokens per call), behavioral anomaly detection, credential lifecycle management, CI/CD GitHub Actions integration, and an optional cloud dashboard for fleet-wide visibility. Core is Apache 2.0. Overhead: 2.7 µs per call.

**Category:** AI Security / Developer Tools

**URL:** https://navil.ai

**Pricing:** Free (open source, Apache 2.0) + paid plans from $59/seat/month

---

## 4. Futurtools.io

**Name:** Navil

**Description:**
Open-source runtime proxy for AI agent security. Sits in front of every MCP server, CLI, and API your agents call — enforcing YAML policies and running 568 threat detection patterns at 2.7 µs overhead. One command secures your full MCP setup: `pip install navil && navil secure`. Free and open source (Apache 2.0).

**Category:** AI Security

**Tags:** mcp, ai-agents, security, governance, open-source, python, rust

**URL:** https://navil.ai

---

## 5. Alternative.to

**Name:** Navil

**Description (plain text, 200 chars):**
Open-source runtime security proxy for AI agents. Enforces YAML policies, detects threats (568 patterns, 36 categories), and cuts MCP schema tokens 94% per call. 2.7 µs overhead. Apache 2.0.

**Tags:** mcp, ai-agents, security, governance, open-source, python, rust, developer-tools, ai-infrastructure

**URL:** https://navil.ai

---

## 6. SaaSHub

**Name:** Navil

**Tagline:**
Production governance for AI agents

**Description (300 chars):**
Open-source runtime proxy that sits in front of every MCP server, CLI, and API your AI agents call. Enforces YAML-defined policies, detects threats (568 patterns, 36 categories), and cuts schema tokens 94% per call. 2.7 µs overhead. Apache 2.0 core. Install: pip install navil.

**Categories (pick 2):**
- Developer Tools
- Cybersecurity

**URL:** https://navil.ai

**Pricing:** Free (open source) · Pro $59/seat/mo · Growth $129/seat/mo · Team $299/mo · Enterprise custom
