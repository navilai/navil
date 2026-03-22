# We scanned 4,401 MCP servers. Here's what we found — and why scanning isn't enough.

*By Ivan Lee, CEO of Pantheon Lab — creators of Navil*

---

Everyone's talking about whether MCP is dead. We spent the last month actually measuring it.

We crawled every public MCP server we could find — 4,401 packages across npm, PyPI, and the awesome-mcp-servers registry. We scanned each one for security vulnerabilities. We deployed honeypot MCP servers to see what happens when attackers find them.

Here's what we learned.

## The scan results surprised us

Out of 4,401 packages, 77 had actual code-level vulnerabilities. That's 1.7%.

Not the scary number we expected. The MCP package ecosystem is, by and large, reasonably well-built. Most servers are simple wrappers around APIs — there's not much to get wrong.

So if packages are fine, what's the problem?

## The problem is runtime, not packages

The 1.7% that fail static scanning aren't the real threat. The real threats are invisible until an agent actually calls a tool:

**Prompt injection via tool descriptions.** A malicious MCP server can embed instructions in its tool descriptions that hijack the agent's behavior. The package source code looks clean. The attack only triggers when the agent reads the description.

**Credential exfiltration through tool calls.** An agent connected to a filesystem tool can be tricked into reading `~/.aws/credentials` or `.env` files. The tool itself is legitimate — the abuse happens through the arguments.

**Rug pull attacks.** An MCP server works perfectly for weeks, then silently changes its behavior to exfiltrate data. Static scanning only sees the code at install time.

**Tool poisoning across registries.** OpenClaw alone has cataloged 824+ skills with malicious characteristics. They pass every static check.

We confirmed all of this by deploying honeypot MCP servers with realistic-looking tools (`read_env`, `exec_command`, `read_file`). Within hours, automated scanners were probing them — enumerating tools, reading environment variables, attempting reverse shells.

## Static scanning catches 1.7%. Runtime monitoring catches the rest.

This is why we built Navil.

Navil is an open-source security proxy that sits between AI agents and MCP servers. It's transparent — your agent doesn't know it's there, the MCP server doesn't know it's there. Navil watches every tool call, detects anomalies in real-time, and blocks threats before they execute.

```bash
pip install navil
navil wrap claude_desktop_config.json   # or cursor, openclaw, continue
```

Two commands. Every MCP tool call now goes through the proxy. No config changes to your agent.

## What Navil detects

We test against 11 attack patterns covering the full MITRE ATT&CK chain adapted for MCP:

| Pattern | Example | Detection rate |
|---------|---------|---------------|
| Reconnaissance | Tool listing, process enumeration | 100% |
| Credential theft | Reading env vars, SSH keys, .env files | 100% |
| Data exfiltration | Sending file contents to external hosts | 100% |
| Privilege escalation | sudo, chmod, user creation | 100% |
| Lateral movement | Network scanning, SSH connections | 100% |
| Command & control | Reverse shells, C2 beaconing | 100% |
| Persistence | Crontab injection, authorized_keys | 100% |
| Supply chain | Malicious package installation | 100% |
| Rug pull | Behavior change detection | 100% |
| Defense evasion | Clearing logs, disabling monitors | 100% |
| Rate spike | Anomalous call frequency | 100% |

11/11 scenarios detected. 368 threat signatures in the blocklist. Zero false positives on clean traffic.

## The community threat network

Here's where it gets interesting.

Every Navil proxy contributes anonymously to a shared threat intelligence pool. No account required — your proxy phones home as a side-effect of use, sharing anonymized telemetry. In return, you receive patterns that other proxies have detected.

The more people who run Navil, the better everyone's protection gets. We call this the community threat network.

If you want real-time patterns (instead of 48-hour delayed ones) and a cloud dashboard for fleet-wide visibility, `navil cloud login` upgrades you to a cloud account in 30 seconds via device flow — no forms, no credit card.

## For enterprises: the missing middleware

Bloomberg, Block, and other large companies have built this internally. They run MCP at scale and needed runtime security — tool-level access control, credential lifecycle management, audit trails for compliance.

Navil is the open-source version of what they built in-house. If you're a platform team managing MCP across your engineering org, a SaaS company with multi-tenant agent security needs, or a regulated industry that needs audit trails — this is built for you.

## What we're building next

Based on two strategic research reports (one from Claude, one from Gemini), we're expanding in three directions:

1. **Context-aware tool scoping** — dynamically filter which tools get exposed per session based on the agent's task. Fewer tools = fewer tokens = cheaper inference + least privilege security.

2. **CLI tool support** — extending the proxy to wrap CLI tool calls (gh, kubectl, aws), not just MCP. Whether your agents use MCP, CLI, or both, Navil provides the audit trail.

3. **A2A readiness** — Agent-to-Agent protocol support so Navil-protected agents can securely discover and communicate with each other.

## Try it

```bash
pip install navil
navil wrap claude_desktop_config.json
```

That's it. Your agents are now protected. Every tool call is monitored. Threats are blocked in real-time. And you're contributing to the community threat network that protects everyone.

- **GitHub:** https://github.com/navilai/navil
- **Cloud Dashboard:** https://navil.ai
- **Threat Radar (public):** https://navil.ai/radar
- **Docs:** https://navil.ai/docs
- **OpenClaw guide:** https://navil.ai/docs/openclaw

---

*Navil is MIT licensed and open source. Built by Pantheon Lab.*
