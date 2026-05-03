# Launch copy — Claude Security news cycle

This week, Anthropic shipped Claude Security (SAST) and embedded Opus 4.7 inside Wiz, CrowdStrike, Palo Alto, SentinelOne, Trend Micro. The natural temptation is to ride the news cycle by saying "we run on Opus too." Don't. The right move is to *contrast*: Anthropic ships single-vendor static analysis; Navil ships vendor-neutral runtime governance. Different problem, different layer, different buyer.

---

## Tweet / X thread (3 posts)

**Post 1**

Anthropic shipped Claude Security this week — a static code scanner. Good product.

But the question CISOs are asking right now is: *which agents are calling which tools in our environment, and what did they try last Tuesday?*

That's a runtime question. SAST doesn't answer it.

**Post 2**

Today we shipped two things:

→ `navil audit-deps --stdio-flaw` detects the MCP STDIO transport vuln Ox researchers disclosed in April. Anthropic declined to patch it (called it "expected behavior"). 200,000 servers exposed.

→ `navil policy generate` reasons over your live tool-call telemetry to produce a least-privilege policy with per-rule rationale. Works with Claude Sonnet, Opus, or Haiku. Vendor-neutral by design.

**Post 3**

The thing Anthropic structurally won't ship — runtime governance across every agent vendor (Cursor, Continue, Claude Code, custom) — is what we ship.

```
$ pip install navil
$ navil secure
$ export ANTHROPIC_API_KEY=sk-ant-...   # for --engine; falls back if unset
$ navil policy generate --engine=opus-4-7
```

Apache 2.0. https://navil.ai

---

## LinkedIn post (long form, one piece)

**Anthropic shipped Claude Security this week. Here's the gap that's left.**

Claude Security is a static code vulnerability scanner. It reads your repo, traces data flows, generates patches. It is not a runtime governance product. It does not enforce policy on tool calls. It does not monitor MCP servers.

Anthropic also shipped Claude Managed Agents — runtime governance for agents that run on Anthropic's infrastructure. Cursor, Continue, custom internal agents, and non-Claude models are out of scope.

We scanned the top 400 public MCP packages last week. 75% carry known CVEs in their dependency tree. Anthropic's own SDK has 6 HIGH-severity vulnerabilities affecting 54-68% of the ecosystem (https://navil.ai/research/state-of-mcp-security-2026).

That gap — the runtime layer for the heterogeneous agent fleet — is where Navil sits. We shipped today:

• `navil audit-deps --stdio-flaw` — detects the MCP STDIO transport vulnerability Ox researchers disclosed in April. Anthropic called the behavior "expected" and declined to patch.

• `navil policy generate` — reasons over your tool-call telemetry to produce least-privilege policy with per-rule rationale. Works across Claude Sonnet, Opus, Haiku, or any compatible model.

Both ship in the open-source CLI today. Apache 2.0.

---

## Blog post (publish on /blog/claude-security-and-the-runtime-gap)

### Claude Security is good. It's also not enough.

Anthropic shipped Claude Security in public beta on April 30. It's a real product, built on a real model (Opus 4.7), backed by real partners (CrowdStrike, Palo Alto, SentinelOne, Wiz, Trend Micro). It scans codebases, traces data flows, generates targeted patches. We've used it; it works.

It is also a static analysis tool. It runs against source code at rest. That's the whole product.

The question security teams are now being asked — by their own engineers, their own auditors, their own boards — is a different one: *which of our agents are calling which tools in production right now, and what did they try that failed last week?*

That's a runtime question. Static analysis doesn't answer it.

#### What Claude Security does not cover

We mapped the announcement against the agent attack surface. Three gaps:

**1. Runtime tool-call enforcement.** Claude Security finds vulnerabilities in code. It doesn't observe what an agent is doing with that code at runtime. If your Cursor instance gets a poisoned response from an MCP server, Claude Security won't see it. The proxy layer between agent and tool is empty.

**2. Multi-vendor agent fleets.** Anthropic also shipped Claude Managed Agents on April 9 — a hosted runtime with permission controls and tool-call tracing. Critical limitation: agents must run on Anthropic infrastructure. The 70% of enterprise agent traffic that comes from Cursor, Continue, custom internal agents, and non-Claude models is structurally out of scope for that product. It cannot ship cross-vendor; it's a Claude product.

**3. The MCP STDIO transport flaw.** In April 2026, researchers at Ox disclosed that the MCP STDIO transport executes arbitrary OS commands regardless of whether they spawn a valid MCP server. Roughly 200,000 servers are affected (150M+ downloads). Anthropic was given the disclosure. They declined to patch the protocol, calling the behavior "expected." So this is now a runtime detection problem — there is no upstream fix coming.

#### What we shipped today

**`navil audit-deps --stdio-flaw`** — local scan of every MCP config on your machine, flagging launch commands that match the STDIO flaw class (shell wrappers, unpinned npx, untrusted authors, remote pipes, unknown binaries). Pure-local, no network calls, finishes in under a second. Report markdown + structured JSON. Anthropic won't patch this; you can detect and mitigate it today.

**`navil policy generate`** — reads your MCP configs and tool-call audit log, calls a reasoning model (default: Claude Sonnet 4.6; `--engine=opus-4-7` available for deeper analysis) with the SAFE-MCP threat catalog as cached context, and produces:

1. A `navil.yaml` policy file with least-privilege scoping
2. A `navil-policy.md` rationale document — *why* each rule exists, what threat class it blocks, which SAFE-MCP tactic it maps to

The rationale doc is the differentiator. Generated policies that nobody can defend in front of an auditor get rolled back. Generated policies with a paragraph of reasoning per rule survive review.

#### Why vendor-neutrality matters

Anthropic's products are excellent and they are also Claude-only by definition. Wiz now has Opus 4.7 inside their platform; Wiz is a great product and it's also CNAPP-only by definition. Snyk and Socket are great SCA products; they're file-system-and-package-manager-only.

The runtime governance layer for AI agents has to work across every model and every agent. A CISO who has to deploy four products to cover their fleet won't deploy any of them.

Navil is one product. It works with Claude Code, Cursor, Continue, OpenClaw, and any custom agent that speaks MCP. It works with any reasoning model the team prefers. The proxy is 2.7 microseconds at p50 in Rust. The catalog is open. The license is Apache 2.0.

```
pip install navil && navil secure
```

We'll keep shipping the runtime layer Anthropic structurally won't.

— The Navil team
