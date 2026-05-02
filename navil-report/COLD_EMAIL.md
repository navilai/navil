# Cold email — CISO / Platform Lead

**Subject:** We scanned 400 MCP packages. 75% carry known CVEs.

---

Hi [Name],

We published a scan this week of the top 400 MCP server packages on npm and PyPI — the packages your engineers are probably pulling in when they build agent integrations.

Three things that may be relevant to your team:

**1. 75% carry known CVEs.** PyPI MCP packages: 89%. These aren't edge cases — they're the top search results.

**2. Anthropic's own SDK is the most widely-distributed vulnerability.** The official `mcp` and `@modelcontextprotocol/sdk` packages each carry 3 HIGH-severity CVEs (DNS rebinding, ReDoS, unhandled exceptions). Because these are foundational dependencies, the CVEs appear in 54–68% of the ecosystem.

**3. Standard SCA catches this at install. The runtime gap is different.** The question I'd expect your team to be getting asked: *which agents in your environment can reach which servers, and what did they call last Tuesday?* Most teams can't answer that today.

We built Navil to answer that question at the runtime layer. Happy to share the full report data or run a private scan of your MCP config if useful.

Full report: https://navil.ai/research/state-of-mcp-security-2026

— Ivan
[ivan@navil.ai](mailto:ivan@navil.ai)

*Methodology: OSV.dev batch API, one level of transitive deps, SAFE-MCP tactic mapping. Data is reproducible: `pip install navil && navil audit-deps`.*

---

# HN Launch Post

**Title:** We scanned 400 MCP packages and found CVEs in 75% of them

---

We built a dependency auditor for MCP servers and ran it against the top 400 packages on npm and PyPI. The numbers were worse than expected.

**Summary:**
- 75% of packages carry at least one known CVE in their dependency tree (89% for PyPI)
- 572 unique CVEs, 3,759 instances
- Anthropic's own SDK (`@modelcontextprotocol/sdk` / `mcp`) has 6 HIGH-severity CVEs across the two packages — affecting 54–68% of the ecosystem because they're the foundational dependencies

**The SDK finding is the interesting part.** Three CVEs on the TypeScript SDK, three on the Python SDK. DNS rebinding protection disabled by default in both. A ReDoS. A cross-client data leak. These aren't theoretical — they're in the GHSA database with reproducible PoCs.

The dependency list reads like any modern web service: `httpx` (CRITICAL), `pydantic` (ReDoS, infinite loop), `axios` (6 CVEs), `fastapi`. Nothing unusual about the stack. The unusual part is that these packages are now in the call path of autonomous agents making decisions with real-world consequences, without a human reviewing each tool call.

Standard `npm audit` / `pip-audit` will flag most of this. The gap is the runtime layer — knowing which agents in your environment can reach which servers, and enforcing policy at the tool-call level while upstream patches are pending.

We open-sourced the auditor. To reproduce: `pip install navil && navil audit-deps --top 200 --ecosystem all`

Full report with per-package breakdown: [link]

Questions welcome. Methodology in the report.

---

# Twitter/X thread (3 posts)

**Post 1:**
We scanned 400 MCP server packages. 75% carry known CVEs in their dependency tree.

Anthropic's own SDK has 6 HIGH-severity CVEs. It's in 54–68% of the ecosystem.

Thread on what we found:

**Post 2:**
The SDK finding matters because of blast radius.

`@modelcontextprotocol/sdk` (TypeScript): ReDoS, DNS rebinding, cross-client data leak.
`mcp` (Python): DNS rebinding, 2× unhandled exception DoS.

These are the foundational deps. CVEs in them don't affect one server. They affect most of the ecosystem simultaneously.

**Post 3:**
Standard npm audit catches this at install. The runtime gap is different.

The question security teams are starting to get: "which agents can reach which servers, and what did they call?"

We built the answer. Full report + reproducible auditor: navil.ai/research/state-of-mcp-security-2026
