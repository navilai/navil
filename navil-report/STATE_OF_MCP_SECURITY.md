# The Security Surface of the Agent-Readable Web

**State of MCP Security, May 2026 — Navil**

---

## Executive Summary

We scanned the top 400 MCP server packages on npm and PyPI — every
package an agent might reach when its operator types `mcp-server` or
`mcp` in a registry search. We resolved each package's dependency tree
and queried the OSV vulnerability database for every dependency.

**Three in four carry known CVEs.** Not obscure edge-case packages.
The top packages by search rank: the ones your engineers are installing
right now.

Key numbers:

| | npm (200 pkgs) | PyPI (200 pkgs) | Combined |
|---|---|---|---|
| Packages with CVEs | 123 (62%) | 178 (89%) | 301 (75%) |
| Total CVE instances | — | — | 3,759 |
| Unique CVEs | — | — | 572 |
| Critical-severity packages | — | — | 103 |
| High-severity packages | — | — | 188 |

The PyPI number — 89% — is not a rounding artifact. Python-based MCP
servers are overwhelmingly built on a shared stack (`mcp`, `httpx`,
`pydantic`, `fastapi`) where CVEs in one package propagate across
hundreds of servers simultaneously.

---

## Finding 1: Anthropic's Own SDK Is the Attack Surface

The most widely-distributed vulnerability in the MCP ecosystem is not
in a random third-party package. It is in the official SDKs.

**`@modelcontextprotocol/sdk` (TypeScript)** has three HIGH-severity CVEs:

- `GHSA-8r9q-7v3j-jr4g` — ReDoS vulnerability. A carefully crafted
  input can pin the event loop indefinitely. An agent processing
  untrusted tool output is the exact attack path.
- `GHSA-w48q-cv73-mx4w` — DNS rebinding protection disabled by
  default. Allows an attacker to pivot from a web page to an agent's
  local MCP server.
- `GHSA-345p-7cg4-v4c7` — Cross-client data leak via shared
  server/transport instance. In multi-tenant deployments, this is a
  tenant-isolation failure.

**`mcp` (Python SDK)** has three HIGH-severity CVEs:

- `GHSA-9h52-p55h-vw2f` — DNS rebinding protection disabled by
  default (same class of issue as the TypeScript SDK).
- `GHSA-j975-95f5-7wqh` — Unhandled exception in Streamable HTTP
  transport. Causes denial of service under normal error conditions.
- `GHSA-3qhf-m339-9g5v` — Validation error in FastMCP Server leading
  to DoS.

The blast radius:

- **54% of audited npm MCP packages** carry `@modelcontextprotocol/sdk`
  CVEs in their dependency tree (107 of 200).
- **68% of audited PyPI MCP packages** carry `mcp` SDK CVEs (137 of 200).

This is the supply-chain problem at its starkest: one upstream package
with unpatched vulnerabilities creates exposure across more than half
the ecosystem. Standard SCA tools will flag these at the package layer.
The gap is at runtime — knowing which of your agents can reach which
servers, and enforcing policy at the tool-call layer even while an
upstream patch is pending.

---

## Finding 2: Shared Infrastructure Amplifies Ecosystem Risk

The ten most common vulnerable dependencies, by number of MCP packages
affected:

| Dependency | Packages Affected | Notes |
|---|---|---|
| `mcp` (Python SDK) | 137 | 6 known CVEs, 3 HIGH |
| `@modelcontextprotocol/sdk` | 108 | 3 HIGH CVEs |
| `httpx` | 66 | CRITICAL CVE (input validation) |
| `pytest` | 54 | Medium; dev dependency pattern |
| `pydantic` | 50 | ReDoS, infinite loop CVEs |
| `fastmcp` | 40 | Depends on vulnerable `mcp` |
| `python-dotenv` | 29 | Credential exposure risk |
| `requests` | 28 | Historical CVEs |
| `axios` | 26 | 6 CVEs including DoS via `__proto__` |
| `uvicorn` | 20 | HTTP server-level |

`httpx` carries a CRITICAL-rated input validation CVE
(`GHSA-h8pj-cxx2-jfg2`) that affects 66 PyPI MCP packages. This is
notable because `httpx` is the HTTP client that MCP servers use to
make outbound calls — the exact code path an agent uses to fetch
external data. A Mythos-class model that can synthesize novel payloads
has a known vulnerable code path to target.

`pydantic` — used for data validation across most Python MCP servers —
carries two vulnerabilities worth noting: a regex denial-of-service
(`GHSA-mr82-8j83-vxmv`) and an infinite-loop bug in datetime field
handling (`GHSA-5jqp-qgf6-3pvh`). Both are exploitable via crafted
tool arguments.

---

## Finding 3: The Attack Surface Is Already Mapped

The SAFE-MCP threat taxonomy provides a framework for categorizing
what attackers can do with these CVEs. We mapped each vulnerability
to the tactic most likely to be exploited via its attack path:

| Attack Tactic | Packages Exposed | % of Audited |
|---|---|---|
| Infrastructure & Runtime | 293 | 73% |
| Code Execution | 289 | 72% |
| Prompt Injection | 122 | 31% |
| Credential Scope | 104 | 26% |
| Privilege Escalation | 89 | 22% |
| Output Weaponization | 86 | 22% |
| RAG & Memory Poisoning | 67 | 17% |
| Tool Poisoning | 43 | 11% |

The Infrastructure & Runtime and Code Execution numbers (73% and 72%)
reflect the pervasiveness of DoS, memory corruption, and execution
vulnerabilities in the shared web stack. These are the foundation.
The tactics higher up the stack — Credential Scope, Privilege
Escalation, Output Weaponization — represent what an attacker does
*after* landing on a vulnerable server.

The Prompt Injection number (31%) is a direct CVE-level signal, not a
theoretical concern. These are packages with documented input-validation
failures that an agent's tool inputs can reach.

---

## What This Means

**For teams running agents in production:** The security model for
agents is not complete at the model layer. An agent's tool surface —
the MCP servers it can reach — is the attack surface that grows with
every new integration. 75% of packages in the ecosystem carry known
vulnerabilities in their dependency tree. Standard SCA scanning at
install time is a necessary but insufficient control: it tells you
about packages at a point in time but says nothing about which agents
can reach them at runtime.

**For MCP server authors:** Three actions have the highest leverage:

1. Run `npm audit` / `pip-audit` in CI and block on HIGH or CRITICAL.
   Most of the CVEs in this report are patchable today.
2. Pin your `@modelcontextprotocol/sdk` / `mcp` version and monitor
   the advisory feeds. The official SDK CVEs are the single highest-
   impact remediations in the ecosystem.
3. Scope your server's tool list to the minimum required. A server
   that exposes fewer tools has a smaller blast radius if a dependency
   is compromised.

**For security teams evaluating MCP adoption:** The question is not
whether MCP servers have CVEs — they do, at scale. The question is
whether your governance model accounts for agent-reachable attack
surfaces the way it accounts for API endpoints. The answer, for most
organizations, is currently no.

---

## Methodology

**Discovery.** We queried the npm registry for packages matching
`mcp-server` and `modelcontextprotocol mcp` keywords, and PyPI's
simple index for packages matching `mcp`. No manual curation — these
are the packages a developer finds when looking for MCP integrations.
200 packages per ecosystem, sorted by registry search rank.

**Dependency resolution.** For each package we fetched its latest
published manifest (`package.json` for npm, PyPI JSON API for PyPI)
and extracted direct dependencies. We then resolved one level of
transitive dependencies. We did not resolve deeper trees; the actual
exposure in production deployments with pinned older versions is
likely higher.

**CVE lookup.** We used the [OSV.dev](https://osv.dev) batch API to
query each unique package@version pair against the OSV database, which
aggregates NVD, GitHub Advisory Database, and ecosystem-specific
sources. For each hit we fetched the full vulnerability record to
extract severity, CVSS score, and description.

**Tactic mapping.** We matched CVE summaries and details against
keyword sets derived from the SAFE-MCP threat taxonomy to assign each
finding to one or more attack tactic categories. This is a heuristic;
some CVEs may be miscategorized.

**Caveats.** Version detection uses the latest published version of
each package. Pinned older versions may carry additional CVEs.
Transitive depth is capped at one level. The PyPI simple index
does not provide download counts, so PyPI packages are unweighted by
popularity. The npm packages are ordered by npm search rank.

---

## Data

The structured JSON data file for this report is available at
[navil.ai/research/state-of-mcp-security-2026.json](https://navil.ai/research/state-of-mcp-security-2026.json).

Generated by [Navil](https://navil.ai) — production governance for AI agents.
Vulnerability data from [OSV.dev](https://osv.dev).
Tactic taxonomy from [SAFE-MCP](https://safe-mcp.org).
Scan completed May 2026.

---

*To reproduce this report: `pip install navil && navil audit-deps --top 200 --ecosystem all`*
