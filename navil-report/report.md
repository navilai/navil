# The Security Surface of the Agent-Readable Web
> State of MCP Security — May 02, 2026

**Navil** scanned the top MCP server packages across npm and PyPI,
cross-referenced every dependency against the OSV vulnerability database,
and mapped findings to the SAFE-MCP threat taxonomy.

---

## Executive Summary

- **400** MCP packages audited (npm, pypi)
- **301** (75%) contain at least one known CVE
- **3759** total vulnerability instances found
- Severity: 306 critical · 1356 high · 965 medium · 201 low

The most-exposed attack surface is **Infrastructure & Runtime**, affecting 293 packages.

---

## Methodology

1. **Discovery** — queried the npm registry for packages with `mcp-server` keyword and PyPI's simple index for packages matching `mcp`.  No manual curation.
2. **Dependency resolution** — fetched each package's published `package.json` / `requires_dist` and extracted direct + first-level transitive dependencies.
3. **CVE lookup** — batch-queried [OSV.dev](https://osv.dev) (the open vulnerability database aggregating NVD, GitHub Advisory, and others) for each package@version pair.
4. **Tactic mapping** — matched CVE summaries and details against keyword sets derived from the [SAFE-MCP threat taxonomy](https://safe-mcp.org) to assign each finding to one or more attack tactic categories.

Limitations: version detection uses the latest published version of each package. Pinned or older deployments may have different (higher) exposure.  Transitive depth is capped at one level; deeper trees may surface additional CVEs.

---

## Findings by SAFE-MCP Tactic

| Attack Tactic | Affected Packages | % of Audited |
|---|---|---|
| Infrastructure & Runtime | 293 | 73.2% |
| Code Execution | 289 | 72.2% |
| Prompt Injection | 122 | 30.5% |
| Credential Scope | 104 | 26.0% |
| Privilege Escalation | 89 | 22.2% |
| Output Weaponization | 86 | 21.5% |
| RAG & Memory Poisoning | 67 | 16.8% |
| Tool Poisoning | 43 | 10.8% |
| Supply Chain | 5 | 1.2% |
| Anti-Forensics | 2 | 0.5% |

---

## Most Common Vulnerable Dependencies

The following packages appeared as dependencies across multiple MCP servers and carried known CVEs — meaning a single upstream fix would reduce exposure across the entire ecosystem.

| Dependency | MCP Packages Affected |
|---|---|
| `mcp` | 137 |
| `@modelcontextprotocol/sdk` | 108 |
| `httpx` | 66 |
| `pytest` | 54 |
| `pydantic` | 50 |
| `fastmcp` | 40 |
| `python-dotenv` | 29 |
| `requests` | 28 |
| `axios` | 26 |
| `uvicorn` | 20 |
| `black` | 16 |
| `fastapi` | 12 |
| `aiohttp` | 10 |
| `express` | 9 |
| `jinja2` | 7 |

---

## Package-Level Findings

Packages with at least one high or critical severity CVE:

### 🔴 `5g-ddos-mcp` v1.0.0 (PyPI)
- **CVEs found:** 296 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning, Tool Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req

### 🔴 `academia-mcp` v1.13.4 (PyPI)
- **CVEs found:** 199 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟠 `GHSA-462w-v97r-4m45` via `jinja2` (HIGH) — Jinja2 sandbox escape via string formatting
  - 🟠 `GHSA-8r7q-cvjq-x353` via `jinja2` (HIGH) — Incorrect Privilege Assignment in Jinja2
  - 🟡 `GHSA-cpwx-vrp4-4pq7` via `jinja2` (MEDIUM) — Jinja2 vulnerable to sandbox breakout through attr filter selecting format metho
  - 🟠 `GHSA-3c5c-7235-994j` via `pillow` (HIGH) — Pillow buffer overflow in ImagingPcdDecode
  - 🔴 `GHSA-3f63-hfp8-52jq` via `pillow` (CRITICAL) — Arbitrary Code Execution in Pillow
  - 🟠 `GHSA-3wvg-mj6g-m9cv` via `pillow` (HIGH) — Pillow Uncontrolled Resource Consumption
  - 🟡 `GHSA-2q4j-m29v-hq73` via `pypdf` (MEDIUM) — pypdf has possible Infinite Loop when processing outlines/bookmarks
  - 🟢 `GHSA-2rw7-x74f-jg35` via `pypdf` (LOW) — pypdf has a possible infinite loop when loading circular /Prev entries in cross-
  - 🟡 `GHSA-3crg-w4f6-42mx` via `pypdf` (MEDIUM) — pypdf: Manipulated XMP metadata entity declarations can exhaust RAM

### 🔴 `1xn-vmcp` v0.6.1 (PyPI)
- **CVEs found:** 192 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req

### 🔴 `agent-mcp` v0.1.8 (PyPI)
- **CVEs found:** 121 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning, Tool Poisoning

  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via

### 🔴 `adiffy-meta-ads-mcp` v1.0.0 (PyPI)
- **CVEs found:** 110 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via

### 🔴 `academic-figures-mcp` v0.4.5 (PyPI)
- **CVEs found:** 103 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Infrastructure & Runtime, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟠 `GHSA-3c5c-7235-994j` via `pillow` (HIGH) — Pillow buffer overflow in ImagingPcdDecode
  - 🔴 `GHSA-3f63-hfp8-52jq` via `pillow` (CRITICAL) — Arbitrary Code Execution in Pillow
  - 🟠 `GHSA-3wvg-mj6g-m9cv` via `pillow` (HIGH) — Pillow Uncontrolled Resource Consumption
  - 🔴 `GHSA-8q59-q68h-6hv4` via `pyyaml` (CRITICAL) — Improper Input Validation in PyYAML
  - 🔴 `GHSA-rprw-h62v-c2w7` via `pyyaml` (CRITICAL) — PyYAML insecurely deserializes YAML strings leading to arbitrary code execution
  - ⚪ `PYSEC-2018-49` via `pyyaml` (UNKNOWN) —

### 🔴 `acg-frontend-mcp` v0.1.4 (PyPI)
- **CVEs found:** 100 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Infrastructure & Runtime, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟠 `GHSA-8h2j-cgx8-6xv7` via `fastapi` (HIGH) — Cross-Site Request Forgery (CSRF) in FastAPI
  - ⚪ `PYSEC-2021-100` via `fastapi` (UNKNOWN) —
  - ⚪ `PYSEC-2024-38` via `fastapi` (UNKNOWN) —
  - 🟠 `GHSA-3c5c-7235-994j` via `pillow` (HIGH) — Pillow buffer overflow in ImagingPcdDecode
  - 🔴 `GHSA-3f63-hfp8-52jq` via `pillow` (CRITICAL) — Arbitrary Code Execution in Pillow
  - 🟠 `GHSA-3wvg-mj6g-m9cv` via `pillow` (HIGH) — Pillow Uncontrolled Resource Consumption

### 🔴 `adversary-mcp-server` v1.11.1 (PyPI)
- **CVEs found:** 96 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi

### 🔴 `acp-mcp-server` v0.0.5 (PyPI)
- **CVEs found:** 56 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req
  - 🟠 `GHSA-33c7-2mpw-hg34` via `uvicorn` (HIGH) — Log injection in uvicorn
  - 🟠 `GHSA-f97h-2pfx-f59f` via `uvicorn` (HIGH) — HTTP response splitting in uvicorn
  - ⚪ `PYSEC-2020-150` via `uvicorn` (UNKNOWN) —
  - 🟠 `GHSA-3936-cmfr-pm3m` via `black` (HIGH) — Black: Arbitrary file writes from unsanitized user input in cache file name
  - 🟡 `GHSA-fj7x-q9j7-g6q6` via `black` (MEDIUM) — Black vulnerable to Regular Expression Denial of Service (ReDoS)
  - ⚪ `PYSEC-2024-48` via `black` (UNKNOWN) —

### 🔴 `aceflow-mcp-server` v3.0.2 (PyPI)
- **CVEs found:** 54 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via

### 🔴 `agentic-ai-mcp` v0.6.5 (PyPI)
- **CVEs found:** 54 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning, Tool Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via
  - 🔴 `GHSA-2qmj-7962-cjq8` via `langchain` (CRITICAL) — langchain arbitrary code execution vulnerability
  - 🟡 `GHSA-3hjh-jh2h-vrg6` via `langchain` (MEDIUM) — Denial of service in langchain-community
  - 🟢 `GHSA-45pg-36p6-83v9` via `langchain` (LOW) — Langchain SQL Injection vulnerability

### 🔴 `academic-mcp` v0.1.7 (PyPI)
- **CVEs found:** 53 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟠 `GHSA-33c7-2mpw-hg34` via `uvicorn` (HIGH) — Log injection in uvicorn
  - 🟠 `GHSA-f97h-2pfx-f59f` via `uvicorn` (HIGH) — HTTP response splitting in uvicorn
  - ⚪ `PYSEC-2020-150` via `uvicorn` (UNKNOWN) —

### 🟠 `12306-mcp` v0.1.7 (PyPI)
- **CVEs found:** 52 (HIGH max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi

### 🟠 `12306-search-mcp` v0.1.4 (PyPI)
- **CVEs found:** 49 (HIGH max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi

### 🔴 `agentcraft-mcp` v0.1.0 (PyPI)
- **CVEs found:** 49 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via
  - 🟠 `GHSA-33c7-2mpw-hg34` via `uvicorn` (HIGH) — Log injection in uvicorn
  - 🟠 `GHSA-f97h-2pfx-f59f` via `uvicorn` (HIGH) — HTTP response splitting in uvicorn
  - ⚪ `PYSEC-2020-150` via `uvicorn` (UNKNOWN) —
  - 🔴 `GHSA-8q59-q68h-6hv4` via `pyyaml` (CRITICAL) — Improper Input Validation in PyYAML
  - 🔴 `GHSA-rprw-h62v-c2w7` via `pyyaml` (CRITICAL) — PyYAML insecurely deserializes YAML strings leading to arbitrary code execution
  - ⚪ `PYSEC-2018-49` via `pyyaml` (UNKNOWN) —

### 🔴 `addgene-mcp` v0.1.3 (PyPI)
- **CVEs found:** 48 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via

### 🔴 `academic-search-mcp` v0.1.8 (PyPI)
- **CVEs found:** 46 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟠 `GHSA-5h2m-4q8j-pqpj` via `fastmcp` (HIGH) — FastMCP OAuth Proxy token reuse across MCP servers
  - 🟠 `GHSA-c2jp-c369-7pvx` via `fastmcp` (HIGH) — FastMCP Auth Integration Allows for Confused Deputy Account Takeover
  - 🟡 `GHSA-m8x7-r2rg-vh5g` via `fastmcp` (MEDIUM) — FastMCP has a Command Injection vulnerability - Gemini CLI
  - 🟡 `GHSA-3mwg-gp5g-fv3q` via `feedparser` (MEDIUM) — feedparser Cross-site Scripting vulnerability
  - 🟠 `GHSA-hjf3-r7gw-9rwg` via `feedparser` (HIGH) — feedparser denial of service vulnerability
  - ⚪ `PYSEC-2011-18` via `feedparser` (UNKNOWN) —

### 🟠 `a2c-smcp` v0.1.5 (PyPI)
- **CVEs found:** 43 (HIGH max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req

### 🔴 `agemcp` v0.5.3 (PyPI)
- **CVEs found:** 43 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning, Tool Poisoning

  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🔴 `GHSA-2xpj-f5g2-8p7m` via `asyncpg` (CRITICAL) — Asyncpg Arbitrary Code Execution Via Access to an Uninitialized Pointer
  - ⚪ `PYSEC-2020-24` via `asyncpg` (UNKNOWN) —
  - 🔴 `GHSA-38fc-9xqv-7f7q` via `sqlalchemy` (CRITICAL) — SQLAlchemy is vulnerable to SQL Injection via group_by parameter
  - 🔴 `GHSA-887w-45rq-vxgf` via `sqlalchemy` (CRITICAL) — SQLAlchemy vulnerable to SQL Injection via order_by parameter
  - 🔴 `GHSA-hfg2-wf6j-x53p` via `sqlalchemy` (CRITICAL) — SQLAlchemy vulnerable to SQL injection

### 🔴 `agentic-store-mcp` v1.0.1 (PyPI)
- **CVEs found:** 42 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟠 `GHSA-8h2j-cgx8-6xv7` via `fastapi` (HIGH) — Cross-Site Request Forgery (CSRF) in FastAPI
  - ⚪ `PYSEC-2021-100` via `fastapi` (UNKNOWN) —
  - ⚪ `PYSEC-2024-38` via `fastapi` (UNKNOWN) —
  - 🟠 `GHSA-462w-v97r-4m45` via `jinja2` (HIGH) — Jinja2 sandbox escape via string formatting
  - 🟠 `GHSA-8r7q-cvjq-x353` via `jinja2` (HIGH) — Incorrect Privilege Assignment in Jinja2
  - 🟡 `GHSA-cpwx-vrp4-4pq7` via `jinja2` (MEDIUM) — Jinja2 vulnerable to sandbox breakout through attr filter selecting format metho

### 🟠 `actionai-mcp` v1.0.0 (PyPI)
- **CVEs found:** 37 (HIGH max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Prompt Injection, RAG & Memory Poisoning

  - 🟢 `GHSA-2vrm-gr82-f7m5` via `aiohttp` (LOW) — AIOHTTP has CRLF injection through multipart part content type header constructi
  - 🟢 `GHSA-3wq7-rqq7-wx6j` via `aiohttp` (LOW) — AIOHTTP has late size enforcement for non-file multipart fields causes memory Do
  - 🟡 `GHSA-45c4-8wx5-qw6w` via `aiohttp` (MEDIUM) — aiohttp.web.Application vulnerable to HTTP request smuggling via llhttp HTTP req

### 🟠 `a2a-mcp` v0.1.0 (PyPI)
- **CVEs found:** 34 (HIGH max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection

  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via
  - 🟠 `GHSA-3ww4-gg4f-jr7f` via `cryptography` (HIGH) — Python Cryptography package vulnerable to Bleichenbacher timing oracle attack
  - 🟡 `GHSA-9v9h-cgj8-h64p` via `cryptography` (MEDIUM) — Null pointer dereference in PKCS12 parsing
  - 🟠 `GHSA-hggm-jpg3-v476` via `cryptography` (HIGH) — RSA decryption vulnerable to Bleichenbacher timing vulnerability
  - 🟠 `GHSA-562c-5r94-xh97` via `flask` (HIGH) — Flask is vulnerable to Denial of Service via incorrect encoding of JSON data
  - 🟠 `GHSA-5wv5-4vpf-pj6m` via `flask` (HIGH) — Pallets Project Flask is vulnerable to Denial of Service via Unexpected memory u
  - 🟢 `GHSA-68rp-wp8r-4726` via `flask` (LOW) — Flask session does not add `Vary: Cookie` header when accessed in some ways
  - 🟠 `GHSA-32pc-xphx-q4f6` via `gunicorn` (HIGH) — Gunicorn contains Improper Neutralization of CRLF sequences in HTTP headers
  - 🟠 `GHSA-hc5x-x2vx-497g` via `gunicorn` (HIGH) — Gunicorn HTTP Request/Response Smuggling vulnerability
  - 🟠 `GHSA-w3h3-4rj7-4ph4` via `gunicorn` (HIGH) — Request smuggling leading to endpoint restriction bypass in Gunicorn

### 🔴 `a2a-mcp-server` v0.1.5 (PyPI)
- **CVEs found:** 32 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-2c2j-9gv5-cj73` via `starlette` (MEDIUM) — Starlette has possible denial-of-service vector when parsing large files in mult
  - 🟠 `GHSA-74m5-2c7w-9w3x` via `starlette` (HIGH) — MultipartParser denial of service with too many fields or files
  - 🟠 `GHSA-f96h-pmfr-66vw` via `starlette` (HIGH) — Starlette Denial of service (DoS) via multipart/form-data
  - 🟠 `GHSA-33c7-2mpw-hg34` via `uvicorn` (HIGH) — Log injection in uvicorn
  - 🟠 `GHSA-f97h-2pfx-f59f` via `uvicorn` (HIGH) — HTTP response splitting in uvicorn
  - ⚪ `PYSEC-2020-150` via `uvicorn` (UNKNOWN) —

### 🔴 `advanced-seo-mcp` v0.1.1 (PyPI)
- **CVEs found:** 30 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via
  - 🟠 `GHSA-5h2m-4q8j-pqpj` via `fastmcp` (HIGH) — FastMCP OAuth Proxy token reuse across MCP servers
  - 🟠 `GHSA-c2jp-c369-7pvx` via `fastmcp` (HIGH) — FastMCP Auth Integration Allows for Confused Deputy Account Takeover
  - 🟡 `GHSA-m8x7-r2rg-vh5g` via `fastmcp` (MEDIUM) — FastMCP has a Command Injection vulnerability - Gemini CLI
  - 🟡 `GHSA-55x5-fj6c-h6m8` via `lxml` (MEDIUM) — lxml's HTML Cleaner allows crafted and SVG embedded scripts to pass through
  - 🟡 `GHSA-57qw-cc2g-pv5p` via `lxml` (MEDIUM) — lxml Cross-site Scripting Via Control Characters
  - 🟡 `GHSA-jq4v-f5q6-mjqq` via `lxml` (MEDIUM) — lxml vulnerable to Cross-Site Scripting

### 🔴 `agent-knowledge-mcp` v2.2.1 (PyPI)
- **CVEs found:** 27 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟠 `GHSA-3936-cmfr-pm3m` via `black` (HIGH) — Black: Arbitrary file writes from unsanitized user input in cache file name
  - 🟡 `GHSA-fj7x-q9j7-g6q6` via `black` (MEDIUM) — Black vulnerable to Regular Expression Denial of Service (ReDoS)
  - ⚪ `PYSEC-2024-48` via `black` (UNKNOWN) —

### 🔴 `agent-knowledge-mcp-fastmcp` v2.2.2 (PyPI)
- **CVEs found:** 27 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟠 `GHSA-3936-cmfr-pm3m` via `black` (HIGH) — Black: Arbitrary file writes from unsanitized user input in cache file name
  - 🟡 `GHSA-fj7x-q9j7-g6q6` via `black` (MEDIUM) — Black vulnerable to Regular Expression Denial of Service (ReDoS)
  - ⚪ `PYSEC-2024-48` via `black` (UNKNOWN) —

### 🔴 `agentfactory-mcp-server` v0.1.0 (PyPI)
- **CVEs found:** 27 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Infrastructure & Runtime, Prompt Injection, RAG & Memory Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - 🟡 `GHSA-5jqp-qgf6-3pvh` via `pydantic` (MEDIUM) — Use of "infinity" as an input to datetime and date fields causes infinite loop i
  - 🟡 `GHSA-mr82-8j83-vxmv` via `pydantic` (MEDIUM) — Pydantic regular expression denial of service
  - ⚪ `PYSEC-2021-47` via `pydantic` (UNKNOWN) —
  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟠 `GHSA-8h2j-cgx8-6xv7` via `fastapi` (HIGH) — Cross-Site Request Forgery (CSRF) in FastAPI
  - ⚪ `PYSEC-2021-100` via `fastapi` (UNKNOWN) —
  - ⚪ `PYSEC-2024-38` via `fastapi` (UNKNOWN) —

### 🔴 `ado-mcp` v0.0.1 (PyPI)
- **CVEs found:** 23 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Output Weaponization, Privilege Escalation, Prompt Injection, RAG & Memory Poisoning

  - 🟡 `GHSA-6w46-j5rx-g56g` via `pytest` (MEDIUM) — pytest has vulnerable tmpdir handling
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via
  - 🟠 `GHSA-5h2m-4q8j-pqpj` via `fastmcp` (HIGH) — FastMCP OAuth Proxy token reuse across MCP servers
  - 🟠 `GHSA-c2jp-c369-7pvx` via `fastmcp` (HIGH) — FastMCP Auth Integration Allows for Confused Deputy Account Takeover
  - 🟡 `GHSA-m8x7-r2rg-vh5g` via `fastmcp` (MEDIUM) — FastMCP has a Command Injection vulnerability - Gemini CLI
  - 🔴 `GHSA-8q59-q68h-6hv4` via `PyYAML` (CRITICAL) — Improper Input Validation in PyYAML
  - 🔴 `GHSA-rprw-h62v-c2w7` via `PyYAML` (CRITICAL) — PyYAML insecurely deserializes YAML strings leading to arbitrary code execution
  - ⚪ `PYSEC-2018-49` via `PyYAML` (UNKNOWN) —

### 🔴 `agent-bus-mcp` v0.5.0 (PyPI)
- **CVEs found:** 23 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Infrastructure & Runtime, Prompt Injection, RAG & Memory Poisoning, Tool Poisoning

  - 🟠 `GHSA-3qhf-m339-9g5v` via `mcp` (HIGH) — MCP Python SDK vulnerability in the FastMCP Server causes validation error, lead
  - 🟠 `GHSA-9h52-p55h-vw2f` via `mcp` (HIGH) — Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection
  - 🟠 `GHSA-j975-95f5-7wqh` via `mcp` (HIGH) — MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to
  - 🟠 `GHSA-8h2j-cgx8-6xv7` via `fastapi` (HIGH) — Cross-Site Request Forgery (CSRF) in FastAPI
  - ⚪ `PYSEC-2021-100` via `fastapi` (UNKNOWN) —
  - ⚪ `PYSEC-2024-38` via `fastapi` (UNKNOWN) —
  - 🟠 `GHSA-33c7-2mpw-hg34` via `uvicorn` (HIGH) — Log injection in uvicorn
  - 🟠 `GHSA-f97h-2pfx-f59f` via `uvicorn` (HIGH) — HTTP response splitting in uvicorn
  - ⚪ `PYSEC-2020-150` via `uvicorn` (UNKNOWN) —
  - 🟠 `GHSA-2fc2-6r4j-p65h` via `numpy` (HIGH) — Numpy arbitrary file write via symlink attack
  - 🟠 `GHSA-5545-2q6w-2gh6` via `numpy` (HIGH) — NumPy NULL Pointer Dereference
  - 🔴 `GHSA-9fq2-x9r6-wfmf` via `numpy` (CRITICAL) — Numpy Deserialization of Untrusted Data

### 🔴 `agentcore-mcp-proxy` v0.1.0 (PyPI)
- **CVEs found:** 23 (CRITICAL max severity)
- **Exposed tactics:** Code Execution, Credential Scope, Infrastructure & Runtime, Privilege Escalation, Prompt Injection

  - 🔴 `GHSA-h8pj-cxx2-jfg2` via `httpx` (CRITICAL) — Improper Input Validation in httpx
  - ⚪ `PYSEC-2022-183` via `httpx` (UNKNOWN) —
  - 🟡 `GHSA-652x-xj99-gmcc` via `requests` (MEDIUM) — Exposure of Sensitive Information to an Unauthorized Actor in Requests
  - 🟡 `GHSA-9hjg-9r4m-mvj7` via `requests` (MEDIUM) — Requests vulnerable to .netrc credentials leak via malicious URLs
  - 🟡 `GHSA-9wx4-h78v-vm56` via `requests` (MEDIUM) — Requests `Session` object does not verify requests after making first request wi
  - 🟡 `GHSA-mf9w-mj56-hr94` via `python-dotenv` (MEDIUM) — python-dotenv: Symlink following in set_key allows arbitrary file overwrite via
  - 🟠 `GHSA-3ww4-gg4f-jr7f` via `cryptography` (HIGH) — Python Cryptography package vulnerable to Bleichenbacher timing oracle attack
  - 🟡 `GHSA-9v9h-cgj8-h64p` via `cryptography` (MEDIUM) — Null pointer dereference in PKCS12 parsing
  - 🟠 `GHSA-hggm-jpg3-v476` via `cryptography` (HIGH) — RSA decryption vulnerable to Bleichenbacher timing vulnerability
  - 🟠 `GHSA-752w-5fwx-jx9f` via `pyjwt` (HIGH) — PyJWT accepts unknown `crit` header extensions
  - 🟠 `GHSA-r9jw-mwhq-wp62` via `pyjwt` (HIGH) — PyJWT vulnerable to key confusion attacks
  - ⚪ `PYSEC-2017-24` via `pyjwt` (UNKNOWN) —

---

## What This Means for Teams Running MCP Servers

**For platform teams:** The findings show that MCP servers carry the same
supply-chain risk as any other Node/Python service — with one additional
dimension: an autonomous agent calling a vulnerable MCP server can be
manipulated into exfiltrating data, escalating privileges, or executing
arbitrary code through a compromised tool response, with no human reviewing
the interaction in real time.

**For security teams:** Standard SCA tools will flag these CVEs at the
package level.  The gap is at the *runtime layer*: knowing which agents
can reach which servers, and enforcing policy on every tool call, not just
at deploy time.

**For MCP server authors:** The most actionable step is keeping
dependencies pinned and running `npm audit` / `pip-audit` in CI.
The second most actionable step is scoping your server's tool list to
the minimum required — reducing the blast radius if a dependency is
compromised.

---

## About This Report

Generated by [Navil](https://navil.ai) — production governance for AI agents.
Data from [OSV.dev](https://osv.dev) and [SAFE-MCP](https://safe-mcp.org).
Scan completed May 02, 2026 UTC.

Report data available as structured JSON.
Methodology and raw data available on request.
