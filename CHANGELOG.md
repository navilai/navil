# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-03-16

### Added

- **Identity system**: OIDC token exchange, delegation chains with scope narrowing, cascade revocation via Redis Lua script, max depth cap (10), human_context on all credentials
- **Rust proxy restructured**: split into `auth.rs`, `proxy.rs`, `telemetry.rs` modules; JWT validation with HMAC fallback; SSE streaming; delegation chain verification via Redis MGET; `X-Human-Identity`/`X-Human-Email`/`X-Delegation-Depth` header injection
- **Blocklist engine**: pattern matcher with Redis hot-load, file-based fallback, Finding-based output, confidence-based alert generation, auto-updater with tier-gated distribution
- **Honeypot MCP servers**: 3 profiles (dev-tools, cloud-creds, database-admin) on isolated Docker bridge, signature extractor with candidate pattern generation
- **MCP Canary kit**: open-source honeypot packaging with standalone deployment
- **SAFE-MCP scenario expander**: 30+ cataloged public attacks, parameterized generator producing 200+ variants, `navil seed-database --full` with 50+ scenarios
- **Static analysis engine**: tree-sitter-based source code scanning for 10 vulnerability classes (SQL injection, command injection, path traversal, secrets, deserialization, etc.)
- **State of MCP Security Report (v3)**: scan of 1,000+ public MCP servers from awesome-mcp-servers, npm, and PyPI
- **Landing page** (`index.html`): developer-facing with hero stats, feature grid, CI/CD quickstart, pricing
- **E2E testing pipeline**: `seed_enterprise_drill.py` (database provisioning) + `enterprise_live_fire.py` (3 Virtual MCPs, 50 normal calls + 17 attacks each)
- **Cloud API routes**: analytics, billing, webhooks management, community threat intel
- **Dashboard pages**: Analytics, Billing, ThreatRules, Webhooks (cloud management)
- **Honeypot Docker Compose** (`docker-compose.honeypot.yaml`): production deployment with isolated networking, read-only filesystems, resource limits
- **Proxy interface spec** (`docs/proxy-interface-spec.md`): shared contract for Python and Rust proxies
- **Plugin-based CLI**: commands loaded from `navil/commands/*.py` with auto-discovery
- **Shared Finding type** (`navil/types.py`): unified output for scanner, blocklist, honeypot, and static analysis
- **Credential Redis storage**: migrated from in-memory dict to Redis hashes with fallback

### Changed

- **Dashboard visual redesign**: dark theme (`#0a0e17` bg, `#00e5c8` teal accent), Inter + JetBrains Mono typography, redesigned all 10 existing pages and shared components
- **Anomaly detector thresholds tuned**: reconnaissance (5→20), lateral movement (3→8), C2 beaconing (5→10 calls, 4→9 intervals), defense evasion arguments (5KB→50KB), persistence interval cap (60s)
- Updated README pricing to match live navil.ai tiers (Team $249)
- Consolidated detector count references to 12 across all documentation

### Fixed

- Resolved CI failures: lint, format, mypy, and pydantic import issues
- Fixed timing side-channel in token comparison (constant-time `hmac.compare_digest`)
- Fixed `_InMemoryStore` missing `set()`/`get()` methods for delegation chain tests
- Resolved 11 adversarial security findings and 3 robustness gaps
- Fixed asyncpg naive/aware datetime mismatch in E2E scripts

## [0.2.0] - 2026-03-15

### Added

- **SARIF v2.1.0 output**: `navil scan --format sarif` produces SARIF documents for GitHub Code Scanning, Azure DevOps, and other SARIF-compatible tools (`navil/sarif.py`)
- **Scan output formats**: `--format` flag on `navil scan` supports `text` (default), `sarif`, and `json`; `--output` flag writes to file instead of stdout
- **GitHub Action**: composite action at `.github/actions/navil-scan/` for automated MCP config scanning in CI with SARIF upload to GitHub Security tab
- **Registry crawler**: `navil crawl registries` discovers MCP servers from awesome-mcp-servers (GitHub), npm, and PyPI with per-domain rate limiting and exponential back-off (`navil/crawler/`)
- **Batch scanner**: `navil scan-batch <dir>` bulk-scans crawl results with 30-second per-scan timeout and JSONL streaming output (`navil/crawler/batch_scanner.py`)
- **State of MCP report**: `navil report-mcp <jsonl>` generates a Markdown security report aggregating batch scan results with severity breakdowns, top vulnerability types, and score distribution (`navil/report/state_of_mcp.py`)
- Tests for SARIF serializer, registry crawler (mocked HTTP), batch scanner (timeout handling, JSONL streaming), and report generator (empty data, division-by-zero guards)
- CI/CD integration docs in README (GitHub Actions, GitLab CI, Security tab viewing)

## [0.1.0] - 2026-03-01

### Added

- Configuration vulnerability scanner with 7 detection methods and 0-100 scoring
- JWT-based credential lifecycle manager (issue, rotate, revoke) with audit logging
- YAML-driven runtime policy engine with rate limiting and data-sensitivity gates
- Statistical behavioral anomaly detector with 12 detection methods (rug-pull, exfiltration, rate spike, privilege escalation, reconnaissance, persistence, defense evasion, lateral movement, C2 beaconing, supply chain)
- Real-time MCP security proxy with JSON-RPC interception and live traffic monitoring
- Penetration testing engine with 11 SAFE-MCP attack simulations (reconnaissance, persistence, defense evasion, lateral movement, C2 beaconing, supply chain, rug pull, data exfiltration, privilege escalation, rate spike, policy bypass)
- LLM-powered analysis: config analysis, anomaly explanation, policy generation, self-healing (Anthropic, OpenAI, Gemini, Ollama)
- Cloud dashboard (React/Vite) with fleet monitoring, alerting, gateway management, and pentest UI
- Adaptive behavioral baselines with pattern learning and feedback loop
- ML-based anomaly detection with Isolation Forest and clustering (optional `[ml]` extra)
- CLI with `scan`, `credential`, `policy`, `monitor`, `report`, `pentest`, `proxy`, `cloud`, `llm`, `adaptive`, and `feedback` commands
- CLI LLM commands support environment variable fallback for API keys (BYOK)
- Sample MCP server configurations (vulnerable and secure)
- Default security policy template
- Comprehensive test suite (198 tests)
- GitHub Actions CI (lint, type-check, test on Python 3.10-3.12, dashboard build)
- Pre-commit hooks configuration
- Apache 2.0 license

### Changed

- Production hardening: fetch timeouts, stable React list keys, error state handling, accessibility labels
