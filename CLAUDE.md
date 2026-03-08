# Navil Project Guidelines for Claude Code
## Project Overview
Navil is an open-source security gateway for the Model Context Protocol (MCP). It intercepts JSON-RPC traffic between AI Agents and MCP servers to provide real-time intrusion prevention, rate-limiting, and anomaly detection.
Our core objective is ultra-low latency. We are transitioning the architecture to an "Open-Core SaaS" model with a strictly separated Control Plane (management) and Data Plane (real-time routing).
## Architectural Directives (CRITICAL)
1. **The Hot Path (Real-time Proxy):** The code in `navil/proxy.py` MUST execute in under 10ms.
   - Never instantiate new HTTP clients per request (use a global `httpx.AsyncClient` pool).
   - Use `orjson` for all JSON serialization/deserialization.
   - Never perform synchronous database writes, LLM API calls, or complex mathematical calculations in the hot path.
   - Security checks in the hot path must be $O(1)$ memory lookups against pre-computed baselines.
2. **The Cold Path (Background):** - Heavy anomaly detection (ML/Stats), telemetry syncing, and LLM features must be handled asynchronously using FastAPI `BackgroundTasks`.
3. **Zero-Knowledge Telemetry:** Any telemetry sent to Navil Cloud must be strictly sanitized. Never transmit raw prompt text, file contents, or JSON-RPC `params`.
## Tech Stack & Style
- Python 3.10+ with strict type hints (`mypy` compliant).
- FastAPI, `httpx`, `orjson`, SQLAlchemy.
- Code must be clean, modular, and prioritize memory safety (no unbounded lists).
## Commands
- Run tests: `pytest`
- Run linting: `ruff check .`
- Type checking: `mypy navil`
