"""MCP Canary Kit — standalone, open-source-ready honeypot package.

A lightweight MCP honeypot that can be deployed independently:

    python -m navil.canary --profile dev-tools --port 8080

Minimal dependencies: just the MCP server + logging, no ML/Redis required.
Optionally contributes anonymized detection data back to the Navil
threat intelligence pool.

Modules:
    server   — Self-contained canary MCP server (extractable, minimal deps)
    config   — Configuration for canary deployment and profiles
    reporter — Anonymized reporting back to Navil cloud
    kit      — High-level orchestrator (wraps server + reporter)
"""

from navil.canary.config import CanaryConfig
from navil.canary.kit import CanaryKit
from navil.canary.reporter import CanaryReporter
from navil.canary.server import CanaryServer

__all__ = ["CanaryConfig", "CanaryKit", "CanaryReporter", "CanaryServer"]
