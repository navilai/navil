"""Navil Honeypot Framework -- decoy MCP servers that log all interactions.

Exposes tempting MCP tools (dev tools, cloud creds, db admin) to lure
and observe malicious agents.  All interactions are logged to a collector
for pattern extraction and blocklist generation.
"""

from navil.honeypot.server import HoneypotMCPServer

__all__ = ["HoneypotMCPServer"]
