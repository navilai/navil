"""MCP Canary Kit — standalone honeypot for MCP threat detection.

Extracts the honeypot server into a lightweight, self-contained package
with minimal dependencies.  Can be run standalone or embedded in
existing infrastructure.

Usage::

    # CLI
    python -m navil.canary --profile dev-tools --port 8080

    # Programmatic
    from navil.canary.kit import CanaryKit
    kit = CanaryKit(profile="dev_tools", port=8080)
    kit.run()
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from typing import Any

logger = logging.getLogger(__name__)

# Profile name mapping (CLI uses hyphens, modules use underscores)
_PROFILE_MAP = {
    "dev-tools": "dev_tools",
    "dev_tools": "dev_tools",
    "cloud-creds": "cloud_creds",
    "cloud_creds": "cloud_creds",
    "db-admin": "db_admin",
    "db_admin": "db_admin",
}

AVAILABLE_PROFILES = ["dev-tools", "cloud-creds", "db-admin"]


class CanaryKit:
    """Standalone MCP canary honeypot.

    Runs a honeypot MCP server with built-in logging and optional
    contribution of anonymized data back to the Navil threat intel pool.

    Args:
        profile: Honeypot profile name (dev-tools, cloud-creds, db-admin).
        port: Port to listen on.
        host: Bind address.
        contribute: If True, send anonymized detections to Navil cloud.
        log_file: Optional path to write JSON interaction logs.
    """

    def __init__(
        self,
        profile: str = "dev_tools",
        port: int = 8080,
        host: str = "0.0.0.0",
        contribute: bool = False,
        log_file: str | None = None,
    ) -> None:
        self.profile = _PROFILE_MAP.get(profile, profile)
        self.port = port
        self.host = host
        self.contribute = contribute
        self.log_file = log_file
        self._server: Any = None
        self._collector: Any = None

    def run(self) -> None:
        """Start the canary honeypot server (blocking)."""
        from navil.honeypot.collector import HoneypotCollector
        from navil.honeypot.server import HoneypotMCPServer

        self._collector = HoneypotCollector()
        self._server = HoneypotMCPServer(
            profile=self.profile,
            host=self.host,
            port=self.port,
            collector=self._collector,
        )

        # Handle graceful shutdown
        def _shutdown(sig: int, frame: Any) -> None:
            logger.info("Shutting down canary...")
            self._on_shutdown()
            sys.exit(0)

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        print(f"MCP Canary started on {self.host}:{self.port}")
        print(f"Profile: {self.profile}")
        print(f"Tools exposed: {len(self._server.tool_list)}")
        if self.contribute:
            print("Contribution mode: ON (anonymized data will be sent to Navil cloud)")
        print("Press Ctrl+C to stop.\n")

        self._server.start()

    def run_background(self) -> None:
        """Start the canary honeypot server in background."""
        from navil.honeypot.collector import HoneypotCollector
        from navil.honeypot.server import HoneypotMCPServer

        self._collector = HoneypotCollector()
        self._server = HoneypotMCPServer(
            profile=self.profile,
            host=self.host,
            port=self.port,
            collector=self._collector,
        )
        self._server.start_background()

    def stop(self) -> None:
        """Stop the canary and flush logs."""
        self._on_shutdown()
        if self._server:
            self._server.stop()

    def _on_shutdown(self) -> None:
        """Flush logs and optionally contribute on shutdown."""
        if self._collector and self.log_file:
            try:
                with open(self.log_file, "w") as fh:
                    fh.write(self._collector.export_json())
                logger.info("Interaction log written to %s", self.log_file)
            except Exception:
                logger.error("Failed to write log file", exc_info=True)

        if self._collector:
            count = self._collector.current_count
            logger.info("Canary recorded %d interactions", count)

    @property
    def records(self) -> list[dict[str, Any]]:
        """Get all recorded interactions."""
        if self._collector:
            return self._collector.records
        return []

    @property
    def server(self) -> Any:
        return self._server


def main() -> int:
    """CLI entry point for the canary kit."""
    parser = argparse.ArgumentParser(
        prog="navil.canary",
        description="MCP Canary Kit - Standalone honeypot for MCP threat detection",
    )
    parser.add_argument(
        "--profile",
        choices=AVAILABLE_PROFILES,
        default="dev-tools",
        help="Honeypot profile to use (default: dev-tools)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--contribute",
        action="store_true",
        help="Send anonymized detection data to Navil threat intel pool",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Path to write JSON interaction log on shutdown",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    kit = CanaryKit(
        profile=args.profile,
        port=args.port,
        host=args.host,
        contribute=args.contribute,
        log_file=args.log_file,
    )
    kit.run()
    return 0
