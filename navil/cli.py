"""
Navil CLI

Command-line interface for MCP security scanning, credential management, policy evaluation,
and anomaly detection.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import pkgutil
import sys

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.credential_manager import CredentialManager
from navil.policy_engine import PolicyEngine
from navil.scanner import MCPSecurityScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class MCPGuardianCLI:
    """CLI interface for Navil (MCP Guardian)."""

    def __init__(self) -> None:
        """Initialize CLI."""
        self.scanner = MCPSecurityScanner()
        self.credential_manager = CredentialManager()
        self.policy_engine = PolicyEngine()
        self.anomaly_detector = BehavioralAnomalyDetector()


def _discover_commands(subparsers: argparse._SubParsersAction) -> None:
    """Auto-discover and register all command modules from navil.commands."""
    import navil.commands as commands_pkg

    for _finder, module_name, _ispkg in pkgutil.iter_modules(commands_pkg.__path__):
        module = importlib.import_module(f"navil.commands.{module_name}")
        if hasattr(module, "register"):
            module.register(subparsers, MCPGuardianCLI)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Navil - Supply Chain Security for MCP Servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  navil scan config.json
  navil credential issue --agent my-agent --scope "read:tools" --ttl 3600
  navil credential revoke --token-id cred_abc123
  navil policy check --tool file_system --agent my-agent --action read
  navil monitor start
  navil report
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Auto-discover and register all command modules
    _discover_commands(subparsers)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    cli = MCPGuardianCLI()

    try:
        if hasattr(args, "func"):
            return int(args.func(cli, args))
        else:
            parser.print_help()
            return 1
    except Exception as e:
        logger.error(f"Error: {e!s}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
