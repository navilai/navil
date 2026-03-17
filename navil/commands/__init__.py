"""
Navil CLI command modules.

Each module in this package exports a ``register(subparsers, cli_class)``
function that adds its argparse subcommands to the top-level parser.
Command modules are auto-discovered by :func:`navil.cli.main`.
"""
