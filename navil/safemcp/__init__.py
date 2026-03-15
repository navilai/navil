"""SAFE-MCP parameterized scenario generator.

Reads attack patterns from public_attacks.yaml and generates multiple
parameterized variants per attack for comprehensive anomaly detector testing.
"""

from navil.safemcp.generator import AttackVariantGenerator, generate_all_variants

__all__ = ["AttackVariantGenerator", "generate_all_variants"]
