"""Optional dependency availability checks with graceful degradation."""

from __future__ import annotations

import importlib


def require_ml(feature_name: str = "ML features") -> None:
    """Raise ImportError with install instructions if scikit-learn is unavailable."""
    try:
        importlib.import_module("sklearn")
    except ImportError:
        raise ImportError(
            f"{feature_name} requires scikit-learn. Install with: pip install navil[ml]"
        ) from None


def has_ml() -> bool:
    """Check if ML dependencies are available."""
    try:
        require_ml()
        return True
    except ImportError:
        return False
