"""Auto-update the local blocklist from Navil Cloud.

On every telemetry sync cycle, the proxy checks if there are new blocklist
patterns available. If the cloud has a newer version, it downloads the delta
and merges it into the local blocklist.

Flow:
1. During telemetry sync, include current blocklist version in request headers
2. Cloud responds with new patterns (if any) in the sync response
3. Local blocklist is updated atomically (write to temp, rename)
4. Proxy reloads the blocklist without restart

Configuration (``~/.navil/config.yaml``)::

    blocklist:
      auto_update: true
      update_url: https://navil-cloud-api.onrender.com/v1/threat-intel/blocklist
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_UPDATE_URL = "https://navil-cloud-api.onrender.com/v1/threat-intel/blocklist"


def get_blocklist_config() -> dict[str, Any]:
    """Load blocklist configuration from ``~/.navil/config.yaml``.

    Returns a dict with keys:
        auto_update (bool): Whether auto-updates are enabled. Default True.
        update_url (str): Cloud endpoint for blocklist updates.
    """
    try:
        from navil.commands.init import load_config

        config = load_config()
    except Exception:
        config = {}

    bl_config = config.get("blocklist", {})
    return {
        "auto_update": bl_config.get("auto_update", True),
        "update_url": bl_config.get("update_url", _DEFAULT_UPDATE_URL),
    }


def get_local_version(blocklist_path: str | None = None) -> int:
    """Read the version number from a local blocklist JSON file.

    Args:
        blocklist_path: Path to the blocklist JSON. If None, uses the
            default ``blocklist_v1.json`` shipped with Navil.

    Returns:
        The integer version, or 0 if the file does not exist or is invalid.
    """
    if blocklist_path is None:
        blocklist_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data",
            "blocklist_v1.json",
        )

    try:
        with open(blocklist_path) as fh:
            data = json.load(fh)
        return int(data.get("version", 0))
    except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
        return 0


def check_for_updates(
    api_url: str,
    current_version: int,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> list[dict[str, Any]] | None:
    """Check the cloud for newer blocklist patterns.

    Calls ``GET <api_url>?since_version=<current_version>``.

    Args:
        api_url: Cloud blocklist endpoint URL.
        current_version: The local blocklist version to compare against.
        headers: Optional HTTP headers (e.g. Authorization).
        timeout: Request timeout in seconds.

    Returns:
        A list of new pattern dicts if the cloud has updates, or None if
        the blocklist is already up to date (or on network error).
    """
    import httpx

    params = {"since_version": str(current_version)}
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    try:
        resp = httpx.get(api_url, params=params, headers=req_headers, timeout=timeout)

        if resp.status_code == 304:
            logger.debug("Blocklist up to date (v%d)", current_version)
            return None

        if resp.status_code >= 400:
            logger.warning("Blocklist update check failed: HTTP %d", resp.status_code)
            return None

        data = resp.json()
        patterns = data.get("patterns", [])
        if not patterns:
            return None

        new_version = data.get("version", current_version)
        logger.info(
            "Cloud has blocklist v%d (local v%d), %d new patterns",
            new_version,
            current_version,
            len(patterns),
        )
        return patterns

    except ImportError:
        logger.warning("httpx not installed, cannot check for blocklist updates")
        return None
    except Exception as exc:
        logger.debug("Blocklist update check failed: %s", exc)
        return None


def merge_patterns(
    existing_blocklist_path: str,
    new_patterns: list[dict[str, Any]],
) -> dict[str, Any]:
    """Merge new patterns into the local blocklist file atomically.

    Reads the existing file, adds new patterns (deduplicating by
    ``pattern_id`` and keeping the higher-confidence entry on conflict),
    then writes to a temp file and renames over the original.

    Args:
        existing_blocklist_path: Path to the local blocklist JSON file.
        new_patterns: List of pattern dicts from the cloud.

    Returns:
        Summary dict with keys: added, updated, total, new_version.
    """
    # Read existing
    try:
        with open(existing_blocklist_path) as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {"version": 0, "patterns": [], "description": "Navil blocklist"}

    existing_patterns = data.get("patterns", [])
    current_version = int(data.get("version", 0))

    # Index existing patterns by pattern_id
    by_id: dict[str, dict[str, Any]] = {}
    for p in existing_patterns:
        pid = p.get("pattern_id", "")
        if pid:
            by_id[pid] = p

    added = 0
    updated = 0
    for p in new_patterns:
        pid = p.get("pattern_id", "")
        if not pid:
            continue
        existing = by_id.get(pid)
        if existing is None:
            by_id[pid] = p
            added += 1
        elif float(p.get("confidence", 0)) > float(existing.get("confidence", 0)):
            by_id[pid] = p
            updated += 1

    new_version = current_version + 1
    merged_data = {
        "version": new_version,
        "description": data.get("description", "Navil blocklist"),
        "created_at": data.get("created_at", ""),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "patterns": list(by_id.values()),
    }

    # Atomic write: write to temp file, then rename
    parent_dir = os.path.dirname(os.path.abspath(existing_blocklist_path))
    fd, tmp_path = tempfile.mkstemp(dir=parent_dir, suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w") as tmp_fh:
            json.dump(merged_data, tmp_fh, indent=2)
        os.replace(tmp_path, existing_blocklist_path)
    except Exception:
        # Clean up temp file on failure
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

    logger.info(
        "Blocklist merged: added=%d, updated=%d, total=%d, version=%d",
        added,
        updated,
        len(by_id),
        new_version,
    )

    return {
        "added": added,
        "updated": updated,
        "total": len(by_id),
        "new_version": new_version,
    }


async def check_for_updates_async(
    api_url: str,
    current_version: int,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> list[dict[str, Any]] | None:
    """Async version of :func:`check_for_updates` for use in the sync loop.

    Args:
        api_url: Cloud blocklist endpoint URL.
        current_version: The local blocklist version to compare against.
        headers: Optional HTTP headers.
        timeout: Request timeout in seconds.

    Returns:
        A list of new pattern dicts, or None.
    """
    import httpx

    params = {"since_version": str(current_version)}
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(api_url, params=params, headers=req_headers)

        if resp.status_code == 304:
            logger.debug("Blocklist up to date (v%d)", current_version)
            return None

        if resp.status_code >= 400:
            logger.warning("Blocklist update check failed: HTTP %d", resp.status_code)
            return None

        data = resp.json()
        patterns = data.get("patterns", [])
        if not patterns:
            return None

        new_version = data.get("version", current_version)
        logger.info(
            "Cloud has blocklist v%d (local v%d), %d new patterns",
            new_version,
            current_version,
            len(patterns),
        )
        return patterns

    except ImportError:
        logger.warning("httpx not installed, cannot check for blocklist updates")
        return None
    except Exception as exc:
        logger.debug("Blocklist update check failed: %s", exc)
        return None
