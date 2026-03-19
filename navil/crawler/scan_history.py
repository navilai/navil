"""Scan history store — SQLite-backed storage for historical scan results.

Stores scan runs and per-server results so that trend analysis can track
how MCP server security changes over time.

Database location: ``~/.navil/scan_history.db``
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".navil" / "scan_history.db"

# ── Data types ────────────────────────────────────────────────


@dataclass
class ScanRecord:
    """Metadata for a single scan run."""

    scan_id: int
    timestamp: str
    total_servers: int
    successful: int
    failed: int
    timed_out: int
    avg_score: float
    min_score: int
    max_score: int
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServerResult:
    """Per-server result within a scan run."""

    scan_id: int
    server_name: str
    source: str
    url: str
    status: str
    score: int
    vulnerabilities_json: str = "[]"
    findings_json: str = "[]"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["vulnerabilities"] = json.loads(self.vulnerabilities_json)
        d["findings"] = json.loads(self.findings_json)
        return d


# ── Store ─────────────────────────────────────────────────────


class ScanHistoryStore:
    """SQLite-backed store for historical scan results."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection with row_factory set to sqlite3.Row."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_servers INTEGER NOT NULL DEFAULT 0,
                    successful INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    timed_out INTEGER NOT NULL DEFAULT 0,
                    avg_score REAL NOT NULL DEFAULT 0.0,
                    min_score INTEGER NOT NULL DEFAULT 0,
                    max_score INTEGER NOT NULL DEFAULT 0,
                    source_file TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS server_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    server_name TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    url TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'unknown',
                    score INTEGER NOT NULL DEFAULT 0,
                    vulnerabilities_json TEXT NOT NULL DEFAULT '[]',
                    findings_json TEXT NOT NULL DEFAULT '[]',
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_server_results_scan_id
                ON server_results(scan_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_server_results_server_name
                ON server_results(server_name)
                """
            )

    # ── Write ─────────────────────────────────────────────────

    def store_scan_results(
        self,
        records: list[dict[str, Any]],
        *,
        source_file: str = "",
    ) -> int:
        """Store results from a batch scan run.

        Args:
            records: List of result dicts (as produced by batch_scanner JSONL).
            source_file: Path of the JSONL file, for reference.

        Returns:
            The scan_id of the newly created scan record.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Compute aggregate stats
        total = len(records)
        successful_recs = [r for r in records if r.get("status") == "success"]
        failed_count = sum(1 for r in records if r.get("status") == "error")
        timed_out_count = sum(1 for r in records if r.get("status") == "timeout")

        scores: list[int] = []
        for r in successful_recs:
            scan = r.get("scan", {})
            score = scan.get("security_score", 0)
            scores.append(int(score))

        avg_score = sum(scores) / len(scores) if scores else 0.0
        min_score = min(scores) if scores else 0
        max_score = max(scores) if scores else 0

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    timestamp, total_servers, successful, failed, timed_out,
                    avg_score, min_score, max_score, source_file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    total,
                    len(successful_recs),
                    failed_count,
                    timed_out_count,
                    avg_score,
                    min_score,
                    max_score,
                    source_file,
                ),
            )
            scan_id = cursor.lastrowid
            assert scan_id is not None

            # Insert per-server results
            for rec in records:
                scan_data = rec.get("scan", {})
                score = (
                    int(scan_data.get("security_score", 0)) if rec.get("status") == "success" else 0
                )
                vulns = scan_data.get("vulnerabilities", [])
                findings = scan_data.get("findings", [])

                conn.execute(
                    """
                    INSERT INTO server_results (
                        scan_id, server_name, source, url, status,
                        score, vulnerabilities_json, findings_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        rec.get("server_name", "unknown"),
                        rec.get("source", ""),
                        rec.get("url", ""),
                        rec.get("status", "unknown"),
                        score,
                        json.dumps(vulns),
                        json.dumps(findings),
                    ),
                )

        logger.info(
            "Stored scan %d: %d servers (%d successful)", scan_id, total, len(successful_recs)
        )
        return scan_id

    # ── Read ──────────────────────────────────────────────────

    def get_scan_history(self, limit: int = 0) -> list[ScanRecord]:
        """Return scan history, most recent first.

        Args:
            limit: Max number of scans to return (0 = all).
        """
        query = "SELECT * FROM scans ORDER BY scan_id DESC"
        params: tuple[Any, ...] = ()
        if limit > 0:
            query += " LIMIT ?"
            params = (limit,)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            ScanRecord(
                scan_id=row["scan_id"],
                timestamp=row["timestamp"],
                total_servers=row["total_servers"],
                successful=row["successful"],
                failed=row["failed"],
                timed_out=row["timed_out"],
                avg_score=row["avg_score"],
                min_score=row["min_score"],
                max_score=row["max_score"],
                source_file=row["source_file"],
            )
            for row in rows
        ]

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        """Return a single scan record by ID."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()

        if row is None:
            return None

        return ScanRecord(
            scan_id=row["scan_id"],
            timestamp=row["timestamp"],
            total_servers=row["total_servers"],
            successful=row["successful"],
            failed=row["failed"],
            timed_out=row["timed_out"],
            avg_score=row["avg_score"],
            min_score=row["min_score"],
            max_score=row["max_score"],
            source_file=row["source_file"],
        )

    def get_scan_results(self, scan_id: int) -> list[ServerResult]:
        """Return all server results for a given scan."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM server_results WHERE scan_id = ? ORDER BY server_name",
                (scan_id,),
            ).fetchall()

        return [
            ServerResult(
                scan_id=row["scan_id"],
                server_name=row["server_name"],
                source=row["source"],
                url=row["url"],
                status=row["status"],
                score=row["score"],
                vulnerabilities_json=row["vulnerabilities_json"],
                findings_json=row["findings_json"],
            )
            for row in rows
        ]

    def get_server_trend(self, server_name: str, limit: int = 0) -> list[dict[str, Any]]:
        """Return score history for a specific server across scans.

        Returns list of dicts with scan_id, timestamp, score, status,
        vulnerabilities count, sorted chronologically (oldest first).
        """
        query = """
            SELECT sr.scan_id, s.timestamp, sr.score, sr.status,
                   sr.vulnerabilities_json
            FROM server_results sr
            JOIN scans s ON sr.scan_id = s.scan_id
            WHERE sr.server_name = ?
            ORDER BY s.scan_id ASC
        """
        params: list[Any] = [server_name]
        if limit > 0:
            query += " LIMIT ?"
            params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            vulns = json.loads(row["vulnerabilities_json"])
            results.append(
                {
                    "scan_id": row["scan_id"],
                    "timestamp": row["timestamp"],
                    "score": row["score"],
                    "status": row["status"],
                    "vulnerability_count": len(vulns),
                }
            )
        return results

    def compare_scans(self, scan_id_1: int, scan_id_2: int) -> dict[str, Any]:
        """Compare two scan runs and return a structured diff.

        Returns a dict with:
          - scan_1, scan_2: metadata for each scan
          - new_servers: servers in scan_2 but not in scan_1
          - removed_servers: servers in scan_1 but not in scan_2
          - score_changes: list of {server_name, old_score, new_score, delta}
          - new_vulnerabilities: vulnerabilities in scan_2 not in scan_1
          - fixed_vulnerabilities: vulnerabilities in scan_1 not in scan_2
          - summary: aggregate stats
        """
        scan_1 = self.get_scan(scan_id_1)
        scan_2 = self.get_scan(scan_id_2)

        if scan_1 is None or scan_2 is None:
            missing = scan_id_1 if scan_1 is None else scan_id_2
            return {"error": f"Scan {missing} not found"}

        results_1 = {r.server_name: r for r in self.get_scan_results(scan_id_1)}
        results_2 = {r.server_name: r for r in self.get_scan_results(scan_id_2)}

        names_1 = set(results_1.keys())
        names_2 = set(results_2.keys())

        new_servers = sorted(names_2 - names_1)
        removed_servers = sorted(names_1 - names_2)
        common_servers = names_1 & names_2

        # Score changes for common servers
        score_changes: list[dict[str, Any]] = []
        for name in sorted(common_servers):
            r1 = results_1[name]
            r2 = results_2[name]
            if r1.score != r2.score:
                score_changes.append(
                    {
                        "server_name": name,
                        "old_score": r1.score,
                        "new_score": r2.score,
                        "delta": r2.score - r1.score,
                    }
                )

        # Vulnerability diffs
        def _vuln_set(result: ServerResult) -> set[str]:
            vulns = json.loads(result.vulnerabilities_json)
            ids: set[str] = set()
            for v in vulns:
                if isinstance(v, dict):
                    ids.add(f"{result.server_name}:{v.get('id', 'UNKNOWN')}")
                else:
                    ids.add(f"{result.server_name}:{v}")
            return ids

        all_vulns_1: set[str] = set()
        all_vulns_2: set[str] = set()
        for name in common_servers:
            all_vulns_1 |= _vuln_set(results_1[name])
            all_vulns_2 |= _vuln_set(results_2[name])

        # Also include vulns from new/removed servers
        for name in names_1:
            all_vulns_1 |= _vuln_set(results_1[name])
        for name in names_2:
            all_vulns_2 |= _vuln_set(results_2[name])

        new_vulnerabilities = sorted(all_vulns_2 - all_vulns_1)
        fixed_vulnerabilities = sorted(all_vulns_1 - all_vulns_2)

        # Summary
        improved = sum(1 for sc in score_changes if sc["delta"] > 0)
        degraded = sum(1 for sc in score_changes if sc["delta"] < 0)

        return {
            "scan_1": scan_1.to_dict(),
            "scan_2": scan_2.to_dict(),
            "new_servers": new_servers,
            "removed_servers": removed_servers,
            "score_changes": score_changes,
            "new_vulnerabilities": new_vulnerabilities,
            "fixed_vulnerabilities": fixed_vulnerabilities,
            "summary": {
                "servers_added": len(new_servers),
                "servers_removed": len(removed_servers),
                "servers_improved": improved,
                "servers_degraded": degraded,
                "new_vulnerability_count": len(new_vulnerabilities),
                "fixed_vulnerability_count": len(fixed_vulnerabilities),
                "avg_score_change": scan_2.avg_score - scan_1.avg_score,
            },
        }

    def get_all_server_names(self) -> list[str]:
        """Return all unique server names seen across all scans."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT server_name FROM server_results ORDER BY server_name"
            ).fetchall()
        return [row["server_name"] for row in rows]

    def get_latest_scan_id(self) -> int | None:
        """Return the scan_id of the most recent scan, or None if no scans."""
        with self._connect() as conn:
            row = conn.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1").fetchone()
        return row["scan_id"] if row else None
