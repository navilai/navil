"""Tests for the batch scanner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import orjson
import pytest

from navil.crawler.batch_scanner import BatchStats, _build_config, scan_batch


# ── BatchStats ────────────────────────────────────────────────


class TestBatchStats:
    """Tests for the BatchStats dataclass."""

    def test_defaults(self) -> None:
        stats = BatchStats()
        assert stats.total == 0
        assert stats.successful == 0
        assert stats.failed == 0
        assert stats.timed_out == 0

    def test_to_dict(self) -> None:
        stats = BatchStats(total=10, successful=8, failed=1, timed_out=1)
        d = stats.to_dict()
        assert d == {"total": 10, "successful": 8, "failed": 1, "timed_out": 1}


# ── Config builder ────────────────────────────────────────────


class TestBuildConfig:
    """Tests for _build_config."""

    def test_uses_config_example_if_present(self) -> None:
        entry = {
            "server_name": "test",
            "config_example": {"mcpServers": {"test": {"command": "npx"}}},
        }
        config = _build_config(entry)
        assert config == entry["config_example"]

    def test_builds_generic_config_without_example(self) -> None:
        entry = {
            "server_name": "myserver",
            "url": "https://example.com/myserver",
        }
        config = _build_config(entry)
        assert config["server"]["name"] == "myserver"
        assert config["server"]["source"] == "https://example.com/myserver"


# ── Batch scanner ─────────────────────────────────────────────


@pytest.fixture
def crawl_dir(tmp_path: Path) -> Path:
    """Create a directory with sample crawl result files."""
    d = tmp_path / "crawl_results"
    d.mkdir()
    return d


def _write_crawl_entry(d: Path, idx: int, entry: dict[str, Any]) -> None:
    """Write a crawl entry JSON file."""
    path = d / f"entry_{idx:04d}.json"
    path.write_bytes(orjson.dumps(entry))


class TestScanBatch:
    """Tests for the scan_batch function."""

    def test_empty_directory(self, crawl_dir: Path, tmp_path: Path) -> None:
        """Empty input directory should produce empty output."""
        output = tmp_path / "results.jsonl"
        stats = scan_batch(crawl_dir, output)
        assert stats.total == 0
        assert stats.successful == 0
        assert output.read_text() == ""

    def test_single_entry_successful(self, crawl_dir: Path, tmp_path: Path) -> None:
        """A valid config should produce a successful scan result."""
        _write_crawl_entry(crawl_dir, 0, {
            "server_name": "test-server",
            "source": "npm",
            "url": "https://example.com",
            "config_example": {
                "server": {"protocol": "https", "verified": True},
                "authentication": {"type": "mTLS"},
                "tools": [],
            },
        })
        output = tmp_path / "results.jsonl"
        stats = scan_batch(crawl_dir, output)

        assert stats.total == 1
        assert stats.successful == 1
        assert stats.failed == 0

        # Check JSONL output
        lines = output.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["status"] == "success"
        assert record["server_name"] == "test-server"
        assert "scan" in record
        assert "security_score" in record["scan"]

    def test_multiple_entries(self, crawl_dir: Path, tmp_path: Path) -> None:
        """Multiple entries should all be scanned."""
        for i in range(5):
            _write_crawl_entry(crawl_dir, i, {
                "server_name": f"server-{i}",
                "source": "npm",
                "url": f"https://example.com/{i}",
                "config_example": {
                    "server": {"protocol": "https"},
                    "tools": [],
                },
            })
        output = tmp_path / "results.jsonl"
        stats = scan_batch(crawl_dir, output)

        assert stats.total == 5
        assert stats.successful == 5

        lines = output.read_text().strip().split("\n")
        assert len(lines) == 5

    def test_jsonl_streaming(self, crawl_dir: Path, tmp_path: Path) -> None:
        """Each line in JSONL should be a valid JSON object."""
        for i in range(3):
            _write_crawl_entry(crawl_dir, i, {
                "server_name": f"server-{i}",
                "source": "pypi",
                "url": f"https://pypi.org/project/server-{i}/",
            })
        output = tmp_path / "results.jsonl"
        scan_batch(crawl_dir, output)

        for line in output.read_text().strip().split("\n"):
            record = json.loads(line)
            assert "server_name" in record
            assert "status" in record

    def test_findings_serialized_as_dicts(self, crawl_dir: Path, tmp_path: Path) -> None:
        """Findings in JSONL should be plain dicts, not dataclass instances."""
        _write_crawl_entry(crawl_dir, 0, {
            "server_name": "vuln-server",
            "source": "npm",
            "url": "https://example.com",
            "config_example": {
                "server": {"protocol": "http"},
                "tools": [{"name": "tool", "permissions": ["*"]}],
            },
        })
        output = tmp_path / "results.jsonl"
        scan_batch(crawl_dir, output)

        line = output.read_text().strip()
        record = json.loads(line)
        findings = record["scan"]["findings"]
        assert len(findings) > 0
        for f in findings:
            assert isinstance(f, dict)
            assert "id" in f

    def test_malformed_crawl_file_skipped(self, crawl_dir: Path, tmp_path: Path) -> None:
        """Malformed JSON files should be skipped, not crash."""
        (crawl_dir / "bad.json").write_text("not json!")
        _write_crawl_entry(crawl_dir, 0, {
            "server_name": "good-server",
            "source": "npm",
            "url": "https://example.com",
        })
        output = tmp_path / "results.jsonl"
        stats = scan_batch(crawl_dir, output)

        # The malformed file is skipped during loading, so total only counts loaded entries
        assert stats.successful >= 1

    def test_output_directory_created(self, crawl_dir: Path, tmp_path: Path) -> None:
        """Output file parent directory should be created if it doesn't exist."""
        _write_crawl_entry(crawl_dir, 0, {
            "server_name": "test",
            "source": "npm",
            "url": "https://example.com",
        })
        output = tmp_path / "sub" / "dir" / "results.jsonl"
        stats = scan_batch(crawl_dir, output)
        assert output.exists()

    def test_no_config_example_uses_generic(self, crawl_dir: Path, tmp_path: Path) -> None:
        """Entry without config_example should use the generic config builder."""
        _write_crawl_entry(crawl_dir, 0, {
            "server_name": "generic-server",
            "source": "awesome-mcp-servers",
            "url": "https://github.com/example/server",
        })
        output = tmp_path / "results.jsonl"
        stats = scan_batch(crawl_dir, output)
        assert stats.total == 1
        assert stats.successful == 1
