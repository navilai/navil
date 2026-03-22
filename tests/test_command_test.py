"""Tests for the navil test command."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from navil.commands.test import (
    _coverage_color,
    format_report,
    stratified_sample,
)


class TestStratifiedSampling:
    """Tests for stratified_sample."""

    def test_no_sampling_when_under_limit(self) -> None:
        items = {"a": [1, 2, 3], "b": [4, 5]}
        result = stratified_sample(items, 10)
        assert sum(len(v) for v in result.values()) == 5

    def test_proportional_allocation(self) -> None:
        items = {"a": list(range(60)), "b": list(range(40))}
        result = stratified_sample(items, 20)
        total = sum(len(v) for v in result.values())
        assert total == 20
        # Category 'a' should get roughly 60% of budget
        assert len(result["a"]) >= 10
        assert len(result["b"]) >= 1

    def test_single_category(self) -> None:
        items = {"only": list(range(100))}
        result = stratified_sample(items, 10)
        assert len(result["only"]) == 10

    def test_many_small_categories(self) -> None:
        items = {f"cat_{i}": [i] for i in range(30)}
        result = stratified_sample(items, 15)
        total = sum(len(v) for v in result.values())
        assert total == 15
        # Each category with items should get at least 0 or 1
        for cat in result:
            assert len(result[cat]) <= 1

    def test_limit_larger_than_total_returns_all(self) -> None:
        items = {"a": [1, 2], "b": [3]}
        result = stratified_sample(items, 100)
        assert sum(len(v) for v in result.values()) == 3

    def test_empty_input(self) -> None:
        result = stratified_sample({}, 10)
        assert result == {}


class TestCoverageReport:
    """Tests for format_report."""

    def test_basic_report_format(self) -> None:
        results = {
            "prompt_injection": {"total": 100, "blocked": 90, "missed": 10},
            "data_exfiltration": {"total": 50, "blocked": 25, "missed": 25},
        }
        report, exit_code = format_report(
            results=results,
            pool_name="default",
            total_vectors=200,
            total_variants=150,
            runtime_seconds=5.0,
            threshold=None,
            use_color=False,
        )
        assert "Navil Test Report" in report
        assert "Pool: default" in report
        assert "5.0s" in report
        assert "TOTAL" in report
        assert exit_code == 0

    def test_threshold_fail(self) -> None:
        results = {
            "prompt_injection": {"total": 100, "blocked": 70, "missed": 30},
        }
        report, exit_code = format_report(
            results=results,
            pool_name="default",
            total_vectors=200,
            total_variants=100,
            runtime_seconds=1.0,
            threshold=90,
            use_color=False,
        )
        assert exit_code == 1
        assert "< threshold 90%" in report

    def test_threshold_pass(self) -> None:
        results = {
            "prompt_injection": {"total": 100, "blocked": 95, "missed": 5},
        }
        report, exit_code = format_report(
            results=results,
            pool_name="default",
            total_vectors=200,
            total_variants=100,
            runtime_seconds=1.0,
            threshold=90,
            use_color=False,
        )
        assert exit_code == 0
        assert ">= threshold 90%" in report

    def test_no_threshold(self) -> None:
        results = {
            "prompt_injection": {"total": 10, "blocked": 5, "missed": 5},
        }
        _report, exit_code = format_report(
            results=results,
            pool_name="default",
            total_vectors=200,
            total_variants=10,
            runtime_seconds=1.0,
            threshold=None,
            use_color=False,
        )
        assert exit_code == 0

    def test_empty_results(self) -> None:
        report, exit_code = format_report(
            results={},
            pool_name="default",
            total_vectors=0,
            total_variants=0,
            runtime_seconds=0.0,
            threshold=None,
            use_color=False,
        )
        assert "TOTAL" in report
        assert exit_code == 0

    def test_color_disabled(self) -> None:
        report, _ = format_report(
            results={"a": {"total": 10, "blocked": 10, "missed": 0}},
            pool_name="default",
            total_vectors=10,
            total_variants=10,
            runtime_seconds=1.0,
            threshold=None,
            use_color=False,
        )
        assert "\033[" not in report

    def test_color_enabled(self) -> None:
        report, _ = format_report(
            results={"a": {"total": 10, "blocked": 10, "missed": 0}},
            pool_name="default",
            total_vectors=10,
            total_variants=10,
            runtime_seconds=1.0,
            threshold=None,
            use_color=True,
        )
        assert "\033[" in report


class TestCoverageColor:
    """Tests for _coverage_color."""

    def test_green(self) -> None:
        result = _coverage_color(95.0, True)
        assert "\033[32m" in result

    def test_yellow(self) -> None:
        result = _coverage_color(80.0, True)
        assert "\033[33m" in result

    def test_red(self) -> None:
        result = _coverage_color(50.0, True)
        assert "\033[31m" in result

    def test_no_color(self) -> None:
        result = _coverage_color(95.0, False)
        assert "\033[" not in result
        assert "95.0%" in result


class TestTestCommandCLI:
    """Integration tests for the test command via CLI."""

    def test_cli_default_pool(self, capsys: pytest.CaptureFixture) -> None:
        from navil.cli import main

        with patch.object(sys, "argv", ["navil", "test", "--no-color", "--limit", "10"]):
            main()
        captured = capsys.readouterr()
        assert "Navil Test Report" in captured.out

    def test_cli_mega_pool_stub(self, capsys: pytest.CaptureFixture) -> None:
        from navil.cli import main

        with (
            pytest.raises(SystemExit),
            patch.object(sys, "argv", ["navil", "test", "--pool", "mega"]),
        ):
            main()

    def test_cli_threshold_exit_code(self) -> None:
        """Threshold logic: coverage below threshold should return exit code 1."""
        results = {
            "prompt_injection": {"total": 100, "blocked": 70, "missed": 30},
        }
        _report, exit_code = format_report(
            results=results,
            pool_name="default",
            total_vectors=200,
            total_variants=100,
            runtime_seconds=1.0,
            threshold=90,
            use_color=False,
        )
        assert exit_code == 1
