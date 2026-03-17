"""Report generators for Navil scan results."""

from navil.report.scan_diff import generate_scan_diff, render_scan_diff_markdown
from navil.report.state_of_mcp import generate_state_of_mcp_report
from navil.report.trend_analyzer import TrendAnalyzer
from navil.report.trend_report import generate_trend_report, render_trend_report_markdown

__all__ = [
    "TrendAnalyzer",
    "generate_scan_diff",
    "generate_state_of_mcp_report",
    "generate_trend_report",
    "render_scan_diff_markdown",
    "render_trend_report_markdown",
]
