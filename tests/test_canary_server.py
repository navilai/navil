"""Tests for the MCP Canary Kit — server, config, and reporter.

Validates:
  - CanaryServer request handling (tools/list, tools/call, errors)
  - CanaryCollector buffering and statistics
  - CanaryConfig profile resolution and environment loading
  - CanaryReporter sanitization (privacy guarantees)
  - HTTP integration (background server, actual HTTP requests)
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from unittest.mock import AsyncMock, patch

import pytest

from navil.canary.config import (
    AVAILABLE_PROFILES,
    CanaryConfig,
    get_profile_tools,
    resolve_profile_name,
)
from navil.canary.reporter import (
    _ALLOWED_FIELDS,
    _BANNED_FIELDS,
    CanaryReporter,
    sanitize_batch,
    sanitize_record,
    summarize_records,
)
from navil.canary.server import CanaryCollector, CanaryRecord, CanaryServer

# ── CanaryRecord ────────────────────────────────────────────────


class TestCanaryRecord:
    """Tests for CanaryRecord."""

    def test_creation(self):
        record = CanaryRecord(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
            source_ip="192.168.1.1",
            request_headers={"Content-Type": "application/json"},
        )
        assert record.tool_name == "read_file"
        assert record.source_ip == "192.168.1.1"
        assert record.timestamp != ""
        assert record.method == "tools/call"

    def test_to_dict(self):
        record = CanaryRecord(
            tool_name="exec_command",
            arguments={"cmd": "ls"},
            source_ip="10.0.0.1",
            request_headers={},
        )
        d = record.to_dict()
        assert d["tool_name"] == "exec_command"
        assert "timestamp" in d
        assert "source_ip" in d
        # raw_body should NOT be in to_dict (privacy)
        assert "raw_body" not in d

    def test_custom_method(self):
        record = CanaryRecord(
            tool_name="test",
            arguments={},
            source_ip="1.2.3.4",
            request_headers={},
            method="tools/list",
        )
        assert record.method == "tools/list"


# ── CanaryCollector ─────────────────────────────────────────────


class TestCanaryCollector:
    """Tests for the standalone collector."""

    def test_record_and_retrieve(self):
        collector = CanaryCollector()
        record = CanaryRecord("test_tool", {"key": "value"}, "1.2.3.4", {})
        collector.record(record)
        assert collector.current_count == 1
        assert collector.total_count == 1

    def test_max_records_ring_buffer(self):
        collector = CanaryCollector(max_records=5)
        record = CanaryRecord("tool", {}, "1.2.3.4", {})
        for _ in range(10):
            collector.record(record)
        assert collector.current_count == 5
        assert collector.total_count == 10

    def test_tool_call_counts(self):
        collector = CanaryCollector()
        for tool in ["read_file", "read_file", "exec_command"]:
            collector.record(CanaryRecord(tool, {}, "1.2.3.4", {}))
        counts = collector.get_tool_call_counts()
        assert counts["read_file"] == 2
        assert counts["exec_command"] == 1

    def test_source_ip_counts(self):
        collector = CanaryCollector()
        for ip in ["1.2.3.4", "1.2.3.4", "5.6.7.8"]:
            collector.record(CanaryRecord("tool", {}, ip, {}))
        counts = collector.get_source_ip_counts()
        assert counts["1.2.3.4"] == 2
        assert counts["5.6.7.8"] == 1

    def test_export_json(self):
        collector = CanaryCollector()
        collector.record(CanaryRecord("test", {"k": "v"}, "1.2.3.4", {}))
        exported = collector.export_json()
        parsed = json.loads(exported)
        assert len(parsed) == 1
        assert parsed[0]["tool_name"] == "test"

    def test_clear(self):
        collector = CanaryCollector()
        for _ in range(5):
            collector.record(CanaryRecord("tool", {}, "1.2.3.4", {}))
        cleared = collector.clear()
        assert cleared == 5
        assert collector.current_count == 0

    def test_get_records_since(self):
        collector = CanaryCollector()
        # Record two entries with a slight time gap
        r1 = CanaryRecord("tool1", {}, "1.2.3.4", {})
        collector.record(r1)
        ts_after_first = r1.timestamp
        r2 = CanaryRecord("tool2", {}, "1.2.3.4", {})
        # Force a later timestamp
        r2.timestamp = "2099-01-01T00:00:00+00:00"
        collector._records.append(r2.to_dict())
        results = collector.get_records_since(ts_after_first)
        assert len(results) >= 1


# ── CanaryServer ────────────────────────────────────────────────


class TestCanaryServer:
    """Tests for the canary MCP server."""

    def test_load_dev_tools_profile(self):
        server = CanaryServer(profile="dev_tools")
        assert len(server.tools) > 0
        assert "read_file" in server.tools

    def test_load_cloud_creds_profile(self):
        server = CanaryServer(profile="cloud_creds")
        assert "get_aws_config" in server.tools

    def test_load_db_admin_profile(self):
        server = CanaryServer(profile="db_admin")
        assert "query_db" in server.tools

    def test_tool_list_format(self):
        server = CanaryServer(profile="dev_tools")
        tools = server.tool_list
        assert len(tools) >= 5
        names = [t["name"] for t in tools]
        assert "read_file" in names
        for t in tools:
            assert "name" in t
            assert "description" in t

    def test_handle_tools_list(self):
        server = CanaryServer(profile="dev_tools")
        response = server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "127.0.0.1",
            {},
        )
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "tools" in response["result"]

    def test_handle_tools_call(self):
        server = CanaryServer(profile="dev_tools")
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
            },
            "192.168.1.1",
            {"Content-Type": "application/json"},
        )
        assert response["jsonrpc"] == "2.0"
        assert "result" in response

    def test_handle_tools_call_unknown_tool(self):
        server = CanaryServer(profile="dev_tools")
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "nonexistent_tool", "arguments": {}},
            },
            "127.0.0.1",
            {},
        )
        # Should still return a result (not error) — honeypot responds to all
        assert "result" in response

    def test_handle_unknown_method(self):
        server = CanaryServer(profile="dev_tools")
        response = server.handle_request(
            {"jsonrpc": "2.0", "id": 4, "method": "unknown/method"},
            "127.0.0.1",
            {},
        )
        assert "error" in response
        assert response["error"]["code"] == -32601

    def test_interactions_are_recorded(self):
        server = CanaryServer(profile="dev_tools")
        server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
            },
            "10.0.0.1",
            {},
        )
        records = server.records
        assert len(records) == 1
        assert records[0]["tool_name"] == "read_file"
        assert records[0]["source_ip"] == "10.0.0.1"

    def test_custom_profile_dict(self):
        custom = {
            "my_tool": {
                "description": "Custom canary tool",
                "response": {"status": "ok"},
            }
        }
        server = CanaryServer(profile=custom)
        assert "my_tool" in server.tools
        assert server.profile_name == "custom"
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "my_tool", "arguments": {}},
            },
            "127.0.0.1",
            {},
        )
        assert response["result"] == {"status": "ok"}

    def test_collector_integration(self):
        collector = CanaryCollector()
        server = CanaryServer(profile="dev_tools", collector=collector)

        server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "exec_command", "arguments": {"cmd": "whoami"}},
            },
            "172.16.0.1",
            {},
        )

        assert collector.current_count == 1
        records = collector.records
        assert records[0]["tool_name"] == "exec_command"
        assert records[0]["source_ip"] == "172.16.0.1"

    def test_tools_list_records_interaction(self):
        """tools/list requests should also be recorded."""
        server = CanaryServer(profile="dev_tools")
        server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "10.0.0.5",
            {},
        )
        assert len(server.records) == 1
        assert server.records[0]["tool_name"] == "__tools_list__"


# ── HTTP Server Integration ────────────────────────────────────


class TestCanaryHTTPServer:
    """Integration tests using the actual HTTP server."""

    @pytest.fixture
    def server(self):
        srv = CanaryServer(profile="dev_tools", host="127.0.0.1", port=0)
        srv.start_background()
        time.sleep(0.1)
        yield srv
        srv.stop()

    def test_http_tools_list(self, server):
        req_body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        req = urllib.request.Request(
            server.url,
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            assert "result" in data
            assert "tools" in data["result"]

    def test_http_tools_call(self, server):
        req_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
            }
        ).encode()
        req = urllib.request.Request(
            server.url,
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            assert "result" in data

    def test_context_manager(self):
        with CanaryServer(profile="dev_tools", host="127.0.0.1", port=0) as srv:
            assert srv.port > 0
            req_body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
            req = urllib.request.Request(
                srv.url,
                data=req_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
                assert "result" in data


# ── CanaryConfig ────────────────────────────────────────────────


class TestCanaryConfig:
    """Tests for canary configuration."""

    def test_default_config(self):
        cfg = CanaryConfig()
        assert cfg.profile == "dev_tools"
        assert cfg.port == 8080
        assert cfg.contribute is False

    def test_profile_alias_resolution(self):
        cfg = CanaryConfig(profile="dev-tools")
        assert cfg.profile == "dev_tools"

        cfg2 = CanaryConfig(profile="cloud-creds")
        assert cfg2.profile == "cloud_creds"

    def test_resolve_profile_name(self):
        assert resolve_profile_name("dev-tools") == "dev_tools"
        assert resolve_profile_name("db-admin") == "db_admin"
        assert resolve_profile_name("unknown") == "unknown"

    def test_get_profile_tools(self):
        tools = get_profile_tools("dev-tools")
        assert "read_file" in tools
        assert "exec_command" in tools

    def test_get_profile_tools_unknown(self):
        with pytest.raises(KeyError):
            get_profile_tools("nonexistent")

    def test_enable_contribution(self):
        cfg = CanaryConfig()
        assert cfg.contribute is False
        cfg.enable_contribution(api_key="test-key")
        assert cfg.contribute is True
        assert cfg.api_key == "test-key"

    def test_get_tools(self):
        cfg = CanaryConfig(profile="cloud-creds")
        tools = cfg.get_tools()
        assert "get_aws_config" in tools

    def test_from_env(self):
        env = {
            "CANARY_PROFILE": "db-admin",
            "CANARY_PORT": "9090",
            "CANARY_CONTRIBUTE": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = CanaryConfig.from_env()
            assert cfg.profile == "db_admin"
            assert cfg.port == 9090
            assert cfg.contribute is True

    def test_all_profiles_have_tools(self):
        for profile_name in AVAILABLE_PROFILES:
            tools = get_profile_tools(profile_name)
            assert len(tools) > 0, f"Profile {profile_name} has no tools"


# ── CanaryReporter Sanitization ─────────────────────────────────


class TestCanaryReporterSanitization:
    """Tests for reporter privacy guarantees."""

    def test_sanitize_strips_source_ip(self):
        record = {
            "tool_name": "read_file",
            "source_ip": "192.168.1.1",
            "arguments": {"path": "/etc/passwd"},
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "source_ip" not in sanitized
        assert "arguments" not in sanitized
        assert "tool_name" not in sanitized

    def test_sanitize_produces_tool_hash(self):
        record = {
            "tool_name": "read_file",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "tool_sequence_hash" in sanitized
        assert len(sanitized["tool_sequence_hash"]) == 64  # SHA-256 hex

    def test_sanitize_only_allowed_fields(self):
        record = {
            "tool_name": "exec_command",
            "source_ip": "10.0.0.1",
            "arguments": {"cmd": "rm -rf /"},
            "request_headers": {"Authorization": "Bearer secret"},
            "raw_body": '{"jsonrpc":"2.0"}',
            "timestamp": "2026-03-01T00:00:00Z",
            "anomaly_type": "RECONNAISSANCE",
            "severity": "HIGH",
            "confidence": 0.9,
        }
        sanitized = sanitize_record(record)
        for key in sanitized:
            assert key in _ALLOWED_FIELDS, f"Field {key} not in allowed set"

    def test_sanitize_rejects_banned_fields(self):
        """No banned field should ever appear in output."""
        for banned in _BANNED_FIELDS:
            record = {
                banned: "test_value",
                "timestamp": "2026-03-01T00:00:00Z",
            }
            sanitized = sanitize_record(record)
            assert banned not in sanitized

    def test_sanitize_generates_contribution_uuid(self):
        record = {
            "tool_name": "test",
            "timestamp": "2026-03-01T00:00:00Z",
        }
        sanitized = sanitize_record(record)
        assert "contribution_uuid" in sanitized

    def test_sanitize_uuid_deterministic(self):
        record = {
            "tool_name": "test_tool",
            "timestamp": "2026-03-01T12:00:00Z",
        }
        s1 = sanitize_record(record)
        s2 = sanitize_record(record)
        assert s1["contribution_uuid"] == s2["contribution_uuid"]

    def test_sanitize_batch_skips_failures(self):
        records = [
            {"tool_name": "ok", "timestamp": "2026-03-01T00:00:00Z"},
            None,  # invalid, should be skipped
            {"tool_name": "also_ok", "timestamp": "2026-03-01T00:00:01Z"},
        ]
        results = sanitize_batch(records)  # type: ignore[arg-type]
        assert len(results) == 2

    def test_summarize_records(self):
        records = [
            {"tool_name": "read_file", "timestamp": "2026-03-01T00:00:00Z"},
            {"tool_name": "read_file", "timestamp": "2026-03-01T00:01:00Z"},
            {"tool_name": "exec_command", "timestamp": "2026-03-01T00:02:00Z"},
        ]
        summary = summarize_records(records, profile_name="dev_tools")
        assert summary["interaction_count"] == 3
        assert summary["unique_tool_count"] == 2
        assert summary["source_type"] == "canary"
        assert summary["profile_name"] == "dev_tools"
        # No raw tool names
        assert "tool_name" not in summary

    def test_summarize_empty_records(self):
        summary = summarize_records([])
        assert summary == {}


# ── CanaryReporter Client ──────────────────────────────────────


class TestCanaryReporter:
    """Tests for the CanaryReporter HTTP client."""

    @pytest.mark.asyncio
    async def test_report_no_data(self):
        reporter = CanaryReporter(api_key="test")
        result = await reporter.report([])
        assert result["submitted"] == 0
        assert result["status"] == "no_data"

    @pytest.mark.asyncio
    async def test_report_success(self):
        reporter = CanaryReporter(api_key="test")

        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        reporter._http_client = mock_client

        records = [
            {"tool_name": "read_file", "timestamp": "2026-03-01T00:00:00Z"},
            {"tool_name": "exec_command", "timestamp": "2026-03-01T00:01:00Z"},
        ]
        result = await reporter.report(records, profile="dev_tools")
        assert result["submitted"] == 2
        assert result["status"] == "ok"

        # Verify the POST was made with sanitized data
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        contributions = payload["contributions"]
        for c in contributions:
            assert "source_ip" not in c
            assert "arguments" not in c
            assert "tool_name" not in c

    @pytest.mark.asyncio
    async def test_report_summary(self):
        reporter = CanaryReporter(api_key="test")

        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        reporter._http_client = mock_client

        records = [
            {"tool_name": "read_file", "timestamp": "2026-03-01T00:00:00Z"},
        ]
        result = await reporter.report_summary(records, profile="dev_tools")
        assert result["submitted"] == 1
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_report_http_error(self):
        reporter = CanaryReporter(api_key="test")

        mock_response = AsyncMock()
        mock_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        reporter._http_client = mock_client

        records = [{"tool_name": "test", "timestamp": "2026-03-01T00:00:00Z"}]
        result = await reporter.report(records)
        assert result["submitted"] == 0
        assert "error" in result["status"]

    @pytest.mark.asyncio
    async def test_close(self):
        reporter = CanaryReporter()
        mock_client = AsyncMock()
        reporter._http_client = mock_client
        await reporter.close()
        mock_client.aclose.assert_called_once()
        assert reporter._http_client is None
