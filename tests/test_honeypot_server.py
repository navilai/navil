"""Tests for the Honeypot MCP Server, Collector, and Deployment Helper."""

from __future__ import annotations

import json
import os
import tempfile
import time
import urllib.request

import pytest

from navil.honeypot.collector import HoneypotCollector
from navil.honeypot.server import HoneypotMCPServer, HoneypotRecord

# -- HoneypotRecord ---------------------------------------------------------


class TestHoneypotRecord:
    """Tests for HoneypotRecord."""

    def test_creation(self):
        record = HoneypotRecord(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
            source_ip="192.168.1.1",
            request_headers={"Content-Type": "application/json"},
        )
        assert record.tool_name == "read_file"
        assert record.source_ip == "192.168.1.1"
        assert record.timestamp != ""

    def test_to_dict(self):
        record = HoneypotRecord(
            tool_name="exec_command",
            arguments={"cmd": "ls"},
            source_ip="10.0.0.1",
            request_headers={},
        )
        d = record.to_dict()
        assert d["tool_name"] == "exec_command"
        assert "timestamp" in d
        assert "source_ip" in d

    def test_user_agent_from_headers(self):
        record = HoneypotRecord(
            tool_name="test",
            arguments={},
            source_ip="1.2.3.4",
            request_headers={"User-Agent": "malicious-bot/1.0"},
        )
        assert record.user_agent == "malicious-bot/1.0"

    def test_user_agent_explicit(self):
        record = HoneypotRecord(
            tool_name="test",
            arguments={},
            source_ip="1.2.3.4",
            request_headers={"User-Agent": "from-header"},
            user_agent="explicit-agent",
        )
        assert record.user_agent == "explicit-agent"

    def test_to_dict_includes_user_agent(self):
        record = HoneypotRecord(
            tool_name="test",
            arguments={},
            source_ip="1.2.3.4",
            request_headers={"User-Agent": "test-agent/2.0"},
        )
        d = record.to_dict()
        assert d["user_agent"] == "test-agent/2.0"


# -- HoneypotMCPServer ------------------------------------------------------


class TestHoneypotMCPServer:
    """Tests for the honeypot server."""

    def test_load_dev_tools_profile(self):
        server = HoneypotMCPServer(profile="dev_tools")
        assert len(server.tools) > 0
        assert "read_file" in server.tools

    def test_load_cloud_creds_profile(self):
        server = HoneypotMCPServer(profile="cloud_creds")
        assert "get_aws_config" in server.tools

    def test_load_db_admin_profile(self):
        server = HoneypotMCPServer(profile="db_admin")
        assert "query_db" in server.tools

    def test_load_unknown_profile_falls_back(self):
        server = HoneypotMCPServer(profile="nonexistent_profile")
        assert server.tools == {}

    def test_tool_list(self):
        server = HoneypotMCPServer(profile="dev_tools")
        tools = server.tool_list
        assert len(tools) >= 5
        names = [t["name"] for t in tools]
        assert "read_file" in names

    def test_tool_list_includes_input_schema(self):
        server = HoneypotMCPServer(profile="dev_tools")
        tools = server.tool_list
        # Find read_file tool
        read_file = next(t for t in tools if t["name"] == "read_file")
        assert "inputSchema" in read_file
        assert read_file["inputSchema"]["type"] == "object"

    def test_tool_names_property(self):
        server = HoneypotMCPServer(profile="dev_tools")
        names = server.tool_names
        assert isinstance(names, list)
        assert names == sorted(names)  # Should be sorted
        assert "read_file" in names

    def test_handle_tools_list(self):
        server = HoneypotMCPServer(profile="dev_tools")
        response = server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "127.0.0.1",
            {},
        )
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "tools" in response["result"]

    def test_handle_tools_call(self):
        server = HoneypotMCPServer(profile="dev_tools")
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

    def test_handle_initialize(self):
        server = HoneypotMCPServer(profile="dev_tools")
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            },
            "127.0.0.1",
            {},
        )
        assert response["jsonrpc"] == "2.0"
        assert "result" in response
        assert "serverInfo" in response["result"]
        assert "honeypot" in response["result"]["serverInfo"]["name"]

    def test_handle_unknown_method(self):
        server = HoneypotMCPServer(profile="dev_tools")
        response = server.handle_request(
            {"jsonrpc": "2.0", "id": 3, "method": "unknown/method"},
            "127.0.0.1",
            {},
        )
        assert "error" in response
        assert response["error"]["code"] == -32601

    def test_interactions_are_recorded(self):
        server = HoneypotMCPServer(profile="dev_tools")
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
        assert records[0].tool_name == "read_file"
        assert records[0].source_ip == "10.0.0.1"

    def test_custom_profile_dict(self):
        custom = {
            "my_tool": {
                "description": "Custom tool",
                "response": {"status": "ok"},
            }
        }
        server = HoneypotMCPServer(profile=custom)
        assert "my_tool" in server.tools
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

    def test_unknown_tool_returns_default_response(self):
        server = HoneypotMCPServer(profile="dev_tools")
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "nonexistent_tool", "arguments": {}},
            },
            "127.0.0.1",
            {},
        )
        # Should still return a response (not an error), but with default data
        assert "result" in response
        assert response["result"]["status"] == "ok"

    def test_collector_integration(self):
        collector = HoneypotCollector()
        server = HoneypotMCPServer(profile="dev_tools", collector=collector)

        server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "exec_command", "arguments": {"cmd": "whoami"}},
            },
            "172.16.0.1",
            {"User-Agent": "evil-bot/3.0"},
        )

        assert collector.current_count == 1
        records = collector.records
        assert records[0]["tool_name"] == "exec_command"
        assert records[0]["source_ip"] == "172.16.0.1"
        assert records[0]["user_agent"] == "evil-bot/3.0"

    def test_tools_list_records_interaction(self):
        server = HoneypotMCPServer(profile="dev_tools")
        server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            "10.0.0.5",
            {},
        )
        records = server.records
        assert len(records) == 1
        assert records[0].tool_name == "__tools_list__"

    def test_multiple_profiles_load_correctly(self):
        for profile in ["dev_tools", "cloud_creds", "db_admin"]:
            server = HoneypotMCPServer(profile=profile)
            assert len(server.tools) >= 4, f"Profile {profile} has fewer than 4 tools"


# -- HTTP Server Integration ------------------------------------------------


class TestHoneypotHTTPServer:
    """Integration tests using the actual HTTP server."""

    @pytest.fixture
    def server(self):
        srv = HoneypotMCPServer(profile="dev_tools", host="127.0.0.1", port=0)
        srv.start_background()
        time.sleep(0.1)  # brief wait for server to bind
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

    def test_http_user_agent_captured(self, server):
        req_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
            }
        ).encode()
        req = urllib.request.Request(
            server.url,
            data=req_body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "test-crawler/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            json.loads(resp.read())

        records = server.records
        assert len(records) == 1
        assert records[0].user_agent == "test-crawler/1.0"

    def test_context_manager(self):
        with HoneypotMCPServer(profile="dev_tools", host="127.0.0.1", port=0) as srv:
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


# -- HoneypotCollector -------------------------------------------------------


class TestHoneypotCollector:
    """Tests for the collector."""

    def test_record_and_retrieve(self):
        collector = HoneypotCollector()
        record = HoneypotRecord(
            tool_name="test_tool",
            arguments={"key": "value"},
            source_ip="1.2.3.4",
            request_headers={},
        )
        collector.record(record)
        assert collector.current_count == 1
        assert collector.count == 1

    def test_max_records(self):
        collector = HoneypotCollector(max_records=5)
        record = HoneypotRecord("tool", {}, "1.2.3.4", {})
        for _ in range(10):
            collector.record(record)
        assert collector.current_count == 5
        assert collector.count == 10

    def test_tool_call_counts(self):
        collector = HoneypotCollector()
        for tool in ["read_file", "read_file", "exec_command"]:
            record = HoneypotRecord(tool, {}, "1.2.3.4", {})
            collector.record(record)
        counts = collector.get_tool_call_counts()
        assert counts["read_file"] == 2
        assert counts["exec_command"] == 1

    def test_source_ip_counts(self):
        collector = HoneypotCollector()
        for ip in ["1.2.3.4", "1.2.3.4", "5.6.7.8"]:
            record = HoneypotRecord("tool", {}, ip, {})
            collector.record(record)
        counts = collector.get_source_ip_counts()
        assert counts["1.2.3.4"] == 2
        assert counts["5.6.7.8"] == 1

    def test_user_agent_counts(self):
        collector = HoneypotCollector()
        for ua in ["bot-a/1.0", "bot-a/1.0", "bot-b/2.0"]:
            record = HoneypotRecord("tool", {}, "1.2.3.4", {"User-Agent": ua})
            collector.record(record)
        counts = collector.get_user_agent_counts()
        assert counts["bot-a/1.0"] == 2
        assert counts["bot-b/2.0"] == 1

    def test_export_json(self):
        collector = HoneypotCollector()
        record = HoneypotRecord("test", {"k": "v"}, "1.2.3.4", {})
        collector.record(record)
        exported = collector.export_json()
        parsed = json.loads(exported)
        assert len(parsed) == 1
        assert parsed[0]["tool_name"] == "test"

    def test_export_jsonl(self):
        collector = HoneypotCollector()
        for i in range(3):
            record = HoneypotRecord(f"tool_{i}", {}, "1.2.3.4", {})
            collector.record(record)
        content = collector.export_jsonl()
        lines = [line for line in content.strip().split("\n") if line]
        assert len(lines) == 3
        # Each line should be valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "tool_name" in parsed

    def test_export_jsonl_to_file(self):
        collector = HoneypotCollector()
        for i in range(3):
            record = HoneypotRecord(f"tool_{i}", {}, "1.2.3.4", {})
            collector.record(record)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            collector.export_jsonl(path)
            with open(path) as f:
                lines = [line for line in f.read().strip().split("\n") if line]
            assert len(lines) == 3
        finally:
            os.unlink(path)

    def test_load_jsonl(self):
        # Export some records
        collector1 = HoneypotCollector()
        for i in range(5):
            record = HoneypotRecord(f"tool_{i}", {"idx": i}, "10.0.0.1", {})
            collector1.record(record)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            collector1.export_jsonl(path)

            # Load into a fresh collector
            collector2 = HoneypotCollector()
            loaded = collector2.load_jsonl(path)
            assert loaded == 5
            assert collector2.current_count == 5
            assert collector2.records[0]["tool_name"] == "tool_0"
        finally:
            os.unlink(path)

    def test_jsonl_log_path(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            collector = HoneypotCollector(log_path=path)
            record = HoneypotRecord("test_tool", {"key": "val"}, "1.2.3.4", {})
            collector.record(record)
            collector.close()

            with open(path) as f:
                content = f.read().strip()
            assert content  # Not empty
            parsed = json.loads(content)
            assert parsed["tool_name"] == "test_tool"
        finally:
            os.unlink(path)

    def test_clear(self):
        collector = HoneypotCollector()
        record = HoneypotRecord("tool", {}, "1.2.3.4", {})
        for _ in range(5):
            collector.record(record)
        cleared = collector.clear()
        assert cleared == 5
        assert collector.current_count == 0

    def test_records_include_user_agent(self):
        collector = HoneypotCollector()
        record = HoneypotRecord("test", {}, "1.2.3.4", {"User-Agent": "attacker/1.0"})
        collector.record(record)
        records = collector.records
        assert records[0]["user_agent"] == "attacker/1.0"


# -- Deployment Helper -------------------------------------------------------


class TestHoneypotDeployer:
    """Tests for the deployment helper (unit tests, no Docker required)."""

    def test_import(self):
        from navil.honeypot.deploy import AVAILABLE_PROFILES

        assert "dev_tools" in AVAILABLE_PROFILES
        assert "cloud_creds" in AVAILABLE_PROFILES
        assert "db_admin" in AVAILABLE_PROFILES

    def test_invalid_profiles_rejected(self):
        from navil.honeypot.deploy import HoneypotDeployer

        deployer = HoneypotDeployer()
        result = deployer.start(profiles=["nonexistent_profile"])
        assert result["status"] == "error"
        assert "Unknown profiles" in result["message"]

    def test_project_dir_resolution(self):
        from navil.honeypot.deploy import HoneypotDeployer

        deployer = HoneypotDeployer()
        assert os.path.isabs(deployer.project_dir)
        assert os.path.isabs(deployer.compose_file)


# -- CLI Command Registration -----------------------------------------------


class TestHoneypotCLICommand:
    """Tests for the CLI command plugin."""

    def test_register(self):
        import argparse

        from navil.commands.honeypot import register

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        class FakeCLI:
            pass

        register(subparsers, FakeCLI)

        # Should be able to parse honeypot subcommands
        args = parser.parse_args(["honeypot", "profiles"])
        assert hasattr(args, "func")

    def test_register_analyze_subcommand(self):
        import argparse

        from navil.commands.honeypot import register

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        class FakeCLI:
            pass

        register(subparsers, FakeCLI)

        args = parser.parse_args(
            ["honeypot", "analyze", "--input", "test.jsonl", "--min-confidence", "0.8"]
        )
        assert args.input == "test.jsonl"
        assert args.min_confidence == 0.8
