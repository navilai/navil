"""Tests for the stdio shim (navil.shim)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from navil.shim import StdioShim, _detect_and_read_message, _write_message

# —— Helper: minimal mock MCP server script ——————————————————————

MOCK_MCP_SERVER = r'''
"""Minimal MCP server over stdio for testing.

Reads Content-Length-framed JSON-RPC from stdin, responds on stdout.
Supports: initialize, tools/list, tools/call.
"""
import json
import sys


def read_message():
    """Read a Content-Length framed message from stdin."""
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.strip()
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
            # Read until blank line
            while True:
                h = sys.stdin.buffer.readline()
                if not h or h.strip() == b"":
                    break
            body = sys.stdin.buffer.read(length)
            return json.loads(body)
        elif line:
            # NDJSON fallback
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue


def write_message(data):
    """Write a Content-Length framed message to stdout."""
    body = json.dumps(data).encode()
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()


TOOLS = [
    {"name": "read_file", "description": "Read a file"},
    {"name": "write_file", "description": "Write a file"},
]


while True:
    msg = read_message()
    if msg is None:
        break

    req_id = msg.get("id")
    method = msg.get("method", "")

    if method == "initialize":
        write_message({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "mock-mcp", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        })
    elif method == "tools/list":
        write_message({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS},
        })
    elif method == "tools/call":
        tool = msg.get("params", {}).get("name", "")
        write_message({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": f"Called {tool}"}]},
        })
    else:
        write_message({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {},
        })
'''


@pytest.fixture
def mock_server_path(tmp_path: Path) -> Path:
    """Write the mock MCP server to a temp file and return its path."""
    server = tmp_path / "mock_mcp_server.py"
    server.write_text(MOCK_MCP_SERVER)
    return server


# —— Unit tests: message framing ——————————————————————————————————


@pytest.mark.asyncio
async def test_detect_and_read_ndjson():
    """Test reading a newline-delimited JSON message."""
    reader = asyncio.StreamReader()
    msg = b'{"jsonrpc":"2.0","method":"initialize","id":1}\n'
    reader.feed_data(msg)
    reader.feed_eof()

    result = await _detect_and_read_message(reader)
    assert result is not None
    parsed = json.loads(result)
    assert parsed["method"] == "initialize"
    assert parsed["id"] == 1


@pytest.mark.asyncio
async def test_detect_and_read_content_length():
    """Test reading a Content-Length framed message."""
    reader = asyncio.StreamReader()
    body = b'{"jsonrpc":"2.0","method":"tools/list","id":2}'
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    reader.feed_data(header + body)
    reader.feed_eof()

    result = await _detect_and_read_message(reader)
    assert result is not None
    parsed = json.loads(result)
    assert parsed["method"] == "tools/list"


@pytest.mark.asyncio
async def test_detect_and_read_eof():
    """Test that EOF returns None."""
    reader = asyncio.StreamReader()
    reader.feed_eof()

    result = await _detect_and_read_message(reader)
    assert result is None


def test_write_message_format():
    """Test that _write_message uses Content-Length framing."""

    class FakeWriter:
        def __init__(self):
            self.data = b""

        def write(self, data):
            self.data += data

    writer = FakeWriter()
    body = b'{"jsonrpc":"2.0","result":{},"id":1}'
    _write_message(writer, body)

    assert writer.data.startswith(b"Content-Length: ")
    assert b"\r\n\r\n" in writer.data
    # Extract body after header
    _, actual_body = writer.data.split(b"\r\n\r\n", 1)
    assert actual_body == body


# —— Unit tests: security checks ——————————————————————————————————


def test_shim_blocks_oversized_payload():
    """Test that the shim rejects payloads exceeding size limit."""
    shim = StdioShim(cmd=["true"], agent_name="test-agent")

    # Create a massive payload
    prefix = b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"x","arguments":'
    big_payload = prefix + b'"' + b"A" * (6 * 1024 * 1024) + b'"' + b"}}"

    allowed, _, error = shim._check_request(big_payload)
    assert not allowed
    assert error is not None
    assert error["error"]["code"] == -32700
    err_msg = error["error"]["message"]
    assert "too large" in err_msg.lower() or "Payload" in err_msg


def test_shim_blocks_deep_json():
    """Test that the shim rejects deeply nested JSON."""
    # Build JSON with depth > 10
    inner = '{"a":' * 15 + "1" + "}" * 15
    payload = (
        f'{{"jsonrpc":"2.0","method":"tools/call","id":1,'
        f'"params":{{"name":"x","arguments":{inner}}}}}'
    )

    shim = StdioShim(cmd=["true"], agent_name="test-agent")
    allowed, _, error = shim._check_request(payload.encode())
    assert not allowed
    assert error is not None
    assert error["error"]["code"] == -32700


def test_shim_allows_valid_request():
    """Test that valid requests pass through security checks."""
    from navil.policy_engine import PolicyEngine

    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}},
        }
    ).encode()

    pe = PolicyEngine()
    pe.policy = {
        "version": "1.0",
        "agents": {"test-agent": {"tools_allowed": ["*"]}},
        "tools": {"read_file": {"allowed_actions": ["tools/call", "read"]}},
    }
    shim = StdioShim(cmd=["true"], agent_name="test-agent", policy_engine=pe)
    allowed, sanitized, error = shim._check_request(payload)
    assert allowed
    assert error is None
    assert len(sanitized) > 0


def test_shim_allows_non_tool_call():
    """Test that non-tools/call methods pass without policy checks."""
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {},
        }
    ).encode()

    shim = StdioShim(cmd=["true"], agent_name="test-agent")
    allowed, _, error = shim._check_request(payload)
    assert allowed
    assert error is None


# —— Integration test: end-to-end shim ————————————————————————————


@pytest.mark.asyncio
@pytest.mark.timeout(15)
async def test_shim_end_to_end(mock_server_path: Path):
    """Test the full shim with a real mock MCP server subprocess."""
    shim = StdioShim(
        cmd=[sys.executable, str(mock_server_path)],
        agent_name="test-agent",
    )

    # We can't easily test the full run() method (it takes over stdin/stdout),
    # so we test the subprocess spawning and message passing directly.
    process = await shim._spawn_server()
    assert process.returncode is None  # still running

    # Send an initialize request
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {},
        }
    ).encode()
    _write_message(process.stdin, request)
    await process.stdin.drain()

    # Read the response
    response = await _detect_and_read_message(process.stdout)
    assert response is not None
    parsed = json.loads(response)
    assert parsed["id"] == 1
    assert "result" in parsed
    assert parsed["result"]["serverInfo"]["name"] == "mock-mcp"

    # Send a tools/call request
    call_request = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 2,
            "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
        }
    ).encode()
    _write_message(process.stdin, call_request)
    await process.stdin.drain()

    call_response = await _detect_and_read_message(process.stdout)
    assert call_response is not None
    call_parsed = json.loads(call_response)
    assert call_parsed["id"] == 2
    assert "result" in call_parsed
    assert "read_file" in call_parsed["result"]["content"][0]["text"]

    # Cleanup
    process.terminate()
    await process.wait()


@pytest.mark.asyncio
@pytest.mark.timeout(15)
async def test_shim_security_with_mock_server(mock_server_path: Path):
    """Test that security checks work with a real subprocess."""
    from navil.policy_engine import PolicyEngine

    pe = PolicyEngine()
    pe.policy = {
        "version": "1.0",
        "agents": {"test-agent": {"tools_allowed": ["*"]}},
        "tools": {"read_file": {"allowed_actions": ["tools/call", "read"]}},
    }
    shim = StdioShim(
        cmd=[sys.executable, str(mock_server_path)],
        agent_name="test-agent",
        policy_engine=pe,
    )

    # Test that sanitization works on a valid request
    valid_req = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {"name": "read_file", "arguments": {"path": "/tmp"}},
        }
    ).encode()

    allowed, sanitized, error = shim._check_request(valid_req)
    assert allowed
    assert error is None

    # Test that invalid JSON is rejected
    allowed, _, error = shim._check_request(b"not json at all")
    assert not allowed
    assert error["error"]["code"] == -32700

    # Verify stats tracking
    assert shim.stats["blocked"] == 0  # valid request wasn't blocked
