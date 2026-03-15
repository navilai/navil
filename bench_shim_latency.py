"""Benchmark: measure the latency overhead added by the Navil stdio shim.

Methodology:
  1. Direct baseline — send N JSON-RPC messages to the mock MCP server
     over stdio (no shim), measure round-trip time per message.
  2. Shim path — send the same N messages through the StdioShim (which
     runs security checks on every message), measure round-trip time.
  3. Compare: the difference is the shim overhead.

We also break down the shim overhead into its components:
  - sanitize_request (JSON parse, depth check, re-serialize)
  - parse_jsonrpc
  - policy check (check_tool_call)
  - anomaly gate (get_alerts scan)
  - orjson.loads for correlation tracking
  - _write_message framing

This runs entirely in-process and as subprocesses — no Redis, no network.
"""

import asyncio
import json
import os
import statistics
import sys
import tempfile
import time

# —— Inline mock MCP server (same as test_shim.py) ———————————————

MOCK_SERVER_CODE = r"""
import json, sys

def read_msg():
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.strip()
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
            while True:
                h = sys.stdin.buffer.readline()
                if not h or h.strip() == b"":
                    break
            body = sys.stdin.buffer.read(length)
            return json.loads(body)
        elif line:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

def write_msg(data):
    body = json.dumps(data).encode()
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()

while True:
    msg = read_msg()
    if msg is None:
        break
    rid = msg.get("id")
    method = msg.get("method", "")
    if method == "tools/call":
        tool = msg.get("params", {}).get("name", "")
        r = {"content": [{"type": "text", "text": f"ok:{tool}"}]}
        write_msg({"jsonrpc": "2.0", "id": rid, "result": r})
    elif method == "tools/list":
        tools = [{"name": "read_file"}, {"name": "write_file"}]
        write_msg({"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
    else:
        write_msg({"jsonrpc": "2.0", "id": rid, "result": {}})
"""


def write_mock_server() -> str:
    """Write mock server to a temp file, return path."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="navil_bench_mock_")
    os.write(fd, MOCK_SERVER_CODE.encode())
    os.close(fd)
    return path


# —— Message framing helpers (duplicated to avoid import side effects) ——


def write_message(pipe, data: bytes):
    header = f"Content-Length: {len(data)}\r\n\r\n".encode()
    pipe.write(header + data)
    pipe.flush()


def read_message(pipe) -> bytes | None:
    """Blocking read of one Content-Length-framed message."""
    while True:
        line = pipe.readline()
        if not line:
            return None
        stripped = line.strip()
        if stripped.lower().startswith(b"content-length:"):
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                h = pipe.readline()
                if not h or h.strip() == b"":
                    break
            body = pipe.read(length)
            return body
        elif stripped:
            return stripped


# —— Benchmark payloads ———————————————————————————————————————


def make_payloads(n: int) -> list[bytes]:
    """Generate N JSON-RPC payloads of varying types."""
    payloads = []
    for i in range(n):
        if i % 3 == 0:
            # tools/call (most security-critical path)
            msg = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": i + 1,
                "params": {
                    "name": "read_file",
                    "arguments": {"path": f"/tmp/file_{i}.txt", "encoding": "utf-8"},
                },
            }
        elif i % 3 == 1:
            # tools/list
            msg = {"jsonrpc": "2.0", "method": "tools/list", "id": i + 1, "params": {}}
        else:
            # initialize / other
            msg = {"jsonrpc": "2.0", "method": "initialize", "id": i + 1, "params": {}}
        payloads.append(json.dumps(msg).encode())
    return payloads


# —— Benchmark 1: Direct (no shim) ———————————————————————————


def bench_direct(server_path: str, payloads: list[bytes]) -> list[float]:
    """Send messages directly to mock server, measure per-message RTT."""
    import subprocess

    proc = subprocess.Popen(
        [sys.executable, server_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    latencies = []
    for payload in payloads:
        t0 = time.perf_counter_ns()
        write_message(proc.stdin, payload)
        resp = read_message(proc.stdout)
        t1 = time.perf_counter_ns()
        assert resp is not None, "Server returned None"
        latencies.append((t1 - t0) / 1_000)  # nanoseconds → microseconds

    proc.terminate()
    proc.wait()
    return latencies


# —— Benchmark 2: Through shim ———————————————————————————————


async def bench_shim(server_path: str, payloads: list[bytes]) -> list[float]:
    """Send messages through shim's security pipeline + subprocess, measure RTT."""
    # Use a permissive policy so tools/call isn't denied
    from navil.policy_engine import PolicyEngine
    from navil.shim import StdioShim, _detect_and_read_message, _write_message

    pe = PolicyEngine()
    pe.policy = {
        "version": "1.0",
        "agents": {"bench-agent": {"tools_allowed": ["*"]}},
        "tools": {
            "read_file": {"allowed_actions": ["tools/call", "read", "write", "list"]},
            "write_file": {"allowed_actions": ["tools/call", "read", "write", "list"]},
        },
    }

    shim = StdioShim(
        cmd=[sys.executable, server_path],
        agent_name="bench-agent",
        policy_engine=pe,
    )
    process = await shim._spawn_server()

    latencies = []
    for i, payload in enumerate(payloads):
        t0 = time.perf_counter_ns()

        # Security check (the hot path we're measuring)
        allowed, sanitized, error = shim._check_request(payload)
        assert allowed, f"Payload {i} was unexpectedly blocked: {error}"

        # Forward to server
        _write_message(process.stdin, sanitized)
        await process.stdin.drain()

        # Read response
        resp = await _detect_and_read_message(process.stdout)
        t1 = time.perf_counter_ns()

        assert resp is not None, f"Server returned None for payload {i}"
        latencies.append((t1 - t0) / 1_000)  # → microseconds

    process.terminate()
    await process.wait()
    return latencies


# —— Benchmark 3: Security checks only (no I/O) ——————————————


def bench_security_checks_only(payloads: list[bytes]) -> dict[str, list[float]]:
    """Microbenchmark each security check in isolation."""
    import orjson

    from navil.policy_engine import PolicyEngine
    from navil.proxy import MCPSecurityProxy
    from navil.shim import StdioShim

    pe = PolicyEngine()
    pe.policy = {
        "version": "1.0",
        "agents": {"*": {"tools_allowed": ["*"]}},
        "tools": {},
    }
    shim = StdioShim(cmd=["true"], agent_name="bench-agent", policy_engine=pe)

    timings: dict[str, list[float]] = {
        "sanitize_request": [],
        "parse_jsonrpc": [],
        "extract_tool_info": [],
        "policy_check": [],
        "anomaly_gate": [],
        "orjson_loads": [],
        "full_check_request": [],
    }

    for payload in payloads:
        # orjson.loads
        t0 = time.perf_counter_ns()
        _ = orjson.loads(payload)
        t1 = time.perf_counter_ns()
        timings["orjson_loads"].append((t1 - t0) / 1_000)

        # sanitize_request
        t0 = time.perf_counter_ns()
        sanitized = MCPSecurityProxy.sanitize_request(payload)
        t1 = time.perf_counter_ns()
        timings["sanitize_request"].append((t1 - t0) / 1_000)

        # parse_jsonrpc
        t0 = time.perf_counter_ns()
        parsed = MCPSecurityProxy.parse_jsonrpc(sanitized)
        t1 = time.perf_counter_ns()
        timings["parse_jsonrpc"].append((t1 - t0) / 1_000)

        # extract_tool_info (only for tools/call)
        if parsed["method"] == "tools/call":
            t0 = time.perf_counter_ns()
            tool_name, action, args = MCPSecurityProxy.extract_tool_info(parsed)
            t1 = time.perf_counter_ns()
            timings["extract_tool_info"].append((t1 - t0) / 1_000)

            # policy_check
            t0 = time.perf_counter_ns()
            shim.policy_engine.check_tool_call("bench-agent", tool_name, action)
            t1 = time.perf_counter_ns()
            timings["policy_check"].append((t1 - t0) / 1_000)

        # anomaly_gate
        t0 = time.perf_counter_ns()
        shim.detector.get_alerts(agent_name="bench-agent")[-10:]
        t1 = time.perf_counter_ns()
        timings["anomaly_gate"].append((t1 - t0) / 1_000)

        # full _check_request
        t0 = time.perf_counter_ns()
        shim._check_request(payload)
        t1 = time.perf_counter_ns()
        timings["full_check_request"].append((t1 - t0) / 1_000)

    return timings


# —— Main —————————————————————————————————————————————————————


def fmt(values: list[float]) -> str:
    """Format stats for a list of microsecond measurements."""
    if not values:
        return "N/A"
    p50 = statistics.median(values)
    p95 = sorted(values)[int(len(values) * 0.95)]
    p99 = sorted(values)[int(len(values) * 0.99)]
    mean = statistics.mean(values)
    return f"mean={mean:>8.1f}µs  p50={p50:>8.1f}µs  p95={p95:>8.1f}µs  p99={p99:>8.1f}µs"


def main():
    # Suppress noisy policy engine logging
    import logging

    logging.basicConfig(level=logging.CRITICAL)

    num_messages = 1000
    warmup = 50

    print("=" * 72)
    print("  Navil Stdio Shim — Latency Benchmark")
    print("=" * 72)
    print(f"  Messages: {num_messages} (+ {warmup} warmup)")
    print("  Payload mix: 1/3 tools/call, 1/3 tools/list, 1/3 initialize")
    print()

    server_path = write_mock_server()
    payloads = make_payloads(num_messages + warmup)

    # —— Warmup + Direct baseline ————————————————————————
    print("  [1/3] Direct baseline (no shim)...")
    all_direct = bench_direct(server_path, payloads)
    direct = all_direct[warmup:]  # discard warmup

    # —— Warmup + Shim path ——————————————————————————————
    print("  [2/3] Shim path (full security pipeline)...")
    all_shim = asyncio.run(bench_shim(server_path, payloads))
    shim_latencies = all_shim[warmup:]

    # —— Security checks microbenchmark ——————————————————
    print("  [3/3] Security checks microbenchmark...")
    payloads_for_micro = make_payloads(num_messages)
    check_timings = bench_security_checks_only(payloads_for_micro)

    # —— Results —————————————————————————————————————————
    overhead = [s - d for s, d in zip(shim_latencies, direct, strict=False)]

    print()
    print("─" * 72)
    print("  RESULTS")
    print("─" * 72)
    print()
    print(f"  Direct RTT:       {fmt(direct)}")
    print(f"  Shim RTT:         {fmt(shim_latencies)}")
    print(f"  Shim overhead:    {fmt(overhead)}")
    print()
    print("─" * 72)
    print("  SECURITY CHECK BREAKDOWN (per message)")
    print("─" * 72)
    print()
    for name in [
        "orjson_loads",
        "sanitize_request",
        "parse_jsonrpc",
        "extract_tool_info",
        "policy_check",
        "anomaly_gate",
        "full_check_request",
    ]:
        vals = check_timings.get(name, [])
        if vals:
            print(f"  {name:<24} {fmt(vals)}")
    print()

    # —— Summary —————————————————————————————————————————
    mean_direct = statistics.mean(direct)
    mean_shim = statistics.mean(shim_latencies)
    mean_overhead = statistics.mean(overhead)
    mean_check = statistics.mean(check_timings["full_check_request"])
    pct = (mean_overhead / mean_direct) * 100 if mean_direct > 0 else 0

    print("─" * 72)
    print("  SUMMARY")
    print("─" * 72)
    print(f"  Mean direct RTT:          {mean_direct:>10.1f} µs")
    print(f"  Mean shim RTT:            {mean_shim:>10.1f} µs")
    print(f"  Mean shim overhead:       {mean_overhead:>10.1f} µs  ({pct:.1f}% of direct RTT)")
    print(f"  Mean security check time: {mean_check:>10.1f} µs  (in-process, no I/O)")
    print()

    if mean_check < 1000:
        print(f"  ✓ Security checks add <1ms per message ({mean_check:.0f}µs)")
    else:
        print(f"  Security checks add {mean_check / 1000:.1f}ms per message")

    # Cleanup
    os.unlink(server_path)
    print()


if __name__ == "__main__":
    main()
