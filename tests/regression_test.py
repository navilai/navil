#!/usr/bin/env python3
"""
Navil Regression Test Suite
============================
Launch-critical quality gate that tests every user-facing command and endpoint.

Usage:
    python3 tests/regression_test.py

Exit codes:
    0 — all tests passed
    1 — one or more tests failed
"""

from __future__ import annotations

import contextlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# ── SSL context (macOS Python may lack system certs) ─────────


def _make_ssl_context() -> ssl.SSLContext:
    """Build an SSL context that works on macOS where certifi may not be installed."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    # Fallback: try the default context (works on Linux, sometimes macOS)
    ctx = ssl.create_default_context()
    with contextlib.suppress(Exception):
        ctx.load_default_certs()
    # Last resort: unverified context (still tests HTTP layer)
    ctx_unverified = ssl.create_default_context()
    ctx_unverified.check_hostname = False
    ctx_unverified.verify_mode = ssl.CERT_NONE
    return ctx_unverified


_SSL_CTX = _make_ssl_context()

# ── ANSI colors ──────────────────────────────────────────────

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if USE_COLOR else text


# ── Result tracking ──────────────────────────────────────────

_results: list[dict[str, Any]] = []


def _record(
    name: str, passed: bool, elapsed: float, detail: str = "", skipped: bool = False
) -> None:
    _results.append(
        {
            "name": name,
            "passed": passed,
            "elapsed": elapsed,
            "detail": detail,
            "skipped": skipped,
        }
    )
    status_str: str
    if skipped:
        status_str = _c("SKIP", YELLOW)
    elif passed:
        status_str = _c("PASS", GREEN)
    else:
        status_str = _c("FAIL", RED)

    timing = _c(f"({elapsed:.2f}s)", DIM)
    print(f"  [{status_str}] {name} {timing}")
    if detail and not passed and not skipped:
        # indent detail lines
        for line in detail.strip().splitlines()[:5]:
            print(f"         {_c(line, DIM)}")


# ── Helpers ──────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NAVIL_CMD = [sys.executable, "-m", "navil"]
BACKEND_BASE = "https://navil-cloud-api.onrender.com"
FRONTEND_BASE = "https://navil.ai"


def run_cli(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a navil CLI command and return the CompletedProcess."""
    return subprocess.run(
        NAVIL_CMD + args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(PROJECT_ROOT),
        env={**os.environ, "NO_COLOR": "1", "NAVIL_TELEMETRY": "0"},
    )


def http_get(url: str, timeout: int = 30) -> tuple[int, str, dict[str, str]]:
    """GET a URL and return (status_code, body, headers_dict)."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "navil-regression-test/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, body, headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, body, headers


def http_post_json(url: str, data: dict, timeout: int = 30) -> tuple[int, str, dict[str, str]]:
    """POST JSON to a URL and return (status_code, body, headers_dict)."""
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "navil-regression-test/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, body, headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, body, headers


def write_temp_json(data: dict, suffix: str = ".json") -> str:
    """Write a dict as JSON to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="navil_regtest_")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return path


def section(title: str) -> None:
    """Print a section header."""
    print()
    print(_c(f"{'=' * 64}", CYAN))
    print(_c(f"  {title}", BOLD))
    print(_c(f"{'=' * 64}", CYAN))
    print()


# ── Test fixtures (temp config files) ────────────────────────

MINIMAL_CONFIG = {
    "server": {
        "name": "Minimal Empty Server",
        "protocol": "http",
        "host": "0.0.0.0",
        "port": 8080,
    }
}

SECURE_CONFIG = {
    "server": {
        "name": "Secure MCP Server",
        "protocol": "https",
        "host": "127.0.0.1",
        "port": 8443,
        "source": "https://verified-registry.example.com/server.bin",
        "verified": True,
        "signature": "sha256:abc123def456",
    },
    "authentication": {
        "type": "mTLS",
        "cert_path": "/etc/mcp/certs/server.crt",
        "key_path": "/etc/mcp/certs/server.key",
        "client_ca_path": "/etc/mcp/certs/ca.crt",
        "key_rotation": True,
        "rotation_interval_days": 30,
    },
    "authorization": {
        "type": "rbac",
        "roles": {
            "viewer": {
                "permissions": ["read"],
                "tools": ["logs"],
                "rate_limit": 100,
            }
        },
    },
    "tools": [
        {
            "name": "logs",
            "description": "Application logs access",
            "allowed_actions": ["read"],
            "rate_limit": 100,
            "audit_enabled": True,
        }
    ],
    "security": {
        "encryption": {"enabled": True, "algorithm": "AES-256-GCM"},
        "logging": {"enabled": True, "level": "INFO"},
        "rate_limiting": {"enabled": True, "default_limit_per_hour": 1000},
        "input_validation": {"enabled": True, "max_payload_mb": 10},
    },
}

CRED_CONFIG = {
    "server": {
        "name": "Server With Leaked Creds",
        "protocol": "http",
        "host": "0.0.0.0",
        "port": 8080,
    },
    "authentication": {
        "type": "api_key",
        "api_key": "sk-1234567890abcdef",
    },
    "tools": [
        {
            "name": "db",
            "description": "Database",
            "db_password": "admin123",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEv...",
        }
    ],
}

WRAP_CONFIG = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        },
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
        },
    }
}


# ══════════════════════════════════════════════════════════════
#  TEST CATEGORIES
# ══════════════════════════════════════════════════════════════


def test_cli_commands() -> None:
    """Test every CLI command runs without crashing."""
    section("CLI Commands")

    # ── navil --help ──
    t0 = time.monotonic()
    r = run_cli(["--help"])
    elapsed = time.monotonic() - t0
    _record(
        "navil --help",
        r.returncode == 0 and "wrap" in r.stdout.lower(),
        elapsed,
        detail=f"rc={r.returncode}, stdout has 'wrap': {'wrap' in r.stdout.lower()}",
    )

    # ── navil wrap --help ──
    t0 = time.monotonic()
    r = run_cli(["wrap", "--help"])
    elapsed = time.monotonic() - t0
    _record(
        "navil wrap --help",
        r.returncode == 0 and "--dry-run" in r.stdout,
        elapsed,
        detail=f"rc={r.returncode}, stdout has '--dry-run': {'--dry-run' in r.stdout}",
    )

    # ── navil scan (text format) ──
    config_path = str(PROJECT_ROOT / "navil" / "sample_configs" / "vulnerable_server.json")
    t0 = time.monotonic()
    r = run_cli(["scan", config_path])
    elapsed = time.monotonic() - t0
    combined = r.stdout + r.stderr
    _record(
        "navil scan (text)",
        r.returncode in (0, 1) and "Security Score" in combined,
        elapsed,
        detail=f"rc={r.returncode}, has 'Security Score': {'Security Score' in combined}",
    )

    # ── navil scan --format sarif ──
    t0 = time.monotonic()
    r = run_cli(["scan", config_path, "--format", "sarif"])
    elapsed = time.monotonic() - t0
    sarif_ok = False
    try:
        sarif_data = json.loads(r.stdout)
        sarif_ok = "$schema" in sarif_data
    except (json.JSONDecodeError, TypeError):
        pass
    _record(
        "navil scan --format sarif",
        r.returncode in (0, 1) and sarif_ok,
        elapsed,
        detail=f"rc={r.returncode}, valid SARIF with $schema: {sarif_ok}",
    )

    # ── navil scan --format json ──
    t0 = time.monotonic()
    r = run_cli(["scan", config_path, "--format", "json"])
    elapsed = time.monotonic() - t0
    json_ok = False
    try:
        json_data = json.loads(r.stdout)
        json_ok = "security_score" in json_data
    except (json.JSONDecodeError, TypeError):
        pass
    _record(
        "navil scan --format json",
        r.returncode in (0, 1) and json_ok,
        elapsed,
        detail=f"rc={r.returncode}, valid JSON with 'security_score': {json_ok}",
    )

    # ── navil pentest ──
    t0 = time.monotonic()
    r = run_cli(["pentest"], timeout=120)
    elapsed = time.monotonic() - t0
    combined = r.stdout + r.stderr
    _record(
        "navil pentest",
        r.returncode == 0 and "Detection Rate: 11/11" in combined,
        elapsed,
        detail=(f"rc={r.returncode}, has '11/11': {'Detection Rate: 11/11' in combined}"),
    )

    # ── navil cloud status ──
    t0 = time.monotonic()
    r = run_cli(["cloud", "status"])
    elapsed = time.monotonic() - t0
    _record(
        "navil cloud status",
        r.returncode == 0,
        elapsed,
        detail=f"rc={r.returncode}",
    )

    # ── navil cloud serve --help ──
    t0 = time.monotonic()
    r = run_cli(["cloud", "serve", "--help"])
    elapsed = time.monotonic() - t0
    combined = r.stdout + r.stderr
    _record(
        "navil cloud serve --help",
        r.returncode == 0 and "--port" in combined,
        elapsed,
        detail=f"rc={r.returncode}, has '--port': {'--port' in combined}",
    )

    # ── navil proxy --help ──
    t0 = time.monotonic()
    r = run_cli(["proxy", "--help"])
    elapsed = time.monotonic() - t0
    _record(
        "navil proxy --help",
        r.returncode == 0,
        elapsed,
        detail=f"rc={r.returncode}",
    )

    # ── navil policy check --help ──
    t0 = time.monotonic()
    r = run_cli(["policy", "check", "--help"])
    elapsed = time.monotonic() - t0
    _record(
        "navil policy check --help",
        r.returncode == 0,
        elapsed,
        detail=f"rc={r.returncode}",
    )

    # ── navil policy auto-generate --help ──
    t0 = time.monotonic()
    r = run_cli(["policy", "auto-generate", "--help"])
    elapsed = time.monotonic() - t0
    _record(
        "navil policy auto-generate --help",
        r.returncode == 0,
        elapsed,
        detail=f"rc={r.returncode}",
    )

    # ── navil credential issue ──
    t0 = time.monotonic()
    r = run_cli(["credential", "issue", "--agent", "test-reg", "--scope", "read", "--ttl", "60"])
    elapsed = time.monotonic() - t0
    combined = r.stdout + r.stderr
    _record(
        "navil credential issue",
        r.returncode == 0 and "Token ID" in combined,
        elapsed,
        detail=f"rc={r.returncode}, has 'Token ID': {'Token ID' in combined}",
    )

    # ── navil credential list ──
    t0 = time.monotonic()
    r = run_cli(["credential", "list"])
    elapsed = time.monotonic() - t0
    _record(
        "navil credential list",
        r.returncode == 0,
        elapsed,
        detail=f"rc={r.returncode}",
    )

    # ── navil a2a card ──
    t0 = time.monotonic()
    r = run_cli(["a2a", "card"])
    elapsed = time.monotonic() - t0
    a2a_ok = False
    try:
        a2a_data = json.loads(r.stdout)
        a2a_ok = "name" in a2a_data
    except (json.JSONDecodeError, TypeError):
        pass
    _record(
        "navil a2a card",
        r.returncode == 0 and a2a_ok,
        elapsed,
        detail=f"rc={r.returncode}, valid JSON with 'name': {a2a_ok}",
    )

    # ── navil test --pool default --limit 5 ──
    t0 = time.monotonic()
    r = run_cli(["test", "--pool", "default", "--limit", "5"], timeout=120)
    elapsed = time.monotonic() - t0
    combined = r.stdout + r.stderr
    _record(
        "navil test --pool default --limit 5",
        r.returncode == 0 and "Coverage" in combined,
        elapsed,
        detail=f"rc={r.returncode}, has 'Coverage': {'Coverage' in combined}",
    )

    # ── navil redteam --help ──
    t0 = time.monotonic()
    r = run_cli(["redteam", "--help"])
    elapsed = time.monotonic() - t0
    _record(
        "navil redteam --help",
        r.returncode == 0,
        elapsed,
        detail=f"rc={r.returncode}",
    )

    # ── navil crawl --help ──
    t0 = time.monotonic()
    r = run_cli(["crawl", "--help"])
    elapsed = time.monotonic() - t0
    combined = r.stdout + r.stderr
    _record(
        "navil crawl --help",
        r.returncode == 0 and "threat-scan" in combined,
        elapsed,
        detail=f"rc={r.returncode}, has 'threat-scan': {'threat-scan' in combined}",
    )


def test_backend_api() -> None:
    """Test live backend endpoints on navil-cloud-api.onrender.com."""
    section("Backend API")

    # ── GET /v1/health ──
    t0 = time.monotonic()
    try:
        status, body, headers = http_get(f"{BACKEND_BASE}/v1/health")
        elapsed = time.monotonic() - t0
        _record("GET /v1/health", status == 200, elapsed, detail=f"status={status}")
    except Exception as e:
        elapsed = time.monotonic() - t0
        _record("GET /v1/health", False, elapsed, detail=str(e))

    # ── GET /v1/coverage ──
    t0 = time.monotonic()
    try:
        status, body, headers = http_get(f"{BACKEND_BASE}/v1/coverage")
        elapsed = time.monotonic() - t0
        coverage_ok = False
        if status == 200:
            try:
                data = json.loads(body)
                coverage_ok = "total_base_vectors" in data
            except json.JSONDecodeError:
                pass
        _record(
            "GET /v1/coverage",
            status == 200 and coverage_ok,
            elapsed,
            detail=f"status={status}, has 'total_base_vectors': {coverage_ok}",
        )
    except Exception as e:
        elapsed = time.monotonic() - t0
        _record("GET /v1/coverage", False, elapsed, detail=str(e))

    # ── GET /v1/radar/stats ──
    t0 = time.monotonic()
    try:
        status, body, headers = http_get(f"{BACKEND_BASE}/v1/radar/stats")
        elapsed = time.monotonic() - t0
        radar_ok = False
        if status == 200:
            try:
                data = json.loads(body)
                # Accept either field name (API may use events_24h or total_events)
                radar_ok = "events_24h" in data or "total_events" in data
            except json.JSONDecodeError:
                pass
        _record(
            "GET /v1/radar/stats",
            status == 200 and radar_ok,
            elapsed,
            detail=f"status={status}, has events field: {radar_ok}",
        )
    except Exception as e:
        elapsed = time.monotonic() - t0
        _record("GET /v1/radar/stats", False, elapsed, detail=str(e))

    # ── GET /v1/badge/events_7d.svg ──
    t0 = time.monotonic()
    try:
        status, body, headers = http_get(f"{BACKEND_BASE}/v1/badge/events_7d.svg")
        elapsed = time.monotonic() - t0
        ct = headers.get("content-type", "")
        _record(
            "GET /v1/badge/events_7d.svg",
            status == 200 and "svg" in ct.lower(),
            elapsed,
            detail=f"status={status}, content-type={ct}",
        )
    except Exception as e:
        elapsed = time.monotonic() - t0
        _record("GET /v1/badge/events_7d.svg", False, elapsed, detail=str(e))

    # ── GET /v1/badge/machines.svg ──
    t0 = time.monotonic()
    try:
        status, body, headers = http_get(f"{BACKEND_BASE}/v1/badge/machines.svg")
        elapsed = time.monotonic() - t0
        _record(
            "GET /v1/badge/machines.svg",
            status == 200,
            elapsed,
            detail=f"status={status}",
        )
    except Exception as e:
        elapsed = time.monotonic() - t0
        _record("GET /v1/badge/machines.svg", False, elapsed, detail=str(e))

    # ── POST /v1/leads/assessment ──
    t0 = time.monotonic()
    try:
        status, body, headers = http_post_json(
            f"{BACKEND_BASE}/v1/leads/assessment",
            {"email": "regression-test@example.com", "score": 42, "grade": "C"},
        )
        elapsed = time.monotonic() - t0
        # 200 = success, 502 = Resend email issue (not a crash)
        _record(
            "POST /v1/leads/assessment",
            status in (200, 502),
            elapsed,
            detail=f"status={status} (200 or 502 accepted)",
        )
    except Exception as e:
        elapsed = time.monotonic() - t0
        _record("POST /v1/leads/assessment", False, elapsed, detail=str(e))


def test_frontend_pages() -> None:
    """Test that frontend pages return 200, not 500."""
    section("Frontend Pages")

    pages = [
        "/",
        "/radar",
        "/assessment",
        "/blog",
        "/enroll",
        "/login",
        "/register",
        "/privacy",
        "/terms",
    ]

    for page in pages:
        url = f"{FRONTEND_BASE}{page}"
        t0 = time.monotonic()
        try:
            status, body, headers = http_get(url, timeout=30)
            elapsed = time.monotonic() - t0
            _record(
                f"GET {url}",
                status == 200,
                elapsed,
                detail=f"status={status}",
            )
        except Exception as e:
            elapsed = time.monotonic() - t0
            _record(f"GET {url}", False, elapsed, detail=str(e))


def test_scanner_scoring() -> None:
    """Regression test for the 'always 100' scoring bug."""
    section("Scanner Scoring Regression")

    temp_files: list[str] = []

    try:
        # ── Minimal config should score LOW (< 60) ──
        minimal_path = write_temp_json(MINIMAL_CONFIG)
        temp_files.append(minimal_path)
        t0 = time.monotonic()
        r = run_cli(["scan", minimal_path, "--format", "json"])
        elapsed = time.monotonic() - t0
        minimal_score = -1
        try:
            data = json.loads(r.stdout)
            minimal_score = data.get("security_score", -1)
        except (json.JSONDecodeError, TypeError):
            pass
        _record(
            "Minimal config scores <= 60",
            0 <= minimal_score <= 60,
            elapsed,
            detail=f"score={minimal_score} (expected <= 60)",
        )

        # ── Secure config should score HIGH (>= 70) ──
        secure_path = write_temp_json(SECURE_CONFIG)
        temp_files.append(secure_path)
        t0 = time.monotonic()
        r = run_cli(["scan", secure_path, "--format", "json"])
        elapsed = time.monotonic() - t0
        secure_score = -1
        try:
            data = json.loads(r.stdout)
            secure_score = data.get("security_score", -1)
        except (json.JSONDecodeError, TypeError):
            pass
        _record(
            "Secure config scores >= 70",
            secure_score >= 70,
            elapsed,
            detail=f"score={secure_score} (expected >= 70)",
        )

        # ── Secure config must score strictly higher than minimal ──
        score_delta_ok = secure_score > minimal_score
        _record(
            "Secure config scores higher than minimal",
            score_delta_ok,
            0.0,
            detail=f"secure={secure_score} > minimal={minimal_score}: {score_delta_ok}",
        )

        # ── Config with plaintext credentials has CRED finding ──
        cred_path = write_temp_json(CRED_CONFIG)
        temp_files.append(cred_path)
        t0 = time.monotonic()
        r = run_cli(["scan", cred_path, "--format", "json"])
        elapsed = time.monotonic() - t0
        has_cred = False
        try:
            data = json.loads(r.stdout)
            findings = data.get("findings", data.get("vulnerabilities", []))
            has_cred = any(
                f.get("id", "").startswith("CRED") or "credential" in f.get("title", "").lower()
                for f in findings
            )
        except (json.JSONDecodeError, TypeError):
            pass
        _record(
            "Plaintext credentials detected",
            has_cred,
            elapsed,
            detail=f"has CRED finding: {has_cred}",
        )

    finally:
        for path in temp_files:
            with contextlib.suppress(OSError):
                os.unlink(path)


def test_a2a_card_validation() -> None:
    """Validate A2A card contains correct identity (not forked origin)."""
    section("A2A Card Validation")

    t0 = time.monotonic()
    r = run_cli(["a2a", "card"])
    elapsed = time.monotonic() - t0

    card_json = r.stdout.strip()
    identity_ok = False
    no_fork_origin = True

    try:
        data = json.loads(card_json)
        # The documentationUrl or any field should reference navilai/navil
        card_str = json.dumps(data)
        identity_ok = "navilai/navil" in card_str or "navil" in data.get("name", "").lower()
        # Must NOT reference old forked-from origin
        no_fork_origin = "nicholasgriffintn" not in card_str
    except (json.JSONDecodeError, TypeError):
        pass

    _record(
        "A2A card references navilai/navil",
        identity_ok and no_fork_origin,
        elapsed,
        detail=f"has navilai/navil: {identity_ok}, no fork origin: {no_fork_origin}",
    )


def test_wrap_roundtrip() -> None:
    """Test wrap/unwrap round-trip preserves config."""
    section("Wrap/Unwrap Round-Trip")

    temp_files: list[str] = []

    try:
        # Write the MCP client config to a temp file
        config_path = write_temp_json(WRAP_CONFIG)
        temp_files.append(config_path)
        backup_path = config_path.replace(".json", ".backup.json")
        temp_files.append(backup_path)

        original_data = json.loads(Path(config_path).read_text())

        # ── Step 1: Wrap ──
        t0 = time.monotonic()
        r = run_cli(["wrap", config_path])
        elapsed_wrap = time.monotonic() - t0

        wrapped_ok = False
        if r.returncode == 0:
            try:
                wrapped_data = json.loads(Path(config_path).read_text())
                servers = wrapped_data.get("mcpServers", {})
                # Check that at least one server is now wrapped (command = "navil")
                wrapped_ok = any(
                    s.get("command", "").endswith("navil") and "shim" in s.get("args", [])
                    for s in servers.values()
                )
            except (json.JSONDecodeError, OSError):
                pass

        _record(
            "navil wrap (servers wrapped)",
            wrapped_ok,
            elapsed_wrap,
            detail=f"rc={r.returncode}, servers wrapped: {wrapped_ok}",
        )

        # ── Step 2: Unwrap (--undo) ──
        t0 = time.monotonic()
        r = run_cli(["wrap", config_path, "--undo"])
        elapsed_undo = time.monotonic() - t0

        restored_ok = False
        if r.returncode == 0:
            try:
                restored_data = json.loads(Path(config_path).read_text())
                # Compare the restored mcpServers to the original
                restored_ok = restored_data.get("mcpServers") == original_data.get("mcpServers")
            except (json.JSONDecodeError, OSError):
                pass

        _record(
            "navil wrap --undo (config restored)",
            restored_ok,
            elapsed_undo,
            detail=f"rc={r.returncode}, config matches original: {restored_ok}",
        )

    finally:
        for path in temp_files:
            with contextlib.suppress(OSError):
                os.unlink(path)


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════


def print_summary() -> None:
    """Print a final summary table."""
    total = len(_results)
    passed = sum(1 for r in _results if r["passed"] and not r["skipped"])
    failed = sum(1 for r in _results if not r["passed"] and not r["skipped"])
    skipped = sum(1 for r in _results if r["skipped"])

    print()
    print(_c("=" * 64, CYAN))
    print(_c("  REGRESSION TEST SUMMARY", BOLD))
    print(_c("=" * 64, CYAN))
    print()

    if failed > 0:
        print(_c("  FAILED TESTS:", RED))
        for r in _results:
            if not r["passed"] and not r["skipped"]:
                print(f"    {_c('x', RED)} {r['name']}")
                if r["detail"]:
                    print(f"      {_c(r['detail'], DIM)}")
        print()

    result_line = f"  {passed + skipped}/{total} tests passed"
    if skipped:
        result_line += f" ({skipped} skipped)"

    if failed == 0:
        print(_c(result_line, GREEN))
        print(_c("  All checks passed.", GREEN))
    else:
        print(_c(result_line, RED))
        print(_c(f"  {failed} test(s) FAILED.", RED))

    total_time = sum(r["elapsed"] for r in _results)
    print(f"  Total time: {total_time:.1f}s")
    print()


def main() -> int:
    print()
    print(_c("  Navil Regression Test Suite", BOLD))
    print(_c(f"  Python: {sys.executable}", DIM))
    print(_c(f"  Project: {PROJECT_ROOT}", DIM))
    print()

    # Run all test categories
    test_cli_commands()
    test_backend_api()
    test_frontend_pages()
    test_scanner_scoring()
    test_a2a_card_validation()
    test_wrap_roundtrip()

    # Summary
    print_summary()

    # Exit code
    any_failed = any(not r["passed"] and not r["skipped"] for r in _results)
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
