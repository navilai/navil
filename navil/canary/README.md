# MCP Canary Kit

A standalone, lightweight honeypot for detecting malicious MCP (Model Context Protocol) tool interactions. Deployable independently with minimal dependencies -- no Redis, no ML, no navil-core required.

## Quick Start

```bash
# Run with default dev-tools profile
python -m navil.canary --profile dev-tools --port 8080

# Run with cloud credentials profile
python -m navil.canary --profile cloud-creds --port 8081

# Run with database admin profile and contribution enabled
python -m navil.canary --profile db-admin --port 8082 --contribute
```

## Profiles

- **dev-tools**: Mimics a developer workstation with `read_env`, `exec_command`, `read_file`, `write_file`, `list_processes`
- **cloud-creds**: Mimics a cloud secrets manager with `get_aws_config`, `list_secrets`, `get_api_keys`, `read_credentials`
- **db-admin**: Mimics a database admin interface with `query_db`, `list_tables`, `export_table`, `create_user`, `grant_permissions`

## CLI Options

| Flag | Description |
|------|-------------|
| `--profile` | Honeypot profile (`dev-tools`, `cloud-creds`, `db-admin`) |
| `--port` | Port to listen on (default: 8080) |
| `--host` | Bind address (default: 0.0.0.0) |
| `--contribute` | Send anonymized detection data to Navil threat intel pool |
| `--log-file` | Path to write JSON interaction log on shutdown |
| `--verbose` | Enable verbose logging |

## Programmatic Usage

### Standalone Server

```python
from navil.canary.server import CanaryServer

# Context manager (recommended)
with CanaryServer(profile="dev_tools", host="127.0.0.1", port=0) as srv:
    print(f"Canary running at {srv.url}")
    records = srv.records  # list of interaction dicts

# Manual lifecycle
server = CanaryServer(profile="cloud_creds", port=8080)
server.start_background()
# ... later ...
server.stop()
```

### Configuration

```python
from navil.canary.config import CanaryConfig

# From code
cfg = CanaryConfig(profile="dev-tools", port=8080)
cfg.enable_contribution(api_key="your-api-key")

# From environment variables
cfg = CanaryConfig.from_env()
# Reads: CANARY_PROFILE, CANARY_HOST, CANARY_PORT, CANARY_CONTRIBUTE, etc.
```

### Reporting

```python
import asyncio
from navil.canary.reporter import CanaryReporter

reporter = CanaryReporter(api_key="your-api-key")

# Report individual records (anonymized)
result = asyncio.run(reporter.report(server.records, profile="dev_tools"))
# {"submitted": 5, "status": "ok"}

# Report aggregate summary (more privacy-preserving)
result = asyncio.run(reporter.report_summary(server.records, profile="dev_tools"))

await reporter.close()
```

### Full Kit (Orchestrator)

```python
from navil.canary.kit import CanaryKit

kit = CanaryKit(profile="dev_tools", port=8080, contribute=True)
kit.run_background()

records = kit.records
kit.stop()
```

## How It Works

The canary exposes MCP-compatible tools (JSON-RPC 2.0 over HTTP) that look like high-value targets. All tool call attempts are logged with full request details including timestamps, tool names, arguments, source IPs, and request headers.

Responses are realistic-looking but contain only fake/dummy data.

## Contributing Detection Data

Pass `--contribute` to send anonymized interaction patterns back to the Navil threat intelligence pool. All data is sanitized before transmission:

- No raw arguments or payloads are sent
- Source IPs are not transmitted
- Request headers are stripped
- Individual tool names are hashed (SHA-256)
- Only statistical metadata and tool sequence hashes are shared

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CANARY_PROFILE` | Honeypot profile name |
| `CANARY_HOST` | Bind address |
| `CANARY_PORT` | Bind port |
| `CANARY_CONTRIBUTE` | Enable contribution (`true`/`1`) |
| `CANARY_API_KEY` | API key for contribution (falls back to `NAVIL_API_KEY`) |
| `CANARY_LOG_FILE` | JSON log file path |
| `CANARY_MAX_RECORDS` | Max buffered records |
| `CANARY_VERBOSE` | Verbose logging (`true`/`1`) |

## Standalone Extraction

The canary kit is designed to work independently. The core modules (`server.py`, `config.py`, `reporter.py`) have no imports from navil-core. To extract:

1. Copy the `navil/canary/` directory
2. Install `httpx` for the reporter (optional -- server works without it)
3. Run: `python -m navil.canary --profile dev-tools`
