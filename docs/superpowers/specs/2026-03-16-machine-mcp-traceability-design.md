# Machine & MCP Server Traceability

**Date:** 2026-03-16
**Status:** Implementing

## Problem

When the cloud dashboard shows a spike in attacks (e.g., `prompt_injection`, `data_exfiltration`), there's no way to trace which **machine** or **MCP server** is the target. The telemetry pipeline strips infrastructure details for privacy, but this makes incident response impossible for organizations running multiple machines with multiple MCP servers.

## Solution

Add two low-privacy-risk identifiers to the telemetry pipeline:

| Field | Source | Privacy Risk | Purpose |
|-------|--------|-------------|---------|
| `machine_id` | UUID4, auto-generated during `navil init` | None — random UUID, no PII | Identify which machine is under attack |
| `machine_label` | Optional user-defined string | Low — user controls it | Human-readable machine name |
| `mcp_server_name` | Config key from `navil wrap config.json` | Low — user-defined label | Identify which MCP server is the attack vector |

## Architecture

### Data Flow

```
navil init (generates machine_id → ~/.navil/config.yaml)
    ↓
navil wrap config.json (MCP names: "filesystem", "github", etc.)
    ↓
navil shim --agent navil-filesystem (agent_name carries MCP identity)
    ↓
telemetry_event.py (adds machine_id from config)
    ↓
anomaly_detector.py (ToolInvocation + AnomalyAlert carry machine_id, mcp_server_name)
    ↓
CloudSyncWorker (machine_id + mcp_server_name in ALLOWED_FIELDS)
    ↓
POST /v1/telemetry/sync (new optional fields in schema)
    ↓
sync_events table (new indexed columns)
    ↓
GET /v1/admin/machines (aggregated view)
```

### Config Format

```yaml
# ~/.navil/config.yaml
machine:
  id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  label: "prod-server-1"  # optional
cloud:
  api_key: navil_live_...
  backend_url: https://api.navil.ai
  sync_enabled: true
```

## Changes by Repository

### navil (local agent)

1. **`navil init`** — generate `machine.id` (UUID4), accept `--machine-label` flag
2. **Config loading** — expose `machine_id` and `machine_label` from config
3. **`telemetry_event.py`** — add `machine_id` parameter
4. **`anomaly_detector.py`** — add fields to `ToolInvocation` and `AnomalyAlert` dataclasses
5. **`cloud/telemetry_sync.py`** — add to `ALLOWED_FIELDS`, pass through in sanitization
6. **`cloud/models.py`** — add columns to local Event and Alert tables
7. **Local API** — expose machine_id/label in overview or settings endpoint

### navil-cloud-backend

1. **`models/sync_event.py`** — add `machine_id` (String 256, nullable, indexed) and `mcp_server_name` (String 256, nullable)
2. **`schemas/sync.py`** — add optional fields to SyncEvent schema
3. **`api/v1/telemetry_sync.py`** — include new fields in batch insert
4. **`schemas/admin.py`** — add `MachineInfo` and `MachinesResponse` schemas
5. **`api/v1/admin.py`** — add `GET /v1/admin/machines` endpoint
6. **Alembic migration** — add columns to `sync_events` table

### navil-cloud-frontend

1. **`hooks/useAdminData.ts`** — add `useAdminMachines()` hook
2. **`app/admin/machines/page.tsx`** — machines & MCP servers table
3. **Admin sidebar** — add "Machines" navigation link

### navil/dashboard (OSS)

1. **`pages/Settings.tsx`** — show machine_id and label in About section

## Privacy Model

- `machine_id` is a random UUID — reveals nothing about the host
- `machine_label` is user-controlled — they choose what to share
- `mcp_server_name` comes from user's config keys — already user-defined
- `target_server` (actual MCP URL) remains BANNED — infrastructure topology stays private
- No hostnames, IPs, or file paths leak to the cloud

## Backward Compatibility

- Both fields are nullable — existing events without machine_id continue to work
- Older navil clients that don't send these fields won't break the sync endpoint
- Cloud dashboard shows "Unknown" for events without machine_id
