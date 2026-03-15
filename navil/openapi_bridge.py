"""OpenAPI-to-MCP bridge — converts OpenAPI v3.0/v3.1 specs into MCP server configurations.

Reads an OpenAPI spec (YAML or JSON), maps each endpoint to an MCP tool, and
generates a Navil-wrapped MCP config that routes tool calls through the
``navil shim`` proxy to the real REST API.

Usage (programmatic):
    from navil.openapi_bridge import openapi_to_mcp_config
    config = openapi_to_mcp_config("petstore.yaml")

Usage (CLI):
    navil openapi wrap petstore.yaml
    navil openapi wrap petstore.yaml --output ./out --dry-run
"""

from __future__ import annotations

import json
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Spec loading
# ---------------------------------------------------------------------------


def load_spec(spec_path: str) -> dict[str, Any]:
    """Load an OpenAPI spec from a YAML or JSON file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the spec is not OpenAPI v3.x.
    """
    path = Path(spec_path)
    if not path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {spec_path}")

    raw = path.read_text()

    if path.suffix in (".yaml", ".yml"):
        import yaml

        spec = yaml.safe_load(raw)
    else:
        spec = json.loads(raw)

    if not isinstance(spec, dict):
        raise ValueError("OpenAPI spec must be a JSON/YAML object")

    # Validate version
    openapi_version = spec.get("openapi", "")
    if not openapi_version.startswith("3."):
        raise ValueError(
            f"Only OpenAPI v3.x is supported (got '{openapi_version}'). "
            "Swagger 2.x specs must be converted first."
        )

    return spec


# ---------------------------------------------------------------------------
# Ref resolution (minimal, single-file)
# ---------------------------------------------------------------------------


def _resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    """Resolve a ``$ref`` pointer within the spec (e.g. ``#/components/schemas/Pet``)."""
    if not ref.startswith("#/"):
        return {}
    parts = ref.lstrip("#/").split("/")
    node: Any = spec
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part, {})
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _deref(spec: dict[str, Any], obj: dict[str, Any]) -> dict[str, Any]:
    """If *obj* is a ``$ref``, resolve it; otherwise return *obj* unchanged."""
    if "$ref" in obj:
        return _resolve_ref(spec, obj["$ref"])
    return obj


# ---------------------------------------------------------------------------
# Tool name derivation
# ---------------------------------------------------------------------------

_CLEAN_RE = re.compile(r"[^a-zA-Z0-9_]")


def _derive_tool_name(method: str, path: str, operation: dict[str, Any]) -> str:
    """Derive an MCP tool name from an OpenAPI operation.

    Prefers ``operationId`` if present; otherwise synthesises from method + path.
    """
    op_id = operation.get("operationId")
    if op_id:
        return _CLEAN_RE.sub("_", op_id)

    # e.g. GET /pets/{petId} -> get_pets_petId
    segments = path.strip("/").replace("{", "").replace("}", "")
    name = f"{method}_{segments}".replace("/", "_").replace("-", "_")
    return _CLEAN_RE.sub("_", name)


# ---------------------------------------------------------------------------
# Schema mapping
# ---------------------------------------------------------------------------


def _build_input_schema(
    spec: dict[str, Any],
    operation: dict[str, Any],
    path: str,
) -> dict[str, Any]:
    """Build a JSON Schema ``inputSchema`` from path/query params + request body."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    # Path parameters
    path_params = operation.get("parameters", [])
    for param in path_params:
        param = _deref(spec, param)
        name = param.get("name", "")
        if not name:
            continue
        schema = _deref(spec, param.get("schema", {}))
        prop: dict[str, Any] = dict(schema)
        description = param.get("description", "")
        if description:
            prop["description"] = description
        location = param.get("in", "query")
        prop["x-param-location"] = location
        properties[name] = prop
        if param.get("required", False) or location == "path":
            required.append(name)

    # Request body
    request_body = operation.get("requestBody", {})
    if request_body:
        request_body = _deref(spec, request_body)
        content = request_body.get("content", {})
        # Prefer application/json
        media = content.get("application/json", content.get(next(iter(content), ""), {}))
        body_schema = _deref(spec, media.get("schema", {}))
        if body_schema:
            # Inline body schema properties
            if body_schema.get("type") == "object" and "properties" in body_schema:
                for prop_name, prop_schema in body_schema["properties"].items():
                    prop_schema = _deref(spec, prop_schema)
                    properties[prop_name] = dict(prop_schema)
                    properties[prop_name]["x-param-location"] = "body"
                for r in body_schema.get("required", []):
                    if r not in required:
                        required.append(r)
            else:
                # Non-object body — wrap as "body" property
                properties["body"] = dict(body_schema)
                properties["body"]["x-param-location"] = "body"
                if request_body.get("required", False):
                    required.append("body")

    input_schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        input_schema["required"] = required
    return input_schema


# ---------------------------------------------------------------------------
# Security scheme mapping
# ---------------------------------------------------------------------------


def _extract_security_requirements(
    spec: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract credential requirements from the spec's security schemes."""
    schemes = spec.get("components", {}).get("securitySchemes", {})
    requirements: list[dict[str, Any]] = []

    for name, scheme in schemes.items():
        scheme = _deref(spec, scheme)
        scheme_type = scheme.get("type", "")
        req: dict[str, Any] = {"name": name, "type": scheme_type}

        if scheme_type == "apiKey":
            req["in"] = scheme.get("in", "header")
            req["param_name"] = scheme.get("name", name)
        elif scheme_type == "http":
            req["scheme"] = scheme.get("scheme", "bearer")
        elif scheme_type == "oauth2":
            flows = scheme.get("flows", {})
            req["flows"] = list(flows.keys())
        elif scheme_type == "openIdConnect":
            req["openIdConnectUrl"] = scheme.get("openIdConnectUrl", "")

        requirements.append(req)

    return requirements


# ---------------------------------------------------------------------------
# Endpoint -> tool conversion
# ---------------------------------------------------------------------------

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def _should_include(method: str, path: str, filter_pattern: str | None) -> bool:
    """Check if an endpoint matches the optional filter pattern.

    Patterns use fnmatch-style matching against ``METHOD path``, e.g.
    ``GET*`` matches all GET endpoints, ``*/pets*`` matches any method on /pets.
    """
    if filter_pattern is None:
        return True
    label = f"{method.upper()} {path}"
    return fnmatch(label, filter_pattern)


def spec_to_tools(
    spec: dict[str, Any],
    *,
    filter_pattern: str | None = None,
) -> list[dict[str, Any]]:
    """Convert every OpenAPI endpoint into an MCP tool descriptor.

    Returns a list of dicts, each with keys: ``name``, ``description``,
    ``inputSchema``, ``method``, ``path``.
    """
    tools: list[dict[str, Any]] = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            if not isinstance(operation, dict):
                continue

            if not _should_include(method, path, filter_pattern):
                continue

            # Skip deprecated by default (scanner can flag them)
            # but still include them so the scanner can report

            tool_name = _derive_tool_name(method, path, operation)
            summary = operation.get("summary", "")
            description = operation.get("description", summary)
            if summary and description and summary != description:
                description = f"{summary}. {description}"
            elif summary and not description:
                description = summary

            input_schema = _build_input_schema(spec, operation, path)

            tools.append(
                {
                    "name": tool_name,
                    "description": description or f"{method.upper()} {path}",
                    "inputSchema": input_schema,
                    "method": method.upper(),
                    "path": path,
                    "deprecated": operation.get("deprecated", False),
                    "tags": operation.get("tags", []),
                }
            )

    return tools


# ---------------------------------------------------------------------------
# MCP config generation
# ---------------------------------------------------------------------------


def openapi_to_mcp_config(
    spec_path: str,
    *,
    filter_pattern: str | None = None,
    api_name: str | None = None,
    policy_path: str | None = None,
) -> dict[str, Any]:
    """Convert an OpenAPI spec file into a Navil-wrapped MCP config.

    Args:
        spec_path: Path to the OpenAPI spec (YAML or JSON).
        filter_pattern: Optional fnmatch pattern to filter endpoints.
        api_name: Override the server name in the config (defaults to spec title).
        policy_path: Navil policy file to attach.

    Returns:
        A dict representing the MCP client config (``mcpServers`` key).
    """
    spec = load_spec(spec_path)
    tools = spec_to_tools(spec, filter_pattern=filter_pattern)

    # Derive server name
    title = spec.get("info", {}).get("title", "api")
    name = api_name or _CLEAN_RE.sub("_", title).lower().strip("_") or "api"

    # Target server URL
    servers = spec.get("servers", [])
    base_url = servers[0]["url"] if servers else "http://localhost"

    # Security requirements
    security_reqs = _extract_security_requirements(spec)

    # Build the bridge config that the openapi_server reads at runtime
    bridge_config: dict[str, Any] = {
        "spec_path": str(Path(spec_path).resolve()),
        "base_url": base_url,
        "tools": tools,
        "security": security_reqs,
    }

    # Write bridge config alongside the spec
    spec_dir = Path(spec_path).resolve().parent
    config_filename = f".navil-openapi-{name}.json"
    config_path = spec_dir / config_filename

    config_path.write_text(json.dumps(bridge_config, indent=2) + "\n")

    # Build the shim command
    bridge_cmd = f"python -m navil.openapi_server {config_path}"

    shim_args = ["shim", "--cmd", bridge_cmd, "--agent", f"navil-openapi-{name}"]
    if policy_path:
        shim_args.extend(["--policy", policy_path])

    mcp_config: dict[str, Any] = {
        "mcpServers": {
            name: {
                "command": "navil",
                "args": shim_args,
                "env": {},
            }
        }
    }

    return {
        "mcp_config": mcp_config,
        "bridge_config_path": str(config_path),
        "tools_count": len(tools),
        "base_url": base_url,
        "server_name": name,
        "security_schemes": [s["name"] for s in security_reqs],
    }


def write_mcp_config(result: dict[str, Any], output_dir: str | None = None) -> str:
    """Write the generated MCP config to disk.

    Returns the path of the written config file.
    """
    mcp_config = result["mcp_config"]
    name = result["server_name"]

    if output_dir:
        out = Path(output_dir)
    else:
        out = Path(result["bridge_config_path"]).parent

    config_file = out / f"navil-openapi-{name}-mcp.json"
    config_file.write_text(json.dumps(mcp_config, indent=2) + "\n")
    return str(config_file)
