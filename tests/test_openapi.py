"""Tests for the OpenAPI bridge, server, scanner, and CLI command."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from navil.openapi_bridge import (
    _build_input_schema,
    _derive_tool_name,
    _extract_security_requirements,
    load_spec,
    openapi_to_mcp_config,
    spec_to_tools,
    write_mcp_config,
)
from navil.openapi_scanner import scan_openapi, scan_openapi_spec
from navil.openapi_server import (
    OpenAPIMCPServer,
    _build_url,
    _split_params,
)
from navil.types import Finding

# ---------------------------------------------------------------------------
# Fixtures — reusable OpenAPI specs
# ---------------------------------------------------------------------------

PETSTORE_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "Petstore", "version": "1.0.0"},
    "servers": [{"url": "https://petstore.example.com/v1"}],
    "paths": {
        "/pets": {
            "get": {
                "operationId": "listPets",
                "summary": "List all pets",
                "description": "Returns all pets from the store.",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer"},
                        "description": "Max items to return",
                    }
                ],
                "responses": {
                    "200": {
                        "description": "A list of pets",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Pet"},
                                }
                            }
                        },
                    }
                },
            },
            "post": {
                "operationId": "createPet",
                "summary": "Create a pet",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "tag": {"type": "string"},
                                },
                                "required": ["name"],
                            }
                        }
                    },
                },
                "responses": {
                    "201": {"description": "Created"},
                },
            },
        },
        "/pets/{petId}": {
            "get": {
                "operationId": "getPetById",
                "summary": "Get a pet by ID",
                "parameters": [
                    {
                        "name": "petId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "A pet",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}
                        },
                    }
                },
            },
            "delete": {
                "summary": "Delete a pet",
                "parameters": [
                    {
                        "name": "petId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"204": {"description": "Deleted"}},
            },
        },
    },
    "components": {
        "schemas": {
            "Pet": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                    "tag": {"type": "string"},
                },
                "required": ["id", "name"],
            }
        },
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
            },
            "apiKey": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
            },
        },
    },
    "security": [{"bearerAuth": []}],
}


INSECURE_SPEC: dict[str, Any] = {
    "openapi": "3.1.0",
    "info": {"title": "Insecure API", "version": "0.1.0"},
    "servers": [{"url": "http://localhost:8080"}],
    "paths": {
        "/admin/users": {
            "get": {
                "summary": "List admin users",
                "responses": {},
            },
            "post": {
                "summary": "Create admin user",
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/internal/debug": {
            "get": {
                "summary": "Debug info",
                "deprecated": True,
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/login": {
            "get": {
                "summary": "Login",
                "parameters": [
                    {
                        "name": "password",
                        "in": "query",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "api_key",
                        "in": "query",
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/data": {
            "put": {
                "summary": "Update data",
                "responses": {"200": {"description": "OK"}},
            },
        },
    },
}


@pytest.fixture
def petstore_yaml(tmp_path: Path) -> str:
    """Write the petstore spec to a YAML file and return the path."""
    path = tmp_path / "petstore.yaml"
    path.write_text(yaml.dump(PETSTORE_SPEC, default_flow_style=False))
    return str(path)


@pytest.fixture
def petstore_json(tmp_path: Path) -> str:
    """Write the petstore spec to a JSON file and return the path."""
    path = tmp_path / "petstore.json"
    path.write_text(json.dumps(PETSTORE_SPEC, indent=2))
    return str(path)


@pytest.fixture
def insecure_yaml(tmp_path: Path) -> str:
    """Write the insecure spec to a YAML file and return the path."""
    path = tmp_path / "insecure.yaml"
    path.write_text(yaml.dump(INSECURE_SPEC, default_flow_style=False))
    return str(path)


@pytest.fixture
def swagger2_json(tmp_path: Path) -> str:
    """Write a Swagger 2.0 spec — should be rejected."""
    spec = {"swagger": "2.0", "info": {"title": "Old", "version": "1"}, "paths": {}}
    path = tmp_path / "swagger2.json"
    path.write_text(json.dumps(spec))
    return str(path)


# ===================================================================
# Tests — Spec loading
# ===================================================================


class TestLoadSpec:
    def test_load_yaml(self, petstore_yaml: str) -> None:
        spec = load_spec(petstore_yaml)
        assert spec["openapi"] == "3.0.3"
        assert spec["info"]["title"] == "Petstore"

    def test_load_json(self, petstore_json: str) -> None:
        spec = load_spec(petstore_json)
        assert spec["openapi"] == "3.0.3"

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_spec("/nonexistent/spec.yaml")

    def test_reject_swagger2(self, swagger2_json: str) -> None:
        with pytest.raises(ValueError, match="Only OpenAPI v3.x"):
            load_spec(swagger2_json)

    def test_reject_non_object(self, tmp_path: Path) -> None:
        path = tmp_path / "array.json"
        path.write_text("[1, 2, 3]")
        with pytest.raises(ValueError, match="must be a JSON/YAML object"):
            load_spec(str(path))


# ===================================================================
# Tests — Tool name derivation
# ===================================================================


class TestDeriveToolName:
    def test_with_operation_id(self) -> None:
        name = _derive_tool_name("get", "/pets", {"operationId": "listPets"})
        assert name == "listPets"

    def test_without_operation_id(self) -> None:
        name = _derive_tool_name("get", "/pets/{petId}", {})
        assert name == "get_pets_petId"

    def test_special_characters_cleaned(self) -> None:
        name = _derive_tool_name("post", "/api/v2/users", {"operationId": "create-user.v2"})
        assert name == "create_user_v2"


# ===================================================================
# Tests — Input schema mapping
# ===================================================================


class TestBuildInputSchema:
    def test_path_and_query_params(self) -> None:
        operation = {
            "parameters": [
                {"name": "petId", "in": "path", "required": True, "schema": {"type": "string"}},
                {"name": "limit", "in": "query", "schema": {"type": "integer"}},
            ]
        }
        schema = _build_input_schema(PETSTORE_SPEC, operation, "/pets/{petId}")
        assert "petId" in schema["properties"]
        assert "limit" in schema["properties"]
        assert "petId" in schema["required"]
        assert schema["properties"]["petId"]["x-param-location"] == "path"
        assert schema["properties"]["limit"]["x-param-location"] == "query"

    def test_request_body_object(self) -> None:
        operation = {
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "tag": {"type": "string"},
                            },
                            "required": ["name"],
                        }
                    }
                },
            }
        }
        schema = _build_input_schema(PETSTORE_SPEC, operation, "/pets")
        assert "name" in schema["properties"]
        assert "tag" in schema["properties"]
        assert "name" in schema["required"]
        assert schema["properties"]["name"]["x-param-location"] == "body"

    def test_request_body_non_object(self) -> None:
        operation = {
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": {"type": "string"}}},
            }
        }
        schema = _build_input_schema(PETSTORE_SPEC, operation, "/upload")
        assert "body" in schema["properties"]
        assert "body" in schema["required"]

    def test_ref_parameter(self) -> None:
        """Parameters with $ref should be resolved."""
        spec = dict(PETSTORE_SPEC)
        spec["components"] = dict(spec.get("components", {}))
        spec["components"]["parameters"] = {
            "LimitParam": {
                "name": "limit",
                "in": "query",
                "schema": {"type": "integer"},
                "description": "Max results",
            }
        }
        operation = {"parameters": [{"$ref": "#/components/parameters/LimitParam"}]}
        schema = _build_input_schema(spec, operation, "/items")
        assert "limit" in schema["properties"]
        assert schema["properties"]["limit"]["description"] == "Max results"


# ===================================================================
# Tests — spec_to_tools
# ===================================================================


class TestSpecToTools:
    def test_all_endpoints(self) -> None:
        tools = spec_to_tools(PETSTORE_SPEC)
        names = {t["name"] for t in tools}
        assert "listPets" in names
        assert "createPet" in names
        assert "getPetById" in names
        # delete has no operationId — derived name
        assert any("delete" in n.lower() for n in names)

    def test_tool_has_required_fields(self) -> None:
        tools = spec_to_tools(PETSTORE_SPEC)
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool
            assert "method" in tool
            assert "path" in tool
            assert tool["inputSchema"]["type"] == "object"

    def test_filter_get_only(self) -> None:
        tools = spec_to_tools(PETSTORE_SPEC, filter_pattern="GET*")
        assert len(tools) == 2
        assert all(t["method"] == "GET" for t in tools)

    def test_filter_path_pattern(self) -> None:
        tools = spec_to_tools(PETSTORE_SPEC, filter_pattern="*/pets/*")
        # Should match /pets/{petId} endpoints
        assert all("/pets/" in t["path"] for t in tools)

    def test_description_combines_summary_and_desc(self) -> None:
        tools = spec_to_tools(PETSTORE_SPEC)
        list_pets = next(t for t in tools if t["name"] == "listPets")
        assert "List all pets" in list_pets["description"]
        assert "Returns all pets" in list_pets["description"]

    def test_deprecated_flag_preserved(self) -> None:
        tools = spec_to_tools(INSECURE_SPEC)
        debug_tool = next((t for t in tools if "/internal/debug" in t["path"]), None)
        assert debug_tool is not None
        assert debug_tool["deprecated"] is True


# ===================================================================
# Tests — Security scheme extraction
# ===================================================================


class TestSecuritySchemes:
    def test_extract_bearer_and_apikey(self) -> None:
        reqs = _extract_security_requirements(PETSTORE_SPEC)
        names = {r["name"] for r in reqs}
        assert "bearerAuth" in names
        assert "apiKey" in names

    def test_bearer_scheme_details(self) -> None:
        reqs = _extract_security_requirements(PETSTORE_SPEC)
        bearer = next(r for r in reqs if r["name"] == "bearerAuth")
        assert bearer["type"] == "http"
        assert bearer["scheme"] == "bearer"

    def test_apikey_details(self) -> None:
        reqs = _extract_security_requirements(PETSTORE_SPEC)
        ak = next(r for r in reqs if r["name"] == "apiKey")
        assert ak["type"] == "apiKey"
        assert ak["in"] == "header"
        assert ak["param_name"] == "X-API-Key"

    def test_no_security_schemes(self) -> None:
        spec = {"openapi": "3.0.0", "components": {}}
        reqs = _extract_security_requirements(spec)
        assert reqs == []

    def test_oauth2_scheme(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "oauth": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "https://example.com/auth",
                                "tokenUrl": "https://example.com/token",
                            }
                        },
                    }
                }
            },
        }
        reqs = _extract_security_requirements(spec)
        assert len(reqs) == 1
        assert reqs[0]["type"] == "oauth2"
        assert "authorizationCode" in reqs[0]["flows"]


# ===================================================================
# Tests — MCP config generation (end-to-end)
# ===================================================================


class TestOpenAPIToMCPConfig:
    def test_generates_valid_config(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml)
        mcp = result["mcp_config"]
        assert "mcpServers" in mcp
        assert "petstore" in mcp["mcpServers"]
        server = mcp["mcpServers"]["petstore"]
        assert server["command"] == "navil"
        assert server["args"][0] == "shim"

    def test_shim_args_contain_cmd(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml)
        server = result["mcp_config"]["mcpServers"]["petstore"]
        args = server["args"]
        assert "--cmd" in args
        cmd_idx = args.index("--cmd")
        assert "navil.openapi_server" in args[cmd_idx + 1]

    def test_tools_count(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml)
        # listPets, createPet, getPetById, delete_pets_petId = 4
        assert result["tools_count"] == 4

    def test_base_url(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml)
        assert result["base_url"] == "https://petstore.example.com/v1"

    def test_bridge_config_written(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml)
        bridge_path = Path(result["bridge_config_path"])
        assert bridge_path.exists()
        bridge = json.loads(bridge_path.read_text())
        assert "tools" in bridge
        assert "base_url" in bridge

    def test_custom_api_name(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml, api_name="my_api")
        assert result["server_name"] == "my_api"
        assert "my_api" in result["mcp_config"]["mcpServers"]

    def test_with_filter(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml, filter_pattern="GET*")
        assert result["tools_count"] == 2

    def test_with_policy(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml, policy_path="/tmp/policy.yaml")
        server = result["mcp_config"]["mcpServers"]["petstore"]
        assert "--policy" in server["args"]
        assert "/tmp/policy.yaml" in server["args"]

    def test_security_schemes_listed(self, petstore_yaml: str) -> None:
        result = openapi_to_mcp_config(petstore_yaml)
        assert "bearerAuth" in result["security_schemes"]
        assert "apiKey" in result["security_schemes"]

    def test_write_mcp_config(self, petstore_yaml: str, tmp_path: Path) -> None:
        result = openapi_to_mcp_config(petstore_yaml)
        config_file = write_mcp_config(result, str(tmp_path))
        assert Path(config_file).exists()
        written = json.loads(Path(config_file).read_text())
        assert "mcpServers" in written


# ===================================================================
# Tests — OpenAPI MCP Server
# ===================================================================


class TestOpenAPIMCPServer:
    @pytest.fixture
    def server(self) -> OpenAPIMCPServer:
        tools = spec_to_tools(PETSTORE_SPEC)
        config = {
            "base_url": "https://petstore.example.com/v1",
            "tools": tools,
            "security": [],
        }
        return OpenAPIMCPServer(config)

    @pytest.mark.asyncio
    async def test_initialize(self, server: OpenAPIMCPServer) -> None:
        msg = json.dumps({"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}).encode()
        resp_bytes = await server.handle_message(msg)
        assert resp_bytes is not None
        resp = json.loads(resp_bytes)
        assert resp["id"] == 1
        assert "protocolVersion" in resp["result"]
        assert resp["result"]["capabilities"]["tools"]["listChanged"] is False

    @pytest.mark.asyncio
    async def test_tools_list(self, server: OpenAPIMCPServer) -> None:
        msg = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 2}).encode()
        resp_bytes = await server.handle_message(msg)
        resp = json.loads(resp_bytes)
        tools = resp["result"]["tools"]
        assert len(tools) == 4
        names = {t["name"] for t in tools}
        assert "listPets" in names
        assert "createPet" in names

    @pytest.mark.asyncio
    async def test_tools_list_no_internal_fields(self, server: OpenAPIMCPServer) -> None:
        msg = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 3}).encode()
        resp_bytes = await server.handle_message(msg)
        resp = json.loads(resp_bytes)
        for tool in resp["result"]["tools"]:
            for prop in tool["inputSchema"].get("properties", {}).values():
                assert "x-param-location" not in prop

    @pytest.mark.asyncio
    async def test_unknown_tool(self, server: OpenAPIMCPServer) -> None:
        msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "nonexistent", "arguments": {}},
                "id": 4,
            }
        ).encode()
        resp_bytes = await server.handle_message(msg)
        resp = json.loads(resp_bytes)
        assert "error" in resp
        assert resp["error"]["code"] == -32602

    @pytest.mark.asyncio
    async def test_unknown_method(self, server: OpenAPIMCPServer) -> None:
        msg = json.dumps(
            {"jsonrpc": "2.0", "method": "resources/list", "params": {}, "id": 5}
        ).encode()
        resp_bytes = await server.handle_message(msg)
        resp = json.loads(resp_bytes)
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_notification_returns_none(self, server: OpenAPIMCPServer) -> None:
        msg = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        ).encode()
        resp_bytes = await server.handle_message(msg)
        assert resp_bytes is None

    @pytest.mark.asyncio
    async def test_ping(self, server: OpenAPIMCPServer) -> None:
        msg = json.dumps({"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 6}).encode()
        resp_bytes = await server.handle_message(msg)
        resp = json.loads(resp_bytes)
        assert resp["id"] == 6
        assert "result" in resp

    @pytest.mark.asyncio
    async def test_parse_error(self, server: OpenAPIMCPServer) -> None:
        resp_bytes = await server.handle_message(b"not json at all")
        resp = json.loads(resp_bytes)
        assert resp["error"]["code"] == -32700


# ===================================================================
# Tests — URL building and param splitting
# ===================================================================


class TestURLBuilding:
    def test_build_url_with_path_params(self) -> None:
        url = _build_url("https://api.example.com/v1", "/pets/{petId}", {"petId": "42"})
        assert url == "https://api.example.com/v1/pets/42"

    def test_build_url_no_params(self) -> None:
        url = _build_url("https://api.example.com/v1", "/pets", {})
        assert url == "https://api.example.com/v1/pets"

    def test_build_url_trailing_slash(self) -> None:
        url = _build_url("https://api.example.com/v1/", "/pets", {})
        assert url == "https://api.example.com/v1/pets"

    def test_split_params(self) -> None:
        tool_def = {
            "inputSchema": {
                "properties": {
                    "petId": {"type": "string", "x-param-location": "path"},
                    "limit": {"type": "integer", "x-param-location": "query"},
                    "name": {"type": "string", "x-param-location": "body"},
                }
            }
        }
        path_p, query_p, body_p = _split_params(
            tool_def, {"petId": "1", "limit": 10, "name": "Fido"}
        )
        assert path_p == {"petId": "1"}
        assert query_p == {"limit": 10}
        assert body_p == {"name": "Fido"}


# ===================================================================
# Tests — OpenAPI Security Scanner
# ===================================================================


class TestOpenAPIScanner:
    def test_no_auth_on_mutating(self) -> None:
        """POST/PUT/DELETE without security should be flagged."""
        findings = scan_openapi_spec(INSECURE_SPEC)
        no_auth = [f for f in findings if f.id == "OPENAPI-NO-AUTH"]
        # POST /admin/users and PUT /data have no auth
        assert len(no_auth) >= 2

    def test_no_auth_skipped_with_global_security(self) -> None:
        """Endpoints with global security should not be flagged."""
        findings = scan_openapi_spec(PETSTORE_SPEC)
        no_auth = [f for f in findings if f.id == "OPENAPI-NO-AUTH"]
        assert len(no_auth) == 0

    def test_missing_rate_limits(self) -> None:
        findings = scan_openapi_spec(INSECURE_SPEC)
        rl = [f for f in findings if f.id == "OPENAPI-NO-RATELIMIT"]
        assert len(rl) == 1

    def test_sensitive_data_in_query(self) -> None:
        findings = scan_openapi_spec(INSECURE_SPEC)
        sensitive = [f for f in findings if f.id == "OPENAPI-SENSITIVE-QUERY"]
        names = {f.affected_field for f in sensitive}
        assert any("password" in n for n in names)
        assert any("api_key" in n for n in names)

    def test_internal_endpoints(self) -> None:
        findings = scan_openapi_spec(INSECURE_SPEC)
        internal = [f for f in findings if f.id == "OPENAPI-INTERNAL-EXPOSED"]
        paths = {f.affected_field for f in internal}
        assert any("/admin" in p for p in paths)
        assert any("/internal" in p or "/debug" in p for p in paths)

    def test_deprecated_endpoints(self) -> None:
        findings = scan_openapi_spec(INSECURE_SPEC)
        deprecated = [f for f in findings if f.id == "OPENAPI-DEPRECATED"]
        assert len(deprecated) >= 1
        assert any("/internal/debug" in f.evidence for f in deprecated)

    def test_missing_response_schemas(self) -> None:
        findings = scan_openapi_spec(INSECURE_SPEC)
        no_schema = [f for f in findings if f.id == "OPENAPI-NO-RESPONSE-SCHEMA"]
        # Most endpoints in INSECURE_SPEC lack response schemas
        assert len(no_schema) >= 1

    def test_missing_body_schema(self) -> None:
        findings = scan_openapi_spec(INSECURE_SPEC)
        no_body = [f for f in findings if f.id == "OPENAPI-NO-BODY-SCHEMA"]
        # POST /admin/users and PUT /data have no requestBody
        assert len(no_body) >= 2

    def test_cors_wildcard(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "CORS Test", "version": "1"},
            "paths": {},
            "x-cors": {"Access-Control-Allow-Origin": "*"},
        }
        findings = scan_openapi_spec(spec)
        cors = [f for f in findings if f.id == "OPENAPI-CORS-WILDCARD"]
        assert len(cors) == 1

    def test_clean_spec_minimal_findings(self) -> None:
        """A well-secured spec should produce only informational findings."""
        findings = scan_openapi_spec(PETSTORE_SPEC)
        high_or_critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert len(high_or_critical) == 0

    def test_scan_from_file(self, petstore_yaml: str) -> None:
        findings = scan_openapi(petstore_yaml)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

    def test_scan_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            scan_openapi("/nonexistent/spec.yaml")

    def test_findings_have_correct_source(self) -> None:
        findings = scan_openapi_spec(INSECURE_SPEC)
        for f in findings:
            assert f.source == "openapi-scanner"


# ===================================================================
# Tests — CLI command registration
# ===================================================================


class TestCLIRegistration:
    def test_openapi_command_registers(self) -> None:
        """The openapi module should register without errors."""
        import argparse

        from navil.commands.openapi import register

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub, type)  # cli_class not used in handlers

        # Parse a valid wrap command
        args = parser.parse_args(["openapi", "wrap", "test.yaml", "--dry-run"])
        assert args.spec == "test.yaml"
        assert args.dry_run is True

    def test_scan_command_parses(self) -> None:
        import argparse

        from navil.commands.openapi import register

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub, type)

        args = parser.parse_args(["openapi", "scan", "api.yaml", "-f", "json"])
        assert args.spec == "api.yaml"
        assert args.format == "json"

    def test_serve_command_parses(self) -> None:
        import argparse

        from navil.commands.openapi import register

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub, type)

        args = parser.parse_args(["openapi", "serve", "api.yaml", "--filter", "GET*"])
        assert args.spec == "api.yaml"
        assert args.filter == "GET*"

    def test_wrap_with_all_options(self) -> None:
        import argparse

        from navil.commands.openapi import register

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub, type)

        args = parser.parse_args(
            [
                "openapi",
                "wrap",
                "spec.yaml",
                "--output",
                "/tmp/out",
                "--name",
                "my_api",
                "--policy",
                "policy.yaml",
                "--filter",
                "POST*",
                "--dry-run",
            ]
        )
        assert args.output == "/tmp/out"
        assert args.name == "my_api"
        assert args.policy == "policy.yaml"
        assert args.filter == "POST*"
        assert args.dry_run is True


# ===================================================================
# Tests — CLI command execution (integration)
# ===================================================================


class TestCLIExecution:
    def test_wrap_dry_run(self, petstore_yaml: str, capsys) -> None:
        import argparse

        from navil.commands.openapi import _openapi_wrap

        args = argparse.Namespace(
            spec=petstore_yaml,
            filter=None,
            output=None,
            dry_run=True,
            name=None,
            policy=None,
        )
        ret = _openapi_wrap(None, args)
        assert ret == 0
        captured = capsys.readouterr()
        # dry-run prints JSON to stdout
        config = json.loads(captured.out)
        assert "mcpServers" in config

    def test_wrap_writes_files(self, petstore_yaml: str, tmp_path: Path) -> None:
        import argparse

        from navil.commands.openapi import _openapi_wrap

        args = argparse.Namespace(
            spec=petstore_yaml,
            filter=None,
            output=str(tmp_path),
            dry_run=False,
            name=None,
            policy=None,
        )
        ret = _openapi_wrap(None, args)
        assert ret == 0
        # Should have created the MCP config file
        mcp_files = list(tmp_path.glob("navil-openapi-*-mcp.json"))
        assert len(mcp_files) == 1

    def test_wrap_nonexistent_spec(self, capsys) -> None:
        import argparse

        from navil.commands.openapi import _openapi_wrap

        args = argparse.Namespace(
            spec="/nonexistent.yaml",
            filter=None,
            output=None,
            dry_run=True,
            name=None,
            policy=None,
        )
        ret = _openapi_wrap(None, args)
        assert ret == 1

    def test_scan_text_output(self, insecure_yaml: str, capsys) -> None:
        import argparse

        from navil.commands.openapi import _openapi_scan

        args = argparse.Namespace(
            spec=insecure_yaml,
            format="text",
            output=None,
        )
        ret = _openapi_scan(None, args)
        assert ret == 1  # findings found
        captured = capsys.readouterr()
        assert "issue(s)" in captured.out

    def test_scan_json_output(self, insecure_yaml: str, capsys) -> None:
        import argparse

        from navil.commands.openapi import _openapi_scan

        args = argparse.Namespace(
            spec=insecure_yaml,
            format="json",
            output=None,
        )
        ret = _openapi_scan(None, args)
        assert ret == 1
        captured = capsys.readouterr()
        findings = json.loads(captured.out)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_scan_clean_spec(self, petstore_yaml: str, capsys) -> None:
        import argparse

        from navil.commands.openapi import _openapi_scan

        args = argparse.Namespace(
            spec=petstore_yaml,
            format="text",
            output=None,
        )
        # Petstore may still have some low-severity findings
        _openapi_scan(None, args)


# ===================================================================
# Tests — Edge cases
# ===================================================================


class TestEdgeCases:
    def test_empty_paths(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Empty", "version": "1"},
            "paths": {},
        }
        tools = spec_to_tools(spec)
        assert tools == []

    def test_openapi_31(self, tmp_path: Path) -> None:
        """OpenAPI 3.1 should be accepted."""
        spec = {
            "openapi": "3.1.0",
            "info": {"title": "Test 3.1", "version": "1"},
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "getItems",
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        path = tmp_path / "spec31.json"
        path.write_text(json.dumps(spec))
        loaded = load_spec(str(path))
        assert loaded["openapi"] == "3.1.0"
        tools = spec_to_tools(loaded)
        assert len(tools) == 1

    def test_no_servers_defaults_to_localhost(self, tmp_path: Path) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "No Servers", "version": "1"},
            "paths": {"/health": {"get": {"responses": {"200": {"description": "OK"}}}}},
        }
        path = tmp_path / "noservers.yaml"
        path.write_text(yaml.dump(spec))
        result = openapi_to_mcp_config(str(path))
        assert result["base_url"] == "http://localhost"

    def test_multiple_path_params(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Multi", "version": "1"},
            "paths": {
                "/orgs/{orgId}/repos/{repoId}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "orgId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                            {
                                "name": "repoId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                        ],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        tools = spec_to_tools(spec)
        assert len(tools) == 1
        schema = tools[0]["inputSchema"]
        assert "orgId" in schema["properties"]
        assert "repoId" in schema["properties"]
        assert "orgId" in schema["required"]
        assert "repoId" in schema["required"]

    def test_operation_without_responses(self) -> None:
        """Operations without responses should still generate tools."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1"},
            "paths": {"/fire-and-forget": {"post": {"operationId": "fireAndForget"}}},
        }
        tools = spec_to_tools(spec)
        assert len(tools) == 1
        assert tools[0]["name"] == "fireAndForget"
