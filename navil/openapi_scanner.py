"""OpenAPI Security Scanner — checks OpenAPI specs for common security issues.

Extends Navil's scanning capabilities to OpenAPI v3.x specs, emitting
:class:`~navil.types.Finding` objects for SARIF compatibility.

Checks performed:
    1. No authentication on sensitive endpoints (POST/PUT/DELETE)
    2. Missing rate limits (no x-ratelimit-* headers documented)
    3. Overly permissive CORS (* in allowed origins)
    4. Sensitive data in query strings (passwords, tokens in GET params)
    5. Missing input validation (no schema on request bodies)
    6. Internal endpoints exposed (/admin, /internal, /debug paths)
    7. Deprecated endpoints still active
    8. Missing response schemas

Usage:
    from navil.openapi_scanner import scan_openapi
    findings = scan_openapi("petstore.yaml")
"""

from __future__ import annotations

import re
from typing import Any

from navil.openapi_bridge import _deref, load_spec
from navil.types import Finding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MUTATING_METHODS = {"post", "put", "patch", "delete"}
_ALL_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

_INTERNAL_PATH_PATTERNS = re.compile(
    r"(?i)(/admin|/internal|/debug|/healthz|/metrics|/_private|/management)"
)

_SENSITIVE_PARAM_PATTERNS = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api_?key|access_?key|auth|credential|ssn|credit_?card)"
)

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_no_auth_on_sensitive(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag mutating endpoints that lack authentication."""
    global_security = spec.get("security", [])
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in _MUTATING_METHODS:
            operation = path_item.get(method)
            if operation is None or not isinstance(operation, dict):
                continue

            # Operation-level security overrides global
            op_security = operation.get("security", global_security)
            if not op_security or op_security == [{}]:
                findings.append(
                    Finding(
                        id="OPENAPI-NO-AUTH",
                        title="No authentication on mutating endpoint",
                        description=(
                            f"{method.upper()} {path} has no security requirement. "
                            "Mutating endpoints should require authentication."
                        ),
                        severity="HIGH",
                        source="openapi-scanner",
                        affected_field=f"paths.{path}.{method}.security",
                        remediation=(
                            "Add a security requirement referencing an appropriate "
                            "security scheme (e.g. bearerAuth, apiKey)."
                        ),
                        evidence=f"No security defined for {method.upper()} {path}",
                    )
                )


def _check_missing_rate_limits(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag specs that document no rate-limit headers anywhere."""
    spec_str = str(spec).lower()
    has_rate_limit = any(
        marker in spec_str
        for marker in ("x-ratelimit", "x-rate-limit", "ratelimit", "rate-limit", "retry-after")
    )

    if not has_rate_limit:
        findings.append(
            Finding(
                id="OPENAPI-NO-RATELIMIT",
                title="No rate-limit documentation",
                description=(
                    "The spec does not document any rate-limit headers "
                    "(x-ratelimit-limit, x-ratelimit-remaining, Retry-After). "
                    "Without rate limits, APIs are vulnerable to abuse."
                ),
                severity="MEDIUM",
                source="openapi-scanner",
                affected_field="responses.headers",
                remediation=(
                    "Document rate-limit response headers (x-ratelimit-limit, "
                    "x-ratelimit-remaining, x-ratelimit-reset) on relevant endpoints."
                ),
            )
        )


def _check_permissive_cors(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag overly permissive CORS (wildcard origin)."""
    spec_str = str(spec)

    # Check for * in Access-Control-Allow-Origin or x-cors-allow-origin
    if re.search(
        r"(?i)(access-control-allow-origin|x-cors-allow-origin|allowedOrigins)" r"[\"':\s]+\*",
        spec_str,
    ):
        findings.append(
            Finding(
                id="OPENAPI-CORS-WILDCARD",
                title="Overly permissive CORS configuration",
                description=(
                    "The API allows requests from any origin (*). "
                    "This can expose the API to cross-site attacks."
                ),
                severity="MEDIUM",
                source="openapi-scanner",
                affected_field="x-cors / headers",
                remediation=(
                    "Restrict Access-Control-Allow-Origin to specific trusted domains "
                    "instead of using a wildcard (*)."
                ),
                evidence="Wildcard (*) found in CORS origin configuration",
            )
        )


def _check_sensitive_data_in_query(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag parameters with sensitive names that are sent as query strings."""
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None or not isinstance(operation, dict):
                continue

            params = operation.get("parameters", [])
            for param in params:
                param = _deref(spec, param)
                name = param.get("name", "")
                location = param.get("in", "")
                if location == "query" and _SENSITIVE_PARAM_PATTERNS.search(name):
                    findings.append(
                        Finding(
                            id="OPENAPI-SENSITIVE-QUERY",
                            title="Sensitive data in query string",
                            description=(
                                f"Parameter '{name}' on {method.upper()} {path} "
                                "is sent as a query parameter. Sensitive data in URLs "
                                "is logged in server logs, browser history, and proxies."
                            ),
                            severity="HIGH",
                            source="openapi-scanner",
                            affected_field=f"paths.{path}.{method}.parameters.{name}",
                            remediation=(
                                f"Move '{name}' to the request body or use an "
                                "Authorization header instead of a query parameter."
                            ),
                            evidence=(
                                f"Sensitive parameter '{name}' in query for {method.upper()} {path}"
                            ),
                        )
                    )


def _check_missing_input_validation(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag mutating endpoints with no request body schema."""
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("post", "put", "patch"):
            operation = path_item.get(method)
            if operation is None or not isinstance(operation, dict):
                continue

            request_body = operation.get("requestBody")
            if not request_body:
                findings.append(
                    Finding(
                        id="OPENAPI-NO-BODY-SCHEMA",
                        title="Missing request body schema",
                        description=(
                            f"{method.upper()} {path} has no requestBody defined. "
                            "Without input schema, the server cannot validate requests."
                        ),
                        severity="MEDIUM",
                        source="openapi-scanner",
                        affected_field=f"paths.{path}.{method}.requestBody",
                        remediation=(
                            "Define a requestBody with a JSON Schema for input validation."
                        ),
                    )
                )
                continue

            request_body = _deref(spec, request_body)
            content = request_body.get("content", {})
            json_media = content.get("application/json", {})
            schema = json_media.get("schema")
            if not schema:
                findings.append(
                    Finding(
                        id="OPENAPI-NO-BODY-SCHEMA",
                        title="Missing request body schema",
                        description=(
                            f"{method.upper()} {path} has a requestBody but no "
                            "JSON schema defined for application/json content."
                        ),
                        severity="MEDIUM",
                        source="openapi-scanner",
                        affected_field=f"paths.{path}.{method}.requestBody.content",
                        remediation=("Add a schema under requestBody.content.application/json."),
                    )
                )


def _check_internal_endpoints(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag paths that look like internal/admin endpoints."""
    paths = spec.get("paths", {})

    for path in paths:
        match = _INTERNAL_PATH_PATTERNS.search(path)
        if match:
            findings.append(
                Finding(
                    id="OPENAPI-INTERNAL-EXPOSED",
                    title="Internal endpoint exposed in public spec",
                    description=(
                        f"Path '{path}' appears to be an internal or administrative "
                        "endpoint that should not be exposed in a public API spec."
                    ),
                    severity="HIGH",
                    source="openapi-scanner",
                    affected_field=f"paths.{path}",
                    remediation=(
                        "Remove internal endpoints from the public spec or protect "
                        "them with strong authentication and network-level restrictions."
                    ),
                    evidence=f"Path contains '{match.group(0)}'",
                )
            )


def _check_deprecated_endpoints(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag deprecated endpoints that are still defined."""
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None or not isinstance(operation, dict):
                continue
            if operation.get("deprecated", False):
                findings.append(
                    Finding(
                        id="OPENAPI-DEPRECATED",
                        title="Deprecated endpoint still active",
                        description=(
                            f"{method.upper()} {path} is marked as deprecated but "
                            "still present in the spec. Deprecated endpoints may "
                            "have known vulnerabilities or lack maintenance."
                        ),
                        severity="LOW",
                        source="openapi-scanner",
                        affected_field=f"paths.{path}.{method}",
                        remediation=(
                            "Remove deprecated endpoints from the spec or add a "
                            "sunset date and migration path for consumers."
                        ),
                        evidence=f"deprecated: true on {method.upper()} {path}",
                    )
                )


def _check_missing_response_schemas(
    spec: dict[str, Any],
    findings: list[Finding],
) -> None:
    """Flag endpoints with no response schema defined."""
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None or not isinstance(operation, dict):
                continue

            responses = operation.get("responses", {})
            if not responses:
                findings.append(
                    Finding(
                        id="OPENAPI-NO-RESPONSE-SCHEMA",
                        title="Missing response schema",
                        description=(
                            f"{method.upper()} {path} has no responses defined. "
                            "Without response schemas, clients cannot validate responses."
                        ),
                        severity="LOW",
                        source="openapi-scanner",
                        affected_field=f"paths.{path}.{method}.responses",
                        remediation="Define response schemas for at least 200/2xx responses.",
                    )
                )
                continue

            # Check if any success response has a schema
            has_schema = False
            for _status, resp in responses.items():
                resp = _deref(spec, resp)
                content = resp.get("content", {})
                for _media_type, media in content.items():
                    if media.get("schema"):
                        has_schema = True
                        break
                if has_schema:
                    break

            if not has_schema:
                findings.append(
                    Finding(
                        id="OPENAPI-NO-RESPONSE-SCHEMA",
                        title="Missing response schema",
                        description=(
                            f"{method.upper()} {path} has responses defined but none "
                            "include a content schema. Response validation is not possible."
                        ),
                        severity="LOW",
                        source="openapi-scanner",
                        affected_field=f"paths.{path}.{method}.responses",
                        remediation="Add a schema under responses.2xx.content.application/json.",
                    )
                )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_openapi(spec_path: str) -> list[Finding]:
    """Scan an OpenAPI spec for security issues.

    Args:
        spec_path: Path to the OpenAPI spec file (YAML or JSON).

    Returns:
        A list of :class:`~navil.types.Finding` objects.
    """
    spec = load_spec(spec_path)
    return scan_openapi_spec(spec)


def scan_openapi_spec(spec: dict[str, Any]) -> list[Finding]:
    """Scan an already-loaded OpenAPI spec dict for security issues.

    Args:
        spec: Parsed OpenAPI spec dictionary.

    Returns:
        A list of :class:`~navil.types.Finding` objects.
    """
    findings: list[Finding] = []

    _check_no_auth_on_sensitive(spec, findings)
    _check_missing_rate_limits(spec, findings)
    _check_permissive_cors(spec, findings)
    _check_sensitive_data_in_query(spec, findings)
    _check_missing_input_validation(spec, findings)
    _check_internal_endpoints(spec, findings)
    _check_deprecated_endpoints(spec, findings)
    _check_missing_response_schemas(spec, findings)

    return findings
