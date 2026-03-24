"""A2A Agent Card — discovery metadata for Navil-protected agents.

Serves /.well-known/agent.json per Google A2A spec v0.2.
The Agent Card advertises the agent's identity, capabilities, skills,
and authentication requirements so other agents can discover and
interact with it.

Architecture:
    Agent A → GET /.well-known/agent.json → Navil Proxy
        → Returns AgentCard with navil security capabilities
        → Agent A learns: auth method, skills, endpoint URL
        → Agent A → POST /a2a/tasks/send → Navil Proxy → Agent B
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentProvider:
    """Identity of the agent's provider/organization."""

    organization: str
    url: str = ""


@dataclass(frozen=True)
class AgentCapabilities:
    """Declares supported A2A features."""

    streaming: bool = False
    push_notifications: bool = False
    extended_agent_card: bool = False


@dataclass(frozen=True)
class AgentSkill:
    """A capability the agent can perform."""

    id: str
    name: str
    description: str
    tags: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityScheme:
    """Authentication method definition."""

    type: str  # "http", "apiKey", "oauth2", "openIdConnect"
    scheme: str = ""  # "bearer" for JWT
    bearer_format: str = ""  # "JWT"
    description: str = ""


@dataclass(frozen=True)
class AgentInterface:
    """Protocol binding declaration."""

    protocol: str  # "jsonrpc", "rest"
    url: str
    content_types: list[str] = field(default_factory=lambda: ["application/json"])


@dataclass
class AgentCard:
    """A2A Agent Card — the discovery document for an agent.

    Served at /.well-known/agent.json per the A2A spec.
    """

    name: str
    description: str
    provider: AgentProvider
    version: str = "1.0.0"
    capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    skills: list[AgentSkill] = field(default_factory=list)
    security_schemes: dict[str, SecurityScheme] = field(default_factory=dict)
    security: list[dict[str, list[str]]] = field(default_factory=list)
    interfaces: list[AgentInterface] = field(default_factory=list)
    documentation_url: str = ""
    extensions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to A2A-compliant JSON dict."""
        card: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "provider": {
                "organization": self.provider.organization,
                "url": self.provider.url,
            },
            "version": self.version,
            "capabilities": {
                "streaming": self.capabilities.streaming,
                "pushNotifications": self.capabilities.push_notifications,
                "extendedAgentCard": self.capabilities.extended_agent_card,
            },
            "interfaces": [
                {
                    "protocol": iface.protocol,
                    "url": iface.url,
                    "contentTypes": iface.content_types,
                }
                for iface in self.interfaces
            ],
        }

        if self.skills:
            card["skills"] = [
                {
                    "id": skill.id,
                    "name": skill.name,
                    "description": skill.description,
                    "tags": skill.tags,
                    "examples": skill.examples,
                }
                for skill in self.skills
            ]

        if self.security_schemes:
            card["securitySchemes"] = {
                name: {
                    "type": scheme.type,
                    "scheme": scheme.scheme,
                    "bearerFormat": scheme.bearer_format,
                    "description": scheme.description,
                }
                for name, scheme in self.security_schemes.items()
            }

        if self.security:
            card["security"] = self.security

        if self.documentation_url:
            card["documentationUrl"] = self.documentation_url

        if self.extensions:
            card["extensions"] = self.extensions

        return card


def build_navil_agent_card(
    agent_name: str = "",
    agent_description: str = "",
    base_url: str = "",
    skills: list[AgentSkill] | None = None,
    provider_org: str = "",
    provider_url: str = "",
) -> AgentCard:
    """Build an AgentCard for a Navil-protected agent.

    Uses environment variables for defaults:
        NAVIL_AGENT_NAME — agent display name
        NAVIL_AGENT_DESCRIPTION — agent description
        NAVIL_BASE_URL — base URL for the agent's A2A endpoint
        NAVIL_PROVIDER_ORG — organization name
        NAVIL_PROVIDER_URL — organization URL

    The card advertises:
    - Navil JWT authentication (bearer token)
    - JSON-RPC interface for A2A task dispatch
    - Navil security extensions (governance, scoping, threat detection)
    """
    name = agent_name or os.environ.get("NAVIL_AGENT_NAME", "navil-agent")
    description = agent_description or os.environ.get(
        "NAVIL_AGENT_DESCRIPTION",
        "An agent protected by Navil agent governance middleware",
    )
    url = base_url or os.environ.get("NAVIL_BASE_URL", "http://localhost:8080")
    org = provider_org or os.environ.get("NAVIL_PROVIDER_ORG", "")
    org_url = provider_url or os.environ.get("NAVIL_PROVIDER_URL", "")

    default_skills = skills or [
        AgentSkill(
            id="mcp-tool-execution",
            name="MCP Tool Execution",
            description="Execute MCP server tools with governance and policy enforcement",
            tags=["mcp", "tools", "governance"],
        ),
    ]

    return AgentCard(
        name=name,
        description=description,
        provider=AgentProvider(organization=org, url=org_url),
        version="1.0.0",
        capabilities=AgentCapabilities(
            streaming=True,
            push_notifications=False,
            extended_agent_card=True,
        ),
        skills=default_skills,
        security_schemes={
            "navil_jwt": SecurityScheme(
                type="http",
                scheme="bearer",
                bearer_format="JWT",
                description="Navil-issued JWT with agent identity and delegation chain",
            ),
        },
        security=[{"navil_jwt": []}],
        interfaces=[
            AgentInterface(
                protocol="jsonrpc",
                url=f"{url}/a2a",
                content_types=["application/json"],
            ),
        ],
        documentation_url="https://github.com/navilai/navil",
        extensions=[
            {
                "name": "navil-governance",
                "version": "1.0.0",
                "description": (
                    "Navil agent governance — policy enforcement, tool scoping, anomaly detection"
                ),
                "fields": {
                    "governance_endpoint": f"{url}/mcp",
                    "policy_version": "1.0",
                    "supports_scoping": True,
                    "supports_threat_detection": True,
                },
            },
        ],
    )
