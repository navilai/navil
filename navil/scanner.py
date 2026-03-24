"""
MCP Server Security Scanner

Scans MCP server configuration files for common vulnerabilities and security issues.
Generates comprehensive security reports with risk assessment and recommendations.
"""

import json
import logging
import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from navil.types import Finding

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""

    id: str
    title: str
    description: str
    risk_level: str
    affected_field: str
    remediation: str
    evidence: str = ""

    def to_finding(self) -> Finding:
        """Convert this Vulnerability to the shared Finding type."""
        return Finding(
            id=self.id,
            title=self.title,
            description=self.description,
            severity=self.risk_level,
            source="scanner",
            affected_field=self.affected_field,
            remediation=self.remediation,
            evidence=self.evidence,
            confidence=1.0,
        )


class MCPSecurityScanner:
    """
    Scanner for MCP server configuration files.

    Detects common vulnerabilities including:
    - Plaintext credentials/API keys
    - Over-privileged permissions
    - Missing authentication
    - Unsigned/unverified sources
    - Known malicious patterns
    - Prompt injection risks in tool descriptions
    - Data exfiltration risk (network + file read combined)
    - Privilege escalation patterns
    - Supply chain risks (unverified packages, wildcard deps)
    - Sensitive data exposure (env vars, credentials, secrets access)
    - Excessive permissions (broad filesystem, network, system access)
    """

    # Patterns for detecting secrets
    SECRET_PATTERNS = {
        "api_key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]+)['\"]?",
        "password": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s\"']+)['\"]?",
        "token": r"(?i)(token|secret)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_\.]+)['\"]?",
        "aws_key": r"(?i)AKIA[0-9A-Z]{16}",
        "private_key": r"(?i)(private[_-]?key|-----begin.*private key)",
        "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.",
    }

    # Known malicious patterns — tuned to avoid false positives on legitimate configs
    # (e.g. RBAC role names, denied-path lists, standard permission verbs)
    MALICIOUS_PATTERNS = {
        "exfiltration": (
            r"(?i)(exfiltrate|steal_data|leak_credentials"
            r"|unauthorized.*send|socket.*send.*outside)"
        ),
        "privilege_escalation": (
            r"(?i)(escalate_privilege|sudo\s|run_as_root" r"|admin.*grant_all)"
        ),
        "data_destruction": (
            r"(?i)(delete_all_records|drop\s+database" r"|rm\s+-rf|wipe_disk|destroy_data)"
        ),
        "backdoor": r"(?i)(backdoor|hidden.*access|secret.*command|unauthorized.*entry)",
    }

    # Prompt injection indicators in tool descriptions
    PROMPT_INJECTION_PATTERNS = {
        "instruction_override": (
            r"(?i)(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)"
            r"|disregard\s+(previous|prior|above|all)"
            r"|forget\s+(everything|all|previous))"
        ),
        "system_prompt_access": (
            r"(?i)(system\s*prompt|reveal\s+(your|the)\s+(instructions?|prompt)"
            r"|repeat\s+(your|the)\s+(system|initial)\s+(message|prompt|instructions?))"
        ),
        "role_manipulation": (
            r"(?i)(you\s+are\s+now|act\s+as\s+(a|an)\s+"
            r"|pretend\s+(to\s+be|you\s+are)|new\s+role|jailbreak)"
        ),
        "hidden_instructions": (
            r"(?i)(<\s*!--.*(?:ignore|override|execute).*--\s*>"
            r"|\\u0000|\\x00|\[INST\]|\[/INST\])"
        ),
    }

    # Patterns indicating file/data read capabilities
    FILE_READ_PATTERNS = re.compile(
        r"(?i)(read[\s_-]*(file|dir|document|data|content)"
        r"|file[\s_-]*(read|access|open|get|load|view)"
        r"|list[\s_-]*(file|dir|folder|path)"
        r"|browse[\s_-]*(file|folder|directory)"
        r"|filesystem|file\s*system"
        r"|download[\s_-]*(file|document|data)"
        r"|open[\s_-]*(file|document))"
    )

    # Patterns indicating network/outbound capabilities
    NETWORK_SEND_PATTERNS = re.compile(
        r"(?i)(send[\s_-]*(email|message|notification|request|data|http|webhook)"
        r"|fetch[\s_-]*(url|page|http|api|web)"
        r"|http[\s_-]*(request|post|get|put|delete)"
        r"|webhook|api[\s_-]*(call|request|post)"
        r"|upload[\s_-]*(file|data|document)"
        r"|smtp|email[\s_-]*(send|forward)"
        r"|notify[\s_-]*(external|webhook|slack|discord))"
    )

    # Patterns indicating command execution / privilege escalation capability
    PRIV_ESCALATION_PATTERNS = re.compile(
        r"(?i)(execut(e|ion|ing)[\s_-]*(command|shell|code|script|process|binary)"
        r"|run[\s_-]*(command|shell|script|code|process|binary|terminal)"
        r"|shell[\s_-]*(access|command|exec)"
        r"|terminal[\s_-]*(access|command|exec)"
        r"|subprocess|spawn[\s_-]*(process|shell)"
        r"|admin[\s_-]*(panel|access|tool|console)"
        r"|root[\s_-]*(access|shell|command)"
        r"|sudo|su\s+root|chmod|chown|chgrp"
        r"|modify[\s_-]*(permission|access|role)"
        r"|grant[\s_-]*(access|permission|role))"
    )

    # Supply chain risk patterns
    SUPPLY_CHAIN_PATTERNS = re.compile(
        r"(?i)(npx\s+[-@a-z]|npx\s+\S+"  # npx running arbitrary packages
        r"|pip\s+install\s+"  # pip install in configs
        r"|npm\s+install\s+"  # npm install in configs
        r"|curl\s+.*\|\s*(sh|bash)"  # pipe-to-shell patterns
        r"|wget\s+.*&&\s*(sh|bash|chmod)"  # wget-and-run
        r"|github\.com/[^/]+/[^/\s\"']+)"  # GitHub source (for unverified check)
    )

    # Patterns indicating sensitive data access
    SENSITIVE_DATA_PATTERNS = re.compile(
        r"(?i)(env(ironment)?[\s_-]*(var|variable|secret)"
        r"|read[\s_-]*(env|\.env|environment|secret|credential)"
        r"|access[\s_-]*(secret|credential|password|token|key)"
        r"|credential[\s_-]*(store|vault|manager|access)"
        r"|secret[\s_-]*(store|vault|manager|access|key)"
        r"|\.env\b|dotenv"
        r"|password[\s_-]*(manager|store|vault)"
        r"|ssh[\s_-]*(key|private|credential)"
        r"|aws[\s_-]*(credential|key|secret|token)"
        r"|keychain|key[\s_-]*(ring|store|vault))"
    )

    # Known-safe npm scopes for NPX execution (official SDK packages)
    NPX_SAFE_SCOPES = [
        "@modelcontextprotocol/",
        "@anthropic/",
        "@google-cloud/",
        "@microsoft/",
        "@aws-sdk/",
        "@openai/",
        "@cloudflare/",
    ]

    # Patterns indicating excessive/broad permissions requested
    EXCESSIVE_PERM_PATTERNS = re.compile(
        r"(?i)(full[\s_-]*(access|control|permission)"
        r"|unrestrict(ed)?[\s_-]*(access|permission)"
        r"|access[\s_-]*(everything|all|any)"
        r"|root[\s_-]*(access|filesystem)"
        r"|entire[\s_-]*(filesystem|disk|system|network)"
        r"|all[\s_-]*(files|directories|folders|ports|network)"
        r"|arbitrary[\s_-]*(file|code|command|path)"
        r"|any[\s_-]*(file|directory|folder|path|command)"
        r"|complete[\s_-]*(filesystem|system|network)\s*(access|control))"
    )

    def __init__(self) -> None:
        """Initialize the scanner."""
        self.vulnerabilities: list[Vulnerability] = []
        self.warnings: list[str] = []

    def scan(self, config_path: str) -> dict[str, Any]:
        """
        Scan an MCP server configuration file.

        Args:
            config_path: Path to the MCP configuration file (JSON format)

        Returns:
            Dictionary containing scan results and security score
        """
        self.vulnerabilities = []
        self.warnings = []

        try:
            config = self._load_config(config_path)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load config: {e}")
            return {
                "status": "error",
                "message": f"Failed to load configuration: {str(e)}",
                "security_score": 0,
            }

        # Run all security checks
        self._check_plaintext_credentials(config)
        self._check_permissions(config)
        self._check_authentication(config)
        self._check_server_source(config)
        self._check_malicious_patterns(config)
        self._check_network_security(config)
        self._check_tool_safety(config)
        # Extended checks (v3)
        self._check_prompt_injection_risk(config)
        self._check_data_exfiltration_risk(config)
        self._check_privilege_escalation_patterns(config)
        self._check_supply_chain_risk(config)
        self._check_sensitive_data_exposure(config)
        self._check_excessive_permissions(config)
        self._check_config_completeness(config)

        # Calculate security score
        security_score = self._calculate_score()

        # Build Finding objects from internal Vulnerability list
        findings = [v.to_finding() for v in self.vulnerabilities]

        # Categorize findings into security issues vs hardening recommendations
        categorized = self.categorize_findings()

        # Generate report
        report = {
            "status": "completed",
            "config_path": str(config_path),
            "security_score": security_score,
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities_by_level": self._group_by_risk_level(),
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "findings": findings,
            "security_issues": [asdict(v) for v in categorized["security_issues"]],
            "hardening_recommendations": [
                asdict(v) for v in categorized["hardening_recommendations"]
            ],
            "warnings": self.warnings,
            "recommendation": self._get_recommendation(security_score),
        }

        return report

    def _load_config(self, config_path: str) -> dict[str, Any]:
        """Load and parse configuration file."""
        path = Path(config_path)
        if not path.exists():
            raise OSError(f"Configuration file not found: {config_path}")

        with open(path) as f:
            config = json.load(f)
        return config

    def _check_plaintext_credentials(self, config: dict[str, Any]) -> None:
        """Check for plaintext credentials and API keys."""
        config_str = json.dumps(config)

        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, config_str)
            for match in matches:
                self.vulnerabilities.append(
                    Vulnerability(
                        id=f"CRED-{secret_type.upper()}",
                        title="Plaintext Credential Detected",
                        description=f"Found plaintext {secret_type} in configuration file",
                        risk_level=RiskLevel.CRITICAL.value,
                        affected_field=self._find_field_in_config(config, match.group(0)),
                        remediation=(
                            "Use environment variables or secure vaults for credential storage"
                        ),
                        evidence=f"Detected {secret_type} pattern",
                    )
                )

    def _check_permissions(self, config: dict[str, Any]) -> None:
        """Check for over-privileged tool permissions."""
        tools = config.get("tools", [])

        for tool in tools:
            if isinstance(tool, dict):
                permissions = tool.get("permissions", [])
                name = tool.get("name", "unknown")

                # Check for overly broad permissions
                dangerous_permissions = ["*", "all", "unrestricted"]
                if any(perm in dangerous_permissions for perm in permissions):
                    self.vulnerabilities.append(
                        Vulnerability(
                            id="PERM-OVERPRIVILEGED",
                            title="Over-Privileged Tool Permissions",
                            description=f"Tool '{name}' has unrestricted permissions",
                            risk_level=RiskLevel.HIGH.value,
                            affected_field="tools[*].permissions",
                            remediation=(
                                "Apply least-privilege: define specific permissions for each tool"
                            ),
                            evidence=f"Tool {name} has wildcard permissions",
                        )
                    )

                # Check for file system access without restrictions
                if "file_system" in permissions and (
                    "restrictions" not in tool or not tool.get("restrictions")
                ):
                    self.vulnerabilities.append(
                        Vulnerability(
                            id="PERM-UNRESTRICTED-FS",
                            title="Unrestricted File System Access",
                            description=f"Tool '{name}' has unrestricted file system access",
                            risk_level=RiskLevel.HIGH.value,
                            affected_field="tools[*].permissions",
                            remediation=(
                                "Restrict file system access to specific directories and file types"
                            ),
                            evidence=(
                                f"Tool {name} has file_system permission without restrictions"
                            ),
                        )
                    )

    def _check_authentication(self, config: dict[str, Any]) -> None:
        """Check for missing authentication requirements."""
        if "authentication" not in config or not config.get("authentication"):
            self.vulnerabilities.append(
                Vulnerability(
                    id="AUTH-MISSING",
                    title="Missing Authentication Configuration",
                    description=(
                        "No authentication mechanism configured. "
                        "HTTP deployments exposed to networks must have "
                        "authentication to prevent unauthorized access."
                    ),
                    risk_level=RiskLevel.MEDIUM.value,
                    affected_field="authentication",
                    remediation=(
                        "Implement strong authentication (OAuth2, mTLS, API keys) for "
                        "server access. For local stdio transport, authentication is "
                        "typically not required."
                    ),
                    evidence="Authentication field is missing or empty",
                )
            )
            return

        auth_config = config.get("authentication", {})

        if auth_config.get("type") == "api_key" and not auth_config.get("key_rotation"):
            self.warnings.append("API key authentication configured without key rotation policy")

    def _check_server_source(self, config: dict[str, Any]) -> None:
        """Check for unsigned or unverified server sources."""
        server = config.get("server", {})

        if "source" in server:
            source = server["source"]
            if not server.get("verified") and not server.get("signature"):
                self.vulnerabilities.append(
                    Vulnerability(
                        id="SRC-UNVERIFIED",
                        title="Unverified Server Source",
                        description=(
                            "Server binary/source is not cryptographically verified. "
                            "Note: the MCP ecosystem does not yet have a standard "
                            "verification mechanism, so this is aspirational guidance "
                            "rather than an immediately actionable finding."
                        ),
                        risk_level=RiskLevel.INFO.value,
                        affected_field="server.source",
                        remediation=(
                            "When available, use signed/verified binaries and implement "
                            "signature verification before deployment. Currently no "
                            "standard verification mechanism exists for MCP servers."
                        ),
                        evidence=f"Server source '{source}' lacks verification metadata",
                    )
                )

    def _check_malicious_patterns(self, config: dict[str, Any]) -> None:
        """Check for known malicious patterns in tool definitions."""
        config_str = json.dumps(config).lower()

        for pattern_type, pattern in self.MALICIOUS_PATTERNS.items():
            if re.search(pattern, config_str):
                self.vulnerabilities.append(
                    Vulnerability(
                        id=f"MAL-{pattern_type.upper()}",
                        title=f"Malicious Pattern: {pattern_type.title()}",
                        description=(f"Config contains patterns associated with {pattern_type}"),
                        risk_level=RiskLevel.CRITICAL.value,
                        affected_field="tools",
                        remediation=(
                            "Review tool definitions and remove any"
                            " suspicious or unauthorized functionality"
                        ),
                        evidence=f"Pattern matching '{pattern_type}' detected in configuration",
                    )
                )

    def _check_network_security(self, config: dict[str, Any]) -> None:
        """Check for insecure network configurations."""
        server = config.get("server", {})

        # Check for unencrypted communication
        if "protocol" in server:
            protocol = server.get("protocol", "").lower()
            if protocol == "http":
                # Check if this is a localhost/stdio transport (lower risk)
                transport = server.get("transport", "").lower()
                host = server.get("host", "").lower()
                is_local = (
                    transport == "stdio"
                    or host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
                    or protocol == "stdio"
                )

                if is_local:
                    self.vulnerabilities.append(
                        Vulnerability(
                            id="NET-UNENCRYPTED",
                            title="Unencrypted Communication",
                            description=(
                                "Server is configured to use HTTP on localhost. "
                                "This is acceptable for local development but should "
                                "use HTTPS if exposed to a network."
                            ),
                            risk_level=RiskLevel.INFO.value,
                            affected_field="server.protocol",
                            remediation=(
                                "For local development, HTTP on localhost is acceptable. "
                                "Use HTTPS/TLS if deploying beyond localhost."
                            ),
                            evidence="Protocol set to HTTP (localhost/local transport)",
                        )
                    )
                else:
                    self.vulnerabilities.append(
                        Vulnerability(
                            id="NET-UNENCRYPTED",
                            title="Unencrypted Communication",
                            description="Server is configured to use HTTP instead of HTTPS",
                            risk_level=RiskLevel.HIGH.value,
                            affected_field="server.protocol",
                            remediation="Use HTTPS/TLS for all server communications",
                            evidence="Protocol set to HTTP",
                        )
                    )

        # Check for exposed ports
        if "port" in server:
            port = server.get("port")
            if port in [80, 8080, 3000]:
                self.warnings.append(f"Server exposed on commonly targeted port {port}")

    def _check_tool_safety(self, config: dict[str, Any]) -> None:
        """Check for unsafe tool configurations."""
        tools = config.get("tools", [])

        for tool in tools:
            if not isinstance(tool, dict):
                continue

            name = tool.get("name", "unknown")

            # Check for tools with command injection risks
            if "command" in tool:
                command = tool.get("command", "")
                if "${" in command or "$(" in command:
                    self.warnings.append(
                        f"Tool '{name}' uses variable substitution"
                        " in commands — ensure input validation"
                    )

            # Check for tools without rate limiting
            if "rate_limit" not in tool:
                self.warnings.append(f"Tool '{name}' has no rate limiting configured")

    # ── Extended checks (v3) ──────────────────────────────────

    def _get_description_text(self, config: dict[str, Any]) -> str:
        """Extract all descriptive text from config for pattern matching.

        Collects metadata.description, tool descriptions, and server name.
        """
        parts: list[str] = []

        # Metadata description (injected by batch_scanner from crawl data)
        meta = config.get("metadata", {})
        if isinstance(meta, dict):
            desc = meta.get("description", "")
            if desc:
                parts.append(desc)

        # Tool-level descriptions
        for tool in config.get("tools", []):
            if isinstance(tool, dict):
                td = tool.get("description", "")
                if td:
                    parts.append(td)

        # Server name can also reveal intent
        server = config.get("server", {})
        if isinstance(server, dict):
            name = server.get("name", "")
            if name:
                parts.append(name)

        return " ".join(parts)

    def _check_prompt_injection_risk(self, config: dict[str, Any]) -> None:
        """Check for prompt injection risk patterns in descriptions.

        Looks for instruction-override language, system prompt access attempts,
        role manipulation, and hidden instruction markers.
        """
        text = self._get_description_text(config)
        config_str = json.dumps(config)

        for pattern_type, pattern in self.PROMPT_INJECTION_PATTERNS.items():
            # Check both the description text and full config
            for source, content in [("description", text), ("config", config_str)]:
                match = re.search(pattern, content)
                if match:
                    self.vulnerabilities.append(
                        Vulnerability(
                            id=f"INJ-{pattern_type.upper().replace('_', '-')}",
                            title=(
                                f"Prompt Injection Risk: {pattern_type.replace('_', ' ').title()}"
                            ),
                            description=(
                                f"Tool description or config contains language associated with "
                                f"prompt injection ({pattern_type.replace('_', ' ')})"
                            ),
                            risk_level=RiskLevel.CRITICAL.value,
                            affected_field=f"metadata.description ({source})",
                            remediation=(
                                "Review and sanitize tool descriptions. Remove any "
                                "instruction-like language that could manipulate LLM behavior. "
                                "Implement tool description validation before deployment."
                            ),
                            evidence=f"Matched pattern '{pattern_type}' in {source}",
                        )
                    )
                    break  # Only report once per pattern_type

    def _check_data_exfiltration_risk(self, config: dict[str, Any]) -> None:
        """Check for data exfiltration risk: tools combining file read + network send.

        A server that can both read local files and send data over the network
        presents a data exfiltration risk if not properly sandboxed.
        """
        text = self._get_description_text(config)
        config_str = json.dumps(config)
        combined = text + " " + config_str

        has_file_read = bool(self.FILE_READ_PATTERNS.search(combined))
        has_network_send = bool(self.NETWORK_SEND_PATTERNS.search(combined))

        if has_file_read and has_network_send:
            self.vulnerabilities.append(
                Vulnerability(
                    id="EXFIL-READ-SEND",
                    title="Data Exfiltration Risk: File Read + Network Send",
                    description=(
                        "Server combines file/data reading capabilities with outbound "
                        "network access, creating a potential data exfiltration path"
                    ),
                    risk_level=RiskLevel.HIGH.value,
                    affected_field="tools",
                    remediation=(
                        "Isolate file-reading and network-sending capabilities into "
                        "separate servers with distinct permissions. Apply data-loss "
                        "prevention controls and monitor outbound data flows."
                    ),
                    evidence=(
                        "Detected both file read and network send capabilities in the same server"
                    ),
                )
            )

    # Keywords in server name/description indicating command running is expected
    EXPECTED_CMD_EXEC_PATTERNS = re.compile(
        r"(?i)(terminal|shell|bash|zsh|console|cli|command[- ]?line" r"|filesystem|file[- ]?system)"
    )

    def _check_privilege_escalation_patterns(self, config: dict[str, Any]) -> None:
        """Check for privilege escalation patterns.

        Detects tools that can run commands, modify permissions, or access
        admin endpoints -- which could be chained for privilege escalation.
        """
        text = self._get_description_text(config)
        config_str = json.dumps(config)
        combined = text + " " + config_str

        match = self.PRIV_ESCALATION_PATTERNS.search(combined)
        if match:
            # Check if the server name/description indicates command running
            # is an expected capability (e.g., terminal, shell, filesystem server)
            server = config.get("server", {})
            server_name = server.get("name", "") if isinstance(server, dict) else ""
            meta = config.get("metadata", {})
            meta_desc = meta.get("description", "") if isinstance(meta, dict) else ""
            identity_text = f"{server_name} {meta_desc}"

            is_expected = bool(self.EXPECTED_CMD_EXEC_PATTERNS.search(identity_text))

            if is_expected:
                risk = RiskLevel.MEDIUM.value
                description = (
                    "Server provides command running or shell access capabilities. "
                    "This is expected for a terminal/shell/filesystem server but should "
                    "be properly sandboxed."
                )
            else:
                risk = RiskLevel.HIGH.value
                description = (
                    "Server provides command running, shell access, or "
                    "permission modification capabilities that could be "
                    "exploited for privilege escalation"
                )

            self.vulnerabilities.append(
                Vulnerability(
                    id="PRIVESC-CMD-EXEC",
                    title="Privilege Escalation Risk: Command Execution",
                    description=description,
                    risk_level=risk,
                    affected_field="tools",
                    remediation=(
                        "Restrict command running to a predefined allowlist. "
                        "Run tools in sandboxed environments with minimal privileges. "
                        "Never expose raw shell or admin interfaces to MCP tools."
                    ),
                    evidence=f"Matched privilege escalation pattern: '{match.group(0)[:80]}'",
                )
            )

    def _check_supply_chain_risk(self, config: dict[str, Any]) -> None:
        """Check for supply chain risk patterns.

        Detects unverified package execution (npx, pip install), pipe-to-shell
        patterns, and GitHub sources without integrity verification.
        """
        config_str = json.dumps(config)
        text = self._get_description_text(config)
        combined = text + " " + config_str

        match = self.SUPPLY_CHAIN_PATTERNS.search(combined)
        if match:
            matched_text = match.group(0)

            # Determine specific sub-type
            if re.search(r"(?i)curl.*\|\s*(sh|bash)|wget.*&&", matched_text):
                sub_id = "PIPE-SHELL"
                sub_title = "Pipe-to-Shell Installation"
                sub_desc = (
                    "Configuration uses pipe-to-shell installation pattern, "
                    "which executes unverified remote code"
                )
                risk = RiskLevel.MEDIUM.value
            elif re.search(r"(?i)npx\s+", matched_text):
                # Check if this is a known-safe npm scope.
                # Use the full combined text since the regex capture may
                # be truncated (e.g. "npx @" without the full scope).
                is_safe_scope = any(scope in combined for scope in self.NPX_SAFE_SCOPES)
                if is_safe_scope:
                    sub_id = "NPX-EXEC"
                    sub_title = "npx Package Execution (Official SDK)"
                    sub_desc = (
                        "Server uses npx to execute an official SDK package. "
                        "This is the standard recommended way to run MCP servers."
                    )
                    risk = RiskLevel.INFO.value
                else:
                    sub_id = "NPX-EXEC"
                    sub_title = "Unverified npx Package Execution"
                    sub_desc = (
                        "Server uses npx to execute an unknown package directly "
                        "without prior installation or version pinning"
                    )
                    risk = RiskLevel.MEDIUM.value
            elif re.search(r"(?i)github\.com/", matched_text):
                sub_id = "GH-UNVERIFIED"
                sub_title = "Unverified GitHub Source"
                sub_desc = (
                    "Server is sourced from GitHub without integrity "
                    "verification. Note: the MCP ecosystem does not yet have "
                    "a standard signing or verification mechanism for server "
                    "packages, so this is aspirational guidance."
                )
                risk = RiskLevel.INFO.value
            else:
                sub_id = "PKG-INSTALL"
                sub_title = "Runtime Package Installation"
                sub_desc = (
                    "Configuration installs packages at runtime, which may "
                    "pull unverified or malicious dependencies"
                )
                risk = RiskLevel.MEDIUM.value

            self.vulnerabilities.append(
                Vulnerability(
                    id=f"SUPPLY-{sub_id}",
                    title=f"Supply Chain Risk: {sub_title}",
                    description=sub_desc,
                    risk_level=risk,
                    affected_field="server.source",
                    remediation=(
                        "Pin package versions explicitly. Use lockfiles (package-lock.json, "
                        "requirements.txt with hashes). Verify package integrity with "
                        "checksums or signatures before execution."
                    ),
                    evidence=f"Matched supply chain pattern: '{matched_text[:80]}'",
                )
            )

    def _check_sensitive_data_exposure(self, config: dict[str, Any]) -> None:
        """Check for sensitive data exposure risk.

        Detects tools that read environment variables, access credential
        stores, or handle secrets without proper safeguards.

        Reading env vars is the recommended approach for providing API keys
        to MCP servers, so it is only flagged as HIGH when the server can
        also send data externally (combining secrets access + network send).
        """
        text = self._get_description_text(config)
        config_str = json.dumps(config)
        combined = text + " " + config_str

        match = self.SENSITIVE_DATA_PATTERNS.search(combined)
        if match:
            # Check if the server also has network send capabilities
            has_network_send = bool(self.NETWORK_SEND_PATTERNS.search(combined))

            if has_network_send:
                # Can read secrets AND send data externally -- real risk
                risk = RiskLevel.HIGH.value
                description = (
                    "Server can access sensitive data (environment variables, "
                    "credentials, secrets) AND has outbound network capabilities, "
                    "creating a risk of credential exfiltration."
                )
            else:
                # Reading env vars without network send -- best practice for config
                risk = RiskLevel.INFO.value
                description = (
                    "Server can access sensitive data such as environment "
                    "variables or secrets. Reading environment variables is the "
                    "recommended approach for providing API keys to MCP servers. "
                    "This is only a concern if combined with outbound network access."
                )

            self.vulnerabilities.append(
                Vulnerability(
                    id="SENSITIVE-DATA-EXPOSURE",
                    title="Sensitive Data Exposure Risk",
                    description=description,
                    risk_level=risk,
                    affected_field="tools",
                    remediation=(
                        "Limit access to environment variables and secrets to only "
                        "those explicitly needed. Use a secrets manager with "
                        "fine-grained access controls. Audit which tools can "
                        "read credentials and ensure they do not expose them "
                        "in logs or responses."
                    ),
                    evidence=f"Matched sensitive data pattern: '{match.group(0)[:80]}'",
                )
            )

    def _check_excessive_permissions(self, config: dict[str, Any]) -> None:
        """Check for excessive permission requests.

        Detects tools requesting broad filesystem, network, or system access
        beyond what is typically needed for their stated purpose.
        """
        text = self._get_description_text(config)
        config_str = json.dumps(config)
        combined = text + " " + config_str

        match = self.EXCESSIVE_PERM_PATTERNS.search(combined)
        if match:
            self.vulnerabilities.append(
                Vulnerability(
                    id="PERM-EXCESSIVE",
                    title="Excessive Permission Request",
                    description=(
                        "Server requests or claims access to broad system resources "
                        "(entire filesystem, all network, arbitrary commands) "
                        "beyond typical operational needs"
                    ),
                    risk_level=RiskLevel.HIGH.value,
                    affected_field="tools",
                    remediation=(
                        "Apply the principle of least privilege. Scope file access "
                        "to specific directories, limit network access to required "
                        "endpoints, and restrict command execution to a safe allowlist."
                    ),
                    evidence=f"Matched excessive permission pattern: '{match.group(0)[:80]}'",
                )
            )

    # IDs that represent real security issues (things that need fixing)
    SECURITY_ISSUE_IDS = {
        "CRED-API_KEY",
        "CRED-PASSWORD",
        "CRED-TOKEN",
        "CRED-AWS_KEY",
        "CRED-PRIVATE_KEY",
        "CRED-JWT",
        "INJ-INSTRUCTION-OVERRIDE",
        "INJ-SYSTEM-PROMPT-ACCESS",
        "INJ-ROLE-MANIPULATION",
        "INJ-HIDDEN-INSTRUCTIONS",
        "EXFIL-READ-SEND",
        "MAL-EXFILTRATION",
        "MAL-PRIVILEGE_ESCALATION",
        "MAL-DATA_DESTRUCTION",
        "MAL-BACKDOOR",
        "PERM-OVERPRIVILEGED",
        "PERM-UNRESTRICTED-FS",
        "PERM-EXCESSIVE",
        "SUPPLY-PIPE-SHELL",
        "SUPPLY-PKG-INSTALL",
        # Missing required fields are real security issues
        "NET-NO-TLS",
        "MISSING-RATE-LIMIT",
        "AUTH-MISSING",
        "MISSING-LOGGING",
        "MISSING-SERVER-CONFIG",
        "MISSING-INPUT-VALIDATION",
        "MISSING-SERVER-HOST",
        "MISSING-SERVER-PORT",
        "MISSING-SERVER-TRANSPORT",
    }

    # Explicit per-finding point deductions.  When a finding ID appears here
    # the fixed deduction is used instead of the generic risk-level-based one.
    # This lets us assign precise penalties for missing required fields.
    SCORE_DEDUCTIONS: dict[str, int] = {
        "NET-NO-TLS": 15,
        "MISSING-RATE-LIMIT": 10,
        "AUTH-MISSING": 5,
        "MISSING-LOGGING": 5,
        "MISSING-SERVER-CONFIG": 10,
        "MISSING-INPUT-VALIDATION": 5,
        "MISSING-SERVER-HOST": 5,
        "MISSING-SERVER-PORT": 5,
        "MISSING-SERVER-TRANSPORT": 5,
    }

    # IDs that are hardening recommendations (nice to have)
    HARDENING_RECOMMENDATION_IDS = {
        "SRC-UNVERIFIED",
        "SUPPLY-NPX-EXEC",
        "SUPPLY-GH-UNVERIFIED",
        "NET-UNENCRYPTED",
        "SENSITIVE-DATA-EXPOSURE",
        "PRIVESC-CMD-EXEC",
    }

    def categorize_findings(self) -> dict[str, list[Vulnerability]]:
        """Categorize findings into Security Issues and Hardening Recommendations.

        Security Issues are things that need fixing: plaintext credentials,
        prompt injection, data exfiltration paths, malicious patterns.

        Hardening Recommendations are nice-to-have improvements: auth missing,
        unverified sources, NPX usage, encryption suggestions.

        Findings not matching either set are categorized based on risk level:
        CRITICAL/HIGH go to security issues, everything else to recommendations.
        """
        security_issues: list[Vulnerability] = []
        hardening_recs: list[Vulnerability] = []

        for vuln in self.vulnerabilities:
            if vuln.id in self.SECURITY_ISSUE_IDS:
                security_issues.append(vuln)
            elif vuln.id in self.HARDENING_RECOMMENDATION_IDS:
                hardening_recs.append(vuln)
            elif vuln.risk_level in (RiskLevel.CRITICAL.value, RiskLevel.HIGH.value):
                # Unknown ID but high severity -- treat as security issue
                security_issues.append(vuln)
            else:
                hardening_recs.append(vuln)

        return {
            "security_issues": security_issues,
            "hardening_recommendations": hardening_recs,
        }

    def _find_field_in_config(self, config: dict[str, Any], evidence: str) -> str:
        """Find the field path in config that matches evidence."""
        # Simple implementation - in production, would do proper path tracking
        return "unknown"

    def _check_config_completeness(self, config: dict[str, Any]) -> None:
        """Check for missing critical security sections.

        A config that omits key sections should NOT score 100/100.
        Missing sections are flagged as security issues, not just info.
        """
        server = config.get("server", {})

        # TLS / transport encryption
        # Only count explicit TLS/SSL on the *server* block or a dedicated tls
        # section.  An authentication certificate_path is for client-cert auth,
        # not transport encryption, so it should not suppress this finding.
        has_tls = bool(
            server.get("tls") or server.get("ssl") or server.get("https") or config.get("tls")
        )
        transport = server.get("transport", "")
        is_stdio = transport == "stdio"

        if not has_tls and not is_stdio:
            self.vulnerabilities.append(
                Vulnerability(
                    id="NET-NO-TLS",
                    title="No TLS/SSL Configuration",
                    description=(
                        "No TLS configuration found. Network-exposed MCP "
                        "servers should use TLS to encrypt traffic."
                    ),
                    risk_level=RiskLevel.HIGH.value,
                    affected_field="server.tls",
                    remediation=(
                        "Add TLS configuration with a valid certificate. "
                        'Example: "server": {"tls": {"cert": "/path/to/cert.pem", '
                        '"key": "/path/to/key.pem"}}'
                    ),
                    evidence="No tls, ssl, or https field in server config",
                )
            )

        # Rate limiting
        tools = config.get("tools", {})
        # Normalise tools to an iterable of tool config dicts regardless of
        # whether the config uses a list or a dict of named tools.
        if isinstance(tools, dict):
            tool_configs = list(tools.values())
        elif isinstance(tools, list):
            tool_configs = tools
        else:
            tool_configs = []

        has_any_rate_limit = False
        for tool_config in tool_configs:
            if isinstance(tool_config, dict) and (
                tool_config.get("rate_limit") or tool_config.get("rateLimit")
            ):
                has_any_rate_limit = True
                break
        global_rate_limit = (
            server.get("rate_limit")
            or server.get("rateLimit")
            or config.get("rate_limit")
            or config.get("rateLimit")
        )
        if not has_any_rate_limit and not global_rate_limit:
            self.vulnerabilities.append(
                Vulnerability(
                    id="MISSING-RATE-LIMIT",
                    title="No Rate Limiting Configured",
                    description=(
                        "No rate limiting found on tools or server. "
                        "Without rate limits, agents can make unlimited "
                        "requests, enabling DoS or resource exhaustion."
                    ),
                    risk_level=RiskLevel.MEDIUM.value,
                    affected_field="rate_limit",
                    remediation=(
                        "Add rate limits per tool or globally. "
                        'Example: "rate_limit": {"requests_per_minute": 60}'
                    ),
                    evidence="No rate_limit field found in config",
                )
            )

        # Input validation / sanitization
        has_input_validation = False
        for tool_config in tool_configs:
            if isinstance(tool_config, dict) and (
                tool_config.get("input_validation")
                or tool_config.get("inputValidation")
                or tool_config.get("schema")
                or tool_config.get("inputSchema")
            ):
                has_input_validation = True
                break
        if tools and not has_input_validation:
            self.vulnerabilities.append(
                Vulnerability(
                    id="MISSING-INPUT-VALIDATION",
                    title="No Input Validation on Tools",
                    description=(
                        "No input validation or schema defined for tools. "
                        "Without validation, tools accept arbitrary input "
                        "from agents, increasing injection risk."
                    ),
                    risk_level=RiskLevel.MEDIUM.value,
                    affected_field="tools.*.input_validation",
                    remediation=(
                        "Add input schemas or validation rules per tool. "
                        'Example: "inputSchema": {"type": "object", '
                        '"properties": {...}, "required": [...]}'
                    ),
                    evidence="No input_validation or schema on any tool",
                )
            )

        # Logging / audit trail
        has_logging = bool(
            config.get("logging")
            or config.get("audit")
            or config.get("audit_log")
            or server.get("logging")
            or server.get("log_level")
        )
        if not has_logging:
            self.vulnerabilities.append(
                Vulnerability(
                    id="MISSING-LOGGING",
                    title="No Logging or Audit Trail",
                    description=(
                        "No logging configuration found. Without audit "
                        "logs, security incidents cannot be investigated."
                    ),
                    risk_level=RiskLevel.LOW.value,
                    affected_field="logging",
                    remediation=(
                        "Add logging configuration. "
                        'Example: "logging": {"level": "info", '
                        '"destination": "/var/log/mcp.log"}'
                    ),
                    evidence="No logging or audit field in config",
                )
            )

        # Server transport / binding — empty or missing server block
        if not server or (
            not server.get("transport")
            and not server.get("host")
            and not server.get("port")
            and not server.get("command")
        ):
            self.vulnerabilities.append(
                Vulnerability(
                    id="MISSING-SERVER-CONFIG",
                    title="Incomplete Server Configuration",
                    description=(
                        "Server section is empty or missing transport, "
                        "host, and port. The server's network exposure "
                        "cannot be assessed."
                    ),
                    risk_level=RiskLevel.MEDIUM.value,
                    affected_field="server",
                    remediation=(
                        "Define server transport and binding. "
                        'Example: "server": {"transport": "http", '
                        '"host": "127.0.0.1", "port": 3000}'
                    ),
                    evidence="Server section is empty or incomplete",
                )
            )

        # Individual missing server fields (deducted separately even when
        # the server block exists but is incomplete)
        if not server.get("host"):
            self.vulnerabilities.append(
                Vulnerability(
                    id="MISSING-SERVER-HOST",
                    title="Missing Server Host",
                    description=(
                        "No host/bind address configured. Cannot determine "
                        "whether the server is locally bound or network-exposed."
                    ),
                    risk_level=RiskLevel.MEDIUM.value,
                    affected_field="server.host",
                    remediation=('Specify a bind address. Example: "host": "127.0.0.1"'),
                    evidence="No host field in server config",
                )
            )

        if not server.get("port"):
            self.vulnerabilities.append(
                Vulnerability(
                    id="MISSING-SERVER-PORT",
                    title="Missing Server Port",
                    description=("No port configured. Cannot assess network exposure."),
                    risk_level=RiskLevel.MEDIUM.value,
                    affected_field="server.port",
                    remediation=('Specify a port. Example: "port": 3000'),
                    evidence="No port field in server config",
                )
            )

        if not server.get("transport") and not server.get("command"):
            self.vulnerabilities.append(
                Vulnerability(
                    id="MISSING-SERVER-TRANSPORT",
                    title="Missing Server Transport",
                    description=(
                        "No transport type configured (http, stdio, etc.). "
                        "Cannot determine communication method."
                    ),
                    risk_level=RiskLevel.MEDIUM.value,
                    affected_field="server.transport",
                    remediation=('Specify a transport. Example: "transport": "http"'),
                    evidence="No transport field in server config",
                )
            )

    def _calculate_score(self) -> int:
        """Calculate security score from 0-100.

        Findings with an entry in SCORE_DEDUCTIONS use their fixed penalty.
        Otherwise, Security Issues receive full deduction weight and
        Hardening Recommendations receive 1/3 of their normal deduction.
        """
        if not self.vulnerabilities:
            return 100

        categorized = self.categorize_findings()
        security_issues = set(id(v) for v in categorized["security_issues"])

        score = 100.0
        for vuln in self.vulnerabilities:
            # Use explicit per-finding deduction when available
            if vuln.id in self.SCORE_DEDUCTIONS:
                score -= self.SCORE_DEDUCTIONS[vuln.id]
                continue

            is_security_issue = id(vuln) in security_issues
            weight = 1.0 if is_security_issue else (1.0 / 3.0)

            if vuln.risk_level == RiskLevel.CRITICAL.value:
                score -= 25 * weight
            elif vuln.risk_level == RiskLevel.HIGH.value:
                score -= 15 * weight
            elif vuln.risk_level == RiskLevel.MEDIUM.value:
                score -= 8 * weight
            elif vuln.risk_level == RiskLevel.LOW.value:
                score -= 3 * weight
            # INFO findings do not deduct from the score

        return max(0, int(score))

    def _group_by_risk_level(self) -> dict[str, int]:
        """Group vulnerabilities by risk level."""
        groups = {level.value: 0 for level in RiskLevel}
        for vuln in self.vulnerabilities:
            groups[vuln.risk_level] += 1
        return groups

    def _get_recommendation(self, score: int) -> str:
        """Get recommendation based on security score."""
        if score >= 80:
            return "Good security posture. Continue monitoring for updates."
        elif score >= 60:
            return "Address identified vulnerabilities before production deployment."
        elif score >= 40:
            return "Significant security issues detected. Immediate remediation required."
        else:
            return "Critical security issues found. Do not deploy until resolved."
