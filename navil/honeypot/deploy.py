"""Honeypot Deployment Helper -- manage honeypot container lifecycle.

Provides start/stop/status operations for honeypot containers via
Docker Compose, with profile selection and log configuration.

Usage::

    from navil.honeypot.deploy import HoneypotDeployer
    deployer = HoneypotDeployer()
    deployer.start(profiles=["dev_tools", "cloud_creds"])
    deployer.status()
    deployer.stop()
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default Docker Compose file for honeypot deployment
_DEFAULT_COMPOSE_FILE = "docker-compose.honeypot.yaml"

# Available honeypot profiles
AVAILABLE_PROFILES = ("dev_tools", "cloud_creds", "db_admin", "openclaw_registry")

# Service name mapping: profile -> docker-compose service name
_PROFILE_SERVICE_MAP = {
    "dev_tools": "honeypot-dev-tools",
    "cloud_creds": "honeypot-cloud-creds",
    "db_admin": "honeypot-db-admin",
    "openclaw_registry": "honeypot-openclaw-registry",
}


class HoneypotDeployer:
    """Manages honeypot container deployment via Docker Compose.

    Args:
        compose_file: Path to docker-compose file. Defaults to
                      docker-compose.honeypot.yaml in the project root.
        project_dir: Project root directory.  Defaults to the navil
                     package root (two levels up from this file).
        log_dir: Directory for honeypot JSONL logs.
    """

    def __init__(
        self,
        compose_file: str | None = None,
        project_dir: str | None = None,
        log_dir: str | None = None,
    ) -> None:
        if project_dir is None:
            # Two levels up from navil/honeypot/deploy.py -> project root
            project_dir = str(Path(__file__).resolve().parent.parent.parent)

        self.project_dir = project_dir
        self.compose_file = compose_file or os.path.join(
            self.project_dir, _DEFAULT_COMPOSE_FILE
        )
        self.log_dir = log_dir or os.path.join(self.project_dir, "honeypot_logs")

    def _docker_compose_cmd(self) -> list[str]:
        """Return the base docker compose command."""
        # Prefer 'docker compose' (v2) over 'docker-compose' (v1)
        if shutil.which("docker") is not None:
            return ["docker", "compose", "-f", self.compose_file]
        if shutil.which("docker-compose") is not None:
            return ["docker-compose", "-f", self.compose_file]
        raise RuntimeError("Neither 'docker compose' nor 'docker-compose' found on PATH")

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run a command and return the result."""
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            cwd=self.project_dir,
            capture_output=True,
            text=True,
            check=check,
        )

    def start(
        self,
        profiles: list[str] | None = None,
        detach: bool = True,
        log_path: str | None = None,
    ) -> dict[str, Any]:
        """Start honeypot containers.

        Args:
            profiles: List of profiles to start.  If None, starts all.
            detach: Run in detached mode (default: True).
            log_path: Override JSONL log path for the collector.

        Returns:
            Dict with start status information.
        """
        profiles = profiles or list(AVAILABLE_PROFILES)
        invalid = [p for p in profiles if p not in AVAILABLE_PROFILES]
        if invalid:
            return {
                "status": "error",
                "message": f"Unknown profiles: {invalid}. Available: {list(AVAILABLE_PROFILES)}",
            }

        services = ["navil-proxy", "redis"]
        services.extend(_PROFILE_SERVICE_MAP[p] for p in profiles)

        cmd = self._docker_compose_cmd() + ["up"]
        if detach:
            cmd.append("-d")
        cmd.extend(services)

        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)

        env = os.environ.copy()
        if log_path:
            env["HONEYPOT_LOG_PATH"] = log_path

        try:
            self._run(cmd)
            logger.info("Honeypot containers started: %s", profiles)
            return {
                "status": "started",
                "profiles": profiles,
                "services": services,
                "log_dir": self.log_dir,
                "compose_file": self.compose_file,
            }
        except subprocess.CalledProcessError as e:
            logger.error("Failed to start honeypot: %s", e.stderr)
            return {
                "status": "error",
                "message": e.stderr.strip(),
                "returncode": e.returncode,
            }

    def stop(self, profiles: list[str] | None = None) -> dict[str, Any]:
        """Stop honeypot containers.

        Args:
            profiles: Specific profiles to stop.  If None, stops all
                      honeypot services.

        Returns:
            Dict with stop status information.
        """
        cmd = self._docker_compose_cmd() + ["down"]

        if profiles:
            # Stop only specific services
            services = [_PROFILE_SERVICE_MAP[p] for p in profiles if p in _PROFILE_SERVICE_MAP]
            cmd = self._docker_compose_cmd() + ["stop"] + services
        else:
            # Stop everything
            cmd = self._docker_compose_cmd() + ["down"]

        try:
            self._run(cmd)
            stopped = profiles or list(AVAILABLE_PROFILES)
            logger.info("Honeypot containers stopped: %s", stopped)
            return {
                "status": "stopped",
                "profiles": stopped,
            }
        except subprocess.CalledProcessError as e:
            logger.error("Failed to stop honeypot: %s", e.stderr)
            return {
                "status": "error",
                "message": e.stderr.strip(),
                "returncode": e.returncode,
            }

    def status(self) -> dict[str, Any]:
        """Get status of honeypot containers.

        Returns:
            Dict with container status information.
        """
        cmd = self._docker_compose_cmd() + ["ps", "--format", "json"]

        try:
            result = self._run(cmd, check=False)
            if result.returncode != 0:
                # Fall back to plain text output
                cmd_plain = self._docker_compose_cmd() + ["ps"]
                result = self._run(cmd_plain, check=False)
                return {
                    "status": "ok",
                    "output": result.stdout.strip(),
                    "format": "text",
                }

            # Parse JSON output (docker compose v2 outputs one JSON per line)
            containers = []
            for line in result.stdout.strip().splitlines():
                if line.strip():
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            return {
                "status": "ok",
                "containers": containers,
                "format": "json",
            }

        except subprocess.CalledProcessError as e:
            return {
                "status": "error",
                "message": e.stderr.strip(),
            }
        except RuntimeError as e:
            return {
                "status": "error",
                "message": str(e),
            }

    def logs(
        self,
        profiles: list[str] | None = None,
        tail: int = 50,
    ) -> dict[str, Any]:
        """Fetch recent logs from honeypot containers.

        Args:
            profiles: Specific profiles to get logs for.
            tail: Number of lines to show.

        Returns:
            Dict with log output.
        """
        services = []
        if profiles:
            services = [_PROFILE_SERVICE_MAP[p] for p in profiles if p in _PROFILE_SERVICE_MAP]

        cmd = self._docker_compose_cmd() + ["logs", "--tail", str(tail)]
        cmd.extend(services)

        try:
            result = self._run(cmd, check=False)
            return {
                "status": "ok",
                "output": result.stdout.strip(),
            }
        except RuntimeError as e:
            return {
                "status": "error",
                "message": str(e),
            }

    def build(self) -> dict[str, Any]:
        """Build honeypot container images.

        Returns:
            Dict with build status.
        """
        cmd = self._docker_compose_cmd() + ["build"]

        try:
            result = self._run(cmd)
            return {"status": "ok", "output": result.stdout.strip()}
        except subprocess.CalledProcessError as e:
            return {
                "status": "error",
                "message": e.stderr.strip(),
                "returncode": e.returncode,
            }
