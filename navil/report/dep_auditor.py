"""MCP ecosystem dependency auditor.

Pipeline:
  1. Discover top MCP packages from npm (keyword: mcp-server) and PyPI.
  2. Fetch each package's direct + first-level transitive dependencies.
  3. Batch-query OSV.dev for CVEs.
  4. Map CVEs to SAFE-MCP tactic categories via keyword heuristics.
  5. Return a structured AuditReport for use by the report generator.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from navil.report.osv_client import OsvVuln, query_packages

logger = logging.getLogger(__name__)

_NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
_NPM_PKG = "https://registry.npmjs.org/{name}/latest"
_PYPI_SIMPLE = "https://pypi.org/simple/"
_PYPI_PKG = "https://pypi.org/pypi/{name}/json"

_TIMEOUT = 20.0
_CONCURRENCY = 10


# ── Data types ────────────────────────────────────────────────────


@dataclass
class PackageDep:
    name: str
    version: str
    ecosystem: str


@dataclass
class AuditedPackage:
    name: str
    version: str
    ecosystem: str
    description: str
    weekly_downloads: int
    github_url: str
    dependencies: list[PackageDep] = field(default_factory=list)
    vulns: list[OsvVuln] = field(default_factory=list)
    dep_vulns: dict[str, list[OsvVuln]] = field(default_factory=dict)
    tactic_exposure: dict[str, list[str]] = field(default_factory=dict)

    @property
    def total_cves(self) -> int:
        return len(self.vulns) + sum(len(v) for v in self.dep_vulns.values())

    @property
    def max_severity(self) -> str:
        all_vulns = list(self.vulns) + [v for vs in self.dep_vulns.values() for v in vs]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if any(v.severity == sev for v in all_vulns):
                return sev
        return "NONE"


@dataclass
class AuditReport:
    generated_at: str
    ecosystems: list[str]
    packages_audited: int
    packages_with_vulns: int
    total_cves: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    tactic_exposure: dict[str, int]
    top_vulnerable_deps: list[dict]
    packages: list[AuditedPackage]


# ── SAFE-MCP tactic keyword mapping ──────────────────────────────


_TACTIC_KEYWORDS: dict[str, list[str]] = {
    "Supply Chain": [
        "supply chain",
        "dependency confusion",
        "typosquat",
        "malicious package",
        "install script",
        "postinstall",
        "package hijack",
    ],
    "Privilege Escalation": [
        "privilege escalat",
        "unauthorized access",
        "permission bypass",
        "escalat",
        "improper authorization",
    ],
    "Code Execution": [
        "remote code execution",
        "rce",
        "arbitrary code",
        "command injection",
        "os command",
        "shell injection",
    ],
    "Prompt Injection": [
        "prompt injection",
        "input validation",
        "cross-site scripting",
        "xss",
        "unsanitized input",
    ],
    "Credential Scope": [
        "credential",
        "token exposure",
        "api key",
        "hardcoded secret",
        "password",
        "auth bypass",
        "oauth misconfiguration",
        "jwt",
    ],
    "Tool Poisoning": [
        "deserialization",
        "prototype pollution",
        "template injection",
        "server-side template",
        "ssti",
        "unsafe deserialization",
    ],
    "RAG & Memory Poisoning": [
        "path traversal",
        "directory traversal",
        "file inclusion",
        "lfi",
        "rfi",
        "arbitrary file read",
        "arbitrary file write",
    ],
    "Infrastructure & Runtime": [
        "denial of service",
        "dos",
        "memory corruption",
        "buffer overflow",
        "null pointer",
        "resource exhaustion",
        "regex denial",
    ],
    "Anti-Forensics": [
        "log bypass",
        "audit trail",
        "bypass detection",
        "obfuscat",
    ],
    "Output Weaponization": [
        "data exfiltration",
        "ssrf",
        "server-side request forgery",
        "open redirect",
        "information disclosure",
    ],
}


def _map_to_tactics(vuln: OsvVuln) -> list[str]:
    text = (vuln.summary + " " + vuln.details).lower()
    matched = [t for t, kws in _TACTIC_KEYWORDS.items() if any(kw in text for kw in kws)]
    return matched or ["Infrastructure & Runtime"]


# ── npm helpers ───────────────────────────────────────────────────


async def _npm_search(client: httpx.AsyncClient, query: str, size: int) -> list[dict]:
    objects: list[dict] = []
    per_page = min(size, 250)
    while len(objects) < size:
        params = {
            "text": query,
            "size": str(per_page),
            "from": str(len(objects)),
            "quality": "0.65",
            "popularity": "1.0",
            "maintenance": "0.5",
        }
        try:
            resp = await client.get(_NPM_SEARCH, params=params, timeout=_TIMEOUT)
            resp.raise_for_status()
            batch = resp.json().get("objects", [])
            if not batch:
                break
            objects.extend(batch)
            if len(batch) < per_page:
                break
        except Exception as exc:
            logger.warning("npm search failed %r: %s", query, exc)
            break
    return objects[:size]


async def _npm_deps(client: httpx.AsyncClient, name: str) -> tuple[str, list[PackageDep]]:
    try:
        resp = await client.get(_NPM_PKG.format(name=name), timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        version = data.get("version", "0.0.0")
        deps = []
        for dep_name, spec in data.get("dependencies", {}).items():
            ver = re.sub(r"[^0-9.]", "", spec.lstrip("^~>=<")) or "0.0.0"
            deps.append(PackageDep(dep_name, ver, "npm"))
        return version, deps
    except Exception as exc:
        logger.debug("npm detail failed %r: %s", name, exc)
        return "0.0.0", []


# ── PyPI helpers ──────────────────────────────────────────────────


async def _pypi_names(client: httpx.AsyncClient, keyword: str, size: int) -> list[str]:
    try:
        resp = await client.get(_PYPI_SIMPLE, timeout=30.0)
        resp.raise_for_status()
        names = re.findall(r'href="[^"]*">([^<]+)</a>', resp.text)
        return [n for n in names if keyword.lower() in n.lower()][:size]
    except Exception as exc:
        logger.warning("PyPI simple index failed: %s", exc)
        return []


async def _pypi_deps(client: httpx.AsyncClient, name: str) -> tuple[str, list[PackageDep]]:
    try:
        resp = await client.get(_PYPI_PKG.format(name=name), timeout=_TIMEOUT)
        resp.raise_for_status()
        info = resp.json().get("info", {})
        version = info.get("version", "0.0.0")
        deps = []
        for req in info.get("requires_dist") or []:
            m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\(([^)]+)\))?", req)
            if not m:
                continue
            ver = re.sub(r"[^0-9.]", "", (m.group(2) or "").lstrip("^~>=<!")) or "0.0.0"
            deps.append(PackageDep(m.group(1), ver, "PyPI"))
        return version, deps
    except Exception as exc:
        logger.debug("PyPI detail failed %r: %s", name, exc)
        return "0.0.0", []


# ── Core audit ────────────────────────────────────────────────────


async def run_audit(
    *,
    top_n: int = 100,
    ecosystems: list[str] | None = None,
    include_transitive: bool = True,
) -> AuditReport:
    ecosystems = [e.lower() for e in (ecosystems or ["npm", "pypi"])]
    sem = asyncio.Semaphore(_CONCURRENCY)
    audited: list[AuditedPackage] = []

    async with httpx.AsyncClient(
        headers={"User-Agent": "navil-audit-deps/1.0 (https://navil.ai)"},
        follow_redirects=True,
    ) as client:
        if "npm" in ecosystems:
            audited.extend(await _audit_npm(client, top_n, sem))
        if "pypi" in ecosystems:
            audited.extend(await _audit_pypi(client, top_n, sem))

    await _enrich_cves(audited, include_transitive)
    for pkg in audited:
        _compute_tactic_exposure(pkg)
    return _build_report(audited, ecosystems)


async def _audit_npm(
    client: httpx.AsyncClient, top_n: int, sem: asyncio.Semaphore
) -> list[AuditedPackage]:
    results = await _npm_search(client, "mcp-server keywords:mcp", top_n)
    results += await _npm_search(client, "modelcontextprotocol mcp", top_n // 2)
    seen: set[str] = set()
    unique = []
    for obj in results:
        name = obj.get("package", {}).get("name", "")
        if name and name not in seen:
            seen.add(name)
            unique.append(obj)

    async def _one(obj: dict) -> AuditedPackage | None:
        async with sem:
            pkg = obj.get("package", {})
            name = pkg.get("name", "")
            if not name:
                return None
            version, deps = await _npm_deps(client, name)
            pop = obj.get("score", {}).get("detail", {}).get("popularity", 0)
            links = pkg.get("links", {})
            return AuditedPackage(
                name=name,
                version=version,
                ecosystem="npm",
                description=pkg.get("description", ""),
                weekly_downloads=int(pop * 1_000_000),
                github_url=links.get("repository", links.get("homepage", "")),
                dependencies=deps,
            )

    results_list = await asyncio.gather(*[_one(o) for o in unique[:top_n]])
    return [r for r in results_list if r is not None]


async def _audit_pypi(
    client: httpx.AsyncClient, top_n: int, sem: asyncio.Semaphore
) -> list[AuditedPackage]:
    names = await _pypi_names(client, "mcp", top_n)

    async def _one(name: str) -> AuditedPackage | None:
        async with sem:
            version, deps = await _pypi_deps(client, name)
            return AuditedPackage(
                name=name,
                version=version,
                ecosystem="PyPI",
                description="",
                weekly_downloads=0,
                github_url="",
                dependencies=deps,
            )

    results_list = await asyncio.gather(*[_one(n) for n in names[:top_n]])
    return [r for r in results_list if r is not None]


async def _enrich_cves(packages: list[AuditedPackage], include_transitive: bool) -> None:
    to_query: list[tuple[str, str, str]] = []
    index: dict[tuple[str, str], list[tuple[str, str | None]]] = {}

    for pkg in packages:
        key = (pkg.name, pkg.version)
        to_query.append((pkg.name, pkg.version, pkg.ecosystem))
        index.setdefault(key, []).append((pkg.name, None))
        if include_transitive:
            for dep in pkg.dependencies:
                dkey = (dep.name, dep.version)
                to_query.append((dep.name, dep.version, dep.ecosystem))
                index.setdefault(dkey, []).append((pkg.name, dep.name))

    seen: set[tuple[str, str, str]] = set()
    unique = [q for q in to_query if not (q in seen or seen.add(q))]  # type: ignore[func-returns-value]

    logger.info("Querying OSV.dev for %d package/version pairs…", len(unique))
    osv = await query_packages(unique)

    pkg_map = {p.name: p for p in packages}
    for (dep_name, dep_version), vulns in osv.items():
        if not vulns:
            continue
        for owner_name, dep_key in index.get((dep_name, dep_version), []):
            owner = pkg_map.get(owner_name)
            if owner is None:
                continue
            if dep_key is None:
                owner.vulns.extend(vulns)
            else:
                owner.dep_vulns.setdefault(dep_key, []).extend(vulns)


def _compute_tactic_exposure(pkg: AuditedPackage) -> None:
    all_vulns = list(pkg.vulns) + [v for vs in pkg.dep_vulns.values() for v in vs]
    exposure: dict[str, list[str]] = {}
    for vuln in all_vulns:
        for tactic in _map_to_tactics(vuln):
            exposure.setdefault(tactic, [])
            if vuln.id not in exposure[tactic]:
                exposure[tactic].append(vuln.id)
    pkg.tactic_exposure = exposure


def _build_report(packages: list[AuditedPackage], ecosystems: list[str]) -> AuditReport:
    with_vulns = [p for p in packages if p.total_cves > 0]
    all_vulns = [
        v
        for p in packages
        for v in (list(p.vulns) + [v for vs in p.dep_vulns.values() for v in vs])
    ]
    sev = Counter(v.severity for v in all_vulns)
    tactic_counts: Counter[str] = Counter()
    for pkg in packages:
        for t in pkg.tactic_exposure:
            tactic_counts[t] += 1
    dep_counts: Counter[str] = Counter()
    for pkg in packages:
        for dep_name, vulns in pkg.dep_vulns.items():
            if vulns:
                dep_counts[dep_name] += 1

    return AuditReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        ecosystems=ecosystems,
        packages_audited=len(packages),
        packages_with_vulns=len(with_vulns),
        total_cves=sum(p.total_cves for p in packages),
        critical_count=sev.get("CRITICAL", 0),
        high_count=sev.get("HIGH", 0),
        medium_count=sev.get("MEDIUM", 0),
        low_count=sev.get("LOW", 0),
        tactic_exposure=dict(tactic_counts),
        top_vulnerable_deps=[
            {"name": n, "affected_packages": c} for n, c in dep_counts.most_common(20)
        ],
        packages=packages,
    )
