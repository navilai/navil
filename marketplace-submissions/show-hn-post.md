# Show HN Draft

## Title (80 char limit)

**Option A:** Show HN: Navil -- Open-source runtime security for AI agents (MCP proxy)

**Option B:** Show HN: Navil -- We scanned 16K MCP servers. 66% have security findings

**Option C:** Show HN: Navil -- pip install navil && navil wrap your_mcp_config.json

Recommendation: **Option B** — leads with the research, not the product. HN rewards insight over promotion.

---

## Post Body

We scanned 16,000 MCP servers across npm, PyPI, and awesome-mcp-servers. 66% have security findings. 100% are missing authentication. The highest CVSS score we found was 9.6 (RCE).

But the real problem isn't the servers — it's what happens at runtime. An MCP server can have perfectly clean source code and still be weaponized: prompt injection via tool calls, data exfiltration through responses, credential exposure, rug pulls after install. Static scanning catches 1.7% of actual threats. The other 98.3% only show up when tools are called.

Navil is an open-source security proxy for MCP. Two lines:

    pip install navil
    navil wrap ~/.cursor/mcp.json

Every MCP server in your config is now behind a proxy that monitors tool calls, enforces policies, detects anomalies, and blocks known attack patterns — with <3us overhead per message. Your original config is backed up automatically.

What it does:

- Behavioral anomaly detection (11 statistical detectors with adaptive baselines)
- Policy enforcement (YAML-driven tool/action allowlists per agent)
- Tool scoping (reduce schema tokens by up to 94% — a code review agent sees 3 tools, not 90)
- Community threat intelligence (anonymized, give-to-get model — 568 patterns in the blocklist)
- Penetration testing (11 SAFE-MCP attack simulations to validate your detectors)
- AI-powered self-healing (LLM analyzes anomalies and suggests policy changes)

The proxy itself is Rust (Axum, sub-millisecond). The detection pipeline is Python. Dashboard included.

Works with Claude Desktop, Cursor, OpenClaw, Continue.dev, and any MCP client that uses config files. For HTTP MCP servers (production deployments), there's an HTTP proxy mode.

We published the full scan results and our threat taxonomy (36 attack categories) as a free report: https://navil.ai/assessment

OSS (Apache 2.0 core, BSL for cloud features): https://github.com/navilai/navil

Live threat radar (real-time data from the community network): https://navil.ai/radar

---

## Posting Strategy

**When:** Wednesday 10am ET (best HN traffic for Show HN)

**First comment** (post immediately after submission — establishes context):

Hi HN, Ivan here. I built this because I kept seeing the same pattern: people install 10+ MCP servers, connect them to Claude or Cursor, and have zero visibility into what those servers do at runtime.

The MCP protocol has real problems — no auth, no observability, context bloat (GitHub MCP dumps 90 tools consuming 50K tokens before the model even thinks). But the answer isn't to abandon the protocol. It's to fix the operational layer.

A few things I learned building this:

1. The "MCP is dead" crowd is right about the problems, wrong about the solution. The protocol works. The operational layer is what's missing.

2. Tool scoping is surprisingly valuable for cost optimization, not just security. Restricting which tools an agent sees cuts inference costs dramatically.

3. Community threat intelligence with a give-to-get model works better than I expected. Every node that detects a new pattern makes every other node smarter within seconds.

Happy to answer questions about the architecture (Rust proxy + Python detection), the threat landscape, or anything else.

---

## Notes

- Don't post links in the body beyond the project URL — HN penalizes multiple links
- The title with the research angle (Option B) is more likely to get upvotes than a product pitch
- First comment should be personal and technical, not salesy
- Respond to every comment in the first 2 hours — comments are a stronger ranking signal than upvotes
- Line up 3-5 people to leave genuine questions/comments right after posting (kickstart discussion)
- Do NOT share the HN link asking for upvotes — vote-ring detection will penalize the post
- The "Show HN:" prefix puts you on the less-competitive "show" tab for longer exposure
