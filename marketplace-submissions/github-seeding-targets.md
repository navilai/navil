# GitHub Seeding Targets

Use these open discussions/issues to add Navil as a relevant reference.
**Rules:** Don't spam. Only comment where genuinely relevant. Lead with insight, not promotion.

## High-Priority Targets

### 1. [RFC] Secure Model Context Protocol (SMCP) v1.0 — Discussion #689
**URL:** https://github.com/orgs/modelcontextprotocol/discussions/689
**Why:** This discussion proposes adding a Security Envelope pattern with fine-grained authorization. Navil's runtime monitoring and policy enforcement is directly relevant as a complementary approach.
**Angle:** "We took a different approach — instead of modifying the protocol, we added a transparent proxy layer that enforces policies at runtime. Here's what we learned from monitoring real MCP traffic across 4,401 servers..."

### 2. MCP Security Issue #544 — Insufficient security design
**URL:** https://github.com/modelcontextprotocol/modelcontextprotocol/issues/544
**Why:** Discusses MCP's lack of auth, permission scoping, and phishing risks. Navil addresses runtime aspects of all three.
**Angle:** "We built runtime detection for these exact vectors. Our honeypot data shows automated probing within hours of exposure..."

### 3. Security IG Meeting Notes — Issue #1541
**URL:** https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1541
**Why:** Security Interest Group meeting notes — the people in this thread are our exact ICP.
**Angle:** Read the notes, contribute substantively to any open questions about runtime security.

### 4. modelcontextprotocol/docs Issues
**URL:** https://github.com/modelcontextprotocol/docs/issues
**Why:** Look for issues about security documentation gaps. Offer to contribute documentation about runtime security best practices.
**Angle:** PR to add security monitoring guidance, with Navil as one reference implementation.

## Medium-Priority Targets

### 5. awesome-mcp-servers
Submit Navil to relevant awesome lists as a security tool.
**Template:** Already prepared at `marketplace-submissions/awesome-mcp-servers.md`

### 6. Popular MCP Server Repos
Search for security-related issues on:
- `modelcontextprotocol/servers` (official)
- Popular community MCP servers (GitHub, filesystem, Slack)
**Angle:** If someone asks about security, offer Navil as a monitoring layer.

## Comment Templates

### For RFC/Discussion threads:
> We've been working on runtime security for MCP and have some data that might be useful here. We scanned 4,401 MCP servers and deployed honeypots — static scanning caught 1.7% of actual threats. The remaining 98.3% (prompt injection, credential exfiltration, rug pulls) only appear at runtime.
>
> Our approach was to build a transparent proxy that sits between the client and servers, enforcing policies without protocol changes. Open source: https://github.com/navilai/navil
>
> Happy to share our threat taxonomy (36 categories) if it's useful for this effort.

### For security-related issues:
> This is a real problem we've observed in production. We deployed honeypot MCP servers and saw automated probing within hours — tool enumeration, credential reads, reverse shell attempts.
>
> We open-sourced a runtime security proxy that catches these patterns: https://github.com/navilai/navil (368 signatures, 11 attack categories). Might be useful context for this discussion.
