# ClawHub Skill Publishing

**Skills to publish:**
1. `navil-shield` -- Always-on runtime security proxy
2. `navil-audit` -- Deep security audit with penetration testing
3. `navil-policy` -- Token cost optimization via tool scoping

**Publisher:** `ivanpantheon`

---

## Pre-Publish Checklist

- [ ] ClawHub account (`ivanpantheon`) is old enough to publish (check minimum account age requirement)
- [ ] Each skill has a valid `SKILL.md` with frontmatter (name, description, version, author, tags)
- [ ] Each skill has been tested locally with `clawhub run <skill-dir>`
- [ ] Skills do not bundle navil itself -- they install it via `pip install navil` at runtime
- [ ] README / description clearly states what the skill does and what permissions it needs
- [ ] License field is set (Apache 2.0 for these skills)
- [ ] Tags are set for discoverability (security, mcp, governance, etc.)
- [ ] Screenshots or example output included where applicable
- [ ] No secrets, API keys, or credentials in any skill file
- [ ] Version follows semver (start at 1.0.0 for initial publish)

## Skill Descriptions

### navil-shield

**What it does:** Wraps all MCP servers in the user's config with Navil's runtime security proxy. Monitors tool calls, enforces policies, detects anomalies, and connects to the community threat network. Set-and-forget protection.

**Key commands used:** `navil wrap`, `navil monitor start`

### navil-audit

**What it does:** Runs a comprehensive security audit of the user's MCP setup. Scans config for vulnerabilities (0-100 score), runs 11 penetration test scenarios, and generates a remediation report. One-shot deep analysis.

**Key commands used:** `navil scan`, `navil pentest`, `navil report`

### navil-policy

**What it does:** Analyzes tool usage patterns and generates optimized policy rules that restrict which tools each agent can see. Reduces schema token bloat by up to 94%, cutting inference costs while improving security posture.

**Key commands used:** `navil policy auto-generate`, `navil policy suggest`

## Publish Commands

### 1. navil-shield

```bash
# Validate the skill locally
clawhub validate skills/navil-shield/

# Dry run to preview what will be published
clawhub publish skills/navil-shield/ --dry-run

# Publish
clawhub publish skills/navil-shield/

# Verify it appears in the registry
clawhub search navil-shield
```

### 2. navil-audit

```bash
# Validate
clawhub validate skills/navil-audit/

# Dry run
clawhub publish skills/navil-audit/ --dry-run

# Publish
clawhub publish skills/navil-audit/

# Verify
clawhub search navil-audit
```

### 3. navil-policy

```bash
# Validate
clawhub validate skills/navil-policy/

# Dry run
clawhub publish skills/navil-policy/ --dry-run

# Publish
clawhub publish skills/navil-policy/

# Verify
clawhub search navil-policy
```

## Post-Publish Verification

```bash
# Confirm all 3 are live and installable
clawhub install ivanpantheon/navil-shield --dry-run
clawhub install ivanpantheon/navil-audit --dry-run
clawhub install ivanpantheon/navil-policy --dry-run

# Check listing pages
clawhub info ivanpantheon/navil-shield
clawhub info ivanpantheon/navil-audit
clawhub info ivanpantheon/navil-policy
```

## Updating Published Skills

When releasing a new version of navil that changes skill behavior:

```bash
# Bump version in SKILL.md frontmatter, then:
clawhub publish skills/navil-shield/ --update
clawhub publish skills/navil-audit/ --update
clawhub publish skills/navil-policy/ --update
```

## Install Commands (for users)

Include these in marketing materials and the navil README:

```bash
clawhub install ivanpantheon/navil-shield
clawhub install ivanpantheon/navil-audit
clawhub install ivanpantheon/navil-policy
```

Or users can paste the ClawHub URLs directly into their OpenClaw chat and the agent handles setup automatically.
