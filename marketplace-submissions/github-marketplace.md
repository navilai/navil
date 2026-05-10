# GitHub Action: Navil MCP Security Scan

**Action:** `navilai/navil-action@v1`
**Marketplace listing:** GitHub Actions Marketplace

---

## Action Metadata

| Field | Value |
|-------|-------|
| **Name** | Navil MCP Security Scan |
| **Author** | Pantheon Lab |
| **Description** | Scan MCP server configs for security vulnerabilities. Produces a 0-100 score, blocks on critical findings, and uploads SARIF results to GitHub Security. |
| **Icon** | `shield` |
| **Color** | `blue` |

## Marketplace Description

### Navil MCP Security Scan

Automatically scan your MCP server configurations for security vulnerabilities on every pull request. Navil checks for missing authentication, exposed credentials, unverified sources, over-privileged permissions, and 568 known attack patterns across 36 categories.

**What it does:**

- Scans any MCP config file (Claude Desktop, Cursor, Continue.dev, OpenClaw) for security issues
- Produces a 0-100 security score with actionable remediation steps
- Outputs SARIF v2.1.0 for native GitHub Code Scanning integration
- Blocks merges on critical or high-severity findings (configurable threshold)
- Runs in under 10 seconds with no external service dependencies

**Why use it:**

- 100% of public MCP servers are missing authentication
- 824 malicious skills detected in the OpenClaw registry
- 8+ CVEs discovered in the MCP protocol in 6 weeks
- Static config scanning catches issues before they reach production

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `config` | Path to MCP config file(s). Supports glob patterns. | Yes | -- |
| `fail-on` | Minimum severity to fail the check. Options: `critical`, `high`, `medium`, `low`, `none`. | No | `critical` |
| `format` | Output format: `sarif`, `json`, `text`. | No | `sarif` |
| `output` | Path for the output file. | No | `navil-results.sarif` |
| `navil-version` | Specific navil version to install. | No | `latest` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Overall security score (0-100) |
| `findings` | Number of findings detected |
| `critical-count` | Number of critical-severity findings |
| `high-count` | Number of high-severity findings |
| `sarif-file` | Path to the generated SARIF file |

## Badges

```markdown
[![Navil MCP Security Scan](https://github.com/<OWNER>/<REPO>/actions/workflows/navil-scan.yml/badge.svg)](https://github.com/<OWNER>/<REPO>/actions/workflows/navil-scan.yml)

[![MCP Security Score](https://navil-cloud-api.onrender.com/v1/badge/score.svg?repo=<OWNER>/<REPO>)](https://navil.ai/radar)
```

## Example Workflows

### Basic: Scan on PR

```yaml
name: MCP Security Scan
on:
  pull_request:
    paths: ["**.mcp.json", ".mcp.json", "openclaw.json", "claude_desktop_config.json"]

jobs:
  navil-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: navilai/navil-action@v1
        with:
          config: mcp_config.json
          fail-on: critical

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif
```

### Multiple configs

```yaml
name: MCP Security Scan
on:
  pull_request:
    paths: ["**/*.mcp.json", "**/*.json"]

jobs:
  navil-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: navilai/navil-action@v1
        with:
          config: |
            .mcp.json
            configs/*.mcp.json
            openclaw.json
          fail-on: high

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif
```

### Strict: Block on any finding

```yaml
name: MCP Security Scan (Strict)
on:
  pull_request:
    paths: ["**.mcp.json"]

jobs:
  navil-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: navilai/navil-action@v1
        id: scan
        with:
          config: .mcp.json
          fail-on: low

      - name: Comment score on PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Navil MCP Security Scan\n\nScore: **${{ steps.scan.outputs.score }}/100**\nFindings: ${{ steps.scan.outputs.findings }} (${{ steps.scan.outputs.critical-count }} critical, ${{ steps.scan.outputs.high-count }} high)`
            })

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif
```

### Scheduled: Weekly full scan

```yaml
name: Weekly MCP Security Audit
on:
  schedule:
    - cron: "0 9 * * 1"  # Every Monday at 9am UTC
  workflow_dispatch:

jobs:
  navil-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: navilai/navil-action@v1
        with:
          config: "**/*.mcp.json"
          fail-on: none
          format: sarif

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif
```

## How Results Appear in GitHub

Once SARIF is uploaded, findings appear in:

1. **Security tab** > **Code scanning alerts** -- each finding with severity, description, and remediation
2. **PR checks** -- the action check shows pass/fail based on the `fail-on` threshold
3. **PR annotations** -- inline annotations on the config file lines with issues

## Links

- **GitHub:** https://github.com/navilai/navil
- **Action source:** https://github.com/navilai/navil-action
- **Documentation:** https://github.com/navilai/navil#cicd-integration
- **Live threat radar:** https://navil.ai/radar
