# Navil MCP Security Scan Action

A GitHub Action that scans MCP (Model Context Protocol) server configurations for security vulnerabilities using [Navil](https://github.com/navilai/navil). Produces SARIF output compatible with GitHub Code Scanning.

## Quick Start

```yaml
- uses: navilai/navil/.github/actions/scan@v1
  with:
    config: mcp_config.json
    fail-on: critical
```

## Inputs

| Input     | Required | Default            | Description                                                         |
|-----------|----------|--------------------|---------------------------------------------------------------------|
| `config`  | Yes      | `mcp_config.json`  | Path to the MCP config file to scan                                 |
| `fail-on` | No       | `critical`         | Severity threshold to fail the action (`critical`, `high`, `medium`, `low`, `info`) |
| `format`  | No       | `sarif`            | Output format (`sarif`, `json`, `text`)                             |

## Outputs

| Output            | Description                         |
|-------------------|-------------------------------------|
| `score`           | Security score from 0 to 100        |
| `vulnerabilities` | Number of vulnerabilities found     |
| `sarif-file`      | Path to the generated SARIF file    |

## Usage Examples

### Basic: Scan on every pull request

```yaml
name: MCP Security Scan
on:
  pull_request:
    paths:
      - 'mcp_config.json'
      - '.mcp.json'

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: navilai/navil/.github/actions/scan@v1
        id: navil
        with:
          config: mcp_config.json
          fail-on: critical

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif
```

### With PR comment summary

```yaml
name: MCP Security Scan
on:
  pull_request:
    paths: ['**.mcp.json', 'mcp_config.json']

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: navilai/navil/.github/actions/scan@v1
        id: navil
        with:
          config: mcp_config.json
          fail-on: high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif

      - name: Comment on PR
        if: always()
        uses: actions/github-script@v7
        env:
          SCORE: ${{ steps.navil.outputs.score }}
          VULNS: ${{ steps.navil.outputs.vulnerabilities }}
        with:
          script: |
            const score = parseInt(process.env.SCORE || '0');
            const vulns = process.env.VULNS || '0';
            const icon = score >= 80 ? ':white_check_mark:' : score >= 50 ? ':warning:' : ':x:';
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## ${icon} Navil MCP Security Scan\n\n**Score:** ${score}/100\n**Vulnerabilities:** ${vulns}\n\nView details in the **Security** tab.`
            });
```

### Block merges on high-severity findings

```yaml
- uses: navilai/navil/.github/actions/scan@v1
  with:
    config: .mcp.json
    fail-on: high
```

This fails the workflow if any `high` or `critical` severity findings are detected.

### JSON output (no SARIF)

```yaml
- uses: navilai/navil/.github/actions/scan@v1
  with:
    config: mcp_config.json
    format: json
    fail-on: medium
```

### Scheduled weekly scan

```yaml
name: Weekly MCP Security Audit
on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9am UTC

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: navilai/navil/.github/actions/scan@v1
        id: navil
        with:
          config: mcp_config.json
          fail-on: medium

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: navil-results.sarif
```

## How It Works

1. Installs Navil via pip
2. Validates the MCP config file exists
3. Runs `navil scan` to analyze the configuration for security issues
4. Generates SARIF output compatible with GitHub Code Scanning
5. Checks findings against the severity threshold and fails if exceeded

## Severity Levels

From lowest to highest:

| Level      | Description                                          |
|------------|------------------------------------------------------|
| `info`     | Informational findings, best practice suggestions    |
| `low`      | Minor issues with limited security impact            |
| `medium`   | Moderate issues that should be reviewed              |
| `high`     | Serious vulnerabilities that need prompt attention   |
| `critical` | Severe vulnerabilities requiring immediate action    |

The `fail-on` input sets the minimum severity that causes the action to fail. For example, `fail-on: high` fails on `high` and `critical` findings but passes on `medium`, `low`, and `info`.

## SARIF Integration

When `format` is `sarif` (default), the action writes results to `navil-results.sarif`. Upload this to GitHub Code Scanning with:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: navil-results.sarif
```

This surfaces findings directly in the **Security** tab and as inline annotations on pull requests.

## License

Apache-2.0 -- see [LICENSE](../../../LICENSE) for details.
