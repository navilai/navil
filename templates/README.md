# Navil Policy Template Library

Production-ready, opinionated `navil.yaml` policies for the most common
MCP servers. Each template is **executable** — paired with a fixture file
of risky tool calls that the policy must catch.

The goal: a security team should be able to drop one of these into a
repo, deploy it behind `navil secure`, and have a sensible
least-privilege starting point in 60 seconds. Then iterate from there.

## Available templates

| Template | Use case | Default scope | Approval gates | Hard denies |
|---|---|---|---|---|
| [`stripe-mcp.yaml`](policies/stripe-mcp.yaml) | Read-only analytics + support agents | `stripe-readonly` | refunds, subscription changes, invoice send/void | charge creation, transfers, payouts, API key creation, webhook creation |
| [`linear-mcp.yaml`](policies/linear-mcp.yaml) | Standup digests, status reports, triage | `linear-reporter` | issue/project deletes, bulk archive | team/org admin, API key creation |
| [`github-mcp.yaml`](policies/github-mcp.yaml) | Code review (Claude Code, Cursor) | `github-reviewer` | PR merge, deploys, releases, workflow dispatch | repo delete, branch protection changes, org member removal |
| [`slack-mcp.yaml`](policies/slack-mcp.yaml) | Channel summaries + status posts | `slack-reader` | every `chat.postMessage`, file uploads, conversation invites | channel delete, app uninstall, user admin actions |
| [`filesystem-readonly.yaml`](policies/filesystem-readonly.yaml) | Code understanding, doc summarization | `filesystem-readonly` | — (read-only by design) | all writes/deletes/moves/exec, plus credential paths (`.env`, `.aws/credentials`, `.ssh/`, etc.) |

## How to use

### Quick start — copy a template into your project

```bash
mkdir -p .navil
curl -fsSL https://raw.githubusercontent.com/navilai/navil/main/templates/policies/github-mcp.yaml \
  > .navil/policy.yaml

# Adjust agent/server names, then activate:
navil secure --policy .navil/policy.yaml
```

### Validate against the fixture

Each policy ships with a fixture of real-world risky tool calls. After
adapting the policy, run the fixture to confirm Navil makes the
expected allow/deny/approval decisions:

```bash
navil policy test \
  --policy .navil/policy.yaml \
  --fixture templates/fixtures/github-risky-calls.jsonl
```

A passing run confirms your policy catches the dangerous-by-default
operations. A failing run prints the divergence so you can tighten
specific rules.

### Combine multiple templates

Most production setups need more than one. The recommended pattern:

```yaml
# .navil/policy.yaml
includes:
  - templates/policies/github-mcp.yaml
  - templates/policies/filesystem-readonly.yaml
  - templates/policies/slack-mcp.yaml

# Project-specific overrides go below the includes.
agents:
  release-bot:
    scope: github-pr-author
    rate_limit_per_hour: 100
```

## Anatomy of a template

Every template uses the same five sections so you can read one and
recognize the rest:

```yaml
version: "1.0"

scopes:
  # Named bundles of allowed tools. Reference these by name in agents.
  some-scope:
    description: "Human-readable purpose"
    tools: [...]

agents:
  # Per-agent rules. `default` applies to any unmatched agent.
  default:
    scope: some-scope
    rate_limit_per_hour: 1000
    tools_denied:
      - tool.that.must.never.run

require_approval:
  # Tools that may be called but require human approval first.
  - tool.that.needs.review

sensitive_data:
  # Field-level audit-log redaction.
  redact_in_logs:
    - api_key
    - oauth_token
```

## Contributing a template

We accept templates for any MCP server with a public spec. Open a PR
that adds:

```
templates/
  policies/<server>-mcp.yaml          # the template itself
  fixtures/<server>-risky-calls.jsonl # 6+ representative calls,
                                      # each with expected_decision
```

Guidelines:
- **Default to read-only.** New tools should be `tools_denied` until
  proven needed.
- **Approval gates over hard denies** for actions that are sometimes
  legitimate (e.g. PR merge, refund).
- **Hard deny for irreversible destructive actions** (delete, revoke,
  transfer money).
- **Annotate every `require_approval` and `tools_denied` entry** with a
  one-line comment explaining why.
- **Provide a fixture** with at least one of each: allowed call,
  approval-required call, hard-denied call.
- **Don't invent tool names** — match the actual MCP server's published
  tool registry. If a tool doesn't exist on a server, don't include it.

## Roadmap

Templates next on the list (PRs welcome):

- [ ] `notion-mcp.yaml` — DB read, page write with approval
- [ ] `postgres-mcp.yaml` — read-only with table allowlist
- [ ] `aws-mcp.yaml` — IAM-bounded read-only telemetry
- [ ] `kubernetes-mcp.yaml` — namespace-scoped read + safe-action subset
- [ ] `jira-mcp.yaml` — ticket triage with project allowlist
- [ ] `gmail-mcp.yaml` — read + draft only, no send

## License

Apache 2.0 — same as the rest of Navil. Use freely in commercial and
private projects, fork, modify, redistribute. The templates are
provided as a starting point; you are responsible for reviewing and
adapting them to your environment.
