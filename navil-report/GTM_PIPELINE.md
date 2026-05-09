# Navil GTM Pipeline

**Internal. Source-controlled view of outreach + Trust Reviews.**

This is the lightweight repo-local operating view, not a CRM. Notion
remains the system of record. This file exists so the team has one
file under version control that answers: *who are we talking to,
what segment are they in, what's the next action, who owns it?*

Update on commit, not on every email. If the answer to "should I open
this file?" is "I want a status summary in 30 seconds," it's working.

---

## Segments

Four buckets. **Each row in the pipeline must have exactly one
segment.** If you can't decide, default to "likely buyer" and revisit
after the first call.

### Strategic credibility (low cost, high signal — slow revenue)

Companies whose name on a customer logo wall, design-partner list, or
quote in the State of MCP Security report changes how every other
buyer evaluates Navil. Examples: Stripe, Linear, Sentry, Notion,
Anthropic/OpenAI ecosystem-adjacent vendors.

- **Goal:** quote, feedback, credibility — not near-term revenue
- **Time horizon:** 12+ months to paid contract
- **Outreach cadence:** founder-led, 1 touch per quarter, low volume
- **Don't waste:** trust review time chasing a paid pilot from these.
  They're the YC-application logo, not the Q3 close.

### Likely buyers (where revenue actually comes from)

Mid-size MCP vendors and agentic app builders with public MCP servers,
active repos, paying customers, and no in-house security team. They
have product liability, they need a "security review" page on their
docs to close their own enterprise customers, and they have budget for
$129–299/seat/month.

- **Goal:** Trust Review → Runtime Gateway Pilot → SaaS conversion
- **Time horizon:** 30–90 days from first call to LOI
- **Outreach cadence:** weekly batches of 5–10
- **ICP filter:** 100–2000 GitHub stars, active commits in last 30
  days, public pricing page, no security@ email address listed

### Community targets (top-of-funnel, distribution layer)

MCP server maintainers, agent power users, security-minded developers
shipping MCP integrations into their own products. The flywheel:
Config Clinic feedback → Policy Template Library contributions →
threat patterns → public reports → more users.

- **Goal:** template contributions, redacted threat patterns, social
  proof on GitHub
- **Time horizon:** ongoing — measured in stars, contributions, and
  Discord/issues activity, not revenue
- **Outreach cadence:** reply-where-asked, comment-where-relevant,
  never cold-DM
- **Conversion path:** community → personal use of Navil at work →
  internal recommendation → likely buyer

### Competitor / market intelligence (no outbound)

MCP gateways, AI security pure-plays, hosted-agent platforms. Tracked
to keep positioning sharp. **Default action: no outbound.** Exception:
explicit partnership conversation initiated by them.

- **Goal:** positioning clarity, partnership angle if it arrives
- **Outreach cadence:** zero
- **Tracking purpose:** so we know what they ship and don't get
  caught flat-footed when their next press release lands

---

## Status options

Use exactly these strings. Don't invent new ones — add to this list
first if you genuinely need a new state.

| Status | Meaning |
|---|---|
| `sourced` | Lead identified, not yet contacted |
| `drafted` | Outreach written, awaiting send |
| `contacted` | Outreach sent, awaiting reply |
| `replied` | They responded; conversation in progress |
| `trust-review-scheduled` | Trust Review on calendar |
| `trust-review-complete` | SOP delivered; debrief done |
| `design-partner` | Bi-weekly cadence active, free pilot |
| `LOI-requested` | Asked for LOI, awaiting decision |
| `LOI-signed` | LOI in hand |
| `pilot-active` | Paid Runtime Gateway Pilot running |
| `closed-no-fit` | Disqualified — wrong size, stage, or workflow |
| `nurture` | Interested but not ready; revisit Q+1 |

---

## ICP score

A rough 1–5 to rank within a segment. Used to triage when there's
more inbound than capacity.

- **5** — Public MCP server, active development, paying customers,
  warm intro, named by another design partner
- **4** — Public MCP server, active development, plausible budget,
  reachable contact
- **3** — Public MCP server OR active agent-tool-calling product;
  needs more verification
- **2** — Adjacent fit (e.g. AI tooling, no MCP yet); future-fit
- **1** — No real workflow today; archive unless they re-engage

---

## Pipeline

| Company / Person | Segment | ICP | Evidence | Contact route | Offer | Status | Next action | Owner | Notes |
|---|---|---|---|---|---|---|---|---|---|
| Stripe | strategic credibility | 5 | Public MCP server; named in our State of MCP Security report; security team is mature | LinkedIn → Patrick C. or Will L.; CSec via Stripe Sec team contact form | Quote permission for redacted finding; long-term design partner | sourced | Draft 3-paragraph outreach citing the Stripe MCP server findings | ivan | Don't ask for paid pilot — credibility play only |
| Linear | strategic credibility | 5 | Public MCP server; security-conscious; small enough to actually respond | Twitter/X → Karri Saarinen; founder warm intro via SF network | Quote permission; mid-term design partner candidate | sourced | DM Karri with the Linear-specific risky-call findings from `linear-mcp.yaml` fixture | ivan | High-signal if they engage |
| Sentry | strategic credibility | 4 | MCP integration in their product surface; security-DNA company | Existing Sentry customer relationship (if any); cold via security@ | Quote permission; potential partnership on threat-intel feed | sourced | Confirm whether we're already a Sentry customer; if so, use that hook | ivan | If no existing customer relationship, lower priority |
| Notion | strategic credibility | 3 | Public MCP server; large enterprise customer base needing trust answers | LinkedIn cold; founder community | Quote permission; future logo | sourced | Wait until Notion-mcp.yaml ships in Policy Template Library, then lead with that | ivan | Tied to template library v0.2 |
| BuildBetter | likely buyer | 4 | Agentic product reaching production data | Cold email → founder; LinkedIn → CTO | Trust Review → Pilot | sourced | Draft cold email; reference State of MCP Security report stat | ivan | Flagged in earlier pass as MCP-heavy |
| Glacier | likely buyer | 3 | Agentic app builder, MCP-adjacent | Cold email; warm intro if available | Trust Review | sourced | Confirm public MCP/tool-calling exposure before reaching out | ivan | ICP score upgrades if MCP server is verified public |
| Minolith | likely buyer | 3 | MCP-adjacent agent builder | Cold email — manual track | Trust Review | sourced | Verify they have a real production workflow before touching | ivan | Manual outreach only — not in automated batch |
| Dust (dust.tt) | strategic credibility / design partner | 4 | Multi-agent platform, MCP-integrated, security-leaning team | Founder network; conference DM | Design partner; potential paid pilot | sourced | Soft DM via Twitter/X — "we ran our scanner against the MCP servers Dust connects to, here's what we found" | ivan | Could go either segment; default to design partner |
| NGS (logistics) | likely buyer | 5 | Warm intro from Ivan's prior work; running agents internally | Direct intro available | Trust Review with LOI ask | sourced | Reach out today; this is the highest-leverage warm contact we have | ivan | Per the Track B plan — first call this week |
| Kim Soon Lee | likely buyer | 5 | Warm intro from Ivan's prior work | Direct intro available | Trust Review with LOI ask | sourced | Reach out today; second highest-leverage warm contact | ivan | Per the Track B plan |
| [TKTK community maintainer 1] | community | — | Maintainer of an MCP server with 200+ GitHub stars | GitHub issue / discussion | Policy template contribution; Config Clinic | sourced | Pick a specific maintainer from `awesome-mcp-servers` filter (100–2000 stars, active in last 30 days) | ivan | Replace placeholder with name before next pipeline review |
| Wiz | competitor / market intel | — | Now embeds Claude Opus 4.7 in their platform (April 30, 2026 announcement); CNAPP runtime layer | — | none | sourced | Track product announcements; no outbound | ivan | Most-feared competitor per YC application |
| Anthropic (Claude Managed Agents) | competitor / market intel | — | Hosted-only runtime governance for Anthropic agents | — | none | sourced | Track Claude.ai/security and Managed Agents roadmap | ivan | Single-vendor; structurally can't ship our cross-vendor lane |

---

## Weekly cadence

Every Monday, 30 minutes:

1. Filter `Status == sourced` — pick top 5 by ICP score per segment
2. Filter `Status == contacted` aged > 7 days — decide: re-touch or
   close-no-fit
3. Filter `Status == trust-review-scheduled` — confirm prep is done
4. Filter `Status == LOI-requested` aged > 14 days — escalate or close
5. Update `Next action` and `Status` in this file
6. Commit the diff with message `gtm: weekly pipeline update YYYY-MM-DD`

---

## Definition of "done" for this file

- Every row has a non-empty `Next action`
- Every row has an `Owner` (right now: `ivan`)
- No row has been in the same status for more than 30 days without
  a status change OR an explicit "stale OK — see notes"
- Strategic + likely-buyer rows are within striking distance of the
  YC interview cycle if the interview lands

If any of those are false, the next pipeline review fixes it before
adding new rows.
