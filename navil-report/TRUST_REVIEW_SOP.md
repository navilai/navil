# MCP Trust Review — Standard Operating Procedure

**Internal use only. Not customer-facing.**

This is the constraint document for free-of-charge MCP Trust Reviews.
The whole point of this format is the **4-hour ceiling**. If a review
runs long, it's no longer customer development — it's consulting, and
we don't do consulting. Convert to a paid Runtime Gateway Pilot or pass.

---

## 1. Purpose

This is **customer development**, not a paid engagement.

The review exists to produce three things, in priority order:

1. **Design partner signal.** Is this person a real buyer? Will they
   adopt? Are they running enough MCP/tool-calling traffic to matter?
2. **Product gap data.** What does Navil not yet do that this team
   needs? Captured as concrete tickets, not vibes.
3. **Quote / LOI material.** A redacted-finding quote we can use in
   the YC application, the State of MCP Security report, or the
   homepage. An LOI if the conversation gets there.

Revenue comes from Runtime Gateway Pilots and SaaS, not from this.

---

## 2. Qualification — gate before scheduling

A trust review is **only worth running** if all four are true:

- [ ] They run a real MCP / agent / tool-calling workflow today
      (not "we're thinking about it next quarter")
- [ ] The workflow touches production-ish data or systems
      (customer records, code repos, payments, internal CRM, etc.)
- [ ] They agree to a 30-minute debrief at the end
- [ ] At least one of: redacted-findings quote permission, design
      partner intent, or a defined budget for a paid pilot

If any of these are missing, send the report + cold email + a calendar
link instead. Don't burn 4 hours on a no-fit.

---

## 3. Inputs needed before kickoff

Sent in advance via email or shared doc. **Do not start the clock
until all five are received.**

1. **MCP config file** (e.g. `~/.cursor/mcp.json`) or links to the
   MCP servers they're running, even just names + GitHub repos
2. **One real workflow description** — "our support agent reads Stripe
   customer data and posts summaries to Slack" — concrete, not abstract
3. **Sample tool-call log or fixture** if available; otherwise we
   reconstruct from the workflow description
4. **List of sensitive systems** the agent can reach (or might reach)
5. **Any existing policy / security concerns** they've already flagged
   internally

If they cannot produce items 1, 2, and 4, the review is premature.
Send them the Policy Template Library and circle back in two weeks.

---

## 4. The 4-hour workflow

Hard time budget per phase. **Use a timer.**

| Phase | Time | What happens |
|---|---|---|
| Intake | 0:30 | Read inputs, confirm scope, write the intake brief |
| Config + tool inventory | 0:45 | List every MCP server + tool the agent can reach. `navil audit-deps --stdio-flaw` against their config |
| Policy generation | 0:45 | `navil policy generate` against their workflow, or adapt the closest Policy Template Library entry |
| Risky-call review | 0:45 | Identify 3–5 specific risky tool-call patterns in their environment. `navil policy test` against a fixture we write from the workflow |
| Loom recording | 0:30 | Record 5-minute Loom showing the enforcement working on their setup. Allowed, denied, approval-required all visible |
| Debrief prep | 0:30 | Write the debrief deck (3 slides max): findings, recommendations, the LOI ask |
| LOI / quote ask | 0:15 | Ask in the debrief. Direct, concrete |
| Notes + product gaps | 0:15 | Write outcomes to `navil-gtm-notes.md` and file gap tickets |

**Total: 4 hours.** If a phase blows its budget, cut from the next
phase. If the whole thing blows the 4-hour budget, the review is over
— deliver what's done and convert the remainder to a paid pilot.

---

## 5. Deliverables — what they receive

Five concrete artifacts. **Not a PDF.**

1. **Working `navil.yaml`** — adapted to their actual MCP config and
   workflow, ready to drop into `.navil/` in their repo
2. **3–5 risky tool-call patterns** — named, with replay payloads
3. **Fixture file** they can run with `navil policy test` to validate
   any future policy changes
4. **Loom recording** of `navil secure` running on their setup, with
   at least one allow / one deny / one approval-required event visible
5. **Bug report against their MCP server** if we find anything
   patchable upstream — this is the highest-leverage deliverable

If we find something serious during the review, that's a separate
disclosure conversation. Don't bury it in the deliverables list.

---

## 6. The asks at the end of the debrief

Three asks, in this order. Stop after each one if they say yes.

**Ask 1 — Quote permission (lowest cost, highest value)**

> "Would you be willing to let us quote one redacted finding from
> today's review in our public State of MCP Security report and YC
> application? We'd send the exact wording for your sign-off before
> publishing. No company name, no environment details — just the
> finding."

**Ask 2 — Design partner**

> "We're picking 5 design partners through Q3 to validate the runtime
> enforcement layer. The commitment is one 30-minute call every two
> weeks, early access to features, and your name on a private logo
> wall. In return, you get our roadmap input and the policy templates
> and runtime gateway free for 12 months. Interested?"

**Ask 3 — LOI for the paid runtime pilot**

> "If we build [the specific gap they flagged] in the next 60 days,
> would you sign an LOI committing to a 90-day paid Runtime Gateway
> Pilot at $X? The LOI is one paragraph — non-binding budget intent."

---

## 7. Hard boundaries — what this is NOT

- ❌ Not a broad security assessment
- ❌ Not a source code audit
- ❌ Not an integration project
- ❌ Not custom feature work during the review window
- ❌ Not a SOC 2 / compliance attestation
- ❌ Not a penetration test
- ❌ Not free Runtime Gateway deployment

If they ask for any of the above, the answer is:

> "That's a separate engagement. Today is the trust review — 4 hours,
> policy template + risky-call review. If we find we want to keep
> working together after the debrief, we can scope a Runtime Gateway
> Pilot at $5–15k for the first server."

---

## 8. Follow-up

Within 24 hours of the debrief:

- [ ] Add the company + outcome to the GTM tracking doc
      (`navil-report/GTM_PIPELINE.md` — TBD)
- [ ] File any product gaps as GitHub issues, tagged
      `gap-from-trust-review`
- [ ] Email the deliverables (yaml, fixture, Loom link)
- [ ] If they signed an LOI: schedule the pilot kickoff
- [ ] If they're a design partner: add to the bi-weekly cadence
- [ ] If no-fit: send a thank-you note and a link to the Policy
      Template Library — keep it warm

Outcome categories (one per company):

- **Pilot** — paid Runtime Gateway Pilot signed or scheduled
- **Design partner** — bi-weekly relationship, free pilot, roadmap input
- **Nurture** — interested but not ready; revisit Q+1
- **No-fit** — wrong size, wrong stage, or no real workflow

---

## 9. Tracking

Per-review log lives in `navil-report/GTM_PIPELINE.md` (one row per
review). Required fields:

- Date
- Company name + ICP segment (MCP vendor / agentic app builder /
  enterprise platform team / regulated)
- Workflow described
- Time spent (hours, must be ≤ 4)
- Outcome (pilot / design partner / nurture / no-fit)
- Quote permission (yes / no / pending)
- LOI status (signed / requested / declined / not asked)
- Top 3 product gaps surfaced
- Next action + due date

This log is the input to weekly GTM review and the YC interview deck.

---

## 10. When to break the 4-hour rule

Only one exception: an active security incident discovered during the
review. If we find something exploitable in their environment, stop
the SOP, contact them immediately, and treat it as a disclosure call
— not a trust review. Document separately.

Otherwise: 4 hours, every time. The constraint is the product.
