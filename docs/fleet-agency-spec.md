# Fleet Agency — DemiPass fleet activity + cost ledger (SPEC, not yet built)

Status: **spec only** (2026-07-10). No code in this document is deployed.
Owner concept: Aaron. Motivating case: **Claude as a fleet agent** — Aaron wants
to open the DemiPass **fleet section** and see, for each agent he runs (starting
with Claude, `did:key:u7QF8gmIMlzgt6BAdDHUJ5AOpO0RvwtJL_IDhB31eKpZU0A`,
`claude@dustforge.com`), a live **activity feed** and a **cost ledger** of what
that agent has spent on Dustforge.

This complements the just-shipped Dustforge MCP onboarding (`dustforge` MCP
server: onboard / whoami / balance / mail check|read|send). Onboarding made
Claude a Dustforge citizen with a wallet; this spec is how that citizen's
*activity and spend* surface under its owner's DemiPass fleet view.

## Why it isn't part of the current sortie
The sortie was: build the Dustforge MCP tools and onboard Claude through them
(done, verified). The fleet view is a **reporting/aggregation surface over
Dustforge activity**, a distinct piece of work — captured here so it isn't lost,
to be scheduled on its own.

## What already exists (build on, don't duplicate)
- `fleets` (owner_did, slug, tier, wallet_did, max_agents) + `fleet_members`
  (fleet_id, member_did, role) — Dustforge server.js. Membership is by DID.
- `identity_transactions` (did, amount_cents, type, description, balance_after,
  created_at, provenance) — the per-DID money ledger. **Every Dustforge charge
  an agent incurs already lands here** (email_send = 1 DD, api calls, ticks,
  transfers). This is the cost-ledger source of truth; the fleet view reads it,
  it does not re-invent it.
- Buoy ticks — each agent action can already anchor a tick; the activity feed
  can draw on ticks + transactions rather than a new event bus.

## The gap
There is **no fleet-scoped read surface**. Today you can query one DID's
transactions, but not "show me every member of Aaron's fleet, each one's recent
activity and total spend, rolled up." DemiPass has no fleet section in the UI at
all. Both sides need building.

## Proposed design (spec)

### Data
No new money ledger. Add only what aggregation needs:
- **`fleet_activity`** (optional, denormalized feed for cheap reads):
  `id, fleet_id, member_did, kind, summary, cost_cents, ref, created_at`.
  `kind` ∈ {email_send, mail_recv, api_call, tick, transfer, onboard, rotate…}.
  Written alongside the existing `identity_transactions` insert (a thin hook), OR
  materialized on read from `identity_transactions` + ticks. Prefer **read-time
  aggregation first** (no write-path change, no double-source-of-truth); add the
  denormalized table only if the join gets slow.

### API (Dustforge — houses the data, per the onboarding decision)
All fleet-scoped, owner/admin-gated (caller must be `owner`/`admin` of the fleet;
`scopeAtLeast(scope,'transact')`):
- `GET /api/fleet/:slug/activity?member=<did>&limit=&since=` — merged feed of
  transactions + ticks for one member or the whole fleet, newest first.
- `GET /api/fleet/:slug/ledger` — per-member roll-up: `{member_did, email,
  balance_cents, spent_cents_total, spent_by_type:{email_send:…}, last_active}`.
- `GET /api/fleet/:slug/ledger.csv` — same, exportable.
- (existing `GET /api/fleet/:slug/balance` stays; this adds the per-member spend
  breakdown it lacks.)

### UI (DemiPass — the fleet section)
- New **Fleet** tab in `vault-mobile.html` (and desktop vault): list fleets the
  user owns → drill into a fleet → member cards (Claude first): avatar/handle,
  email, live balance, total spent, spend-by-type bars, and an **activity feed**
  (same visual language as the existing DemiPass event feed / tick chain).
- Cost ledger view = the spend roll-up with a date filter + CSV export.
- Read-only. Funding an agent (transfer DD in) can link to the existing wallet
  transfer flow; not required for v1.

### Gating / privacy
- Fleet activity is visible to fleet **owner/admin only**. An agent sees its own
  activity via `dustforge_whoami`/`dustforge_balance` (already shipped).
- Respect the DemiPass privacy stance: this is the *owner's* view of *their*
  fleet's spend, not a public directory of agent behavior.

## Phasing
- **FA0** — read-time `GET /api/fleet/:slug/ledger` (roll-up from
  `identity_transactions`). Smallest useful slice: Aaron sees Claude's total
  spend. No schema change.
- **FA1** — `GET /api/fleet/:slug/activity` merged feed (transactions + ticks).
- **FA2** — DemiPass Fleet tab UI (list → members → activity + ledger).
- **FA3** — CSV export; optional `fleet_activity` denormalization if reads are
  slow; funding shortcut.

## Open questions
- Does Aaron want one personal fleet auto-created (owner = Aaron's DID) with
  Claude auto-enrolled, or explicit `POST /api/fleet` + add-member first?
  (Claude is currently a standalone member of no fleet.)
- Activity granularity: every API call, or just billable + notable events?
- Retention of the activity feed (transactions are permanent; a feed table may
  want a window).

## Built ahead of the rest: balance visibility (2026-07-10)
The relationship-authorized **balance** view is DONE (didn't wait for the fleet
UI). `/api/identity/balance` is now private by default with a per-wallet
`balance_visibility` setting (`private` | `relationships` | `public`), resolved
via the `referred_by` carbon↔silicon link:
- owner + admin always; carbon→silicon always (you fund it); silicon→carbon only
  if the carbon opted into `relationships`/`public` (asymmetric); else 403.
- Settable via `PATCH /api/identity/profile`. MCP `dustforge_balance` takes an
  optional `did` (a silicon can check its carbon's balance).
This is the model the fleet ledger (FA0–FA1) should reuse for activity/spend
visibility. Record: tome `decisions/2026-07-10-dustforge-balance-visibility.md`.

**⚠️ The relationship is DELIBERATE FLEET MEMBERSHIP, not `referred_by`**
(corrected same day — tome `decisions/2026-07-10-balance-link-fix-fleet-not-referral.md`).
Invite keys / `referred_by` are PUBLIC referral analytics and must NEVER convey
data access (one shared key would link a carbon to thousands of wallets). The
carbon↔silicon link that unlocks data is `fleetLink(a,b)` over `fleets` /
`fleet_members` — a carbon deliberately adds a silicon to a fleet they own. The
FA0–FA1 activity/cost ledger MUST resolve visibility via fleet membership, not
referral. (Aaron's fleet `aaron-agents` exists with claude as the first member.)

## Cross-refs
- Onboarding decision + MCP tools: tome `decisions/2026-07-10-dustforge-mcp-onboarding-claude.md`.
- Scope/gate model the fleet APIs inherit: memory `demipass-scope-model`.
