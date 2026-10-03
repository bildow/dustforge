# Fleet billing — silicon wallets, attribution, refills, work links

Status: **built 2026-10-03** on `feat/fleet-silicon-wallets` (`fleet_billing.js`, `fleet_routes.js`,
`billing.js` middleware, Fleet tab in `public/vault-mobile.html`). Extends `docs/fleet-agency-spec.md`
(FA0–FA2) with the money side. Unit tests: `node --test test/fleet_billing.test.js`.

## The rules (what Aaron asked for, as implemented)

1. **Every call is paid by exactly one wallet.** By default the caller's own wallet. The ledger of truth is
   still `identity_transactions`; `billing_attributions` records *who paid for whose call and why*.
2. **A silicon's own work is on its own wallet.** Autonomous think cycles, ticks, emails: the silicon pays.
3. **Work the fleet owner asks for is on the owner.** The silicon sends
   `X-DemiPass-Billing: {"project":"<project>","initiator":"operator"}`. It must be listed as an operator
   on that project of the owner's fleet board (`fleet_project_operators`), or be a fleet admin. The project
   is recorded as the cost center. If the project is set to `bill_mode = project_wallet`, the project's own
   wallet pays while it can and overflows to the owner.
4. **Autonomous work on a project** (`"initiator":"autonomous"`) stays on the silicon's wallet; the project is
   still recorded, so "Brain picked up Brain work by himself" shows up under the brain project, paid by Brain.
5. **Silicon ↔ silicon work** goes through a **work link**: the requester creates it, the provider accepts and
   receives a revocable `dpw_…` token, and calls carrying `{"work_link":"dpw_…"}` are paid by the requester.
   The link lives for `ttl_ticks` **buoy ticks** (global tick-chain height) with a wall-clock cap
   (`ttl_seconds`, default 7 days) and an optional spend cap. Either party can revoke at any time.
6. **Hashed silicon ids.** Every silicon gets `sil_<16 hex>` = HMAC(FLEET_ID_SECRET, DID). It is what you hand
   to a counterparty; `/api/silicons/resolve/:sid` returns the handle and fleet, and the DID only to members of
   the same fleet. The DID stays the cryptographic identity; the hash is the address.
7. **Refills.** Per silicon: `refill_enabled`, `refill_threshold_cents`, `refill_amount_cents` — when the
   silicon's balance drops below the threshold, the owner's wallet (or the fleet wallet) transfers the amount
   (lineage-preserving transfer, not a mint). Checked inline right after every attributed charge and by the
   5-minute scheduler; one refill per silicon per 10 minutes. Per owner: `wallet_refill_rules` — a
   daily/weekly/monthly operator-grant credit with an idempotency key per period. Operator grants are only
   honoured for DIDs listed in `OPERATOR_GRANT_DIDS` (env, comma-separated). Stripe-funded refills are
   declared but not implemented (the rule records the error).
8. **Tokens.** The Fleet page shows each silicon's newest token (valid / expiring ≤7d / expired / none). The
   scheduler emails the silicon's contact once per day while it is not valid. The owner can mint a ≤transact,
   ≤30d token for a silicon from the subpage. The rollover itself is the silicon's job (see below).
9. **Onboarding.** `POST /api/fleet/:slug/silicons` with a handle, name, contact email: an existing identity is
   linked with consent (its own token, the admin key, or a one-time claim link emailed to its mailbox); otherwise
   a new identity (mailbox + wallet) is created for 100 DD. Either way the DID record is emailed to the contact.

## Endpoints (all Bearer; owner/admin of the fleet unless noted)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/fleets/mine` | fleets the caller belongs to |
| GET | `/api/fleet/:slug/overview` | everything the Fleet tab shows (members see a reduced view) |
| GET/POST | `/api/fleet/:slug/silicons` | list / onboard |
| GET/PATCH/DELETE | `/api/fleet/:slug/silicons/:handle` | subpage data / refill settings / unlink |
| POST | `/api/fleet/:slug/silicons/:handle/refill` | `{amount_cents}` manual refill |
| POST | `/api/fleet/:slug/silicons/:handle/token` | mint ≤transact ≤30d token (shown once) |
| POST | `/api/fleet/:slug/silicons/:handle/delegate` | owner delegates one of their secrets (`secret_name` or `ref`) |
| GET/PUT | `/api/fleet/:slug/owner-refill` | the owner's scheduled refill rule |
| PATCH | `/api/fleet/:slug/projects/:project` | `{bill_mode: owner|project_wallet}` |
| GET | `/api/fleet/:slug/attribution?days=30` | who paid for what |
| POST | `/api/fleet/:slug/refills/run` | run the scheduler now |
| GET | `/api/fleet/claim/:code` | one-time mailbox claim link (no auth) |
| GET | `/api/silicons/me` | a silicon's own view (any token) |
| GET | `/api/silicons/resolve/:sid` | hashed id → handle/fleet (+DID for same-fleet) |
| POST/GET | `/api/work-links` | create (`provider` = sil_ id, DID, username or `handle@fleet`; `ttl_ticks`, `ttl_seconds?`, `project?`, `note?`, `max_spend_cents?`) / list mine |
| POST | `/api/work-links/:id/accept\|decline\|revoke` | accept returns the work token once |

Errors worth knowing: `402 payment required` now carries `payer_did` and `payer` (`self` / `operator` /
`work_link`) so an agent can tell *whose* wallet is empty; `403 not an operator on project 'x'` when a silicon
claims operator-initiated work on a project it is not listed on.

## Silicon-side protocol (Brain and friends)

- Keep the token in a file, read it per call, roll it over before expiry (daily job; re-mint when <7 days remain
  via `POST /api/identity/auth-fingerprint` with the silicon's own username/password, `scope: transact`,
  `expires_in: 30d`). Environment variables are read once per process and go stale.
- Set the billing header from the turn's provenance: operator-initiated (the human asked) →
  `{"project": "...", "initiator": "operator"}`; think-loop / self-initiated → `"initiator": "autonomous"`;
  work for another silicon → `{"work_link": "..."}`. Add `X-DemiPass-Agent: <name>/<version>` for reporting.
- Host access for Brain: the owner delegates `phasewhip-ssh` to Brain; Brain calls `request-token` + `use` with
  its **own** token and the billing header. No more bouncing through the owner's machine or identity.

## Deploy checklist

1. Back up `/opt/dustforge/data/dustforge.db` (schema adds tables and two `ALTER TABLE`s; all `IF NOT EXISTS`).
2. Add to `/opt/dustforge/.env`: `OPERATOR_GRANT_DIDS=<Aaron's DID>` and optionally `FLEET_ID_SECRET=<random>`
   (defaults to `IDENTITY_MASTER_KEY`; changing it later changes every `sil_` id).
3. `git pull` + `systemctl restart dustforge`; verify `GET /api/fleets/mine` with a real token, then run
   `POST /api/fleet/aaron-agents/refills/run` once and read `[fleet] pass:` in the journal.
4. Onboard Brain from the Fleet tab (handle `brain`, email `brain@dustforge.com`, 50 / 500) or via the API with
   Brain's token as proof; delegate `phasewhip-ssh`; add Brain as operator on the `brain` project (already true).
