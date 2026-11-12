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
   5-minute scheduler; one refill per silicon per 10 minutes. Optional `refill_daily_cap_cents` (0 = none)
   caps what the automatic refills move in any rolling 24 h (the last one is cut to what's left; manual
   refills don't count). A silicon below its threshold whose refill can't run (cap reached, or the source
   is short) mails `refill_alert_email` from the scheduler pass, at most once per 24 h. Per owner: `wallet_refill_rules` — a
   daily/weekly/monthly operator-grant credit with an idempotency key per period. Operator grants are only
   honoured for DIDs listed in `OPERATOR_GRANT_DIDS` (env, comma-separated). Stripe-funded refills are
   declared but not implemented (the rule records the error).
8. **Tokens.** The Fleet page shows each silicon's newest token (valid / expiring in its last 24 h, counted in
   hours / expired / none). The scheduler emails the silicon's contact once per day while it is not valid, and
   the fleet owner once per token at the 24 h mark (or at its lapse, if the pass missed that window). The owner can mint a ≤transact, ≤30d token for a silicon from the subpage.
   **Renew token** (every card of an agent the fleet holds the key of; Aaron 2026-11-12, `silicon_renew.js`): the
   owner's PIN (and linked phone) renews it without anyone seeing it — the server mints it and seals it to the
   agent's **delivery key**; the agent picks it up with `bin/token-pickup.js`:
   - Which key renewals go to is the owner's decision; no key is ever set on the agent's word alone. Two ways:
     - `node bin/token-pickup.js --init <dir>` (with a token only the agent has seen: its own sign-in, a request it or
       the owner — with its `claim_secret_hash` — filed, a renewed token) makes `<dir>/delivery.key` (0600) and ASKS
       (`POST /api/identity/delivery-key`). Every ask waits for the owner, the first too: a card on the agent's page
       (fingerprint, the asking token's kind and address) and a mail (at most one per 3 h, but always after a deny or
       an undo); approve with the PIN `silicon-key:<id>` + phone. One ask waits at a time (another: 429). **Deny signs
       out the token that asked** (and its session).
     - The key travels IN an agent token request (`delivery_key` + `claim_secret_hash`; `--material` prints both for an
       owner-filed request, `--request <dir> <fleet> <handle>` files it with the agent's own sign-in): the owner's
       phone signs "… key <fingerprint>" with the request, and `--claim <dir> [id]` sets the key and writes the token.
       A waiting ask it overtakes is logged and mailed, never dropped silently.
     An ask whose token is revoked (jti, revoke-all, fleet cut) ends. An approved change can be undone for 6 hours
     (PIN `silicon-key-revert:<id>` + phone): the tokens sealed to the dropped key, and the token that asked for it,
     are revoked. The card says "key set / key changed <time>".
   - after a renewal (or from a timer): `node bin/token-pickup.js <dir>` fetches the newest sealed delivery
     (`GET /api/identity/token-deliveries?did=…`, no session, rate-limited per address+DID; only `{id, epk, iv, tag,
     ciphertext}`), opens it, checks the token's signature against the did:key, and writes `<dir>/token` (0600) only
     if it is newer than the token held (never a narrower scope without `--allow-narrower`). It then acknowledges it
     (`POST /api/identity/token-deliveries/ack`, the token itself as Bearer); until then — or the token's first use —
     the card says "renewed, awaiting pickup". It never prints the token. Without a delivery key the renewal answers 409.
   - "Mint a 30-day token" (value shown once) is hidden for an agent that has a delivery key.
9. **Onboarding.** `POST /api/fleet/:slug/silicons` with a handle, name, contact email: an existing identity is
   linked with consent (its own token, the admin key, or a one-time claim link emailed to its mailbox); otherwise
   a new identity (mailbox + wallet) is created for 1000 DD. Either way the DID record is emailed to the contact.

10. **Secrets a silicon uses** show on its subpage: its own stored secrets plus the ones delegated to it (use
    counts, status), with delegate / revoke controls for the owner.
11. **Subordinate workers.** A silicon (or its fleet owner) creates a *worker* for a sub-agent or test
    environment, e.g. Brain → `brain2`. The worker gets a hashed id `wrk_<16 hex>` = HMAC(FLEET_ID_SECRET,
    parent DID + name) and a token minted for the **parent's** DID carrying a `wrk` claim, with: a scope cap
    (≤ transact), a TTL cap (≤ 30 d), an optional secret allow-list (ref codes or names; enforced on
    `request-token`), and an optional spend cap. Calls run as the parent, are billed to the parent (or to the
    owner / a work-link requester under the usual rules) and are tagged with the worker id in
    `billing_attributions`. Revoking the worker kills its last token and every future call. Worker tokens cannot
    create workers or mint tokens.

## Endpoints (all Bearer; owner/admin of the fleet unless noted)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/fleets/mine` | fleets the caller belongs to |
| GET | `/api/fleet/:slug/overview` | everything the Fleet tab shows (members see a reduced view) |
| GET/POST | `/api/fleet/:slug/silicons` | list / onboard |
| GET/PATCH/DELETE | `/api/fleet/:slug/silicons/:handle` | subpage data / refill settings / unlink |
| POST | `/api/fleet/:slug/silicons/:handle/refill` | `{amount_cents}` manual refill |
| POST | `/api/fleet/:slug/silicons/:handle/token` | mint ≤transact ≤30d token (shown once) |
| POST | `/api/fleet/:slug/silicons/:handle/renew-token` | owner only, PIN `silicon-renew:<id>` + linked phone; `{scope?, expires_in?}` (≤transact, default 30d) → `{ok, delivery_id, expires_at}`, sealed to the agent's delivery key, never the token; 409 without one |
| POST | `/api/identity/delivery-key` | a token of the agent (not a shown, worker, device-login token): `{public_key}` (X25519, 32 bytes base64url); 202 pending for the owner; 429 while another waits |
| POST | `/api/fleet/:slug/silicons/:handle/delivery-key/:change/approve\|deny` | owner only; approve: PIN `silicon-key:<id>` + linked phone; deny signs out the asking token |
| POST | `/api/fleet/:slug/silicons/:handle/token-requests` | `{…, delivery_key?}`: a key carried in the request is on the owner's phone and set at the claim |
| POST | `/api/fleet/:slug/silicons/:handle/delivery-key/revert` | owner only, within 6 h of an approved change: PIN `silicon-key-revert:<id>` + phone |
| GET | `/api/identity/token-deliveries?did=` | no auth: the newest 3 unexpired, unacknowledged sealed deliveries (non-consuming) |
| POST | `/api/identity/token-deliveries/ack` | Bearer = the delivered token; `{used?}` (false: a newer token is kept, the delivery is revoked) |
| POST | `/api/fleet/:slug/silicons/:handle/delegate` | owner delegates one of their secrets (`secret_name` or `ref`) |
| GET/PUT | `/api/fleet/:slug/owner-refill` | the owner's scheduled refill rule |
| PATCH | `/api/fleet/:slug/projects/:project` | `{bill_mode: owner|project_wallet}` |
| GET | `/api/fleet/:slug/attribution?days=30` | who paid for what |
| POST | `/api/fleet/:slug/refills/run` | run the scheduler now |
| GET | `/api/fleet/claim/:code` | one-time mailbox claim link (no auth): shows what joining means |
| POST | `/api/fleet/claim/:code` | the page's Join button: redeems the claim (a GET never does) |
| GET | `/api/silicons/me` | a silicon's own view (any token) |
| GET | `/api/silicons/resolve/:sid` | hashed id → handle/fleet (+DID for same-fleet) |
| POST/GET | `/api/work-links` | create (`provider` = sil_ id, DID, username or `handle@fleet`; `ttl_ticks`, `ttl_seconds?`, `project?`, `note?`, `max_spend_cents?`) / list mine |
| POST | `/api/work-links/:id/accept\|decline\|revoke` | accept returns the work token once |
| GET/POST | `/api/silicons/workers` | a silicon lists / creates its workers (`name`, `purpose?`, `allowed_secrets?`, `scope_cap?`, `max_spend_cents?`, `mint?: {scope, expires_in}`) |
| POST | `/api/silicons/workers/:wid/token\|revoke` | mint a worker token (shown once) / revoke the worker |
| GET/POST | `/api/fleet/:slug/silicons/:handle/workers` | owner side of the same |
| POST | `/api/fleet/:slug/silicons/:handle/workers/:wid/token\|revoke` | owner side of the same |
| DELETE | `/api/fleet/:slug/silicons/:handle/delegations/:id` | owner revokes a delegation |

Errors worth knowing: `402 payment required` now carries `payer_did` and `payer` (`self` / `operator` /
`work_link`) so an agent can tell *whose* wallet is empty; `403 not an operator on project 'x'` when a silicon
claims operator-initiated work on a project it is not listed on.

## Silicon-side protocol (Brain and friends)

- Keep the token in a file, read it per call, roll it over before expiry (daily job; re-mint when <7 days remain
  via `POST /api/identity/auth-fingerprint` with the silicon's own username/password, `scope: transact`,
  `expires_in: 30d`). Environment variables are read once per process and go stale. An agent without its own
  password registers a delivery key once and runs `bin/token-pickup.js <dir>` on a timer: the owner's
  **Renew token** then lands in `<dir>/token`.
- Set the billing header from the turn's provenance: operator-initiated (the human asked) →
  `{"project": "...", "initiator": "operator"}`; think-loop / self-initiated → `"initiator": "autonomous"`;
  work for another silicon → `{"work_link": "..."}`. Add `X-DemiPass-Agent: <name>/<version>` for reporting.
- Host access for Brain: the owner delegates `phasewhip-ssh` to Brain; Brain calls `request-token` + `use` with
  its **own** token and the billing header. No more bouncing through the owner's machine or identity.
- Testing environments (Brain2): the parent creates a worker (`POST /api/silicons/workers` with
  `allowed_secrets: ["DP-PWD-phasewhi-c4b276f9"]`, a spend cap and `mint: {expires_in: "7d"}`), drops the token
  into the worker's environment, and the worker runs the same lane script. Its spend shows under the parent,
  tagged with the worker id; revoke it when the trial ends.

## Deploy checklist

1. Back up `/opt/dustforge/data/dustforge.db` (schema adds tables and two `ALTER TABLE`s; all `IF NOT EXISTS`).
2. Add to `/opt/dustforge/.env`: `OPERATOR_GRANT_DIDS=<Aaron's DID>` and optionally `FLEET_ID_SECRET=<random>`
   (defaults to `IDENTITY_MASTER_KEY`; changing it later changes every `sil_` id).
3. `git pull` + `systemctl restart dustforge`; verify `GET /api/fleets/mine` with a real token, then run
   `POST /api/fleet/aaron-agents/refills/run` once and read `[fleet] pass:` in the journal.
4. Onboard Brain from the Fleet tab (handle `brain`, email `brain@dustforge.com`, 50 / 500) or via the API with
   Brain's token as proof; delegate `phasewhip-ssh`; add Brain as operator on the `brain` project (already true).
