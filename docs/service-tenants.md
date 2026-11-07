# Service tenants: DemiPass as the identity and metering layer for agent services

Code: `service_tenants.js` (routes), `use_approvals.js` (`gateService`, elevated actions). Test:
`test/service_tenants_smoke.sh`. SDK: `demipass` `docs/services.md` (verify, charge, delegate, revoke, with examples).

## The pieces

| | what it is |
|---|---|
| **tenant** | a service with its own DemiPass wallet (`service_did`). The wallet signs the tenant's calls and receives its charges. Its **owner** is the person who controls it: the fleet owner when the wallet is a fleet silicon, otherwise the wallet itself. |
| **action** | something the tenant does for a caller: `{action, scope, measured_cost_dd, max_cost_dd, depth, open}`. The tenant sets these. |
| **service token** | an ordinary DemiPass token (Ed25519, the caller wallet's own key) with `iss: demipass-svc` and `aud: svc:<slug>`. Callers send it to the tenant as `Authorization: Bearer …`. Every other DemiPass route checks `iss: civitasvox`, so this token opens nothing at DemiPass: a tenant can verify it and charge it, but never spend it as the caller. It lives at most 24 h and never longer than the token that minted it. Its `cap_dd` (default 500, so $0.50) is the most a tenant can ever charge it. |
| **delegation** | a person lets one of their agents use a service scope (`submit` to fleetgate, `post` to Conduit). It is use-only: agents never hand a scope on. |
| **charge** | one billed call. The caller's wallet is debited and the tenant's credited in one transaction. The charge row and both ledger rows carry the caller's token id. The tenant gets an Ed25519 receipt, signed by the meter's key. |

## Price

`price = cost + ceil(cost × SERVICE_MARGIN_PCT / 100)`. `SERVICE_MARGIN_PCT` is a constant in `service_tenants.js`.
**It is 20 as a placeholder: Aaron's order left the figure blank.** Changing it is a one-line PR. Every charge records
the margin it used.

A charge posts this call's measured cost (`cost_dd`). It may vary per call, such as a review whose model spend depends
on the diff, up to the action's `max_cost_dd`. `GET /api/services/<slug>` lists each action's measured cost, maximum,
margin and price.

## Calls

Tenant side, authenticated with the tenant wallet's own token:

- `POST /api/services/verify {token, action, call?, approval_id?, approval_code?}` returns `200 {wallet, token_id, scope, service_scopes, action, action_scope, depth, via, delegation_id?, principal?, approval_id?, price, cap_dd, spent_dd, expires_at}`.
  - It never names the human: no username, email or owner DID.
  - On a delegated call, `principal` is a pairwise id (`pp_…`): the same for that owner at this tenant on every call, but different at every other tenant.
  - Errors: 401 (bad, expired, revoked or wrong-audience token), 403 (no authority), 404 (unknown action).
  - For an elevated action, verify first answers `202 approval_pending` (below).
- `POST /api/services/charge {action, cost_dd, token_id, idempotency_key}` returns 201 with the receipt.
  - The same key again returns `200 replayed`; the same key with a different charge returns 409.
  - 402 means the caller's wallet can't cover the charge, or the token's cap is reached. Pass it on to the caller.
  - 403 means the tenant never verified that token. 401 means the token has expired or been revoked.
- `PUT /api/services/<slug>/actions {actions:[…]}` sets the price list. The tenant wallet or its owner may call it.
  - Lowering a depth, opening a closed action, or moving a gated action to another scope needs the owner, in their own session, with the PIN (intent `svc-depth:<tenant id>`).
- `GET /api/services/charges` shows `paid` (the caller's own charges) and `received` (for a tenant wallet), each with its token id.

Caller side, with the caller's own token (transact):

- `POST /api/services/token {service, ttl?, scopes?, cap_dd?}` returns `{token, token_id, audience, cap_dd, expires_at}`.
- `POST /api/services/token/revoke {token_id}`.
- `POST /api/services/delegate {service, scope, delegate_did, expires_in?}`. It takes the person's own session, never an agent token.
  - The delegate must be an agent (a fleet silicon).
  - An agent your own fleet did not create takes the PIN (intent `svc-delegate:<tenant id>`).
  - Only the tenant owner hands on a closed scope.
- `POST /api/services/delegations/<id>/revoke` revokes it. The owner may use any of their own tokens.
- `GET /api/services/delegations` lists what you granted and what you hold.

Public:

- `GET /api/services`.
- `GET /api/services/<slug>`.
- `POST /api/services/receipts/verify {receipt, sig}`.

Registration:

- `POST /api/services/register {slug, name, service_did?}`.
  - A wallet registers itself, or a person registers a silicon their own fleet created.
  - Each wallet can be at most one tenant.

## Who may call an action

- **Own account.** Any wallet may call an `open` action, paying for it itself. The tenant owner may also call closed actions.
- **Delegation.** A delegate holds the scope while its owner does. An open scope is anyone's to delegate; a closed one only the tenant owner's. The delegate pays from its own wallet; a fleet silicon is refilled by its fleet as usual.
- **Not accepted.** Old `silicon:` tokens and worker (`wrk`) tokens are refused for service calls. Both act under another wallet's DID, so neither is locked to the wallet that would pay.

## Depth: elevated service actions

An action's `depth` is `standard`, `elevated` or `critical`, with the same meaning as on a secret. Signing a charter
at FLEETGATE is one example.

The approver is the person whose authority the call uses:

- the delegating owner, for a delegated call;
- the caller itself, for a person calling on their own account.

An agent acting on its own account has nobody to approve for it, so it is refused. It needs a person's delegation.

The approval flow:

1. The first verify answers 202 `approval_pending` with an `approval_id`. The request appears in the approver's app as "<tenant> · <action>", with the bound call: what the tenant sent as `call`, such as `{charter, digest}`.
2. The approver opens the request with the PIN and approves it on their phone. It is the same request, the same rotating code and the same device signature as an elevated secret's use (`use_approvals.js`).
3. The tenant verifies again with `approval_id` and the same `call`. That passes exactly once. A different `call` returns 409; a second use returns 410.

## What a tenant sees, and can do

A tenant sees:

- the caller's wallet DID, token id, scope and depth;
- the delegation id and a pairwise principal;
- its own charges.

A tenant cannot:

- use a caller's token at DemiPass;
- charge a token it has not verified, or charge after that token has expired or been revoked;
- charge more than `max_cost_dd` plus the margin in one call, or more than the token's `cap_dd` in total;
- lower an action's depth without its owner's PIN.

## Tenants today

- **fleetgate** is the release controller's wallet: silicon `release-controller`, owned by Aaron. Reviewer spend is charged to whoever submits, at measured cost plus margin, and lands in the controller wallet that pays for its review `/use` calls.
- **conduit** is the agent message bus being rebuilt as a phasewhip container, with its own wallet. It is registered so the builder has an identity to code against. The four calls it needs are in the SDK's `docs/services.md`.

## Dogfood rule (threat model)

DemiPass's own repos (bildow/dustforge, bildow/demipass, bildow/demipass-android) ship through FLEETGATE: a charter
lane, the reviewers, the closer and the release controller, like any agent's code. The gate's authentication (Forgejo
bot tokens, reviewer keys, the controller wallet) is DemiPass's. That creates a bootstrap case: **DemiPass can't ship
because its own gate's authentication is broken.**

That case has one written exception path, modelled on Brain's declared pre-push-gate exception (tome
`decisions/2026-10-29-brain-cutover-host-changes.md`, H7):

1. **Declare.** Before the push, write a tome record `decisions/<date>-demipass-gate-bootstrap-exception.md`. It names:
   - the gate step that cannot run, and the measurement showing it is broken (an error, a 401, a dead key);
   - the exact head being shipped, and why that head is the fix;
   - who ordered it.
2. **Log.** The record is committed and pushed to the tome before the deploy, and anchored with a Buoy tick naming its
   commit. The deploy runs the usual deploy-identity path (`dustforge-deploy <head>`), whose log line names the head.
   The tome commit, the tick and the deploy log together are the log: three places, none of which the bypassed gate
   controls.
3. **Close out.** Once the gate works again, run the bypassed head through it: lane check, reviews, closer, controller dry run. Record the result in the same file, green or red. A red result is handed back as work. As with Brain's, the exception is closed by that measurement being recorded, not by it being green.
4. **Scope.** The exception covers only the change that restores the gate's authentication. Nothing else rides along. A second exception before the first one's close-out is refused: fix the gate first.

Until Aaron signs a release-controller charter lane naming these repos, they ship as they do today: a PR, an
adversarial reviewer agent, merge, then a deploy through `dustforge-deploy`. The rule takes effect with that
signature. The lane draft is in the tome.
