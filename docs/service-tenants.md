# Service tenants: DemiPass as the identity and metering layer for agent services

Code: `service_tenants.js` (routes), `use_approvals.js` (`gateService`, elevated actions). Test:
`test/service_tenants_smoke.sh`. SDK: `demipass` `docs/services.md` (verify, charge, delegate, revoke, with examples).

## The pieces

| | what it is |
|---|---|
| **tenant** | a service with its own DemiPass wallet (`service_did`). The wallet signs the tenant's calls and receives its charges. Its **owner** is the person who controls it: the fleet owner when the wallet is a fleet silicon, otherwise the wallet itself. |
| **action** | something the tenant does for a caller: `{action, scope, measured_cost_dd, max_cost_dd, depth, open}`. The tenant sets these. |
| **consent** | a wallet's standing permission for one tenant to charge it, with a daily cap. The person who answers for the wallet approves it in the DemiPass app: the wallet itself if it's a person, or its fleet owner if it's an agent. |
| **service token** | an ordinary DemiPass token (Ed25519, the caller wallet's own key) with `iss: demipass-svc` and `aud: svc:<slug>`. Every other DemiPass route accepts only `iss: civitasvox`, so a tenant can verify and charge this token but never spend it as the caller. Details below. |
| **delegation** | a person lets an agent their own fleet created use a service scope (`submit` to fleetgate, `post` to Conduit). It is use-only: agents never hand a scope on. |
| **charge** | one billed call. The caller's wallet is debited and the tenant's credited in one transaction. The charge row and both ledger rows carry the caller's token id. The tenant gets a receipt signed with the meter's key. |

A service token:

- lives at most 24 h, and never longer than the token that minted it;
- carries the minting token's session id;
- dies when the minting token is revoked, when its session ends, or when its agent leaves its fleet;
- has a `cap_dd`, which is the most a tenant can ever charge it and is at most the daily consent.

## Approvals: a token alone asks, a person grants

A charge moves DD out of a wallet, so three things wait on a person's approval:

- **registering a tenant**: approved by the owner;
- **consenting to pay one**: approved by the person who answers for the wallet;
- **weakening a tenant's gates**: approved by the tenant owner.

Weakening means:

- lowering a depth;
- opening a closed action;
- moving a gated action to another scope;
- adding an action to a scope someone holds by delegation.

All three use the same requests elevated secrets use (`use_approvals.js`, `gateService`). The flow:

1. The call answers `202 approval_pending` with an `approval_id`.
2. The request shows in the approver's app.
3. The approver opens it with the PIN and approves. A linked phone signs the decision.
4. The caller makes the same call again with `approval_id`. It passes once.

An agent holding its owner's session, or a stolen token, can ask but never grant. A 202 never names the approver.

## Price

`price = cost + ceil(cost × SERVICE_MARGIN_PCT / 100)`, and the whole price goes to the tenant: the tenant's price is
its measured cost plus margin. `SERVICE_MARGIN_PCT` is a constant in `service_tenants.js`. **It is 20 as a placeholder:
Aaron's order left the figure blank.** Changing it is a one-line PR. Every charge records the margin it used.

A charge posts this call's measured cost (`cost_dd`). It may vary per call, up to the action's `max_cost_dd`. Four
limits apply to every charge:

- that ceiling plus the margin, per call;
- the token's `cap_dd`, in total;
- the consent's daily cap, per tenant;
- the barrel tier, for amounts over 1000 DD, as for transfers.

`GET /api/services/<slug>` lists each action's measured cost, maximum, margin and price.

## Calls

Tenant side, authenticated with the tenant wallet's own token:

- `POST /api/services/verify {token, action, call?, approval_id?, approval_code?}` returns `200 {wallet, token_id, scope, service_scopes, action, action_scope, depth, via, delegation_id?, principal?, approval_id?, price, cap_dd, spent_dd, expires_at}`.
  - It returns no username, email or owner DID.
  - On a delegated call, `principal` is a pairwise id (`pp_…`): the same for that owner at this tenant on every call, but different at every other tenant.
  - The wallet DID is public. A tenant can look up the username of a wallet calling on its own account through `/api/identity/lookup`. A delegated call exposes only the agent's DID and the pairwise principal.
  - Errors: 401 (bad, expired, revoked or wrong-audience token), 403 (no authority), 404 (unknown action), 202 (an elevated action waiting on a person).
- `POST /api/services/charge {action, cost_dd, token_id, idempotency_key}` returns 201 with the receipt.
  - It only accepts an action that was verified on that token. For an elevated action, that means only after its approval passed.
  - The same key again returns `200 replayed`; the same key with a different charge returns 409.
  - 402 means one of: no consent, too little DD, the token's cap reached, or the daily cap reached. Pass it on to the caller.
  - 403 means the tenant never verified that token or action. 401 means the token has expired or been revoked.
- `PUT /api/services/<slug>/actions {actions:[…], approval_id?}` sets the price list. The tenant wallet or its owner may call it. A change that weakens a gate is approved by the owner (above).
- `GET /api/services/charges` shows `paid` (the caller's own charges) and `received` (for a tenant wallet), each with its token id.

Caller side, with the caller's own token (transact):

- `POST /api/services/consent {service, daily_cap_dd, approval_id?}` asks for a consent; once it's approved, the same call creates it.
  - `GET /api/services/consents` lists them.
  - `POST /api/services/consents/<id>/revoke` revokes one. The payer or the approver may revoke.
- `POST /api/services/token {service, ttl?, scopes?, cap_dd?}` returns `{token, token_id, audience, cap_dd, expires_at}`. It needs a consent.
- `POST /api/services/token/revoke {token_id}`.
- `POST /api/services/delegate {service, scope, delegate_did, expires_in?}` delegates a scope.
  - It takes the person's own session, never an agent token.
  - The delegate must be an agent the person's own fleet created.
  - Only the tenant owner hands on a closed scope.
- `POST /api/services/delegations/<id>/revoke` revokes it.
- `GET /api/services/delegations` lists what you granted and what you hold.

Public:

- `GET /api/services`.
- `GET /api/services/<slug>`.
- `POST /api/services/receipts/verify {receipt, sig}`. The signature is Ed25519 over `"dustforge-service-charge:v1\n" + receipt`, so a service receipt never passes as a meter receipt, or a meter receipt as a service one.

Registration:

- `POST /api/services/register {slug, name, service_did?, approval_id?}`.
  - A wallet registers itself, or a person registers a silicon their own fleet created. The owner approves.
  - Each wallet can be at most one tenant.
  - The slugs `demipass`, `dustforge`, `admin`, `meter`, `services` and `api` are reserved.

## A tenant's own token: requested, never minted for it

A tenant's wallet is usually a fleet silicon. Its DemiPass token is **requested** through dustforge #78
(`silicon_token_requests.js`).

1. File the request from the tenant's own container: `POST /api/fleet/<fleet>/silicons/<handle>/token-requests {scope, expires_in, claim_secret_hash}`.
2. The fleet owner approves it in the app, with the PIN and the phone.
3. The holder of the claim secret collects the token once: `POST /api/silicon-token-requests/<id>/claim`.

Nothing should ask the owner to mint a token.

**An agent that does not exist yet is requested the same way** (Aaron 2026-11-09):
1. File the request with `create`: `POST /api/fleet/<fleet>/silicons/<new-handle>/token-requests {create: {display_name?, username?}, scope, expires_in, claim_secret_hash}`.
2. The owner's card and phone text say "create". On approval (PIN and phone), the fleet creates the agent exactly as the owner's own `POST /api/fleet/<fleet>/silicons {create}` does:
   - a new wallet and mailbox;
   - charged like a provision to the fleet's payer;
   - `created_by_fleet = 1`.

   The server then mints the agent's first token.
3. The claim hands over the token and the new DID, once. The new mailbox's password goes to nobody. It would be a full sign-in, beyond the scope the owner's phone signed for.

Nothing should ask the owner to create an agent in their own session either.

**How long requests wait** (#77):
- DemiPass grants (consent, registration, gate-weakening) wait 24 h.
- A use of a secret, or an elevated tenant action, waits 1 h.

Pending requests of both kinds, and agent token requests, reach the owner's still-linked phone through its signed
alerts check, which app 1.12+ notifies.

## Who may call an action

- **Own account.** Any wallet may call an `open` action, paying for it itself. The tenant owner may also call closed actions.
- **Delegation.** A delegate holds the scope only while its owner holds it and while it's still an agent of the owner's fleet. Leaving or removal ends it. The delegate pays from its own wallet, under its own consent.
- **Not accepted.** Old `silicon:` tokens and worker (`wrk`) tokens are refused. Both act under another wallet's DID, so neither is locked to the wallet that would pay.

## Depth: elevated service actions

An action's `depth` is `standard`, `elevated` or `critical`, with the same meaning as on a secret. Signing a charter
at FLEETGATE is one example.

The approver is the person whose authority the call uses:

- the delegating owner, for a delegated call;
- the caller itself, for a person calling on their own account.

An agent acting on its own account has nobody to approve for it, so it is refused.

The approval binds two things:

- the exact call: what the tenant sent as `call`, such as `{charter, digest}`;
- the authority it was given under: the approver's pairwise principal and the delegation id.

So:

- a different `call` returns 409;
- an approval given under one delegation doesn't redeem under another (409);
- a second use returns 410.

## What a tenant sees, and can do

A tenant sees:

- the caller's wallet DID, token id, scope and depth;
- the delegation id and a pairwise principal;
- its own charges.

A tenant cannot:

- use a caller's token at DemiPass;
- charge a wallet that hasn't consented to it;
- charge a token or action it has not verified, or charge after that token has expired or been revoked;
- charge past any of the limits above;
- weaken its own gates without its owner's approval.

**Known limits:**

- A tenant's owner is fixed at registration.
- A device-flow token for an agent that holds a person's session counts as the person when delegating. This is the same as `/api/blindkey/delegate`. Granting consent or registering still needs the PIN.

## Tenants today

- **fleetgate** is the release controller's wallet: silicon `release-controller`, owned by Aaron.
  - A submission through the fleetgate door prepays its review round at the measured median: about 480 DD for three reviewers, from 105 review receipts, with a maximum of 1300.
  - The charge lands in the controller wallet, which pays the gate's DemiPass use.
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
