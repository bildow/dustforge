# Sharing secrets between people, and moving them

Code: `secret_sharing.js` (routes), `secret_types.js` (vault types). Test: `test/sharing_smoke.sh`, `test/secret_types.test.js`.

## The rule
A person never reads or types a secret value. People press buttons in the app; their agents hold delegations and
call `/use`. A flow that needs a person to see a value is a defect to name. The reveal grant below is the emergency
door for the rare case DemiPass cannot reach, not a normal path.

Being connected to someone (a wallet-network contact) or being in a fleet gives no access to any secret. Access exists
only as a delegation row: an agent delegation (`/delegate`, to your own agents) or a share (below, to a person).

## Shares (person → person)
A share is a `demipass_delegations` row with `delegate_kind = 'person'`, the same shape as an agent delegation.

| Step | Who | Call | Gate |
|---|---|---|---|
| offer | owner | `POST /api/demipass/shares {secret, to, expires_in_days?=90 (1–365), context?, max_uses?, note?}` | owner's PIN, intent `share:<secret id>` |
| accept | recipient | `POST /api/demipass/shares/:id/accept` | their own session (no PIN) — the only step on their side |
| use | recipient and agents signed in as them | `POST /api/demipass/use {ref, params}` | the share must be active and unexpired |
| decline / stop | recipient | `POST /api/demipass/shares/:id/decline` | — |
| revoke | owner | `POST /api/demipass/shares/:id/revoke` | — |
| list | either | `GET /api/demipass/shares` → `{given, received, waiting_for_you}` | — |
| audit | either | `GET /api/demipass/shares/:id/audit` → who offered, accepted, used, granted and revealed, and when | — |

- Only to a **person you are connected to** (`network_peers`), never to an agent wallet (that is `/delegate`).
  `/delegate` to a connected person answers 409 and points here.
- An offer is inert (`status 'suspended'`, `offer_state 'offered'`): every use path reads `status = 'active'`.
- Use-only by default; scoped to all contexts or one; always expires; revocable by either side.
- A use-token minted before a revoke, an expiry or a transfer is refused when redeemed.
- A ref names one owner's secret: a caller with a same-named secret of their own still reaches the ref's secret.
- Agents: device-login tokens and fleet worker tokens act as the person and reach shares like the person does.
  `silicon:` tokens (silicon_agents) are refused by `/use`'s auth for every secret today, own or shared.

### Emergency reveal
- Owner: `POST /api/demipass/shares/:id/reveal-grant {allow:true, reveals?=1 (1–5), minutes?=60 (1–1440)}` with the
  PIN (intent `reveal-grant:<share id>`); `{allow:false}` closes it early.
- Recipient: `POST /api/demipass/shares/:id/reveal` with their own PIN (intent `share-reveal:<share id>`), once per
  granted reveal, inside the window.
- Every reveal: a critical `secret_revealed` security event on the recipient, a ledger tick on both accounts, and a
  `share_revealed` entry in the share's audit.

## Transfer (move a secret to another person's vault)
`POST /api/demipass/transfer {secret, to, keep?='use'|'none', keep_days?=365, new_name?}`, owner's PIN (intent
`transfer:<secret id>`). Only to a connected person.
- The ref stays the same; contexts, username, host binding, note and labels move with it.
- Every delegation and share the old owner gave on it ends; outstanding use-tokens end.
- With `keep:'use'` the old owner keeps a use-only share (`via:'transfer'`), live at once (they asked for it), which
  the new owner sees under `given` and can revoke. Nothing for the new owner to accept.
- A name the new owner already uses → 409 `name_taken`; send `new_name`.

## Deposit (into your agent's vault)
`POST /api/demipass/deposit {target_silicon | target_did | target_username, name, value, secret_type?, contexts?}`.
Admin key: any identity. A person's token: only an agent of a fleet they own. Never a person (share or transfer).

## Vault types (`secret_types.js`)
`api_key token oauth_token password passphrase ssh_credential signing_key webhook_secret connection_string certificate
multi_string other`; aliases `ssh_key cert …`. A named type that is not one of these is refused (400), never filed as
`api_key`. No type: inferred from the value (PEM private key → `ssh_credential`, `postgres://…` → `connection_string`,
JWT/`ghp_…` → `token`, a username given → `password`, else `api_key`). Ref prefixes and default actions come from the
same table (`ssh_credential` → `DP-SSH-`, `ssh_exec`).

## Store fields for manual entry
`POST /api/demipass/store` also takes `username` (the account it signs in as — `ssh_exec`'s default user), `host`
(binds the default context to that machine, or to `https://host/*` for http types), `note` (≤500), and
`if_absent:true` (409 instead of overwriting a name already in the vault). Manual entry is itself a defect under the
rule above (a person types the value); the next ingress paths are photo, extension capture and QR.

## SSH hosts
`BLINDKEY_SSH_HOSTS_EXTRA` (comma-separated) adds hosts to the built-in ssh_exec allow-list.

## Confirmed contacts only (2026-11-06, red team item 6)

A share offer, the acceptance of an offer, and a secret transfer all need the two wallets to be contacts **confirmed in
person** by QR pairing (docs/network.md, "Pairing in person"). A contact made by name request alone gets
`403 {pair_required: true}`. Shares that were already accepted keep working.

## Transfers wait (2026-11-06, red team item 6)

A transfer (`POST /api/blindkey/transfer`) no longer happens at once.

**Starting it**
- The call answers `202 {pending: true, transfer: {id, execute_at, …}}`.
- The transfer runs after the owner's delay. The default is 1 hour; it can be set from 5 minutes to 7 days.
- Both sides are emailed when it starts.
- While it waits, the secret stays the owner's, and a second transfer of the same secret gets 409.

**Cancelling and listing**
- Either side can cancel: `POST /api/blindkey/transfers/:id/cancel`. No PIN is needed, because cancelling keeps things as they are.
- Both sides are emailed on a cancel.
- `GET /api/blindkey/transfers` lists transfers in and out.

**When it runs**
- A 30-second sweep carries it out. Every check is made again at that moment:
  - the owner still has the secret, active, not frozen and not rotating;
  - both accounts are active;
  - the recipient is not an agent;
  - they are still contacts confirmed in person;
  - the name is free in the recipient's vault.
- If any check fails, the status becomes `failed` with the reason and nothing changes.
- Both sides are emailed either way.

**The delay setting**
- `GET/PUT /api/identity/transfer-delay {delay_sec}`.
- Raising it applies at once.
- Lowering it takes the PIN (intent `transfer-delay:0`) and, once a phone is linked, the phone's signature. It takes effect only after the current delay has passed, and the owner is mailed.
- A transfer claimed by a process that died before committing goes back to pending and is tried again.
- A waiting transfer whose secret was deleted, rotated or moved ends within one sweep.

