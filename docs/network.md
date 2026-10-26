# DemiPass network — connect wallets, join a fleet, send DD

Server: `network_routes.js`. Phone wallet: the Fleet tab of `public/vault-mobile.html` (+ Wallet, request cards on
the vault home, Send DD). Tests: `test/network_smoke.sh` (HTTP), `test/vault_ui.test.js` (wallet page).

Base URL `https://api.dustforge.com`. Every call carries `Authorization: Bearer <token>`: the wallet's own token,
scope `transact` (person: the vault sign-in or a device-flow token; agent: `POST /api/identity/auth-fingerprint
{username, password, scope:'transact'}`, sent with a real `User-Agent` header). `silicon:` tokens (they act for
their owner) and worker tokens are refused (403).

## Kinds of connection

| `as` | Who asks | On accept |
|---|---|---|
| `person` | anyone | the two wallets become contacts and can send each other DD |
| `agent` | a fleet owner | the target wallet joins the asker's fleet as an agent (silicon) |
| `join` | an agent | the asker joins the target's fleet as an agent |

An agent that joins through the network **keeps its own key**: the owner sees its balance and spend, refills it,
delegates secrets to it, and the two can send each other DD, but the owner never mints its tokens or creates its
workers (`joined_via = 'network'`; the mint and worker routes answer 403). Silicons the owner created, or linked with
the member's token / the admin key / a claim link, are `joined_via = 'owner'`: the owner holds their key as before.
A wallet is an agent of at most one fleet; a wallet that is an agent cannot own a fleet with agents; a wallet whose
fleet has agents (active or invited) cannot join one. The owner's fleet is created on the first agent that joins
(slug = the owner's username).

Leaving (`POST /api/network/leave-fleet`, the agent's own sign-in; not a fleet-minted token) ends the membership,
the fleet's minted tokens and the workers its owner made. When the owner held the key (`owner`), every session of
the wallet is also signed out — tokens, refresh tokens, workers, registered `silicon:` agents — and it signs in
again; check its recovery email too. A network agent stays signed in.

Only the target decides. `join` is for wallets without a PIN (agents); a wallet with a PIN asks to be invited.
When the target is the one joining a fleet (`agent` request) and has a vault PIN, it accepts with the PIN: the 403 names `intent: join:<id>`; prove it with `POST /api/identity/gate/verify
{gate:'pin', pin, intent}` and accept again. A wallet with no PIN (an agent) accepts with its token alone.

## Endpoints

- `GET /api/network` → `{ me, fleet, member_of, people[], agents[], incoming[], outgoing[] }`. Each request has
  `id, kind, direction, other, effect` (what accepting does, in words), `needs_pin`, `intent`, `note`, `expires_at`.
- `POST /api/network/requests { to, as, handle?, note? }` → 201 `{ request }`. `to` is a username, an email or a
  DID. `handle` (fleet kinds) defaults to the agent's username. 404 no such wallet; 409 already connected, already
  waiting (either direction: accept theirs instead), or a fleet rule above; 429 more than 20 of yours waiting, or
  you asked the same wallet in the last 24 h and it was declined or withdrawn. The target gets a short mail (no
  note, no links but the wallet). Requests expire after 14 days.
- `POST /api/network/requests/:id/accept` (target) · `/decline` (target) · `/withdraw` (asker).
- `POST /api/network/people/remove { username | did }` — either side ends a contact.
- `POST /api/network/leave-fleet` — an agent leaves its fleet (see above; the owner removes one with
  `DELETE /api/fleet/:slug/silicons/:handle`, which also ends its minted tokens and owner-made workers).

Fleet-minted tokens (`auth_method: fleet_owner_mint`) act as the wallet but cannot change fleet membership, manage
a fleet, create one, approve a device login, register agents or manage workers.

### Sending DD (to a contact, your agent, or your fleet's owner)

1. `POST /api/network/transfers { to, amount_cents, note? }` → 201 `{ transfer: { id, intent:'send:<id>', needs_pin } }`.
   Nothing moves yet; the recipient and amount are fixed. `amount_cents` is whole DD, 1 to 1,000,000.
2. `POST /api/network/transfers/:id/confirm` from the same token. With a PIN set: 403 + `missing:['pin']`,
   `intent:'send:<id>'` → verify the PIN for that intent → confirm again. Without a PIN: it sends.
   → 200 `{ status:'sent', amount_cents, balance_after }`. Unconfirmed transfers expire after 5 minutes;
   `POST /api/network/transfers/:id/cancel` drops one. Transfers over 100 DD need the double barrel, like every
   transfer (`/api/identity/barrel`). Both ledgers show `Transfer to/from <username>: <note>`.

## Example: an agent asks to join a fleet

```
TOKEN=$(curl -s -A 'my-agent/1.0' -H 'content-type: application/json' https://api.dustforge.com/api/identity/auth-fingerprint \
  -d '{"username":"<agent username>","password":"<agent password>","scope":"transact"}' | jq -r .token)
curl -s -A 'my-agent/1.0' -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  https://api.dustforge.com/api/network/requests -d '{"to":"<owner username>","as":"join","note":"hello"}'
```

The owner sees the request on their wallet's home and in Fleet, and accepts it there.
