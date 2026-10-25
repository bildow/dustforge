# DemiPass browser fill — API contract (flights 1–3)

The browser extension (flight 1 + the client half of flight 2) and the agent fill
tool (flight 3) build against this contract. The server half lives in
`server.js` on dustforge branch `feat/browser-fill`.

Base URL: `https://api.dustforge.com`. Every call carries `Authorization: Bearer <token>`.

## Who calls

| Caller | Token | How it gets one |
|---|---|---|
| Extension (a person's browser) | carbon JWT, scope `transact` | device flow: `POST /api/identity/device/code {agent_label, scope:'transact'}` → approve at `https://demipass.com/device` → poll `POST /api/identity/device/token {device_code}` (428 `authorization_pending` while waiting). Refresh with `POST /api/identity/refresh {refresh_token}` — the pair rotates, store both again. |
| Phone wallet (`vault-mobile.html`) | carbon JWT | existing vault sign-in |
| Agent fill tool | silicon token (`silicon:…`) | existing silicon registration |

## Origins

A secret is filled only into a page whose origin is bound to it. An origin is
`new URL(x).origin`: `https://host[:port]`. Opaque origins (`about:blank`,
`data:`, sandboxed frames — origin `null`) are refused. Plain `http:` is accepted only for
`localhost` and `127.0.0.1`. Matching is exact — `https://login.example.com` and
`https://example.com` are different origins; bind both if both are used. At most
10 origins per secret.

## Endpoints

### `POST /api/blindkey/store` (existing, two new fields)
- `origins: ["https://example.com"]` — binds the secret to these origins.
- `login: "me@example.com"` — the account name the password belongs to (an
  email or username; up to 256 characters). It comes back as `username` from
  `candidates` and `redeem`. It is a separate field from the SSH `username`
  binding (dustforge PR #10), which only accepts SSH account names.

For a website login use `secret_type: 'password'`; for a pasted key, `api_key` or
`oauth_token` (`token` is not a type — it silently becomes `api_key`). A secret
stored with origins gets no default `/use` context: it is for browser fill only.
`/store` needs a `write`-scoped token or better. Storing again under the same
name replaces the value; `origins`/`login` left out keep what was there.

### `POST /api/blindkey/origins` — carbon only
`{ ref | name, origins: [...], mode: 'add' | 'set' }` → `{ ok, ref, origins }`.
`set` with `[]` unbinds every origin.

### `GET /api/blindkey/fill/candidates?origin=<origin>`
→ `{ ok, origin, candidates: [{ ref, name, username, secret_type }] }`.
Never a value. Carbon: the owner's secrets bound to that origin. Silicon: only
secrets it holds `action:browser_fill` for (resource `<ref>`, `<name>` or `*`).

### `POST /api/blindkey/fill/request`
`{ ref, origin, client_label? }`.
- Origin not bound to the secret → 403 `{ error, bound_origins }`.
- Carbon → 201 `{ ok, request_id, status: 'pending', expires_in: 120 }`. A person
  approves it in the phone wallet with the vault PIN.
- Silicon with `action:browser_fill` on the secret → 201 `{ ok, request_id,
  status: 'approved', expires_in: 120 }`. Without it → 403.

`request_id` is an opaque string (`dpf_…`). `client_label` is display-only.

### `POST /api/blindkey/fill/redeem`
`{ request_id }` — only the session that made the request can redeem it. A
carbon session is one access token (its `jti`): a token refreshed while the
request waits gets a new session, and the old request answers 404. So refresh
*before* asking when the access token expires within 5 minutes, and if a
refresh happens anyway, ask again. A silicon's session is its agent identity.
- 428 `{ error: 'approval_pending' }` — poll again (every 2 s is fine).
- 403 `{ error: 'denied' }`, 410 `{ error: 'expired' | 'already_redeemed' }`.
- 200 `{ ok, value, username, origin, name, ref }` — once. The request is then
  spent. Logged as a `secret_filled` security event, not a reveal.

### Wallet side — carbon only, never the requesting session
- `GET /api/blindkey/fill/pending` → `{ ok, requests: [{ id, intent, name, ref,
  username, origin, client_label, created_at, expires_at }] }`.
- Approve: `POST /api/identity/gate/verify { gate:'pin', pin, intent }` with the
  request's `intent` (`fill:<id>`), then `POST /api/blindkey/fill/<id>/approve`.
  The PIN proof is spent by the approval. The session that made the request
  cannot approve it (409).
- Deny: `POST /api/blindkey/fill/<id>/deny`.

## What this does and does not protect

- The value never passes through a chat, a pane, a transcript or the clipboard.
- A carbon fill needs the PIN on a second session (the phone), every time.
- A page cannot ask for a value: only the extension's background worker calls
  the API, and it reports the tab's real origin, not one the page claims.
- Whatever the value is filled into can read it: the page itself, and anything
  that drives the browser (DevTools / CDP). For agents this is leak prevention
  (nothing lands in the model's context or logs), not containment of a hostile
  agent.
