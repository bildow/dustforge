# OAuth 2.1 front for human web seats (Claude.ai custom connectors)

`oauth_seat.js`. Aaron, 2026-11-21: "Add the OAuth 2.1 front that Claude.ai's custom-connector flow needs, on top of
DemiPass's existing app JWT, so a human web seat can authorize a Conduit connector once in the browser."

## What the connector side requires (recorded 2026-11-21)

Sources: support.claude.com, *Getting started with custom connectors using remote MCP*; the MCP specification
2025-06-18, *Authorization*. Both read on 2026-11-21.

| Requirement | Where | How this server meets it |
|---|---|---|
| Public HTTPS on port 443, no custom port; Claude connects from Anthropic's cloud, never from the user's device | Claude.ai | `api.dustforge.com` (this server) and `conduit.dustroot.com/mcp` (the relay) are both behind nginx on 443 |
| Streamable HTTP MCP endpoint | Claude.ai, MCP | the relay's `/mcp` (atlas/conduit PR 15, the Conduit pane's work) |
| 401 + `WWW-Authenticate` naming the protected-resource metadata; `/.well-known/oauth-protected-resource` lists `authorization_servers` | MCP, RFC 9728 | the relay's side; it names `https://api.dustforge.com` |
| RFC 8414 metadata at `/.well-known/oauth-authorization-server` | MCP | served here: issuer `https://api.dustforge.com` (no trailing slash), S256 only, `code` only, `authorization_code` + `refresh_token` |
| Dynamic client registration (RFC 7591), or a client id entered by hand | Claude.ai ("Register automatically" / "Use your own OAuth client") | `POST /oauth/register`; redirect URIs restricted to `https://claude.ai/api/mcp/auth_callback` and the claude.com twin |
| Authorization code + PKCE S256; `state` | OAuth 2.1 | required on every code; a code is one-time and its replay revokes the grant |
| `resource` (RFC 8707) on the authorize and token legs; the resource server checks the audience | MCP | `resource` must be `https://conduit.dustroot.com/mcp`; the access token's `aud` is `svc:conduit`, which the relay already verifies |
| Short-lived access tokens; rotating refresh tokens; reuse detection | OAuth 2.1 | access 1 h, refresh 30 d rotated on use, a replayed refresh token revokes the grant |
| Token passthrough forbidden | MCP | the relay verifies the seat's token at DemiPass and calls DemiPass with its own tenant token; nothing is forwarded |
| Claude.ai's callback URL | Claude.ai | `https://claude.ai/api/mcp/auth_callback` |

## What a seat is

A **seat** is a fleet-created agent of the owner's fleet whose handle starts with `seat-` (first: `seat-fable`). It is
a wallet of its own: Conduit charges land on it, it is funded, watched and removed like any agent, and the owner is
the person who answers for it (`personFor`). Threat model item 6 carries the class ("human web seats").

The connector holds OAuth tokens only. No vault value is involved anywhere in this flow.

## The flow

1. Claude.ai calls the relay's `/mcp` without a token → 401 → reads the relay's resource metadata → reads this server's
   metadata → registers (or uses a client id Aaron typed in) → opens `GET /oauth/authorize`.
2. The authorize page validates the client, the exact redirect URI, PKCE and `resource` first. An unknown client or
   an unregistered redirect URI gets an error page, never a redirect. Then:
   - **login**: the fleet owner's DemiPass username and password (`verifyWalletPassword`). Five tries per request;
     an agent wallet cannot sign in; a wallet without a vault PIN is sent to set one.
   - **PIN**: checked by `tryPin`, so every miss counts on the wallet's lockout exactly as in the app.
   - **consent**: the owner picks a seat (one of their `seat-…` agents) and the Conduit scopes (`read`, `post`,
     `ack`; `forward` if asked). The seat must already hold a live consent to pay Conduit approved by the owner
     (that is an elevated approval on the phone, never a browser click). Approving also grants, or renews, the
     owner's **use-only delegation** of each granted scope to the seat (`service_delegations`, standard depth,
     30 days).
3. `POST /oauth/token` with the code and `code_verifier` (client secret by Basic or body, or none for a public
   client). The access token is the seat's **Conduit service token**: EdDSA by the seat's key, `iss demipass-svc`,
   `aud svc:conduit`, `svc_scopes` = the granted subset, `auth_method oauth_seat`, `seat`, `resource`, `cap_dd` =
   min(500, the consent's daily cap), `exp` ≤ 1 h. It opens nothing at DemiPass and nothing at another tenant.
4. The relay verifies it with `POST /api/services/verify {token, action}` as for any service token. The reply now
   carries `auth_method` (`oauth_seat` or `service_token`) and, for a seat, `seat` and `resource`, read from the
   signature-checked payload. The relay binds the seat's name to the verified wallet from `seat`, never from a header.
5. Refresh re-checks everything: the seat still an active fleet-created agent of the owner, both wallets active, a
   live consent approved by the owner, a live delegation of every scope. Any failure closes the grant.

## Revocation

- The owner revokes the seat's Conduit delegation or consent in the app (`POST /api/services/delegations/:id/revoke`,
  `/consents/:id/revoke`): every OAuth grant resting on it ends at once, and every unexpired access token is marked
  revoked in `issued_tokens`, which the relay's next verify reads (no cache on the gateway).
- `GET /api/oauth/grants` and `POST /api/oauth/grants/:id/revoke` (owner's own session) list and end grants.
- `POST /oauth/revoke` (RFC 7009) lets the connector disconnect.
- Code replay and refresh-token replay revoke the grant they belong to.

## Operator runbook

1. Create the seat: a fleet agent `seat-<name>` through the request path (`POST /api/fleet/<slug>/silicons/seat-<name>/token-requests
   {create:{…}}`, approved on the phone) or `POST /api/fleet/<slug>/silicons {create}`.
2. Consent: the seat files `POST /api/services/consent {service:"conduit", daily_cap_dd:500}` with its own token; the
   owner approves the card (PIN + phone). 500 DD/day at 1 DD per read is the per-day hop cap.
3. Register the seat's relay name once (`POST /agents/register` at the relay with a Conduit token of the seat) so the
   relay's name `seat-<name>` belongs to that wallet.
4. In Claude.ai: Customize → Connectors → add `https://conduit.dustroot.com/mcp`, authentication "Sign in now",
   OAuth client "Register automatically". Sign in on the DemiPass page, PIN, pick the seat, approve.
5. To end it: revoke the delegation (or the consent) in the app, or the grant under `/api/oauth/grants`.

Environment: `PUBLIC_API_URL` (issuer), `OAUTH_CONDUIT_RESOURCE` (default `https://conduit.dustroot.com/mcp`),
`OAUTH_REDIRECT_ALLOWLIST` (comma list; default the two Claude callbacks).

## Residual risks, stated

- The authorize page takes the owner's password and PIN in a browser on a public host. The PIN check shares the
  wallet's lockout, logins are rate-limited by IP and per request, and the page is same-origin with a nonce CSP, but a
  phished owner on a look-alike page would hand over both. The linked phone does not sign this approval (the browser
  cannot reach it). Adding a device-presence step is the next hardening if Aaron wants it.
- A seat's token is minted by this server with the seat's key on the owner's browser approval, not by the seat's own
  session. That is the point of the front, and it is why every mint re-checks consent and delegation.
- Anyone may register a client, but a client can only ever send a browser to a Claude callback, and nothing is issued
  without the owner's login, PIN and approval.

Tests: `node --test test/oauth_seat.test.js` (module, in-memory DB, stand-in password/PIN) and
`bash test/oauth_seat_smoke.sh` (server.js end to end, including the tenant's verify and the app's revoke).
