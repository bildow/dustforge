# Dustforge Patch Plan — 2026-04-15

Branch: `codex-sandbox-audit-fixes-2026-04-15`
Base: `4d69bac`

## Scope

This plan is based on:
- static review of `server.js`, `billing.js`, and `stripe-service.js`
- bounded live validation against `https://dustforge.com`
- test identity only, no destructive or third-party-impacting traffic

## Confirmed Issues

### P0 — Fix immediately

1. `auth-fingerprint` is fail-open
- Live result: wrong password still returned `200` and a valid transact token.
- Root cause: password check only rejects when Stalwart returns a non-null password that does not match; lookup failure falls through to token issuance.
- Files:
  - `server.js`

2. Blindkey `http_header` exfiltrates the secret
- Live result: secret was reflected back through `postman-echo.com` in the API response body.
- Root cause: caller controls outbound URL and Dustforge returns upstream response content verbatim.
- Files:
  - `server.js`

3. `/api/billing/topup` is unauthenticated
- Live result: wallet credited without a bearer token.
- Root cause: public credit route with no auth or admin gate.
- Files:
  - `server.js`

4. `/api/prepaid/purchase` does not require email verification
- Live result: purchase succeeded and returned a Stripe checkout session without `verification_token`.
- Root cause: verification check only runs when token is present.
- Files:
  - `server.js`

5. Stripe account creation stores raw password in Stripe metadata
- Static result: raw `password` written to checkout session metadata; success page provisions directly from it.
- Files:
  - `stripe-service.js`
  - `server.js`

### P1 — Fix in the same patch set if possible

6. Blindkey `verify_match` is an equality oracle
- Live result: exact candidate returned `matches: true`.
- Root cause: direct string comparison API over stored secret.
- Files:
  - `server.js`

7. `/api/relay/create` allows arbitrary external forwarding destinations
- Live result: arbitrary external address accepted as a relay target.
- Root cause: no destination trust policy, daily cap, or abuse guard beyond cost.
- Files:
  - `server.js`

8. `/api/stripe/checkout/topup-external` leaks username-by-DID to unauthenticated callers
- Live result: returned checkout session plus target username for supplied DID.
- Root cause: public lookup embedded in checkout flow.
- Files:
  - `server.js`

### P2 — Review after core fixes land

9. `/api/prepaid/check` is a status oracle for exact keys
- Likely acceptable if key entropy remains strong, but should be reviewed after purchase/redeem flow hardening.

10. Stripe success-page direct provisioning and webhook path inconsistency
- Success page provisions directly.
- Webhook path provisions with a different password strategy.
- Needs one canonical fulfillment path.

## Patch Order

### Phase 1 — Stop active exploit paths

1. Make `auth-fingerprint` fail closed
- If Stalwart lookup fails, return `503`.
- If lookup succeeds and password mismatches, return `401`.
- Never issue a token when password verification is unavailable.

2. Disable public wallet credit
- Remove or hard-gate `/api/billing/topup`.
- If needed for ops, require an admin-only shared secret or internal-only route.

3. Restrict Blindkey actions
- Remove `http_header` entirely, or hard-allowlist destinations and redact upstream response bodies.
- Remove `verify_match`, or replace it with a bounded internal-use-only mechanism unavailable to silicons.

4. Enforce prepaid email verification
- Require `verification_token`.
- Verify token/email pairing and expiry.
- Invalidate or consume token at purchase start.

### Phase 2 — Fix onboarding/payment integrity

5. Remove raw passwords from Stripe metadata
- Store pending account state server-side.
- Put only opaque checkout/session reference in Stripe metadata.

6. Make Stripe fulfillment single-path and idempotent
- Prefer webhook as the canonical creation path.
- Success page should only display status for an already-fulfilled session.
- Ensure one idempotency key covers account creation.

### Phase 3 — Abuse and privacy hardening

7. Harden relay creation
- Add destination policy.
- Add per-identity forward limits beyond just rule count.
- Consider verified-destination or sponsor-controlled allowlist.

8. Reduce public identity leakage in `topup-external`
- Either keep it intentionally public but stop returning username before payment, or require a public handle instead of raw DID.

## Concrete Implementation Targets

### `server.js`
- `POST /api/identity/auth-fingerprint`
- `POST /api/billing/topup`
- `POST /api/blindkey/use`
- `POST /api/prepaid/purchase`
- `GET /api/prepaid/success`
- `POST /api/relay/create`
- `POST /api/stripe/checkout/topup-external`
- `GET /api/stripe/success`
- `POST /api/stripe/webhook`

### `stripe-service.js`
- `createAccountCheckout()`
- potentially add server-side pending-checkout support

## Acceptance Criteria

1. Wrong password on `auth-fingerprint` returns `401`.
2. Stalwart outage on `auth-fingerprint` returns `503`, never `200`.
3. Blindkey secret cannot be exfiltrated through caller-controlled outbound requests.
4. Blindkey cannot be used as a direct equality oracle by a silicon.
5. `/api/billing/topup` rejects unauthenticated callers.
6. `/api/prepaid/purchase` rejects missing or invalid verification tokens.
7. Stripe metadata no longer contains raw passwords.
8. Account creation occurs through one canonical idempotent flow.
9. Relay creation is no longer an unrestricted arbitrary forwarding surface.
10. Public topup flow no longer reveals target username before payment completion.

## Recommended Test Pass

### Manual
- create a disposable account
- verify wrong password fails
- verify temporary auth dependency failure fails closed
- store a Blindkey test secret and confirm no action returns it
- confirm prepaid purchase without verification token fails
- confirm external wallet credit requires auth or internal credentials

### Regression
- account checkout still creates one account
- wallet topups still credit exactly once
- prepaid key redeem still creates one account per key
- relay creation still works for allowed destinations

