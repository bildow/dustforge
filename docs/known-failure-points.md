# Dustforge Known Failure Points

Updated: 2026-04-18
Scope: `main` at local `HEAD` during Brain audit pass 2

This document tracks confirmed correctness defects in the live Dustforge codebase. It is not a wishlist. Every item below is tied to an observed code path on `main` and should be treated as an active failure mode until fixed and re-verified.

## Confirmed Findings

### DFP-01 — Secret rotation reactivates revoked contexts

- Severity: High
- Status: Open
- Surface: `POST /api/blindkey/rotate`
- Code: [server.js](/root/sandbox/dustforge/server.js:2041)
- Detail: rotation copies every `blindkey_contexts` row from the old secret onto the new version, but only carries `context_name`, `action_type`, patterns, `allowed_by`, `max_uses`, and a reset `use_count`.
- Failure mode: revoked or suspended contexts come back on the new secret as implicit `active` rows because `status` is not preserved during the copy.
- Impact: a secret owner or admin can rotate a compromised secret and silently re-enable contexts that were intentionally disabled.
- Fix direction: preserve `status` during rotation and explicitly decide whether `use_count` should reset per context state.

### DFP-02 — Admin secret lookup is ambiguous across tenants

- Severity: Medium
- Status: Open
- Surface: `GET /api/blindkey/delegate/chain`, `GET /api/blindkey/history`
- Code: [server.js](/root/sandbox/dustforge/server.js:1491), [server.js](/root/sandbox/dustforge/server.js:5858)
- Detail: admin-mode lookups can resolve a secret by `name` alone and then pick the most recently updated matching row globally.
- Failure mode: an admin asking for a common secret name like `github-token` can inspect the wrong tenant's history or delegation chain.
- Impact: cross-tenant confusion in the operator console, with a credible risk of auditing or revoking the wrong secret lineage.
- Fix direction: require `did` or `username` for admin secret inspection, then resolve within that owner scope only.

### DFP-03 — Rowen and direct owner flows enforce different HTTP host policies

- Severity: Medium
- Status: Open
- Surface: `POST /api/blindkey/use`, `POST /api/rowen/deliver`
- Code: [server.js](/root/sandbox/dustforge/server.js:1700), [server.js](/root/sandbox/dustforge/server.js:1839), [server.js](/root/sandbox/dustforge/server.js:2564)
- Detail: direct owner and use-token execution hard-block non-whitelisted HTTP hosts, while Rowen delivery allows private-network targets after context validation.
- Failure mode: the same approved context succeeds through Rowen but fails through the normal owner path.
- Impact: inconsistent product behavior, brittle debugging, and a policy surface that depends on which route invoked the secret rather than on the approved context.
- Fix direction: centralize host policy so direct, token, and mediated execution use the same allow/deny decision.

### DFP-04 — Delegation quotas burn on token issuance, not token redemption

- Severity: High
- Status: Open
- Surface: `POST /api/blindkey/request-token`
- Code: [server.js](/root/sandbox/dustforge/server.js:1616)
- Detail: delegated requests increment `demipass_delegations.use_count` immediately after a use-token is issued.
- Failure mode: if the caller never redeems the token, lets it expire, or intentionally spams token requests, the delegation quota is still consumed.
- Impact: low-cost denial of service against delegated secret access, especially where `max_uses` is small.
- Fix direction: increment delegation usage only after successful redemption, or separately track `issued_count` versus `redeemed_count`.

### DFP-05 — Rowen mediation cannot resolve rotated secrets by base name

- Severity: Medium
- Status: Open
- Surface: `POST /api/rowen/authorize`, `POST /api/rowen/deliver`, `/api/conductor/rowen/*`
- Code: [server.js](/root/sandbox/dustforge/server.js:1370)
- Detail: secret mediation looks up `blindkey_secrets` with an exact active `name` match instead of using the same latest-version resolver as the normal owner flows.
- Failure mode: after rotation from `secret` to `secret_v2`, Rowen or Conductor requests using the base name can fail with `secret not found for requestor_did` while direct owner flows still succeed.
- Impact: mediation becomes less reliable precisely after a security rotation event.
- Fix direction: switch mediation to `resolveLatestBlindkeySecret(...)` so all execution lanes share the same version-resolution semantics.

### DFP-06 — Escrow release bypasses counterparty acceptance

- Severity: High
- Status: Open
- Surface: `POST /api/escrow/:id/release`
- Code: [server.js](/root/sandbox/dustforge/server.js:5451)
- Detail: the release route allows release while escrow status is either `pending` or `active`.
- Failure mode: the creator can lock collateral and immediately release it to the beneficiary without the counterparty ever accepting the contract.
- Impact: the acceptance step becomes advisory instead of enforced, which breaks the expected escrow handshake and any workflow built on explicit counterparty acknowledgment.
- Fix direction: restrict release to `active` only, or document and rename the route semantics if pre-accept release is actually intended.

## Secondary Risks Worth Verifying After Fixes

- Rowen deliver marks its internal use-token as `used` before decryption and execution complete, which may strand retryable failures as already-consumed attempts. Code: [server.js](/root/sandbox/dustforge/server.js:2539)
- Expired escrow contracts are marked `expired` by cleanup, but collateral stays locked until a separate refund call occurs. Code: [server.js](/root/sandbox/dustforge/server.js:1186)

## Verification Notes

- Static validation: `node --check server.js` passed during audit.
- Test coverage: Dustforge still has no automated runtime test suite in `package.json`, so these findings are code-audit confirmed rather than integration-tested.
