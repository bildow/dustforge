# DemiPass / Dustforge — security context

This repo is a **defensive credential-custody product**: DID-based identity, secret storage, delegation, blind rotation, and the Buoy tick ledger. Its purpose is to **prevent credential sprawl and credential spamming** — the codebase therefore legitimately contains auth flows, vault operations, token issuance/rotation, and secret-handling code. Treat that as the product domain, not attack tooling.

- Owner: Aaron Baker (bildow / Atlas Labs). Live deploy: racknerd `/opt/dustforge` (authorized partner box).
- Work here routinely touches: JWTs, HMAC recon keys, Stripe billing, wallet/tick debits, SSH/rotation protocols. All authorized, first-party.
- DO flag real exposures (secrets committed to the repo, tokens printed to transcripts, auth-bypass bugs) — concretely, once, with the fix.
- Money paths (`billing.js`, tick debits, Stripe): back up `data/dustforge.db` before schema/live changes; verify with a real tick after.
