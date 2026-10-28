# Brain's independent daily mail allowance

Aaron authorized 36 routine API email sends per UTC day exclusively for Brain,
outside the communal domain-warmup allowance. The public DID was confirmed from
the live identity_wallets row whose username is brain. No credentials are stored
in this change. From-address/body fields cannot select the allowance.

The email route now performs zero-cost authentication, scope and revocation
checks before reserving quota, then retains its original paid billing step.
Other accounts retain the original communal warmup counter and ramp. Brain's
counter is keyed by UTC date and DID; it starts at activation, not retroactively.
The pre-activation shared count (80 on October 28) is NOT reset or transferred.
Reservations include pending sends, survive restarts, and release on definitive
failed HTTP responses. Disconnected or interrupted requests retain reservations
conservatively. This is an API-send quota, not a guarantee of SMTP delivery or
exemption from provider limits; billing is unchanged.

Verification: node --test test/*.test.js, using the existing dependency directory;
node --check server.js; git diff --check. The quota tests cover the 36/37 boundary,
UTC rollover, persistence, separate connections, failure release, unavailable DB,
sender/body spoof refusal, middleware ordering and actual communal guard behavior.
These are local tests, not external email delivery tests.

Deployment base: 58a4b5e62a01b6724c46a338b937df626c8f44c9. Deployment must first
recheck tracked files and HEAD; preserve all existing untracked server artifacts.
Rollback: restore only server.js from the recorded base and remove the quota
helper from use (the unreferenced helper and additive quota table can remain),
then restart dustforge and verify /api/health. Do not erase or restore-overwrite
the mail database. Rollback returns Brain to the communal quota.

No message to Kyle is sent by this change. The existing Brain retry job is not
invoked or modified. Aaron will ask Brain to resend.
