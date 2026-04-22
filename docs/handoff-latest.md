# Brain Audit Handoff — 2026-04-21 Evening

## Tips
| Repo | SHA | npm |
|------|-----|-----|
| bildow/dustforge | e74aa3f | — |
| bildow/demipass | b8b69cd | 1.5.0 |
| bildow/rowen | 107bc40 | — |

## Audit scope (new since last audit):

1. **ODT genesis protocol** — POST /api/identity/genesis (submit refraction), /genesis/verify (re-auth), /genesis/seed (public), /genesis/status. Permanent, non-rotatable origin fingerprint. Verify: refraction length/content validation, hash storage, duplicate prevention, structural similarity scoring in verify endpoint.

2. **Graduated suspension tiers** — graduatedSuspensionTier() uses getResonanceScore() to modulate response: high resonance (>70) gets warning first, medium (40-70) gets 1h/12h suspend, low (<40) gets locked until re-auth. Verify: the warn path returns true (allows request), not false.

3. **Progressive barrel auth** — BARREL_RESONANCE_GATES with checkBarrelAuth(did, tier). Single (0+), double (20+), critical (50+). NOT yet wired into endpoints — function exists but no endpoint calls it. Verify: is this a problem or acceptable as staged delivery?

4. **Genesis backup** — GET /api/admin/genesis-backup exports all origin hashes with integrity hash for air-gap. Admin-only. Verify: does it leak anything that shouldn't be in a backup?

5. **User telemetry** — GET /api/admin/telemetry returns signups, active users, secrets count, ticks, waitlist, suspended. Admin-only. Verify: no PII leakage beyond username/email.

6. **Founders page** — public/founders.html with 100-limit counter from /api/capacity. Calls POST /api/stripe/checkout/founders (not yet wired). Verify: sold-out state works correctly, no way to bypass the 100 limit client-side.

7. **demipass@1.5.0** — 4 new genesis MCP tools (seed, submit, verify, status). Self-healing context uses target_host_pattern correctly. whoami extracts DID from JWT.

8. **Codex validated ONBOARDING.md** — self-onboarded from docs alone, found whoami bug (fixed).

## Known issues
- Stripe founders checkout route not wired yet (card 34)
- Progressive barrel auth not enforced on endpoints yet
- .mcp.json still has plaintext tokens (ODT genesis designed but not replacing stored tokens yet)
