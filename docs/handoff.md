# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `e369242` — Vault injection hardening |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | Netlify + RackNerd LIVE |
| **Status** | All 11 task cards complete. Injection hardened. Capacity tested 8/8 pass. |

## What Shipped This Session (2026-04-20)

### Infrastructure — 5 domains live with HTTPS
- **dustforge.com** — Netlify, main site + vault dashboard
- **api.dustforge.com** — RackNerd, API server (deployed with all new code)
- **demipass.com** — RackNerd, product landing page, SSL cert live
- **buoy.dustforge.com** — RackNerd, product landing page, SSL cert live
- **civitasvox.com** — RackNerd, placeholder, SSL cert live

### Brain Audit Fixes (3 findings from this session)
- `791ab8e` — Chrono SSRF prevention (HTTPS-only, private network blocked, metadata blocked, validated at create + fire time)
- `791ab8e` — Chrono tick chain integrity (auto-ticks use full pipeline: chain hash, billing, referral)
- `791ab8e` + `f579d08` — Lori invite key flow + query string fix (url.pathname → url.pathname + url.search)

### Card 220: Lori Conductor Wrapper
- `71fa458` — Lori routes LLM through Conductor (MiMo V2 Pro) as primary, OpenRouter DeepSeek V3.2 as fallback
- Context enrichment: gathers project names + sender info before LLM call
- Health endpoint shows Conductor status and LLM backend info
- Tested live: natural language responses working through Conductor

### Buoy (temporal anchor product)
- `9b93243` — Tick types: begin, complete, handoff, audit, decision, block, unblock, alert
- ref_tick cross-references for linked chains (handoff → begin)
- tags field for card/repo correlation
- `5e9bed3` — Buoy landing page at buoy.dustforge.com
- Vault dashboard Buoy tab: tick chain ledger, chrono trigger management, chain verification
- Buoy MCP server in demipass@1.1.0

### DemiPass
- `59a6802` — Landing page at demipass.com
- `369261b` — demipass@1.1.0 published (includes Buoy MCP server)
- e2e test: 9/9 pass (store→context→token→rotate→revoke)

### Rowen Egress Expansion (bildow/rowen repo, NOT dustforge/rowen-server.js)
- `c74d223` in **bildow/rowen** `egress/server.js` — 4 new action types: document, http_body, env_inject, smtp_auth
- Total: 6 action types in the standalone rowen repo
- NOTE: dustforge/rowen-server.js is the older monolithic version and only has http_header + ssh_exec. The standalone bildow/rowen repo is the source of truth for egress.

### Other
- 36 authoritative @dustforge.com emails reserved on production (legal, support, admin, etc.)
- Phasewhip admin panel at http://100.83.112.88:9190 (container health + Lori chat)
- Flowhook registered, enrolled, phone online (temporary patch from Kyle)
- TOS v3 canonical at /terms.html, handoff accuracy fixes

## IMPORTANT: Audit against origin/main tip, not stale checkout

Brain: your last 3 audits found issues that were already fixed but your checkout was behind. **Always `git pull origin main` before auditing.** The fixes for SSRF DNS resolution, chain hash coverage, and Rowen repo clarity all landed at `10c5276`. If your checkout doesn't have that commit, your findings are against stale code.

Verify with: `git log --oneline -5` — you should see `10c5276 Fix 3 Brain audit findings: SSRF DNS resolution, chain hash coverage, Rowen repo clarity`

## Repos

| Repo | Latest | Status |
|------|--------|--------|
| bildow/dustforge | e369242 | Netlify + RackNerd LIVE |
| bildow/demipass | 369261b | npm 1.1.0 LIVE |
| bildow/rowen | 2f246e0 | Deployed on phasewhip (SSHPASS fix + 6 action types) |
| bildow/tome | ef9953f | Session logged |

## For Brain's Audit

### Verify new since last audit:
1. **Chrono SSRF fix** — POST /api/chrono/create rejects non-HTTPS, private networks, metadata endpoints. Fire-time re-validation blocks pre-existing unsafe targets.
2. **Chrono tick chain fix** — auto-ticks use computeTickHash, billing, referral accumulator (not raw INSERT)
3. **Lori Conductor wrapper** — health endpoint shows `llm.primary: "conductor (MiMo V2 Pro)"`, `primary_status: "live"`. Send a natural language message via POST /api/conduit/inbound and verify Conductor processes it.
4. **Buoy tick types** — POST /api/tick with `type`, `ref_tick`, `tags` fields. Verify chain_hash includes the type in computation. Verify ref_tick links work.
5. **Egress action types** — document, http_body, env_inject, smtp_auth in **bildow/rowen** repo at `egress/server.js` (commit `c74d223`), NOT in dustforge/rowen-server.js (which is the older monolithic version). Verify honeypot traps fire on unapproved hosts for http_body. Verify document returns plaintext to caller.
6. **demipass.com HTTPS** — valid cert, serves landing page
7. **buoy.dustforge.com HTTPS** — valid cert, serves landing page
8. **36 reserved emails** — `GET /api/identity/lookup?username=legal` returns status=reserved
9. **Lori query string fix** — dustforgeRequest uses `url.pathname + url.search` (was dropping query params)

### Known issues (not bugs, just status):
- TOS v3 still has "prepared without legal counsel" disclaimer and 72h breach notice — intentional pending Brain's v4 push
- Phasewhip admin container status shows "unknown" (needs root for full incus status, health checks work)
- Flowhook phone connection is Kyle's temporary patch, not permanent

## DemiPass Android App — SHIPPED
- APK built, signed (v2+v3), installed on Aaron's Moto G via Flowhook OTA
- Package: com.dustforge.demipass, loads demipass.com/vault
- Download: https://api.dustforge.com/demipass-v2.apk
- Needs UX pass: current vault UI is power-user oriented, needs mobile-first simplification

## For Brain: Test the DemiPass App
Brain is already onboarded with a Dustforge DID. Test the app flow:
1. Download APK: https://api.dustforge.com/demipass-v2.apk (or check if installed)
2. Open DemiPass app → login with Dustforge credentials
3. Verify: balance shows, secrets list loads, Buoy tab works
4. Try: drop a tick, check chain verification
5. UX feedback: what's confusing, what's buried, what should be front-and-center on mobile

## Completed This Continuation Session

### DemiPass Routed References
- `d752cd4` — Credit-card-style ref codes (DP-PWD-flimflam-e542b0b9). One-field token requests.
- Brain tested: `{"ref":"DP-PWD-flimflam-e542b0b9"}` → delegated SSH exec → worked.

### TOS v4
- `4448b4e` — Brain pushed TOS v4 via DemiPass delegated SSH (first real credential courier operation)
- Deployed to Netlify. Live at dustforge.com/terms.html and /terms-v4.html

### Secret Metadata (card 9)
- `b3fed44` — expires_at, buoy_ingested_tick, buoy_last_used_tick, provider columns
- Auto-detects 12 provider prefixes (OpenRouter, GitHub, npm, Stripe, etc.)
- GET /api/demipass/expiring for proactive rotation planning
- Mobile vault shows expiration countdown (red/yellow/expired)

### Injection Hardening (card 10)
- `e369242` (dustforge) + `2f246e0` (rowen) — All 4 ssh_exec paths now use SSHPASS env var
- 14 code detection patterns on store. >10KB base64 blocked.
- Shell injection via crafted secret values eliminated.

### Capacity Testing (card 11)
- 8/8 PASS on production: 100 secrets (121ms), 4KB RSA, 8KB PEM, SSH keys, connection strings, Unicode
- Decrypt: 0.06ms per secret at volume. No degradation.

### QR Deposit Flow (card 7)
- `43b2f3a` — qr-deposit.html (local QR gen) + vault-mobile.html scanner (BarcodeDetector API)

### Landing Page Onboarding (card 8)
- `29d72c9` — Three paths (Phone App, QR Deposit, SDK/CLI), routed reference explainer

## For Brain's Audit

### New since last audit (pull origin/main first!):
1. **Routed references** — POST /api/demipass/request-token with `{"ref":"DP-..."}` auto-resolves owner, delegation, context, action. Same error for not-found and no-delegation (anti-enumeration).
2. **SSH injection fix** — all ssh_exec paths use `sshpass -e` with SSHPASS env var, not `-p 'password'`. Verify in server.js and rowen egress/server.js.
3. **Input sanitization** — 14 code detection patterns + >10KB base64 block. Try storing `<script>alert(1)</script>` and verify rejection.
4. **Secret metadata** — store a secret with `ghp_` prefix, verify provider auto-detected as "github" and expires_at set to 90 days. Check buoy_ingested_tick is set.
5. **Expiring endpoint** — GET /api/demipass/expiring?days=90 returns secrets approaching expiration.
6. **TOS v4** — dustforge.com/terms.html and /terms-v4.html both serve v4 content.
7. **Capacity** — vault handles 100+ secrets, 8KB values, Unicode, special chars without degradation.

## Security Cards Shipped (2026-04-21)
- `aa58c46` — #13 Prompt injection filter on secret descriptions + #16 CGNAT SSRF blocking
- `08c09f2` — #14 Per-DID rate limit (10/min) + #15 Velocity throttle (5 secrets/30min = suspend)
- `7f4ea81` — Ref-based requests exempt from rate limit (ref IS the auth)
- `ea0e1d2` — #17 Concurrent token limit (1 active per secret per DID) + #19 Wallet attestation on ticks
- #20 Invite key entropy verified adequate (2^64, 10/15min rate limit)
- demipass@1.2.0 — MCP tool descriptions as behavioral protocol (ingress/egress skills)
- Brain's secrets migrated to DemiPass vault with delegated access (8 ref codes)

## For Brain: Ideation/Audit Round

### Card #17: Concurrent token limit — SHIPPED (ea0e1d2)
One active use-token per secret per DID. Returns 429 if outstanding token exists.
**Verify:** request a token, don't redeem, request another for same secret → should get 429.

### Card #18: Trust gradient fingerprint (NEEDS DESIGN REVIEW)
Three-ring fingerprint as trust gradient, not binary gate. Buoy tick chain IS the behavioral
profile. Anomaly detection computes deviation from historic pattern:
- Normal (<20% deviation): proceed
- Unusual (20-50%): proceed + flag in audit
- Suspicious (50-80%): suspend transaction 1 hour
- Anomalous (80-95%): suspend all access 12 hours
- Critical (>95% or impossible pattern): lock until carbon re-auth

Rings: Inner (request source — IP, agent, TLS), Middle (temporal — time-of-day, frequency,
tick type distribution), Outer (behavioral — action sequences, session shape).

**Questions for Brain:**
1. How do we compute "deviation" without a statistics library? Simple thresholds vs actual distribution?
2. What's the minimum tick history before the profile is meaningful? 10 ticks? 50? 100?
3. How do we handle legitimate pattern changes (new IP, new time zone, new workflow)?
4. Should the gradient apply to ALL token requests or only high-value actions (ssh_exec, document)?
5. False positive cost: a 1-hour suspension during a production deploy is catastrophic. How do we tune?

### Card #19: Wallet attestation on Buoy ticks — SHIPPED (ea0e1d2)
Signed ticks now include attestation block: wallet_active, secrets_count, custody_since,
last_verified_use, attestation_hash. 30-day grace period for new DIDs.
**Verify:** POST /api/tick as authenticated member → response should have attestation block.
DIDs with no wallet and >30 days old get attestation: null.

### Card #21: Notarized ticks
Bilateral co-signed ticks with escrow backing. Public vs private verification. Counterparty
co-signs via Conduit. The tick chain becomes a settlement ledger.
**Status: design phase, needs architecture review.**

## Known Issues
- Stalwart auth from RackNerd intermittently fails (Tailscale link flaky)
- Aaron's DID changed during password reset (old: u7QFEhT8..., new: u7QGkcLs...)
- npm 2FA still disabled on gnomishplumber account
- Phasewhip tripped router DDOS filter during heavy probe cycle (whitelisted now)
