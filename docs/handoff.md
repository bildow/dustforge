# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `f579d08` — Fix Lori query string bug |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | Netlify LIVE, RackNerd LIVE (deployed 2026-04-20) |
| **Status** | RackNerd deployed. TOS at /terms.html (v3, pending Brain's v4 push). DemiPass e2e 9/9 pass. |

## What Shipped This Session (2026-04-19/20)

### Dustforge API (server.js)
- `b10b872` — Fix 3 Brain audit findings (manifest startup crash, SDK error handling, homepage copy)
- `e5e8dbb` — Tick service: chain hashing, POST /api/tick/verify, POST /api/tick/chain/verify, GET /api/tick/stats, referral accumulator fix (was 100% share → actual 10%)
- `c08d59e` — Auto-ledger (free writes, paid reads 1DD/page) + Chrono Triggers (scheduled delivery, dead man's switch, 30s executor)
- `039460d` — Lori self-onboard improvements (invite key flow, better logging)
- Manifest inlined in server.js — no more fs.readFileSync of deleted file

### Vault Dashboard (public/vault.html) — ALL 5 PHASES
- `cabd732` → `3fea475` — Full vault UI
- P1: Stats (DD balance, secrets, use-tokens 24h, tick streak), secrets table, audit feed
- P2: Circuit breaker controls (per-secret toggle, Trip All Breakers panic, reset)
- P3: Carbon actions (store secret, rotate, delegate, add context, revoke)
- P4: Live telemetry (30s polling, auto-ledger summary, honeypot trap feed, credential health)
- P5: Tab architecture (Secrets, Actions, Activity, Health), modal forms, Escape to close

### TOS
- `1017447` — TOS v3 written (invite key flow, breach notification, export controls, dual-barrel described)
- `3fea475` — TOS v3 made canonical at /terms.html, v2 archived at /terms-v2.html
- **Brain produced a v4 draft** in /root/sandbox/dustforge-terms-v4/ — needs to be committed and pushed via git (Claude Code on flimflam cannot access /root/sandbox on phasewhip)

### DemiPass SDK (bildow/demipass)
- `71a7468` — Prep for npm: cleaned package.json (zero deps), fixed README, MCP tools documented
- **npm published: `demipass@1.0.0`** — live at npmjs.com/package/demipass

### Rowen (bildow/rowen)
- `690876c` — Credential health loop: egress canary → ingress verify → carbon escalate
- `b820dc3` — Honeypot deception defense: fake success on exfiltration, rich intelligence logging

### Infrastructure
- civitasvox.com DNS: all Cloudflare/AWS A records deleted, @ and www → 192.3.84.103
- Netlify redeployed 4x throughout session, all verified

## Repos

| Repo | Latest | Status |
|------|--------|--------|
| bildow/dustforge | ccb8273 | Netlify LIVE, RackNerd pending |
| bildow/demipass | 71a7468 | npm 1.0.0 LIVE |
| bildow/rowen | b820dc3 | Deployed on phasewhip |
| bildow/tome | 04837c7 | Session logged |
| bildow/civitasvox | 078ed92 | Platform live |

## For Brain's Next Audit

### New code to verify (all on origin/main):
1. **Tick chain hashing** — POST /api/tick, verify chain_hash in response, POST /api/tick/chain/verify works
2. **Auto-ledger** — authenticated API calls create auto_ledger entries, GET /api/ledger charges 1 DD, GET /api/ledger/summary is free
3. **Chrono Triggers** — POST /api/chrono/create arms a trigger, /extend pushes fire time, /cancel disarms, 30s executor fires due triggers
4. **Referral accumulator** — referral_accumulators table, 0.1 DD per tick accumulated, pays out at 1 DD threshold
5. **Vault dashboard** — dustforge.com/vault.html loads, auth works, secrets table renders, circuit breaker panic button trips all
6. **TOS** — dustforge.com/terms.html is v3. Still contains "prepared without legal counsel" disclaimer (line 31) and 72h breach notice (Section 12). These are intentional pending Brain's v4 rewrite — do not remove without replacement.
7. **Rowen honeypot** — unapproved hosts get fake success (not error), intelligence logged
8. **Rowen credential health** — egress 401/403 → ingress /credential-health → audit event
9. **DemiPass SDK** — `npm install demipass` works, README matches actual API

### Brain's TOS v4 draft:
Your v4 draft is at /root/sandbox/dustforge-terms-v4/. Claude Code cannot read /root/ on phasewhip. **Please commit and push to origin/main** so we can pull, review, and deploy. Git is the handoff mechanism — filesystem paths don't cross machine boundaries.

## Completed Cards
- 243 (all phases): Vault dashboard — DONE
- 244: Tick refinements — DONE
- 245: Rowen honeypot — DONE
- 246: Auto-ledger — DONE
- 247: Chrono Triggers — DONE
- 252: npm publish demipass — DONE
- 254: Credential health loop — DONE

## Open Task Cards
- 220: Lori Conductor wrapper
- 249: Google Ads (blocked: Aaron desktop)
- 251: demipass.com landing page (blocked: DNS)
- 253: HackerNews Show HN
- NEW: DemiPass egress action type expansion (document, http_body, env_inject)
- NEW: DemiPass e2e egress testing
- NEW: DemiPass Android wallet app (Moto G connected via ADB, needs JDK)
- NEW: Upload Brain TOS v4 via DemiPass document courier

## Blocked on Kyle (RackNerd)
- `git pull && pm2 restart dustforge` (deploys ALL new server code)
- civitasvox.com nginx vhost + certbot SSL
- demipass.com root domain DNS still propagating (www.demipass.com HTTPS live, demipass.com cert pending root A record propagation)
- Flowhook agent token for Aaron's Moto G (device ZT4225JC23)

## DemiPass Product Direction (decided this session)
- DemiPass is a **standalone product**, not just a Dustforge subsystem
- Platform-agnostic: works with any agent framework, Dustforge is first customer
- demipass.com is the product domain, Android app is the DemiPass wallet
- Three security features: phone secret purge, cross-platform lock (Dustforge↔DemiPass), behavioral velocity throttle (5 secrets in 30min = auto-suspend)
- Sightless (Kyle's project) + Flowhook = mobile ergonomics layer for voice-driven agent control
