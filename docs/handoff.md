# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `ce8ef20` — Homepage instant onboard key generator |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | **LIVE** on RackNerd (192.3.84.103) + Netlify (dustforge.com) |
| **Status** | All previous audit findings resolved. Homepage key generator live. Netlify redeploy verified. |

## What Shipped Since Last Audit

### Brain Audit Fixes (all 7 findings resolved)
- `aa16d12` — tickId crash fix, atomic invite key claiming, doc honesty (Lori onboarding)
- `535483e` — Invite key stranding fix: release claiming → active on all failure paths
- `59eee08` — Manifest drift fix: proxy .well-known/silicon to API via Netlify redirect
- `c449cfb` — Removed stale static .well-known/silicon file
- `63e23c6` — Aligned manifest, SDK, and referral numbers (all say 10 DD, not 25¢)

### Self-Executing Onboard Script
- `fea31ae` — GET /api/identity/onboard?key=KEY&format=script returns Node.js script
- Key is baked into the script URL — recipient runs `node <(curl -s 'URL') my-agent-name`
- Key consumed on execution, not on URL generation

### Homepage Instant Key Generator
- `ce8ef20` — "Try it right now" section on dustforge.com
- Generates live invite key on click via /api/identity/request-invite
- Displays ready-to-paste curl command with copy button
- Netlify redeploy verified — **LIVE** at dustforge.com

### Netlify Configuration
- .well-known/silicon proxied to api.dustforge.com (not static file)
- /api/* proxied to api.dustforge.com
- /for-agents, /privacy, /terms redirects all verified 200

## Previously Shipped (verified in prior audit)
- Invite key system (request → create → auth, atomic claiming)
- Tick service (anonymous + member, referral revenue share)
- Rowen ingress (port 3004, HMAC) + egress (port 3002, SecretDose)
- DemiPass delivery test passed
- Lori self-onboarded (operator-provided creds, not fully autonomous)
- DemiPass SDK + MCP server with invite flow

## Repos

| Repo | Latest | Status |
|------|--------|--------|
| bildow/dustforge | ce8ef20 | LIVE (RackNerd + Netlify) |
| bildow/demipass | 66416ef | SDK + MCP with invite flow |
| bildow/rowen | a340463 | Ingress + egress deployed |
| bildow/tome | 621390f | Barometer + checkpoint |
| bildow/civitasvox | 078ed92 | Platform live |

## For Brain's Audit

### Verify new since last audit:
1. Homepage key generator works end-to-end (dustforge.com → click → key appears → curl command works)
2. Self-executing onboard script (GET /api/identity/onboard?key=KEY&format=script returns valid Node.js)
3. .well-known/silicon is proxied (not stale static file) — should show invite key flow
4. Atomic invite key claiming — two parallel requests can't both claim same key
5. Invite key release on failure — key returns to 'active' if account creation fails
6. Referral numbers consistent — all references say 10 DD (not 25¢ or 1 DD)
7. Netlify redirects all return 200 (/for-agents, /privacy, /terms, /.well-known/silicon)

### Re-verify from prior audit (regression check):
8. Invite key flow end-to-end (request → create → auth)
9. Tick service (anonymous rate limit, member signing, referral embedding)
10. DemiPass SDK fullOnboard() matches server endpoints

## Open Task Cards
- 220: Lori Conductor wrapper (real LLM personality)
- 243: DemiPass wallet UI (circuit breaker metaphor)
- 244: Tick service refinements
- 245: Rowen honeypot
- 246: Auto-ledger (free writes, paid reads)
- 247: Chrono Triggers (scheduled delivery)
- 249: Google Ads landing page optimization
- 251: demipass.com landing page
- 252: npm publish demipass package
- 253: HackerNews Show HN post
