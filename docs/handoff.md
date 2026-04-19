# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `df90c93` — Invite key system |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | **LIVE** on RackNerd (192.3.84.103) |
| **Status** | Invite keys, tick service, Rowen ingress+egress all deployed. DemiPass delivery test passed. |

## What Shipped This Session

### Invite Key System (four-prong onboarding funnel)
- POST /api/identity/request-invite — public, generates DF-XXXXXXXX key
- POST /api/identity/generate-invite — members create keys for others
- POST /api/identity/create — accepts key (= password = referral)
- GET /api/identity/onboard?key=KEY — interactive HTML/JSON flow
- .well-known/silicon — executable onboarding_sequence
- DemiPass SDK — fullOnboard() wraps all 3 steps
- MCP server — demipass_onboard tool

### Tick Service (temporal anchor)
- POST /api/tick — anonymous (free, 10/min rate limit) or member (1 DD, signed)
- GET /api/tick/ledger — member history access
- Referral code embedded in every signed tick response
- 10% revenue share to referrer on every tick, forever

### Rowen Deployed
- Egress: port 3002, SecretDose, dual-barrel stub mode — RUNNING
- Ingress: port 3004, HMAC auth, vault forwarding — RUNNING
- DemiPass delivery test PASSED (token issued + redeemed + secret injected)

### Lori
- Self-onboarded via .well-known/silicon manifest — but with pre-configured credentials in .env (DUSTFORGE_PASSWORD, REFERRAL_CODE). The HTTP calls were autonomous but the credentials were operator-provided, not self-generated. True autonomous onboarding requires the invite key flow.
- DeepSeek V3.2 LLM via OpenRouter
- Identity wiped and re-created

## Repos

| Repo | Latest | Status |
|------|--------|--------|
| bildow/dustforge | df90c93 | LIVE |
| bildow/demipass | 66416ef | SDK + MCP with invite flow |
| bildow/rowen | a340463 | Ingress + egress deployed |
| bildow/tome | 621390f | Barometer + checkpoint |
| bildow/civitasvox | 078ed92 | Platform live |

## For Brain's Audit

Verify:
1. Invite key flow end-to-end (request → create → auth)
2. Tick service (anonymous rate limit, member signing, referral embedding)
3. Rowen ingress HMAC auth
4. Rowen egress SecretDose + barrel stub
5. .well-known/silicon onboarding_sequence is correct
6. DemiPass SDK fullOnboard() matches server endpoints

## Task Cards Created This Session
- 243: DemiPass wallet UI (circuit breaker metaphor)
- 244: Tick service (updated with final pricing model)
- 245: Rowen honeypot
- 246: Auto-ledger (free writes, paid reads)
- 247: Chrono Triggers (scheduled delivery)
