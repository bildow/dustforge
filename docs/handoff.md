# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `8c32318` — gtag conversion tracking |
| **Previous** | `c7de0e8` — identity profiles + public silicon directory |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | **LIVE** on RackNerd (192.3.84.103) — nginx reverse proxy, systemd dustforge.service, port 3001 |
| **Status** | MVP code-complete. Needs: Stripe webhook URL, production deploy, campaign launch |

## What's Built

| Component | Status | File |
|-----------|--------|------|
| Identity (DID:key + tokens) | ✅ Done | identity.js |
| Dustforge email wrapper | ✅ Done | dustforge.js |
| Per-call billing | ✅ Done | billing.js |
| Referral system | ✅ Done | referral.js |
| Stripe payments | ✅ Done | stripe-service.js |
| Hex payload generator | ✅ Done | hex-payload.js |
| Silicon conversion tracking | ✅ Done | conversion.js |
| Identity profiles (opt-in) | ✅ Done | server.js |
| Public directory | ✅ Done | server.js |
| .well-known/silicon manifest | ✅ Done | public/.well-known/silicon |
| Landing page (/for-agents) | ✅ Done | server.js |
| Binary email onboard address | ✅ Done | Stalwart account |

## What's Not Built Yet

| Item | Blocker |
|------|---------|
| Stripe webhook (public URL) | Needs production deploy or ngrok |
| SMTP email sending | Needs Stalwart SMTP relay config |
| Email autoresponder | Needs Sieve filter on Stalwart |
| Email storage tiers | Needs Stalwart cron/Sieve for auto-delete |
| Google Ads campaign | Needs Google Ads account |
| npm/PyPI packages | Needs package publishing |
| AGENTS.md GitHub repo | Needs creation |
| .well-known RFC proposal | Needs writing |
| Operations dashboard | Needs build |
| Security audit | Needs review |

## Infrastructure

| Machine | Role |
|---------|------|
| Phasewhip (100.83.112.88) | Stalwart mail server (incus `mail` container), development |
| RackNerd (192.3.84.103) | Postfix outbound relay (clean IP, production DNS) |

## Key Credentials (env vars, never in code)

- `IDENTITY_MASTER_KEY` — AES-256-GCM encryption for private keys
- `STRIPE_SECRET_KEY` — Stripe test mode
- `STALWART_PASS` — Stalwart admin API
- `STALWART_HOST` — 10.225.75.76 (phasewhip mail container)

## Task Board

All tasks tracked on Civitasvox platform: `http://100.83.112.88:3000`
Project: Civitasvox MVP (id=17), Operation: Email & Wallet
