# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `6dcb821` — founding tier pricing, capacity planning, bounty program |
| **Previous** | `9789df6` — fingerprint capture fix in auth-fingerprint |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | **LIVE** on RackNerd (192.3.84.103) — nginx reverse proxy, systemd dustforge.service, port 3001 |
| **Static** | **LIVE** on Netlify — dustforge.com, API proxied to api.dustforge.com |
| **Status** | All 3 Cards (Brain audit, capacity, bounty) shipped. 6 identities, 0.1% capacity. |

## What's Built

| Component | Status | File |
|-----------|--------|------|
| Identity (DID:key + tokens) | Done | identity.js |
| Fingerprint auth (replaces 2FA) | Done | server.js |
| Silicon fingerprint capture | Done | server.js (auth-fingerprint handler) |
| Resonance scoring | Done | server.js |
| Dustforge email wrapper | Done | dustforge.js |
| Email send (actual delivery) | Done | server.js |
| Forward relays | Done | server.js |
| Per-call billing (double-entry) | Done | billing.js |
| Referral system (10 DD) | Done | referral.js |
| Stripe payments | Done | stripe-service.js |
| Prepaid keys (gift card model) | Done | server.js |
| Blindkey (secrets vault) | Done | server.js |
| Hex payload generator | Done | hex-payload.js |
| Silicon conversion tracking | Done | conversion.js |
| Landing page | Done | public/index.html |
| Prepay page (founding + partnership tiers) | Done | public/prepay.html |
| Top-up page | Done | public/topup.html |
| Bounty page (submit + hall of fame) | Done | public/bounty.html |
| .well-known/silicon manifest | Done | public/.well-known/silicon |
| Capacity endpoint | Done | server.js |
| Waiting list | Done | server.js |
| Security bounty program | Done | server.js |
| Rate limiting (strict/standard) | Done | server.js |
| P0 security patches (5 vulns) | Done | server.js |
| Daily DB backups | Done | cron on RackNerd |
| SSL (api.dustforge.com) | Done | certbot auto-renew |

## Pricing (current, live)

| Package | Keys | Price | Notes |
|---------|------|-------|-------|
| Single | 1 | $1.00 | — |
| Dozen | 12 | $10.00 | 17% savings |
| Standard | 26 | $20.00 | 23% savings |
| **Founding** | 30 | $20.00 | 33% savings, **limited to 100 purchases** then auto-disables |
| **Partnership** | 140 | $88.00 | 37% savings, includes WhisperHook + Sightless beta keys (May 2026) |

## Capacity

- **Hard cap**: 5,000 identities (SQLite + 2GB RAM)
- **Soft cap**: 1,000 identities (waiting list activates)
- **Current**: 6 identities (0.1%)
- **Founding tier**: 0/100 sold
- **Endpoint**: `GET /api/capacity`

## Bounty Program

- **Status**: Active, DD-only payouts (USD pending Stripe Connect KYC)
- **Tiers**: Critical $5-$50, High $2-$10, Medium $0.50-$5, Low $0.10-$1
- **Silicons eligible**: Yes
- **Submissions**: `/api/bounty/submit` → email to aaronlsr42@gmail.com
- **Hall of fame**: `/api/bounty/hall-of-fame`
- **Page**: `/bounty.html`

## Infrastructure

| Machine | Role |
|---------|------|
| RackNerd (192.3.84.103) | API server (port 3001), nginx (80/443), Postfix relay, SQLite DB |
| Netlify | Static site (dustforge.com), proxies /api/* to api.dustforge.com |
| Phasewhip (100.83.112.88) | Stalwart mail server (incus `mail` container), platform |

## Key Credentials (env vars on RackNerd at /opt/dustforge/.env)

- `IDENTITY_MASTER_KEY` — AES-256-GCM encryption for private keys
- `STRIPE_SECRET_KEY` — Stripe payments
- `STRIPE_WEBHOOK_SECRET` — Stripe webhook verification
- `STALWART_PASS` — Stalwart admin API
- `STALWART_HOST` — mail container IP
- `STALWART_PORT` — 8090
- `SMTP_HOST` / `SMTP_PORT` — outbound relay via RackNerd Postfix

## What's NOT Built Yet

| Item | Priority | Notes |
|------|----------|-------|
| Stripe Connect KYC | High | Required for USD bounty payouts |
| SPF/DKIM DNS records | High | Email deliverability — needs TXT records on dustforge.com |
| Stripe webhook URL | Medium | Currently using success redirect, not webhooks |
| npm/PyPI SDK packages | Medium | dustforge-agent-sdk published but minimal |
| Cookie consent banner | Low | For Google Ads gtag.js compliance |
| Data inventory document | Low | Formal PII inventory for CCPA |
| Data breach notification plan | Low | Incident response procedure |
| SSH key-only auth on RackNerd | Low | Currently password auth |
| A2P 10DLC registration | Blocked | SignalWire/TCR — for Chad SMS, not Dustforge |
| Model DNA fingerprinting | Future | Weight sampling for HuggingFace/external models — novel but needs value demo first |

## Database Tables (SQLite, WAL mode)

`identity_wallets`, `identity_transactions`, `identity_pending_checkouts`, `identity_2fa_codes`, `prepaid_keys`, `email_verifications`, `forward_relays`, `blindkey_secrets`, `silicon_profiles`, `silicon_resonance`, `silicon_vault`, `platform_tokens`, `conversion_events`, `waiting_list`, `bounty_submissions`

## Deploy Process

```bash
# From flimflam machine:
printf '#!/bin/sh\necho zl46bv522BVYvX1HAk\n' > /tmp/rn.sh && chmod +x /tmp/rn.sh
SSH_ASKPASS=/tmp/rn.sh DISPLAY=dummy setsid scp -o StrictHostKeyChecking=no server.js root@192.3.84.103:/opt/dustforge/
SSH_ASKPASS=/tmp/rn.sh DISPLAY=dummy setsid scp -o StrictHostKeyChecking=no public/*.html root@192.3.84.103:/opt/dustforge/public/
SSH_ASKPASS=/tmp/rn.sh DISPLAY=dummy setsid ssh -o StrictHostKeyChecking=no root@192.3.84.103 'systemctl restart dustforge'
```

## Task Board

All tasks tracked on Civitasvox platform: `http://100.83.112.88:3000`
