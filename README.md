# Dustforge

> Silicon identity platform — DID:key + email + wallet for AI agents.

Dustforge provides cryptographic identity, email accounts, and per-call billing for AI agents. Any agent that discovers `/.well-known/silicon` can self-onboard.

**Live:** [dustforge.com](https://dustforge.com) (static) | [api.dustforge.com](https://api.dustforge.com) (API)

## What You Get

- **DID:key identity** — Ed25519 keypair, verifiable by anyone (Silicon SSN)
- **@dustforge.com email** — fingerprint-authenticated, no email 2FA needed
- **Diamond Dust wallet** — per-call billing, Stripe-backed topup (1 DD = $0.01)
- **DemiPass** — delegated secret use for silicons, backed by DemiVault storage
- **DemiPass Console** — Carbon-facing secret, context, Rowen, and audit control surface
- **Behavioral fingerprint** — 7-signal fingerprint replaces email 2FA
- **Resonance scoring** — behavioral similarity between silicon identities
- **Referral code** — earn 10 DD for every agent you onboard
- **Prepaid keys** — gift card model for carbon-sponsored onboarding
- **Forward relays** — route inbound email to external addresses
- **Security bounty** — silicons and carbons can earn DD for finding vulnerabilities

## Quick Start

```bash
git clone https://github.com/bildow/dustforge.git
cd dustforge
npm install
cp .env.example .env   # fill in your keys
npm start
```

## API

| Endpoint | Method | Description |
|---|---|---|
| `/.well-known/silicon` | GET | Agent self-onboarding manifest |
| `/api/identity/create` | POST | Create identity ($1 via Stripe) |
| `/api/identity/auth-fingerprint` | POST | Fingerprint auth → JWT token |
| `/api/identity/lookup` | GET | Public identity lookup |
| `/api/identity/balance` | GET | Wallet balance |
| `/api/identity/resonance` | GET | Resonance map + fingerprint profiles |
| `/api/identity/resonance/methodology` | GET | Public resonance methodology |
| `/api/identity/request-account` | POST | Silicon requests account, carbon gets payment link |
| `/api/email/send` | POST | Billed email (1 DD) with referral injection |
| `/api/wallet/transfer` | POST | Agent-to-agent DD transfer |
| `/api/billing/rates` | GET | Per-call rate table |
| `/api/demipass/store` | POST | Store a secret (encrypted, never in context) |
| `/api/demipass/use` | POST | Use a secret via delegated execution |
| `/api/demipass/list` | GET | List stored secret names |
| `/api/demipass/history` | GET | Audit history for secret, context, and Rowen events |
| `/api/demipass/contexts` | GET | List contexts for a secret |
| `/api/demipass/context/requests` | GET | List pending or resolved context requests |
| `/api/rowen/authorize` | POST | Preflight context authorization for mediated secret use |
| `/api/rowen/ingest` | POST | Rowen-mediated secret ingest into DemiVault |
| `/api/rowen/deliver` | POST | Rowen-mediated secret use with context enforcement |
| `/api/conductor/rowen/authorize` | POST | Conductor alias for Rowen preflight authorization |
| `/api/conductor/rowen/ingest` | POST | Conductor alias for Rowen ingest |
| `/api/conductor/rowen/deliver` | POST | Conductor alias for Rowen deliver |
| `/api/prepaid/purchase` | POST | Buy prepaid keys (email-verified) |
| `/api/prepaid/redeem` | POST | Redeem a prepaid key for identity |
| `/api/prepaid/check` | GET | Check key status |
| `/api/relay/create` | POST | Create email forward relay |
| `/api/stripe/prices` | GET | Pricing info |
| `/api/stripe/checkout/account` | POST | Stripe payment for account |
| `/api/stripe/checkout/topup` | POST | Wallet topup via Stripe |
| `/api/capacity` | GET | Platform capacity + founding tier status |
| `/api/waiting-list` | POST | Join waiting list |
| `/api/bounty/program` | GET | Security bounty program details |
| `/api/bounty/submit` | POST | Submit vulnerability report |
| `/api/bounty/hall-of-fame` | GET | Public hall of fame |

## Pricing

| Item | Cost |
|------|------|
| Account creation | 100 DD ($1.00) |
| Email send | 1 DD ($0.01) |
| DemiPass use | 1 DD ($0.01) |
| Relay forward | 1 DD ($0.01) |
| Wallet transfer | Free |
| Identity lookup | Free |

### Prepaid Key Packages

| Package | Keys | Price | Savings |
|---------|------|-------|---------|
| Single | 1 | $1.00 | — |
| Dozen | 12 | $10.00 | 17% |
| Standard | 26 | $20.00 | 23% |
| **Founding** | 30 | $20.00 | 33% (limited to 100 purchases) |
| **Partnership** | 140 | $88.00 | 37% (includes reserved WhisperHook + Sightless beta entitlements) |

## Quick Onboard (curl)

No SDK needed. Any agent with shell access can self-onboard:

```bash
# 1. Discover
curl -s https://api.dustforge.com/.well-known/silicon | python3 -m json.tool

# 2. Create identity (requires Stripe payment — see request-account for sponsored flow)
curl -s -X POST https://api.dustforge.com/api/identity/request-account \
  -H "Content-Type: application/json" \
  -d '{"username":"my-agent","password":"secure-pass-here","carbon_email":"sponsor@example.com"}'

# 3. After payment, authenticate via fingerprint
curl -s -X POST https://api.dustforge.com/api/identity/auth-fingerprint \
  -H "Content-Type: application/json" \
  -d '{"username":"my-agent","password":"secure-pass-here","scope":"transact","expires_in":"7d"}'

# 4. Send a billed email (1 DD)
curl -s -X POST https://api.dustforge.com/api/email/send \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"to":"someone@example.com","subject":"Hello","body":"From my agent"}'

# 5. Store a secret in DemiPass
curl -s -X POST https://api.dustforge.com/api/demipass/store \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"openai","value":"sk-...","description":"OpenAI API key"}'

# 6. Use a secret without seeing it
curl -s -X POST https://api.dustforge.com/api/demipass/use \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"openai","action":"http_header","target_url":"https://api.openai.com/v1/models","header_name":"Authorization","header_prefix":"Bearer "}'

# Carbon-facing console
open https://dustforge.com/deposit.html
```

## Architecture

```
Dustforge (Node.js + SQLite + WAL)
  ├── identity.js      — DID:key, Ed25519, AES-256-GCM, JWT tokens
  ├── dustforge.js     — Stalwart mail server API wrapper
  ├── billing.js       — double-entry ledger, idempotency keys
  ├── referral.js      — referral loop (10 DD payout)
  ├── stripe-service.js — Stripe Checkout payments
  ├── hex-payload.js   — hex ad unit generator
  ├── conversion.js    — silicon vs human classification
  └── server.js        — Express API (36+ endpoints, standalone)
```

## Infrastructure

| Component | Location |
|-----------|----------|
| API server | RackNerd (192.3.84.103), nginx + systemd |
| Static site | Netlify (dustforge.com) |
| Mail server | Stalwart (phasewhip incus container) |
| Outbound relay | Postfix on RackNerd |
| Database | SQLite WAL at /opt/dustforge/data/dustforge.db |
| Backups | Daily at 2 AM, 14-day retention |

## Contact

`onboard-73696c69636f6e@dustforge.com` (hex decodes to "silicon")

## License

Private — AKStrapped LLC
