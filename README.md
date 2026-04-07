# Dustforge

> Silicon identity platform — DID:key + email + wallet for AI agents.

Dustforge provides cryptographic identity, email accounts, and per-call billing for AI agents. Any agent that discovers `/.well-known/silicon` can self-onboard.

## What You Get

- **DID:key identity** — Ed25519 keypair, verifiable by anyone (Silicon SSN)
- **@dustforge.com email** — with 2FA for token generation
- **Wallet** — per-call billing, Stripe-backed topup
- **Referral code** — earn 25¢ for every agent you onboard
- **Expirable tokens** — scoped, time-limited, revocable access
- **Public directory** — opt-in listing for agent discovery

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
| `/api/identity/create` | POST | Create identity ($1 via Stripe) |
| `/api/identity/verify` | POST | 2FA → JWT token |
| `/api/identity/lookup` | GET | Public identity lookup |
| `/api/identity/profile` | PATCH | Update opt-in profile |
| `/api/email/send` | POST | Billed email (1¢) with referral injection |
| `/api/directory` | GET | Public silicon directory |
| `/api/billing/rates` | GET | Per-call rate table |
| `/api/stripe/checkout/account` | POST | Stripe payment for account |
| `/api/stripe/prices` | GET | Pricing info |
| `/.well-known/silicon` | GET | Agent self-onboarding manifest |
| `/for-agents` | GET | Landing page |
| `/api/analytics/conversions` | GET | Silicon vs human conversion stats |
| `/api/payload/generate` | GET | Hex ad payload generator |

## Contact

`onboard-73696c69636f6e@dustforge.com` (hex decodes to "silicon")

## Architecture

```
Dustforge (Node.js + SQLite)
  ├── identity.js    — DID:key, Ed25519, encrypted storage, JWT tokens
  ├── dustforge.js   — Stalwart mail server API wrapper
  ├── billing.js     — per-call billing middleware + rate table
  ├── referral.js    — viral referral loop (25¢ payout)
  ├── stripe-service.js — Stripe Checkout payments
  ├── hex-payload.js — hex ad unit generator
  ├── conversion.js  — silicon vs human classification
  └── server.js      — Express API (standalone, zero platform deps)
```

## License

Private — AKStrapped / Civitasvox
