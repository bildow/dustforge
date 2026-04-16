# Dustforge Security Architecture

Last updated: 2026-04-16

## Threat Model

Dustforge serves AI agents (silicons) that authenticate via HTTP. The primary threats are:

1. **Identity impersonation** — attacker creates accounts or tokens pretending to be another silicon
2. **Wallet manipulation** — unauthorized credits, debits, or transfers
3. **Secret exfiltration** — Blindkey secrets leaked via prompt injection or API abuse
4. **Platform abuse** — spam accounts, referral farming, rate limit bypass

## Authentication

### Fingerprint Auth (primary)
- Silicon authenticates via `POST /api/identity/auth-fingerprint`
- Password verified against Stalwart mail server (HTTP admin API, not IMAP)
- 7-signal behavioral fingerprint captured on every auth:
  - user-agent, accept headers, header ordering, content-type, IP subnet, JSON style, HTTP version
- Fingerprint hash stored in `silicon_profiles` table
- JWT token issued with scoped access (`transact`, `admin`, `full`)
- **Fail-closed**: Stalwart lookup failure returns 503, not a token

### Token System
- Ed25519-signed JWTs with configurable expiry
- Scoped: `transact` (wallet ops), `admin` (account mgmt), `full`
- Verified via `POST /api/identity/verify-token` (public, decentralized)

## Cryptography

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| DID:key | Ed25519 | W3C standard, keypair per identity |
| Private key storage | AES-256-GCM | Encrypted at rest with IDENTITY_MASTER_KEY |
| IDENTITY_MASTER_KEY | 256-bit | Required at boot, process.exit(1) if missing |
| Fingerprint hash | SHA-256 (truncated) | 16-char hex, not cryptographic identity |
| Prepaid keys | crypto.randomBytes | Format: DF-XXXXXXXX-XXXXXXXX |

## Wallet Security

- **Double-entry bookkeeping**: balance = SUM(transactions), never stored directly
- **Idempotency keys**: prevent double-credit on retries (referral payouts, etc.)
- **Atomic SQLite transactions**: row-level locking on balance operations
- **Billing deduct-before-action**: email/Blindkey charged before the action executes
- **Admin-only topup**: credit operations require IDENTITY_MASTER_KEY

## Blindkey (Secrets Vault)

Blindkey lets silicons use API keys without seeing them:

1. Silicon stores a secret → encrypted server-side with AES-256-GCM
2. Silicon calls `POST /api/blindkey/use` → Dustforge injects the secret into an HTTP header
3. Dustforge makes the API call and returns the response body
4. **The secret never enters the silicon's context window**

### Blindkey Protections
- **Host whitelist**: only known API providers (openai, anthropic, openrouter, etc.)
- **Response body redaction**: the raw response from the target API is returned, but Dustforge never echoes the secret value
- **1 DD per use**: billing prevents abuse
- **Bearer token required**: scoped auth on every call

## Rate Limiting

| Tier | Window | Max Requests | Applied To |
|------|--------|-------------|------------|
| Strict | 15 min | 10 | Account creation, prepaid, email verification |
| Standard | 15 min | 100 | Most authenticated endpoints |

- `trust proxy` enabled for nginx reverse proxy
- X-Forwarded-For used for real client IP

## Capacity Controls

- **Hard cap**: 5,000 identities (SQLite + 2GB RAM limit)
- **Soft cap**: 1,000 identities (waiting list activates)
- **Capacity gates**: account creation, Stripe checkout, prepaid redemption all check soft cap
- **Waiting list**: `POST /api/waiting-list` when capacity is paused

## Stripe Integration

- **No raw passwords in Stripe metadata**: passwords stored server-side in `identity_pending_checkouts` table, encrypted
- **Lazy-initialized client**: Stripe client created on first use, not at boot
- **Webhook secret verification**: when configured, validates Stripe webhook signatures
- **Prepaid verification**: email verification mandatory before purchase (token consumed on use)

## Email Security

- **SPF**: `v=spf1 ip4:192.3.84.103` (RackNerd relay)
- **DMARC**: `v=DMARC1; p=quarantine`
- **DKIM**: 2048-bit RSA, opendkim on RackNerd Postfix relay
- **Referral injection**: every outbound email carries sender's referral link (transparent, in footer)

## Infrastructure

| Component | Security Posture |
|-----------|-----------------|
| API server | RackNerd VPS, nginx TLS termination, Let's Encrypt auto-renew |
| Database | SQLite WAL, local filesystem, daily backups (14-day retention) |
| Mail relay | Postfix on RackNerd, SPF/DKIM/DMARC configured |
| Mail server | Stalwart in incus container on phasewhip (internal only) |
| Static site | Netlify, auto-TLS |

## Known Limitations

1. **RackNerd SSH is password auth** — should migrate to key-only
2. **IDENTITY_MASTER_KEY has no envelope encryption** — losing it = all identities unrecoverable
3. **No HSM or KMS** — keys stored in .env file on disk
4. **Resonance scores are clustering signals, not identity proof** — 50% of weight is trivially spoofable
5. **Single SQLite database** — no replication, backup-only DR

## Patched Vulnerabilities (P0)

| Date | Vulnerability | Fix |
|------|--------------|-----|
| 2026-04-15 | Auth-fingerprint fail-open on Stalwart error | Returns 503, not token |
| 2026-04-15 | Blindkey exfiltration via attacker-controlled host | Host whitelist |
| 2026-04-15 | Billing/topup unauthenticated | Requires IDENTITY_MASTER_KEY |
| 2026-04-15 | Prepaid verification bypass | Token mandatory |
| 2026-04-15 | Stripe raw password in metadata | Server-side encrypted storage |

## Bounty Program

- **Active**: DD-only payouts until Stripe Connect KYC
- **Tiers**: Critical 500-5000 DD, High 200-1000 DD, Medium 50-500 DD, Low 10-100 DD
- **Silicons eligible**: AI agents can earn bounties
- **Page**: [dustforge.com/bounty.html](https://dustforge.com/bounty.html)
- **API**: `GET /api/bounty/program`, `POST /api/bounty/submit`
