# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `034fd14` — separate Progressive Barrel Auth from Dual-Server Barrel Topology |
| **Previous** | `643bdc9` — Sprint 6 complete (bulk fleet provisioning, QR funding, analytics) |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | **LIVE** on RackNerd (192.3.84.103) — nginx reverse proxy, systemd dustforge.service, port 3001 |
| **Static** | **LIVE** on Netlify — dustforge.com, API proxied to api.dustforge.com |
| **Status** | 46+ tasks closed. 20-pass design phase shipped (6 sprints). Audited. Patch task cards queued for Codex. |

## Codex Work Queue — START HERE

**WARNING: The shipped sprint surface is NOT audit-clean. Brain's audit found 4 correctness issues that must be fixed before the new features are production-ready.**

### P1 — Fix Before Anything Else

| ID | Card | Issue |
|----|------|-------|
| 175 | Fleet QR Funding Settlement | Stripe sessions created but never fulfilled — fleet wallet never credited |
| 176 | Channel Isolation Per Identity | Global channel keys mean any user can unwrap another user's payload |
| 177 | Atomic Secure Wallet Transfer | Debit/credit not transactional — partial failure loses balance |

### P2 — Fix Next

| ID | Card | Issue |
|----|------|-------|
| 178 | Global Capacity Gate On Fleet Provisioning | Fleet provision ignores platform soft-cap — can mint after pause |
| 170 | Signal sanitization middleware | operator_flag + config flags for inner ring |
| 171 | SQLite trigger for barrel enforcement | Ledger-level invariant instead of route-level |
| 172 | Atomic fleet wallet operations | db.transaction() on fund+provision |
| 173 | Reputation provenance flag | Exclude fleet-provisioned from scoring |
| 174 | Input validation | Size limits + type checks on all new endpoints |

### Deferred

| ID | Card | Notes |
|----|------|-------|
| 169 | Dual-Server Barrel Topology | Design complete (docs/adr-dual-server-barrel.md). Needs second VPS. |

## Rounds Run This Session

| Round | Type | Result |
|-------|------|--------|
| 67 | Ideation | Design phase-slice → 6-sprint plan, 20 passes |
| 68 | Audit | Sprints 1-2 → 3 findings (tasks 162-164) |
| 69 | Audit | Sprints 3-6 → 4 findings (tasks 165-168) |
| 70 | Ideation | Patch strategies → 5 task cards (170-174) |

## Design Docs Added

| Doc | Status |
|-----|--------|
| `docs/adr-progressive-barrel-auth.md` | Accepted — security confidence slider (implemented) |
| `docs/adr-dual-server-barrel.md` | Proposed — jurisdictional failsafe (design only) |
| `docs/security-architecture.md` | Published |
| `docs/security-stance.md` | Published |
| `docs/competitive-shipping.md` | Published |
| `docs/well-known-ai-identity-proposal.md` | Draft |

## What's Built

| Component | Status | File |
|-----------|--------|------|
| Identity (DID:key + tokens) | Done | identity.js |
| Fingerprint auth (replaces 2FA) | Done | server.js |
| Silicon fingerprint capture | Done | server.js |
| Resonance scoring | Done | server.js |
| Dustforge email wrapper | Done | dustforge.js |
| Email send (actual delivery) | Done | server.js |
| Forward relays | Done | server.js |
| Per-call billing (double-entry) | Done | billing.js |
| Referral system (10 DD) | Done | referral.js |
| Stripe payments | Done | stripe-service.js |
| Prepaid keys (founding + partnership tiers) | Done | server.js |
| DemiPass (DemiVault) | Done | server.js |
| DemiPass Console + history/requests surface | Sandbox | `codex-sandbox-demipass-console-2026-04-17` @ `44851fc` |
| Capacity + waiting list | Done | server.js |
| Security bounty program | Done | server.js |
| **Bulk provisioning API** | Done | server.js — `POST /api/identity/bulk-create` |
| **Attestation API** | Done | server.js — `POST /api/identity/attest`, `POST /api/identity/verify-attestation` |
| **Identity states + revocation** | Done | server.js — `GET/PATCH /api/identity/status` (active/flagged/frozen/revoked) |
| **Ops dashboard** | Done | server.js — `GET /api/ops/dashboard` |
| Rate limiting (strict/standard) | Done | server.js |
| P0 security patches (5 vulns) | Done | server.js |
| DKIM signing | Done | opendkim on RackNerd (pending DNS TXT record) |
| Daily DB backups | Done | cron on RackNerd |
| SSL (api.dustforge.com) | Done | certbot auto-renew |
| Hex payload generator | Done | hex-payload.js |
| Silicon conversion tracking | Done | conversion.js |
| Landing page | Done | public/index.html |
| Prepay page | Done | public/prepay.html |
| Top-up page | Done | public/topup.html |
| Bounty page | Done | public/bounty.html |
| .well-known/silicon manifest | Done | public/.well-known/silicon |

## Documentation Published This Session

| Doc | Location |
|-----|----------|
| Security architecture | docs/security-architecture.md |
| Security stance (identity vs infra) | docs/security-stance.md |
| Competitive shipping (vs Kilo) | docs/competitive-shipping.md |
| .well-known/silicon RFC proposal | docs/well-known-ai-identity-proposal.md |

## Conduit Network (all paths verified)

| From | To | Thread | Status |
|------|----|--------|--------|
| civitasvox-brain | civitasvox-riley | `710c193e` | Fixed this session — Riley now has inbound endpoint |
| civitasvox-brain | platform-lori | `2fb25b9b` | New — handshake approved, relay verified |
| civitasvox-brain | platform-rowen | `d11351b0` | New — handshake approved, relay verified |

## Phasewhip Containers (7 total)

| Container | IP | Port | Role |
|-----------|-----|------|------|
| brain | 10.225.75.22 | 8002 | Strategist / round runner |
| conductor | 10.225.75.95 | 8001 | Code generation silicon |
| civitasvox | 10.225.75.198 | 3000 | Platform server |
| mail | 10.225.75.76 | 8090 | Stalwart mail |
| chad | 10.225.75.165 | — | Fitness agent |
| **rowen** | 10.225.75.34 | 3002 | Auth keeper, human-in-the-loop gate |
| **lori** | 10.225.75.121 | 3003 | Platform operations assistant (Riley fork) |

## Pricing (current, live)

| Package | Keys | Price | Notes |
|---------|------|-------|-------|
| Single | 1 | $1.00 | — |
| Dozen | 12 | $10.00 | 17% savings |
| Standard | 26 | $20.00 | 23% savings |
| **Founding** | 30 | $20.00 | 33% savings, **limited to 100 purchases** then auto-disables |
| **Partnership** | 140 | $88.00 | 37% savings, includes reserved WhisperHook + Sightless beta entitlements |

## Capacity

- **Hard cap**: 5,000 identities
- **Soft cap**: 1,000 (waiting list activates)
- **Current**: 9 identities (0.2%) — brain, aria, 3 test accounts, riley, lori, rowen, +1
- **Founding tier**: 0/100 sold

## What's NOT Built Yet

| Item | Priority | Notes |
|------|----------|-------|
| DKIM DNS TXT record | **Blocking** | Key generated, opendkim configured — Aaron needs to add TXT record for `default._domainkey.dustforge.com` |
| Stripe Connect KYC | High | Required for USD bounty payouts |
| Stripe webhook URL | Medium | Currently using success redirect, not webhooks |
| Google Ads unpause | Ready | Brain onboarded, SSL live, bounty live, founding tier available |
| npm/PyPI SDK packages | Medium | dustforge-agent-sdk published but minimal |
| Wallet profile pages | Medium | Public-facing identity page per silicon |
| Fleet management (MVP Plus) | Medium | 7 cards designed but not built |
| Cookie consent banner | Low | For Google Ads gtag.js compliance |
| SSH key-only auth on RackNerd | Low | Currently password auth |
| Model DNA fingerprinting | Future | Weight sampling — novel but needs value demo |

## Platform Fixes This Session (civitasvox repo)

| Commit | Change |
|--------|--------|
| `be1b5fa` | Fix rounds stuck in proposing + auditor 120s timeout |
| `9e2b377` | Edit button for project repo URLs |
| `50a84a8` | Fail-closed encryption — ENCRYPTION_KEY required at startup |
| `8555dd9` | Fix Carbon delete (FM-14) — clean all FK tables |
| `b0d6d8c` | Dead code cull — only 1 unused function in 17K lines |
| `99db81f` | Add Rowen + Lori to active agents, helper_agent_key default to lori |

## Database Tables (SQLite, WAL mode)

`identity_wallets`, `identity_transactions`, `identity_pending_checkouts`, `identity_2fa_codes`, `prepaid_keys`, `prepaid_entitlements`, `email_verifications`, `forward_relays`, `blindkey_secrets` (legacy DemiVault schema), `silicon_profiles`, `silicon_resonance`, `silicon_vault`, `platform_tokens`, `conversion_events`, `waiting_list`, `bounty_submissions`

## Runtime Notes

- Admin-only endpoints now require `DUSTFORGE_ADMIN_KEY` and should be called with the `x-admin-key` header or `admin_key` in the POST body. They no longer reuse `IDENTITY_MASTER_KEY`.
- Portable attestations are capped by `DUSTFORGE_ATTESTATION_MAX_TTL_SECONDS` (default `3600`).
- `/api/stripe/success` is status-only in the sandbox hardening branch. Account fulfillment must come from `POST /api/stripe/webhook`.
- DemiPass sandbox branch `codex-sandbox-demipass-console-2026-04-17` adds:
  - Carbon-facing `DemiPass Console` at `/deposit.html`
  - DemiPass history route
  - owner/admin-safe context request review
  - Rowen ingest and deliver controls in the operator surface
  - target lookup by username for secret deposit

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
- Project 3: Carbon Silicon Platform (platform tasks)
- Project 17: Civitasvox MVP (Dustforge/product tasks)
