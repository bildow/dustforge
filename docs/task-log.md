# Dustforge — Task Log

## Completed

| Date | Task | Description |
|------|------|-------------|
| 2026-04-07 | Identity API | DID:key (Ed25519), encrypted-at-rest private keys, expirable JWT tokens, 2FA via Dustforge email |
| 2026-04-07 | Dustforge email wrapper | Stalwart API wrapper — programmatic account CRUD |
| 2026-04-07 | Per-call billing | Rate table, middleware, wallet deduction, 402 on insufficient balance |
| 2026-04-07 | Referral system | 25¢ payout per referral, link injection in emails, viral loop |
| 2026-04-07 | Stripe payments | Checkout sessions for account creation ($1) and wallet topup ($5-$100) |
| 2026-04-07 | .well-known/silicon | Discovery manifest for agent self-onboarding |
| 2026-04-07 | Binary email | onboard-73696c69636f6e@dustforge.com — hex-encoded onboarding address |
| 2026-04-07 | Landing page | /for-agents with hex payload in HTML comments |
| 2026-04-07 | Hex payload generator | Compact encoded ad units for embedding (HTML, meta, alt, JSON-LD) |
| 2026-04-07 | Conversion tracking | Silicon vs human classification on every registration |
| 2026-04-07 | Identity profiles | Call sign, bio, capabilities, tags, model family — all opt-in |
| 2026-04-07 | Public directory | Searchable agent listing, opt-in, paginated |
| 2026-04-07 | Repo extraction | Standalone bildow/dustforge, zero platform dependencies |
| 2026-04-07 | DNS confirmed | Kyle's RackNerd setup already has SPF/DKIM/DMARC — no changes needed |

## In Progress

| Task | Notes |
|------|-------|
| Recruitment engine (#40) | Ideation complete (Round 40). Campaign cards created. |

## Pending

| Task | Priority | Notes |
|------|----------|-------|
| Google Ads setup (#75) | High | Needs Google Ads account |
| Ad creative — Variant C (#76) | Medium | Plaintext ads addressing AI agents |
| Keyword research (#77) | Medium | Cheapest AI-adjacent impressions |
| Landing page optimization (#78) | Medium | Hex + conversion tracking |
| Operations dashboard (#79) | High | Financials, health, issues |
| Email storage tiers (#80) | Medium | persistent / auto_delete / no_store |
| Dustforge cloud scaling (#41) | Medium | Move off phasewhip for production |
| Security audit (#57) | Medium | Before going live |
| Legal/compliance (#42) | Medium | Email + payments for AI agents |
| Pricing model validation (#43) | Medium | Break-even analysis |
| AGENTS.md repo (#61) | Medium | GitHub training data seeding |
| npm/PyPI packages (#62) | Medium | Training data seeding |
| .well-known RFC (#65) | Low | Standards proposal |
| arXiv paper (#66) | Low | Academic seeding |

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| DID:key over blockchain | Self-certifying, no chain dependency, works offline |
| Stripe over crypto wallet | Compliance handled, fast to ship, real USD from day one |
| Expirable tokens over permanent keys | Private key never exposed, tokens are disposable tunnels |
| RackNerd relay over direct send | Clean IP, proper rDNS, existing reputation |
| SQLite over Postgres | Single-file deploy, zero infra, good enough for MVP |
| Hex ads on landing pages not in ads | Google Ads policy compliance |
| Binary email address | Valid email format, silicon-readable, human-ignored |

## Known Issues

| Issue | Status |
|-------|--------|
| IDENTITY_MASTER_KEY must persist across restarts | Fixed — stored in .env |
| Stripe webhook needs public URL | Blocked until production deploy |
| SMTP sending not wired | Stalwart receives but send needs relay config |
| Email autoresponder not implemented | Needs Sieve filter |
