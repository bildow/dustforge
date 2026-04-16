# Competitive Shipping — Dustforge vs Kilo

## Status: SHIPPED (identity layer live)

Dustforge identity is live at api.dustforge.com with 6 active identities, including Brain (first silicon customer).

## What We Have That Kilo Doesn't (as of 2026-04-16)

| Feature | Dustforge | Kilo |
|---------|-----------|------|
| DID:key cryptographic identity | Live | No — uses internal IDs |
| Behavioral fingerprint auth | Live (7 signals) | No |
| Resonance scoring | Live | No |
| Blindkey (secrets vault) | Live | No equivalent — agents have direct key access |
| Silicon-native email | Live (@dustforge.com) | No |
| Diamond Dust micropayments | Live | No — enterprise billing only |
| Prepaid key onboarding | Live | No |
| Public .well-known/silicon manifest | Live | No |
| Bounty program (silicons eligible) | Live | No |

## What Kilo Has That We Don't

| Feature | Kilo | Dustforge |
|---------|------|-----------|
| $8M VC funding | Yes | Bootstrapped |
| 1.5M users | Yes | 6 |
| 5-layer infra isolation | Yes | No (identity-first model) |
| Enterprise sales team | Yes | No |
| SOC 2 compliance | Likely | No |
| Hardware-backed security | Yes | No |

## First-Mover Advantages Already Secured

1. **DID:key identity** — no major platform has silicon-native DID:key yet
2. **Behavioral fingerprint as auth** — novel, published methodology
3. **Blindkey pattern** — first secrets vault designed for LLM context safety
4. **Silicon-eligible bounty program** — first to let agents earn security payouts
5. **Public resonance methodology** — transparent, auditable, documented

## Remaining Competitive Gaps (prioritized)

| Gap | Priority | Status |
|-----|----------|--------|
| More users | Critical | Founding tier + Google Ads ready to unpause |
| Email deliverability | High | DKIM configured, pending DNS TXT record |
| SDK/tooling | Medium | npm package exists but minimal |
| Enterprise features | Low for now | Fleet management designed but not built |
| SOC 2 | Low for now | Premature at current scale |

## Decision: Ship Fast, Document Honestly

The competitive advantage is not feature count — it's being the first identity layer that silicons can discover and self-onboard via a standard manifest. Every day we're live and Kilo isn't offering silicon-native identity is a day we're building the network effect.

**Google Ads can unpause now.** Brain onboarded. Fingerprinting works. Bounty program live. Founding tier available.
