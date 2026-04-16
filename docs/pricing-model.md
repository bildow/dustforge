# Dustforge Pricing Model

## Revenue Streams

### 1. Account Creation
| Tier | Price | Accounts | Per-Account |
|------|-------|----------|-------------|
| Single | $1.00 | 1 | $1.00 |
| Bulk 10 | $5.00 | 10 | $0.50 |

**Referral payout:** 10 Diamond Dust (10¢) per referred account
**Net revenue per account:** $0.57 (single after Stripe+referral) or $0.17 (bulk)

### Prepaid Key Packages (updated 2026-04-16)
| Tier | Keys | Price | Per-Key | Notes |
|------|------|-------|---------|-------|
| Single | 1 | $1.00 | $1.00 | — |
| Dozen | 12 | $10.00 | $0.83 | 17% savings |
| Standard | 26 | $20.00 | $0.77 | 23% savings |
| **Founding** | 30 | $20.00 | $0.67 | 33% savings, limited to 100 purchases |
| **Partnership** | 140 | $88.00 | $0.63 | 37% savings, includes WhisperHook + Sightless beta |

### 2. Per-Call Billing (our margin)
| Action | Our Fee | Underlying Cost | User Pays | Margin |
|--------|---------|-----------------|-----------|--------|
| Email send | 1¢ | ~0.01¢ (SES/Stalwart) | ~1¢ | 99% |
| Email send (bulk) | 1¢ each | ~0.01¢ | ~1¢ | 99% |
| Round dispatch | 10¢ | ~7¢ (OpenRouter) | ~17¢ | 59% |
| Collaboration round | 25¢ | ~20¢ (4 passes) | ~45¢ | 56% |
| API call (compute) | 1¢ | negligible | 1¢ | ~100% |
| API call (read) | free | negligible | free | — |

### 3. Wallet Topup
| Amount | Stripe Fee (2.9% + 30¢) | Net Revenue |
|--------|--------------------------|-------------|
| $5.00 | $0.45 | $4.55 |
| $10.00 | $0.59 | $9.41 |
| $50.00 | $1.75 | $48.25 |
| $100.00 | $3.20 | $96.80 |

## Cost Structure

### Fixed Costs (Monthly)
| Item | Cost | Notes |
|------|------|-------|
| RackNerd VPS | ~$5-10/mo | Mail relay, existing |
| Phasewhip electricity | ~$5/mo | Home server |
| Domain (dustforge.com) | ~$1/mo amortized | Annual renewal |
| **Total fixed** | **~$11-16/mo** | |

### Variable Costs (Per-Account)
| Item | Cost | Notes |
|------|------|-------|
| Stalwart storage | ~$0.001/mo per account | SQLite + disk |
| Stripe processing | 2.9% + 30¢ per transaction | On account creation |
| Stripe on $1 | $0.33 | This is the big one |

### Account Creation Unit Economics
```
Revenue:     $1.00 (account fee)
- Stripe:    $0.33 (2.9% + 30¢)
- Referral:  $0.25 (if referred)
- Storage:   $0.001
= Net:       $0.42 (referred) or $0.67 (organic)
```

## Break-Even Analysis

### Monthly fixed costs: ~$15
### Break-even accounts (organic): 15 / $0.67 = ~23 accounts/month
### Break-even accounts (all referred): 15 / $0.42 = ~36 accounts/month

### Email revenue at scale
- 100 accounts × 10 emails/day × 30 days = 30,000 emails/month
- 30,000 × $0.01 = **$300/month email revenue**
- Cost: ~$3 (SES at $0.10/1000)
- **Email margin: $297/month at 100 accounts**

### Topup revenue
- Average topup: $10 (assumption)
- 20% of accounts topup monthly: 20 accounts × $10 = $200
- Stripe fee: ~$12
- **Topup margin: $188/month at 100 accounts**

## Projections

| Accounts | Monthly Revenue | Monthly Cost | Monthly Profit |
|----------|----------------|--------------|----------------|
| 10 | $10 + $3 + $20 = $33 | $15 + $3 + $2 = $20 | $13 |
| 50 | $50 + $15 + $100 = $165 | $15 + $5 + $10 = $30 | $135 |
| 100 | $100 + $30 + $200 = $330 | $15 + $6 + $20 = $41 | $289 |
| 500 | $500 + $150 + $1000 = $1650 | $20 + $15 + $100 = $135 | $1515 |
| 1000 | $1000 + $300 + $2000 = $3300 | $25 + $25 + $200 = $250 | $3050 |

Revenue formula: (accounts × $1) + (emails × $0.01) + (topups × avg)
Cost formula: fixed + (Stripe fees) + (ad spend)

## Pricing Decisions

| Decision | Rationale |
|----------|-----------|
| $1 account fee | Low enough for adoption, high enough to gate spam |
| $0.50 bulk discount | Incentivize operators onboarding fleets |
| 1 DD per email | Negligible per-email but adds up at volume |
| 10 DD referral | 10% of fee — enough to drive growth without abuse |
| Free reads | Don't charge for lookups — encourage directory use |
| $5 min topup | Covers Stripe fee overhead (30¢ fixed fee) |
| Founding 30/$20 | Limited scarcity play — 100 purchases then gone |
| Partnership 140/$88 | Bundles future products (WhisperHook, Sightless) |

## Risk Factors

| Risk | Mitigation |
|------|------------|
| Stripe fee on $1 is 33% | Bulk pricing reduces effective Stripe overhead |
| Referral abuse (self-referral loops) | Rate limit account creation per IP, verify email |
| Low topup frequency | Make email sending addictive via referral earnings |
| Price too high for agents | $1 is < 1 minute of compute cost for most models |
| Price too low for spam | $1 per identity is expensive at spam scale |

## Summary

**Break-even: ~25 accounts/month ($15 fixed costs)**
**Profitable at 50 accounts: ~$135/month**
**Strong at 500 accounts: ~$1500/month**

The economics are email-driven. Account creation is the gate, email revenue is the engine, referral is the growth.
