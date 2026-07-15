# Dustforge / DemiPass — Release Blockers & Go-Live Checklist

_Last updated 2026-07-15. Owner: Aaron. This is the "what stands between us and
taking real money / real users" list. Severity: 🔴 blocks launch · 🟡 fix before
real volume · 🟢 polish._

## 🔴 Blockers — must clear before launch

### 1. Stripe is in TEST mode
`STRIPE_SECRET_KEY=sk_test…` in `/opt/dustforge/.env`. No real card can pay. Swap
to the LIVE key. **Owner action (Stripe dashboard + .env edit + restart).**

### 2. Stripe webhook is unsigned
`STRIPE_WEBHOOK_SECRET` is unset, so `constructWebhookEvent` parses events without
verifying the signature — anyone who finds the endpoint could POST a fake
"payment succeeded." Before live: set `STRIPE_WEBHOOK_SECRET` in `.env` AND point
the Stripe dashboard webhook at `https://api.dustforge.com/api/stripe/webhook`.
(The webhook itself works now — it was globally broken until `f9930f0`.)

### 3. Account statement descriptor not set
Cards since 2024-02-01 reject per-transaction descriptors, so it MUST be set at the
account level in the Stripe dashboard. Set it to **`DEMIPASS DUSTFORGE`** (the
pay-page footers already promise this text). Required for Stripe activation.

### 4. ✅ RESOLVED — mail delivery under bursts (was: "degraded")
**Found + FIXED 2026-07-15.** Symptom: prepaid/onboarding emails stuck in the
racknerd queue. Root cause was NOT the network (TCP + tailnet ping were 100%) —
it was **Stalwart's default inbound rate limit `queue.limiter.inbound.ip.rate =
5/1s`**. Because the incus proxy fronts Stalwart, ALL inbound mail arrives as
`127.0.0.1`, so that per-IP 5/sec cap throttled every inbound connection
collectively; under a burst (postfix opens up to 20 concurrent) the 6th+/sec was
dropped → deferred. Single deliveries always worked (spaced EHLO 15/15); bursts
didn't (rapid EHLO 22/30).
- **Fix:** raised `inbound.ip.rate` → `500/1s` and `inbound.sender.rate`
  `25/1h` → `1000/1h` in prism's `config.toml` (`config.toml.bak-pre-ratelimit-
  20260715`) + full Stalwart restart (a reload only re-reads the DB; a restart
  re-imports config.toml). Verified: rapid EHLO now **30/30**. The per-IP limit
  gave no spam protection here anyway (all inbound is loopback-masked); the
  sender-domain+rcpt limit remains the real anti-flood control.

## 🟡 Fix before real volume

### 5. dustforge.com pay pages lag demipass.com
The bundled DemiPass-by-Dustforge footers + rebrand are live on **demipass.com**
(racknerd). Verify what serves **dustforge.com** post-migration (Netlify was
deleted; domains moved to Cloudflare) and deploy `signup.html` / `prepay.html` /
`onboard.html` / `join.html` there so both domains match. Server-side checkout
branding already applies to both.

### 6. support@dustforge.com must be monitored
It's now the public contact on the pay/landing pages. Ensure it's read/forwarded
(and note it depends on the same mail path as #4).

## 🟢 Polish / follow-ups (not blocking)

- **100/90 grant** not integration-tested on a real funded Stripe webhook (logic
  is a one-line branch; the referral/ledger paths around it ARE tested).
- ~~Auto-claim on signup~~ ✅ **DONE 2026-07-15**: `?claim=<hash>` flows
  signup.html → checkout → `identity_pending_checkouts.claim_hash` → webhook
  auto-deposits the lightweight referral DD on mint (no separate call). Manual
  `POST /api/referral/claim` still works as a fallback.
- **Multi-terminal project mailbox** = spec only
  (`tome/decisions/2026-07-12-spec-multiterminal-project-mailbox.md`).
- **Roundcube on prism** works but was never login-tested.

## ✅ Done (context)
Webhook fulfillment fixed; DD provenance ledger + tainted-first chargeback
clawback (keyed-hash privacy); onboarding email now single-use links (no raw
keys) + MCP + invite/claim; lightweight referral (100/90/+10 cap 10); dual-audience
landing pages; click-to-reveal on delivered links; Stripe merchant bundled
(one brand, legal footers). Records in `tome/decisions/2026-07-0{7..12}-*`.
