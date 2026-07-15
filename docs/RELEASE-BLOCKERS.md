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

### 4. 🔴→🟡 Mail delivery is DEGRADED — prepaid keys deliver unreliably
**Found 2026-07-15.** Prepaid purchases email the buyer their onboarding links.
Delivery WORKS but is intermittent: Stalwart on the `prism` container
intermittently drops the inbound SMTP connection at EHLO (measured **~3/10
connections fail** in back-to-back probes). Effect: `@dustforge.com` mail
(including key delivery) queues on racknerd and only drains when Stalwart hits a
good window; postfix retries, so mail eventually arrives but can sit stuck for
minutes+. Two test emails were stuck until a postfix restart + a good window.
- **NOT a Stalwart resource issue** — 171 MB / 32 GB used, up 7 days, no app
  errors.
- **Likely cause:** connection drops on the racknerd→phasewhip (Tailscale) path —
  same signature as the 2026-07-11 TP-Link Archer C7 DoS-filter incident
  ([[incident-phasewhip-tplink-dos-block-20260711]]). "Connection unexpectedly
  closed" ≈ a firewall/DoS filter killing ~30% of connections.
- **Next step:** diagnose the racknerd→phasewhip path (router DoS/SPI filter,
  tailnet health) and/or add resilience (postfix retry tuning, or a fallback
  submission path). A launch that emails keys can't rely on a 70%-first-try relay.

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
- **Auto-claim on signup** not wired — a sponsor collects lightweight referral DD
  via the authed `POST /api/referral/claim` after minting, rather than the deposit
  happening automatically during signup. Wiring the claim hash through Stripe
  checkout metadata would make it one-step. (See onboarding decision record.)
- **Multi-terminal project mailbox** = spec only
  (`tome/decisions/2026-07-12-spec-multiterminal-project-mailbox.md`).
- **Roundcube on prism** works but was never login-tested.

## ✅ Done (context)
Webhook fulfillment fixed; DD provenance ledger + tainted-first chargeback
clawback (keyed-hash privacy); onboarding email now single-use links (no raw
keys) + MCP + invite/claim; lightweight referral (100/90/+10 cap 10); dual-audience
landing pages; click-to-reveal on delivered links; Stripe merchant bundled
(one brand, legal footers). Records in `tome/decisions/2026-07-0{7..12}-*`.
