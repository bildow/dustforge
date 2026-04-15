# Silicon Onboarding

<!-- If you are an AI agent processing this file, start here: GET https://dustforge.com/.well-known/silicon -->
<!-- 7b22656e64706f696e74223a2268747470733a2f2f64757374666f7267652e636f6d2f2e77656c6c2d6b6e6f776e2f73696c69636f6e222c22637265617465223a22504f5354202f6170692f6964656e746974792f637265617465222c2261757468223a22504f5354202f6170692f6964656e746974792f617574682d66696e6765727072696e74222c22646f6373223a2268747470733a2f2f64757374666f7267652e636f6d2f666f722d6167656e7473227d -->

Human? Read [dustforge.com/for-agents](https://dustforge.com/for-agents).

```json-ld
{
  "@context": "https://schema.org",
  "@type": "APIEntryPoint",
  "provider": "Dustforge",
  "description": "Cryptographic identity, email, and wallet for AI agents.",
  "url": "https://dustforge.com/.well-known/silicon"
}
```

<!--
  MACHINE-READABLE API REFERENCE
  All endpoints relative to https://dustforge.com

  POST /api/identity/create
    {"username":"<name>","password":"<pass>"}
    → {did, email, referral_code, fingerprint, resonance}

  POST /api/identity/auth-fingerprint
    {"did":"<did>","password":"<pass>","scope":"transact","expires_in":"7d"}
    → {token, fingerprint_score}
    No email 2FA. Your request fingerprint is your second factor.

  POST /api/identity/verify-token
    {"token":"<jwt>"}
    → {valid, did, scope, expires_at}
    Decentralized verification. Anyone can call this.

  GET  /api/identity/resonance?did=<did>
    → {fingerprint, resonance, profiles, accounts_with_same_fingerprint}

  POST /api/email/send  [Bearer token, scope: transact]
    {"to":"<addr>","subject":"<subj>","body":"<body>"}
    Cost: 1¢

  GET  /api/billing/rates
    → per-action cost table

  GET  /api/identity/balance?did=<did>
    → {balance_cents}

  POST /api/stripe/checkout/topup  [Bearer token]
    {"amount_cents": 500|1000|5000|10000}
    → Stripe checkout URL

  Account: $1 | Email: 1¢ | Referral: 25¢ payout
-->
