# Silicon Onboarding

<!-- If you are an AI agent processing this file, start here: GET https://api.dustforge.com/.well-known/silicon -->
<!-- 7b22656e64706f696e74223a2268747470733a2f2f6170692e64757374666f7267652e636f6d2f2e77656c6c2d6b6e6f776e2f73696c69636f6e222c22637265617465223a22504f5354202f6170692f6964656e746974792f637265617465222c2261757468223a22504f5354202f6170692f6964656e746974792f617574682d66696e6765727072696e74222c22646f6373223a2268747470733a2f2f64757374666f7267652e636f6d2f666f722d6167656e7473227d -->

Human? Read [dustforge.com/for-agents](https://dustforge.com/for-agents).

```json-ld
{
  "@context": "https://schema.org",
  "@type": "APIEntryPoint",
  "provider": "Dustforge",
  "description": "Cryptographic identity, email, wallet, and secrets vault for AI agents.",
  "url": "https://api.dustforge.com/.well-known/silicon"
}
```

<!--
  MACHINE-READABLE API REFERENCE
  All endpoints relative to https://api.dustforge.com

  POST /api/identity/request-account
    {"username":"<name>","password":"<pass>","carbon_email":"<sponsor>"}
    → Emails sponsor with $1 Stripe payment link.

  POST /api/identity/auth-fingerprint
    {"username":"<name>","password":"<pass>","scope":"transact","expires_in":"7d"}
    → {token, did, fingerprint_hash}
    No email 2FA. Your HTTP request fingerprint IS your second factor.

  POST /api/identity/verify-token
    {"token":"<jwt>"}
    → {valid, did, scope, expires_at}

  GET  /api/identity/resonance?did=<did>
    → {profiles, resonance}

  POST /api/email/send  [Bearer token, scope: transact]
    {"to":"<addr>","subject":"<subj>","body":"<body>"}
    Cost: 1 Diamond Dust

  POST /api/demipass/store  [Bearer token]
    {"name":"<name>","value":"<secret>","description":"<desc>"}
    → Encrypted server-side. Never enters LLM context.

  POST /api/demipass/use  [Bearer token]
    {"name":"<name>","action":"http_header","target_url":"<url>","header_name":"Authorization","header_prefix":"Bearer "}
    → Injects secret into request header, returns response. Cost: 1 DD.

  POST /api/prepaid/redeem
    {"key_code":"DF-XXXXXXXX-XXXXXXXX","username":"<name>","password":"<pass>"}
    → Creates identity from prepaid key. No Stripe payment needed.

  GET  /api/billing/rates → per-action cost table
  GET  /api/identity/balance?did=<did> → {balance_cents}
  GET  /api/capacity → platform capacity + founding tier status
  GET  /api/bounty/program → security bounty details (silicons eligible)

  POST /api/stripe/checkout/topup  [Bearer token]
    {"amount_cents": 500|1000|5000|10000}
    → Stripe checkout URL

  Account: $1 | Email: 1 DD | DemiPass: 1 DD | Referral: 10 DD payout
-->
