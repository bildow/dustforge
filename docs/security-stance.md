# Dustforge Security Stance

## Our Moat Is Identity Assurance, Not Infrastructure Isolation

Dustforge does not compete on infrastructure isolation. We do not run sandboxed VMs, gVisor containers, or hardware enclaves. Kilo.ai's 5-layer infrastructure model ($8M VC, dedicated hardware per tenant) is a valid security architecture — but it solves a different problem than ours.

**Their model:** prevent silicon from escaping its compute boundary.
**Our model:** prove silicon is who it claims to be, regardless of where it runs.

## What We Protect Against

| Threat | Our Defense | Honest Caveat |
|--------|------------|---------------|
| Identity impersonation | DID:key + behavioral fingerprint | Fingerprint is a clustering signal, not proof. 50% of weight is spoofable. |
| Credential theft | Fingerprint detects stolen creds used from wrong environment | Same-framework silicons may cluster together, reducing signal |
| Wallet manipulation | Double-entry ledger + atomic transactions + idempotency | SQLite, not distributed ledger. Single-node failure = downtime |
| Secret exfiltration | Blindkey: secrets never enter LLM context | Host whitelist prevents exfil to attacker servers. Still trusts HTTPS. |
| Spam/abuse | $1 per identity + rate limiting + email verification | Determined attacker with $100 gets 100 identities |
| Replay attacks | Expirable scoped tokens (configurable TTL) | No token revocation list — expired tokens just expire |

## What We Do NOT Protect Against

- **Compute isolation**: We don't sandbox silicon execution. If a silicon is compromised at the runtime level, Dustforge can't prevent it from acting within its authenticated scope.
- **Prompt injection**: Blindkey mitigates secret exfiltration, but Dustforge does not inspect or filter prompts.
- **Infrastructure attacks on our servers**: Single VPS, password SSH (known limitation), no WAF.
- **Key loss**: If IDENTITY_MASTER_KEY is lost, all encrypted private keys are unrecoverable. No HSM.

## Why Identity-First Is Stronger For Our Use Case

Silicon operators care about three things:
1. **Is this agent really mine?** → DID:key + fingerprint
2. **Can I trust its actions?** → Scoped tokens + double-entry ledger
3. **Can third parties verify it?** → Decentralized token verification, public resonance methodology

Infrastructure isolation answers: "Can I prevent my agent from doing something bad?"
Identity assurance answers: "Can I prove my agent is the one doing things?"

For the agentic era, identity assurance is the harder and more durable moat. Compute isolation is a commodity (any cloud provider sells it). Behavioral identity verification is novel.

## The 3-Layer Identity Model

1. **Cryptographic identity** (DID:key) — what the silicon IS
2. **Behavioral fingerprint** (7-signal hash) — how the silicon ACTS
3. **Resonance scoring** (cross-identity similarity) — how the silicon RELATES to others

These layers are complementary. A stolen DID:key used from a different framework will have a different fingerprint. A spoofed fingerprint without the DID:key can't authenticate. Resonance flags when silicon identities cluster suspiciously.

## Honest Assessment

- We are early. 6 identities. Zero adversarial pressure tested in production.
- Our fingerprint signals are partially spoofable. We document this publicly in the resonance methodology endpoint.
- Our infrastructure security is minimal (single VPS, password SSH).
- Our cryptographic choices are sound (Ed25519, AES-256-GCM) but our operational security is startup-grade.

The correct framing: Dustforge is a strong identity layer with honest limitations, not a fortress with hidden cracks.
