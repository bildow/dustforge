# ADR: Double Barrel Authentication Topology

- **Status**: Accepted
- **Date**: 2026-04-16
- **Authors**: Aaron, Kyle Mayer

## Context

Dustforge currently authenticates silicons through a single-server flow: fingerprint capture, password verification against Stalwart, and JWT issuance all happen on one server behind one TLS endpoint. This works for reads, lookups, and low-value wallet operations, but high-value operations (large transfers, key export, identity mutations) need stronger assurance than a single authentication channel provides.

The original Double Barrel concept (Aaron and Kyle, 2026-04-11) envisioned two physically separate authentication servers in different jurisdictions. This ADR adapts that vision into an incremental architecture: two logical channels on the same server today, with a clean separation boundary that allows splitting to two servers later without changing the client protocol.

## Decision

Introduce two logical authentication channels and a tiered barrel model that gates operations by assurance level.

### Channel Architecture

**Auth Channel** — handles identity verification, token issuance, and fingerprint capture.

- All payloads between client and server are encrypted with AES-256-GCM.
- Issues barrel tokens: short-lived, scoped to a specific assurance tier.
- Captures the 7-signal behavioral fingerprint on every authentication event.
- Owns the fingerprint store, resonance scores, and session state.

**Ledger Channel** — handles wallet operations, transfers, and billing.

- Encrypted separately from the Auth Channel with its own AES-256-GCM key.
- Key rotation is independent from the Auth Channel.
- All wallet mutations (credit, debit, transfer) flow through this channel.
- Verifies barrel tokens issued by the Auth Channel before executing any operation.

Both channels run on the same server process for now. They are separated at the code layer (distinct key material, distinct middleware stacks, distinct token validation paths) so that splitting them onto separate servers later requires only infrastructure changes, not protocol changes.

### Barrel Model

Three assurance tiers, each building on the previous:

| Tier | Requirements | Authorized Operations |
|------|-------------|----------------------|
| **Single barrel** | Fingerprint auth only | Reads, lookups, email send, Blindkey use, wallet balance checks |
| **Double barrel** | Fingerprint + wallet binding verified | Transfers > 100 DD, identity status changes, Blindkey store/delete, resonance attestations |
| **Critical barrel** | Double barrel + fresh re-auth within 5 minutes | Key export, account deletion, SSN derivation, recovery key generation |

**Single barrel** is the default. A silicon authenticates via fingerprint, receives a single-barrel JWT, and can perform all standard operations.

**Double barrel** requires the silicon to prove wallet binding: the Auth Channel verifies identity, the Ledger Channel confirms the wallet is bound to that identity, and a double-barrel token is issued only when both channels agree. This token is short-lived and scoped to the operation class.

**Critical barrel** requires a fresh re-authentication (fingerprint + wallet binding) within the last 5 minutes. No session carry-over. The re-auth timestamp is embedded in the token and verified server-side before any critical operation executes. This is the dead man's switch pattern: trust decays to zero after 5 minutes.

### Channel Encryption

Each channel derives its own AES-256-GCM key from `IDENTITY_MASTER_KEY` via HKDF (RFC 5869):

```
auth_channel_key    = HKDF(IDENTITY_MASTER_KEY, salt, info="dustforge-auth-channel-v1")
ledger_channel_key  = HKDF(IDENTITY_MASTER_KEY, salt, info="dustforge-ledger-channel-v1")
```

Key rotation is independent per channel. Rotating the Auth Channel key does not affect the Ledger Channel and vice versa. The `info` string is versioned so that key rotation produces a new derivation without ambiguity.

The shared `IDENTITY_MASTER_KEY` is the single root of trust. This is a known limitation at current scale (see Trade-offs).

## Implementation Plan

Per the sprint plan:

| Sprint Day | Deliverable |
|-----------|-------------|
| D2 | Tunnel stub — encrypted channel abstraction, HKDF key derivation, channel middleware skeleton |
| D3 | Auth Channel — fingerprint auth migrated to channel encryption, single-barrel token issuance |
| D4 | Ledger Channel — wallet operations migrated to channel encryption, double-barrel token flow |
| D5 | Critical re-auth gate — 5-minute freshness check, critical-barrel token issuance and verification |

Each day produces a working system. Single barrel works after D3. Double barrel works after D4. Critical barrel works after D5.

## Trade-offs

**Single server, shared fate.** Both channels run on one server. A full server compromise defeats channel separation. This is acceptable at current scale (single VPS, < 1,000 identities) because:
- The threat model targets identity impersonation and wallet manipulation, not nation-state server seizure.
- Channel separation still defends against partial compromise (e.g., memory leak in one middleware stack does not expose the other channel's key material).
- The code-level boundary means splitting to two servers later is an infrastructure task, not a rewrite.

**Shared IDENTITY_MASTER_KEY.** Both channel keys derive from one master key. Compromising the master key compromises both channels. Mitigations: the master key is required at boot and not persisted in the database; envelope encryption or HSM backing is a future enhancement (noted in security-architecture.md as a known limitation).

**5-minute critical window.** Short enough to limit replay risk, long enough that a silicon can complete a multi-step critical operation without re-authing mid-flow. If operations routinely exceed 5 minutes, this window may need adjustment.

**Jurisdictional arbitrage deferred.** The original vision places each channel in a different legal jurisdiction so no single government can compel both halves. This requires two servers, two hosting providers, two legal entities. Deferred until the threat model warrants it or the user base crosses a scale threshold that justifies the operational cost.

## References

- [Security Architecture](security-architecture.md) — current auth, crypto, and threat model
- [Identity Architecture notes](project_identity_architecture.md) — original Double Barrel ideation (2026-04-11)
- [Silicon Fingerprint spec](project_silicon_fingerprint.md) — three-layer identity model (SSN + Profile + Resonance)
