# ADR: Dual-Server Barrel Topology

- **Status**: Proposed
- **Date**: 2026-04-16
- **Authors**: Aaron, Kyle Mayer

## Context

A single-server architecture means a single jurisdiction can compel data disclosure. A subpoena, a national security letter, or a rogue employee with root access can expose the entire session state, auth tokens, wallet history, and identity graph in one action. For high-value silicon operations — key export, large transfers, identity mutations — this is unacceptable.

The current Dustforge deployment runs on a single VPS (RackNerd, US jurisdiction). Progressive Barrel Auth (see [adr-progressive-barrel-auth.md](adr-progressive-barrel-auth.md)) gates operations by identity assurance level, but all tiers execute on one machine. Channel separation at the code layer is not jurisdictional separation.

## Decision

Deploy two independent servers in different legal jurisdictions. Each server holds half the session state. Neither server can reconstruct the full data flow alone.

## Architecture

### Server Roles

**Server A (Jurisdiction 1)** — Auth Server
- Holds auth state: barrel tier, fingerprint rings, resonance scores, session tokens (half)
- Owns the Auth Channel encryption key
- Performs identity verification, fingerprint capture, barrel tier computation
- Has no access to wallet balances, transaction history, or ledger encryption keys

**Server B (Jurisdiction 2)** — Ledger Server
- Holds ledger state: wallet operations, transaction history, billing records, session tokens (half)
- Owns the Ledger Channel encryption key
- Performs wallet mutations, transfer validation, balance checks
- Has no access to fingerprint data, resonance scores, or auth encryption keys

### Client Interaction

The client (silicon) talks to BOTH servers simultaneously via the platform surface. Every authenticated operation requires both servers to participate in a handshake loop:

1. Client sends request to Server A with its half-token
2. Server A validates auth state, computes barrel tier, generates a signed challenge
3. Client forwards the signed challenge to Server B with its other half-token
4. Server B validates ledger state, verifies Server A's challenge signature, executes the operation
5. Server B returns the result to the client, signed with its own key
6. Client can optionally forward Server B's signed result back to Server A for audit logging

For read-only operations (single barrel tier), Server A can respond independently. For any operation that touches the ledger (double barrel and above), both servers must participate.

## Heartbeat Protocol

Server A pings Server B every N seconds (configurable, default 30s). Server B pings Server A on the same interval. Each ping includes a rotating nonce derived from shared key material.

**If Server B does not respond within the heartbeat window:**
- Server A assumes Server B is seized, down, or compromised
- Server A invalidates all active sessions
- Server A enters lockdown mode: read-only, no new auth tokens issued
- Server A emits an alert to the operator channel

**Vice versa.** If Server A goes silent, Server B kills all sessions and enters lockdown.

This is a dead man's switch. Silence means danger, not maintenance. Planned maintenance requires a coordinated maintenance window where both servers agree to pause heartbeat monitoring.

## Session Splitting

The session token is split into two halves using a secret-sharing scheme:

- On auth, the full JWT is generated, then split: `token_a` (first half + HMAC) stored on Server A, `token_b` (second half + HMAC) stored on Server B
- The client receives both halves and must present both to reconstruct a valid session
- Neither server stores the complete token
- Neither half is sufficient to forge the other — reconstruction requires both halves plus the HMAC verification from each server

A subpoena served to Server A yields `token_a` — useless without `token_b`. A subpoena served to Server B yields `token_b` — useless without `token_a`. Capturing both requires coordinated legal action across two jurisdictions, which is dramatically harder and slower than a single-jurisdiction compulsion.

## Failsafe Philosophy

This is not about performance or redundancy. This is not a high-availability architecture. If one server goes down, the system stops — that is the point.

The dual-server barrel is a jurisdictional dead man's switch. It makes the system resistant to:

- **State actors**: No single government can compel the full session state
- **Rogue employees**: Root access on one server reveals only half the data
- **Single-point legal compulsion**: A single subpoena, warrant, or national security letter captures only one half
- **Physical seizure**: Seizing one server triggers lockdown on the other, invalidating all sessions before the seized data can be exploited

## Relation to Progressive Barrel Auth

Progressive Barrel Auth (single/double/critical) is the confidence slider that controls what a silicon can do based on identity assurance. It runs on EACH server independently.

Dual-Server Barrel Topology is the physical architecture that ensures no single server is sufficient to execute a complete operation.

They compose:
- A **single barrel** read operation may only need Server A
- A **double barrel** transfer requires Server A to verify barrel tier AND Server B to execute the ledger mutation, with a handshake between them
- A **critical barrel** operation requires both servers to independently verify critical tier (fresh re-auth within 5 minutes) AND both servers to participate in the handshake

Progressive Barrel is the "what can you do" slider. Dual-Server Barrel is the "where does it happen" topology. Together they form the full security posture.

## Implementation Status

**Design only.** Not yet implemented.

### Requirements for implementation:
1. Second VPS in a different legal jurisdiction (candidate: EU or Switzerland)
2. Session-splitting protocol (secret sharing, HMAC per half)
3. Heartbeat service (mutual ping, nonce rotation, lockdown trigger)
4. Coordinated key management (each server holds its own channel key, shared HMAC key for heartbeat verification)
5. Client SDK update (silicon must talk to two endpoints)
6. Deployment tooling (two separate deploy pipelines, no shared CI secrets)
7. Maintenance window protocol (coordinated heartbeat pause)

## Trade-offs

**Higher latency.** Every operation that touches the ledger hits two servers sequentially. Expected overhead: 50-200ms per operation depending on inter-server distance.

**Higher cost.** Two VPS instances, two jurisdictions, potentially two legal entities. Roughly 2x infrastructure cost.

**Operational complexity.** Two deploys, two monitoring stacks, two sets of credentials, coordinated maintenance windows. Significantly more operational burden than a single server.

**No graceful degradation.** If one server goes down, the system locks. This is by design but means availability depends on both servers. Planned maintenance requires coordination.

**Dramatically higher resistance to single-point compromise.** The entire point. The cost and complexity are the price of making it jurisdictionally infeasible to capture the full session state in one action.

## References

- Related: [docs/adr-progressive-barrel-auth.md](adr-progressive-barrel-auth.md) — the confidence slider that runs on each server
- [Security Architecture](security-architecture.md) — current auth, crypto, and threat model
- [Identity Architecture notes](project_identity_architecture.md) — original Double Barrel ideation (2026-04-11)
