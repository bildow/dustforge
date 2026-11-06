# Trust model

**The proxy holds every secret in plaintext at the moment `/use` fires. Whoever has root on the DemiPass host has every
standard-depth secret.** This is the product's trust model today (red team, tome
`decisions/2026-11-05-THREAT-MODEL-demipass-red-team-v0.1.md`, item 1).

- Secrets are encrypted at rest under a key the host holds. That defends a stolen disk or a copied backup without the
  key — nothing else. Root on the host, the Node process, or the host's key reads every secret.
- **Standard** depth: an agent with a delegation (or the owner's token) uses the secret through `/use`; the value never
  reaches the agent, but the host decrypts it for every use.
- **Elevated / critical** depth today adds a human approval of each exact call (`docs/approvals.md`). The host can
  still decrypt these secrets. Making it unable to — wrapping them under a key that exists only on the owner's enrolled
  device, unwrapped once per approved use — is designed (threat model § Design — item 1) and not yet built.
- What use-only does and does not stop: an agent never receives the value, and it can only point the proxy at the
  hosts, routes and (for SSH) commands the owner set for that secret (`docs/sharing.md`, red team item 2). A target on
  that list that echoes the credential back can still leak it; keep scopes narrow.
