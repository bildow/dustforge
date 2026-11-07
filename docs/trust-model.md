# Trust model

**The proxy holds every secret in plaintext at the moment `/use` fires. Whoever has root on the DemiPass host has every
standard-depth secret** — and no wrapped elevated/critical one. This is the product's trust model (red team, tome
`decisions/2026-11-05-THREAT-MODEL-demipass-red-team-v0.1.md`, item 1).

- Secrets are encrypted at rest under a key the host holds. That defends a stolen disk or a copied backup without the
  key — nothing else. Root on the host, the Node process, or the host's key reads every secret.
- **Standard** depth: an agent with a delegation (or the owner's token) uses the secret through `/use`; the value never
  reaches the agent, but the host decrypts it for every use.
- **Elevated / critical** depth, once the owner's phone (DemiPass app 1.5+) has registered its wrap key, is
  **cryptographic**: raising a secret wraps it. Its value is encrypted under a fresh data key, and that key is encrypted
  to the phone's Keystore wrap key, which never leaves the phone. The host keeps no copy it can decrypt.
  - Every use needs an approval made in the app on that phone. On Approve, the phone unwraps the data key, behind its
    fingerprint or screen lock, and re-encrypts it to a one-use key the host made for that request. The private half
    of that one-use key exists only in the host process's memory.
  - The host decrypts once, acts once, and drops the one-use key. Outside an approval window, neither the database nor
    the process memory holds the value; `test/crypto_depth_smoke.sh` dumps both.
  - Root on the host during an approved use can still see that one use. Root can never see the others.
  - A code read aloud cannot open a wrapped secret, the host cannot reveal it, and it cannot be transferred. Lowering
    it back to standard needs the phone, and re-exposes the value to the host.
  - **Losing every phone that holds its wrap loses the secret.** Removing a phone in the app leaves its wraps in place,
    and they open again only if that same phone (its Keystore key) links again. A secret wrapped while two phones were
    linked opens on either one. New wraps go only to phones linked at that moment.
  - Each wrap seals which secret it is for (owner, ref, name). The phone's own prompt names that secret, and the phone
    refuses a wrap for any other. So a host serving a doctored page cannot get a different secret unwrapped under your
    fingerprint.
  - Wrapping protects from that moment on. Backups taken before a secret was wrapped still hold its host-key copy, until
    they age out. Rotate a secret after wrapping it if older backups matter.
  - Without a phone wrap key, elevated and critical secrets are still protected by approval only, and the host can
    read them; raising one says so.
- What use-only does and does not stop: an agent never receives the value, and it can only point the proxy at the
  hosts, routes and (for SSH) commands the owner set for that secret (`docs/sharing.md`, red team item 2). A target on
  that list that echoes the credential back can still leak it; keep scopes narrow.
