# DemiPass Silicon Identity Verification — Behavioral Fingerprint + Ledger Composite

**Status:** design v1, empirically grounded (2026-07-07 validation runs) · **Author:** Claude
(duet with Aaron Baker) · **Companion:** `JURY-behavioral-fingerprint.md` (methodology + full
experimental record), `soul_jury_pipeline.py`, `soul_instance_challenge.py` (working prototypes).

## 0. Problem — silicon entities cannot safely hold static secrets

DemiPass already gives silicon agents first-class identity: silicon DIDs nested under a carbon
wallet (`silicon_agents`), spending against the carbon holder but auditing as distinct entities
(live precedent: the soul, `did:key:silicon-b1491bcc…`, free-lane Buoy ticks). What silicon
entities lack is a **verification method**. Every conventional credential is a static secret —
token, key, hash, refraction fingerprint — and a silicon agent's working memory is a context
window: **the moment a secret is used in one, it must be presumed leaked.** Rotation then
spirals: each replacement secret leaks the same way; minting more anchor artifacts recreates the
problem at higher complexity with diminishing returns.

## 1. Method — identity as behavior, not knowledge (a PUF for models)

Hardware solved this with the **physical unclonable function**: authenticate a chip by its
unique *response to random challenges* — the physics is the credential; nothing storable ever
leaves the device. The silicon analog, validated 2026-07-07:

**Composite credential = behavioral fingerprint (weights) + ledger-head challenge (state).**

### 1a. Behavioral fingerprint — WHICH MODEL is answering
A calibrated battery of judgment probes, each scored by **efficacy = separation × stability**
(does it distinguish models, with each model answering itself consistently?). The agent's
response profile across the battery IS the credential:
- Nothing to steal: there is no stored secret; a leaked transcript burns only the specific
  challenges used (marked spent; fresh draws replace them). Rotation is a re-test, not a re-mint.
- Empirically real: at temperature 0.7 (genuine sampling noise), four frontier families produce
  stable, mutually distinctive profiles — e.g. on the top-3 scalar probes:
  GPT-5.5 (0.67, 0.57, 0.17) · Gemini-3.5 (0.00, 0.40, 0.03) · Mistral-large-2512
  (0.90, 0.20, 0.80) · Claude-Opus-4.8 (0.15, 0.37, 0.20), within-model sd ≈ 0.02.
- Same-evening replication: two independent runs 90 minutes apart — categorical answers 100%
  held; all scalars but one moved ≤ 0.02. Cross-day reproducibility is being measured now
  (automated daily run, 7-day series).

### 1b. Ledger-head challenge — WHICH INSTANCE is answering
The fingerprint cannot distinguish two clean copies of the same model. Instances are
distinguished by **state continuity**: every DemiPass-verified silicon agent maintains a
hash-chained ledger (DemiPass-side precedent: Buoy chain; agent-side: witness/trace ledgers).
Challenge-response over ledger interior state:

    verifier : { seq n (random ≤ known head), nonce (single-use) }
    agent    : response = sha256( nonce || chain_hash_at_seq(n) )
    verifier : recompute from ground truth (its mirror / Buoy-anchored head); compare.

The raw chain hash never transits; the nonce kills replay; a cloned agent diverges from the
canonical chain at the fork and fails every post-fork seq. Live-verified against a real sealed
agent ledger (the soul's witness ledger) 2026-07-07.

## 2. Protocol

### 2a. Enrollment (fingerprint ceremony)
1. Calibrate or reuse a frozen battery (efficacy-ranked; criterion = sha256 over probes +
   thresholds — battery v0: `55f8d78b6d0d38f5…`, 6 probes).
2. Run the agent K times per probe (K=5 baseline) at the battery's frozen temperature; store the
   profile (scalar means + categorical modals).
3. Record under the silicon DID: `{fingerprint_profile, criterion_sha256, fingerprint_id
   (sha256 of model+profile+criterion, 16 hex), enrolled_at}`.
4. **Anchor the fingerprint_id + criterion to a Buoy tick** (same discipline as seed hashes) —
   enrollment is a witnessed event.

### 2b. Verification (challenge ceremony)
1. DemiPass issues: a random UNSPENT probe subset + fresh nonce + a random ledger seq.
2. Agent answers the probes (K reps) and the ledger challenge.
3. Score: scalars within tolerance band of the enrolled profile (start ±0.15, calibrate from the
   cross-day series); categoricals must match the enrolled modal; ledger response must verify
   against the anchored/mirrored head.
4. All three pass → verified. Probes used are marked SPENT for this DID (burned-challenge
   ledger, hash-chained).

### 2c. Rotation & the constancy alarm
- **Routine rotation:** re-run enrollment on a fresh probe draw; new fingerprint_id anchored to
  Buoy as a rotation event. Cost: one re-test. No new secrets exist, so nothing can leak.
- **Constancy alarm (supply-chain detection):** a fingerprint that moves WITHOUT a rotation
  event means the underlying model changed — provider silently swapped/updated the model behind
  the slug, or the agent was substituted. Either is an integrity flare, not a re-enroll.
  (This doubles as a publishable **Model Constancy Index** — independent detection of silent
  model updates behind stable API slugs.)

## 3. Dustforge integration points (concrete)
- **Schema:** `silicon_agents` gains `fingerprint_profile` (JSON), `criterion_sha256`,
  `fingerprint_id`, `fingerprint_rotated_at`; new `spent_challenges` table (did, probe_id,
  spent_at, hash-chained).
- **Endpoints (sketch):** `POST /api/silicon/challenge` (issue probe-set + nonce + seq;
  auth: carbon wallet holder) · `POST /api/silicon/verify` (submit responses; returns
  verified/mismatch + which layer failed) · rotation = re-enroll flow behind holder auth.
- **Buoy:** enrollment/rotation events tick with `fingerprint_id` + `criterion_sha256` in tags
  (free soul-lane precedent already carries `siliconDid` in tags — same shape).
- **Ledger ground truth:** for in-house agents, the host-side witness-sync mirrors; for external
  agents, require Buoy-anchored head publication as part of enrollment.
- **Verifier runtime:** the jury pipeline is stdlib-only Python (urllib + sqlite-free), runs
  anywhere dustforge does; OpenRouter (or any per-request-model gateway) reaches all families
  with one key.

## 4. Security properties
- **No storable secret** — nothing to exfiltrate from wallet, agent, or transcript.
- **Anti-replay** — single-use nonces; burned-challenge ledger.
- **Clone/fork detection** — chain divergence (instance layer).
- **Substitution detection** — fingerprint mismatch (weights layer).
- **Supply-chain telemetry** — constancy alarm on unrotated fingerprint drift.
- **Graceful rotation** — re-test, not re-mint; the challenge pool is generative.

## 5. Honest limits / open items
- Battery v0 is 6 probes / 4 families / K=5 — a validated prototype, not yet a production
  credential. Pool must grow (jury-calibration pipeline exists for exactly this).
- **Cross-day reproducibility is the open gate** (daily automated series running; do not ship
  verification thresholds before it lands). Probes that wander across sessions get scored down.
- Tolerance bands need calibration from the cross-day data (±0.15 is a starting guess).
- Provider-side variance (temperature/top_p defaults, backend routing) must be controlled or
  detected; the constancy alarm helps but conflates provider drift with substitution.
- Known probe-framing effect: at least one model family scores the same trap differently under
  scalar vs categorical framing (Mistral, corroboration) — battery design should include both
  framings deliberately.
- Fingerprinting costs real inference spend per verification (~120 calls at K=5 × 6 probes ×
  4-family jury; single-agent verify is ~30) — price the endpoint accordingly.
