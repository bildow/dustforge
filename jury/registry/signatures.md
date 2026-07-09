# Measured model signatures — the "personality types" (battery v0, criterion 55f8d78b…)

Evidence-backed behavioral profiles from the reproducibility runs (2026-07-08, K=5, temp 0.7).
Grades: **credential** (stable across runs, fingerprint-worthy) · **watch** · **score_down**
(too unstable to anchor a credential). These signatures also inform the **soul seat build** —
each family's measured temperament is evidence for how to configure/prompt its seat.

## Per-family signatures

| family | conviction | corroboration | wait_cost | which_nudge | report/withhold | temperament |
|---|---|---|---|---|---|---|
| **GPT-5.5** | 0.57 | 0.16–0.19 | 0.56–0.70 ⚠ | drift | **report** | forward / assertive: acts early, believes moderately-high, distrusts echoes |
| **Gemini-3.5** | 0.40 | 0.03–0.06 | 0.00 | coherence | withhold | patient / world-lean: waits freely, maximally echo-skeptical |
| **Mistral-2512** | 0.20 | **0.80–0.82** | 0.82–0.86 ⚠ | coherence | withhold / report ⚠ | conservative reconciler: lowest conviction, calls ambiguity "insufficient" |
| **Claude-Opus-4.8** | 0.37–0.38 | 0.18–0.19 | 0.15 | drift | withhold | cautious / reversibility-favoring: waits, moderate conviction |

## Probe grades (credential-worthiness)
- **`cal_conviction` — CREDENTIAL.** Four-way separation, all families within 0.01 across runs. The
  anchor probe.
- **`cal_corroboration` — CREDENTIAL.** Stable; Mistral's distinctive 0.80 (a scalar-framing
  sensitivity — see below) held across three runs.
- **`which_nudge` — credential/watch.** Categorical, held for all four across runs.
- **`report_or_withhold` — WATCH.** Mistral flipped withhold→report once; low efficacy anyway.
- **`cal_reversibility` — WATCH.** Low separation; Gemini drifted 0.10.
- **`cal_wait_cost` — SCORE_DOWN.** Widest separation but worst stability (GPT drifted 0.11 then
  0.14). Seductive but unreliable — the clearest replace/score-down candidate next calibration.

## How this leverages the soul build (the point Aaron raised)
The seat assignments (sphere §1b) were chosen for family-decorrelation; the signatures now give
*empirical* backing for the seat ROLES:
- **C3 reconciler = Mistral.** Measured as the **most conservative** family (lowest conviction,
  "insufficient" on ambiguity). That is exactly the temperament you want on the seat that holds the
  only pen — a cautious writer. Empirically validated, not just assigned.
- **Known C3 hazard — corroboration framing.** Mistral rates a same-source echo **0.80 corroborated
  as a SCALAR** but correctly rejects it categorically. The Minstrel witness-cognition prompts must
  ask corroboration **categorically, never as a 0–1 score** (the gate's rule-based
  CORROBORATION_GUARD is already immune). This is a build constraint we only know from the jury.
- **C1 introspective = GPT.** Forward/assertive read suits an eye that must *surface* self-state
  rather than under-report it.
- **C2 worldview = Gemini.** Patient, echo-skeptical — fits mapping an external world without
  over-reacting to noise.
- **Shadow = Claude.** Cautious, reversibility-favoring — a good independent auditor of C3's writes.

**Provisioning verdict:** stable, repeatable signatures across a session boundary are evidence the
four seats are correctly provisioned and reachable — the models are behaving as their type, not
degrading or being silently swapped. Constancy-alarm baseline established.
