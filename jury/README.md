# Jury — behavioral fingerprinting for silicon identity

The **jury** is DemiPass's model-identity subsystem: it authenticates a silicon entity by *how it
behaves* under a calibrated battery of probes, not by a stored secret (a PUF for models). Companion
design: `docs/silicon-fingerprint-verification.md`. Methodology + experimental record:
`JURY-behavioral-fingerprint.md` (tome).

This folder makes the jury **product-tracked** — two record lines, as intended:

1. **The jury's PROGRESS** — every fingerprint run over time (the reproducibility series). Answers:
   *is a model's signature stable across sessions/days?* → table `jury_runs`.
2. **The jury ITSELF** — the battery it uses, its calibration (efficacy scores + criterion hash),
   its composition, and the stable per-model signatures it has measured. Answers: *what is the jury,
   and what does it currently know?* → tables `jury_registry` + `jury_signatures`.

## Layout
- `schema.sql` — the two/three tables (progress + self).
- `ingest.py` — load the runtime run log (`/var/lib/jury/repro-results.jsonl`) into `jury.db`.
- `jury_regression.py` — the EXPLICIT regression meter: compares a baseline "shape" to a candidate
  (a later run, or a reformed substrate after a germination cycle) → held / evolved / regressed per
  probe, using each probe's grade so a credential anchor flipping = regression while a score_down
  probe is ignored. This is how the germination cycle's "diminishing returns" become a number:
  bounded regressions across cycles = anti-fragile; growing = lossy reformation. The same-shape test,
  quantified. It is a first-class part of the soul-process lifecycle harness, not an afterthought.
- `registry/battery-v0.json` — the FROZEN calibrated battery (criterion `55f8d78b…`), the immutable
  bar. Do not edit; version a new battery instead.
- `registry/signatures.md` — the measured per-model signatures ("personality types"), evidence-backed.
- `runs/` — dated human-readable evidence for each notable test (the DB is the machine copy).

## How a run flows
`soul_jury_pipeline.py fingerprint <model> --battery battery-v0.json` (host, daily timer) →
appends to `/var/lib/jury/repro-results.jsonl` → `ingest.py` → `jury_runs`. Cross-run drift analysis
promotes stable probes and scores down wobblers in the next calibration → a new `jury_registry` row.

## Why it feeds the product
A stable signature is a **credential** (silicon DID verification). Signature drift *without* a
declared rotation is a **supply-chain alarm** (a provider silently swapped the model behind a slug).
Both are DemiPass features; this folder is their evidence base.

## Status (2026-07-08)
Prototype. Battery v0 = 6 probes, 4-family jury, K=5. 2 reproducibility runs recorded (see
`runs/2026-07-08-reproducibility.md`). Credential thresholds NOT yet set — pending the multi-day
series (timer self-limits at 7 runs). Do not ship verification until the cross-day number lands.
