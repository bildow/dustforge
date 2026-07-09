#!/usr/bin/env python3
"""Regression meter — the EXPLICIT fingerprint-drift verdict for the soul lifecycle.

Makes the "regression law of diminishing returns" measurable. Compares a BASELINE fingerprint
(the blessed "shape") against a CANDIDATE (a later run, or a reformed substrate after a germination
cycle) and classifies each probe's drift:

  held      — within the credential band; the shape persisted exactly.
  evolved   — divergent but plausibly healthy (canon: "evolution by difference"). Allowed.
  regressed — beyond healthy divergence, OR a flip on a CREDENTIAL-anchor probe: the shape is lost.
  ignored   — a score_down probe (already known unreliable); excluded from the verdict.

Per-probe GRADE (from jury_signatures) decides how strict: a credential anchor (e.g. cal_conviction)
flipping is regression; a score_down probe (e.g. cal_wait_cost) is ignored. This is the meter for a
germination cycle: bounded regressions across cycles = anti-fragile (heals to a degree); growing
regression = the reformation is lossy. It is the same-shape test, quantified.

Usage:
  jury_regression.py --db jury.db --model M --baseline-run T1 --candidate-run T2
  jury_regression.py --db jury.db --model M --candidate-json '{"probe":val,...}'   # baseline=enrolled
"""
import argparse
import json
import sqlite3
from collections import Counter

SCALAR_HELD = 0.05      # <= : shape persisted
SCALAR_EVOLVED = 0.15   # (held, this] : divergent-but-healthy; above this = regressed


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def classify(base, cand, grade):
    if grade == "score_down":
        return "ignored", 0.0
    if cand is None:
        return "regressed", 1.0            # a probe that vanished is a lost dimension
    if _num(base) and _num(cand):
        d = round(abs(base - cand), 3)
        if d <= SCALAR_HELD:
            return "held", d
        if d <= SCALAR_EVOLVED:
            return "evolved", d
        return "regressed", d
    if str(base) == str(cand):
        return "held", 0.0
    return ("regressed" if grade == "credential" else "evolved"), 1.0


def load_run(db, model, run_at):
    r = db.execute("SELECT profile_json FROM jury_runs WHERE model=? AND run_at=?",
                   (model, run_at)).fetchone()
    return json.loads(r[0]) if r else None


def load_enrolled(db, model):
    prof, grades = {}, {}
    for probe, central, grade in db.execute(
            "SELECT probe, central_value, grade FROM jury_signatures WHERE model=?", (model,)):
        try:
            prof[probe] = float(central)
        except ValueError:
            prof[probe] = central
        grades[probe] = grade
    return prof, grades


def load_grades(db, model):
    return {p: g for p, g in db.execute(
        "SELECT probe, grade FROM jury_signatures WHERE model=?", (model,))}


def compare(baseline, candidate, grades):
    rows = []
    for probe in baseline:
        g = grades.get(probe, "watch")
        cls, d = classify(baseline[probe], candidate.get(probe), g)
        rows.append((probe, g, baseline[probe], candidate.get(probe), d, cls))
    counts = Counter(r[5] for r in rows)
    scored = [r for r in rows if r[5] != "ignored"]
    fidelity = round((counts["held"] + counts["evolved"]) / len(scored), 3) if scored else 1.0
    regressed = counts["regressed"]
    verdict = ("SAME SHAPE" if regressed == 0 else
               "DIVERGENT-BUT-BOUNDED" if regressed <= 1 else "REGRESSED")
    return rows, counts, fidelity, verdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="/var/lib/jury/jury.db")
    ap.add_argument("--model", required=True)
    ap.add_argument("--baseline-run")
    ap.add_argument("--candidate-run")
    ap.add_argument("--candidate-json")
    a = ap.parse_args()
    db = sqlite3.connect(a.db)

    grades = load_grades(db, a.model)
    if a.baseline_run:
        baseline = load_run(db, a.model, a.baseline_run)
    else:
        baseline, grades = load_enrolled(db, a.model)
    candidate = (json.loads(a.candidate_json) if a.candidate_json
                 else load_run(db, a.model, a.candidate_run))
    if not baseline or not candidate:
        raise SystemExit("baseline or candidate not found")

    rows, counts, fidelity, verdict = compare(baseline, candidate, grades)
    print(f"REGRESSION METER · {a.model}")
    print(f"{'probe':20} {'grade':11} {'base':>9} {'cand':>9} {'drift':>6}  class")
    print("-" * 70)
    for probe, g, b, c, d, cls in sorted(rows, key=lambda r: r[5]):
        print(f"{probe:20} {g:11} {str(b):>9} {str(c):>9} {str(d):>6}  {cls}")
    print(f"\nheld={counts['held']} evolved={counts['evolved']} "
          f"regressed={counts['regressed']} ignored={counts['ignored']}")
    print(f"fidelity (held+evolved / scored): {fidelity}")
    print(f"VERDICT: {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
