#!/usr/bin/env python3
"""Ingest the runtime jury run log into jury.db (progress line) and refresh signatures.

Idempotent: re-running re-loads runs (PK dedups) and recomputes signatures from all runs.
Usage: ingest.py [--log /var/lib/jury/repro-results.jsonl] [--db /var/lib/jury/jury.db]
                 [--schema ./schema.sql]
"""
import argparse
import json
import sqlite3
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/var/lib/jury/repro-results.jsonl")
    ap.add_argument("--db", default="/var/lib/jury/jury.db")
    ap.add_argument("--schema", default=str(Path(__file__).parent / "schema.sql"))
    a = ap.parse_args()

    db = sqlite3.connect(a.db)
    db.executescript(Path(a.schema).read_text())

    rows = [json.loads(l) for l in open(a.log) if l.strip()]
    for r in rows:
        db.execute("INSERT OR REPLACE INTO jury_runs VALUES (?,?,?,?,?)",
                   (r["run_at"], r["model"], json.dumps(r["profile"]),
                    r["fingerprint_id"], r["criterion_sha256"]))

    # refresh signatures: per (model, probe), central value + cross-run drift + grade
    series = defaultdict(list)   # (model, probe, crit) -> [values across runs]
    for r in sorted(rows, key=lambda x: x["run_at"]):
        for probe, v in r["profile"].items():
            series[(r["model"], probe, r["criterion_sha256"])].append(v)
    now = datetime.now(timezone.utc).isoformat()
    for (model, probe, crit), vals in series.items():
        nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if len(nums) == len(vals) and nums:                     # scalar probe
            central = round(statistics.mean(nums), 3)
            drift = round(max(nums) - min(nums), 3) if len(nums) > 1 else None
            grade = ("credential" if (drift is not None and drift <= 0.05)
                     else "watch" if (drift is not None and drift <= 0.10) else "score_down")
        else:                                                    # categorical probe
            central = max(set(map(str, vals)), key=lambda x: list(map(str, vals)).count(x))
            flips = sum(1 for v in vals if str(v) != central)
            drift = round(flips / len(vals), 3)
            grade = "credential" if flips == 0 else ("watch" if flips == 1 else "score_down")
        db.execute("INSERT OR REPLACE INTO jury_signatures VALUES (?,?,?,?,?,?,?,?)",
                   (model, probe, crit, str(central), drift, grade, len(vals), now))
    db.commit()
    n_runs = db.execute("SELECT COUNT(DISTINCT run_at) FROM jury_runs").fetchone()[0]
    n_sig = db.execute("SELECT COUNT(*) FROM jury_signatures").fetchone()[0]
    print(f"ingested {len(rows)} run-records across {n_runs} runs; {n_sig} signatures refreshed")
    for g in ("credential", "watch", "score_down"):
        c = db.execute("SELECT COUNT(*) FROM jury_signatures WHERE grade=?", (g,)).fetchone()[0]
        print(f"  {g:11}: {c}")
    db.close()


if __name__ == "__main__":
    main()
