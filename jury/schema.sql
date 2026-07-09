-- Jury schema — two record lines: the jury's PROGRESS and the jury ITSELF.
-- Runtime DB lives at /var/lib/jury/jury.db (NOT in git — this DDL is the tracked source of truth).

------------------------------------------------------------------- PROGRESS
-- Every fingerprint run over time. One row per (run, model). The reproducibility series.
CREATE TABLE IF NOT EXISTS jury_runs (
    run_at            TEXT NOT NULL,          -- ISO8601 UTC of the run
    model             TEXT NOT NULL,          -- e.g. mistralai/mistral-large-2512
    profile_json      TEXT NOT NULL,          -- {probe: value} — the fingerprint this run
    fingerprint_id    TEXT NOT NULL,          -- sha256(model+profile+criterion)[:16]
    criterion_sha256  TEXT NOT NULL,          -- which frozen battery produced it
    PRIMARY KEY (run_at, model)
);
CREATE INDEX IF NOT EXISTS idx_runs_model ON jury_runs(model, run_at);

------------------------------------------------------------------- THE JURY ITSELF
-- Each calibrated battery version: what the jury is + how it was calibrated.
CREATE TABLE IF NOT EXISTS jury_registry (
    criterion_sha256  TEXT PRIMARY KEY,       -- the frozen battery's anchor (Buoy-anchored at bless)
    version           TEXT NOT NULL,          -- e.g. v0
    created_at        TEXT NOT NULL,
    battery_json      TEXT NOT NULL,          -- the probe definitions
    efficacy_json     TEXT NOT NULL,          -- {probe: {separation, stability, efficacy}} from calibration
    jury_models_json  TEXT NOT NULL,          -- the family composition used
    k                 INTEGER NOT NULL,       -- samples per probe
    temp              REAL NOT NULL,
    notes             TEXT
);

-- The stable per-model signatures the jury has MEASURED (the "personality types").
-- Updated as the reproducibility series accumulates; grade = how credential-worthy the probe is.
CREATE TABLE IF NOT EXISTS jury_signatures (
    model             TEXT NOT NULL,
    probe             TEXT NOT NULL,
    criterion_sha256  TEXT NOT NULL,
    central_value     TEXT NOT NULL,          -- modal (categorical) or mean (scalar)
    cross_run_drift   REAL,                   -- max |delta| observed across runs (NULL until >=2 runs)
    grade             TEXT,                   -- credential | watch | score_down  (from stability)
    n_runs            INTEGER NOT NULL DEFAULT 1,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (model, probe, criterion_sha256)
);
