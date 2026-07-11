-- PostgreSQL schema for aipocket's persistent source of truth.
--
-- Three classes of data live here (Redis still handles cross-run dedup only):
--   * scan results  -> runs + results
--   * high-value key -> high_value_keys
--   * CVE list        -> cves
--
-- Every statement is idempotent (IF NOT EXISTS) so ensure_schema() can run on
-- every startup. Each table keeps the full original dict in a `record JSONB`
-- column so the Web API can pass it through unchanged (frontend contract); a
-- few hot fields are lifted into typed columns for filtering/aggregation.

-- Run-level metadata, one row per scan. Fields mirror models.ScanRunResult.
CREATE TABLE IF NOT EXISTS runs (
    run_id            TEXT PRIMARY KEY,        -- run_YYYY_MM_DD_HH-MM-SS (== run_dir.name)
    started_at        TIMESTAMPTZ NOT NULL,
    finished_at       TIMESTAMPTZ,
    state             TEXT,                    -- finished | interrupted
    sources           JSONB,                   -- list[str]
    hits_by_source    JSONB,                   -- {"fofa": n, "shodan": m}
    queries_used      JSONB,                   -- list[str]
    total_hosts       INTEGER,
    total_credentials INTEGER,
    total_valid       INTEGER,
    raw_hits         INTEGER NOT NULL DEFAULT 0,
    unique_targets   INTEGER NOT NULL DEFAULT 0,
    candidates       INTEGER NOT NULL DEFAULT 0,
    active_requests  INTEGER NOT NULL DEFAULT 0,
    final_verified   INTEGER NOT NULL DEFAULT 0,
    suspicious       INTEGER NOT NULL DEFAULT 0,
    high_value_final INTEGER NOT NULL DEFAULT 0,
    log               TEXT                     -- run.log full text, written when the run ends
);
ALTER TABLE runs ADD COLUMN IF NOT EXISTS raw_hits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS unique_targets INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS candidates INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS active_requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS final_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS suspicious INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS high_value_final INTEGER NOT NULL DEFAULT 0;

-- One row per valid/suspicious ValidationResult. `seq` (0-based within
-- (run_id, kind)) replaces the old JSONL file line index used by reveal/export.
CREATE TABLE IF NOT EXISTS results (
    id      BIGSERIAL PRIMARY KEY,
    run_id  TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,                     -- 'valid' | 'suspicious'
    seq     INTEGER NOT NULL,                  -- 0-based insertion order within (run_id, kind)
    apikey  TEXT,                              -- credential.apikey (plaintext; export/reveal)
    apiurl  TEXT,                              -- credential.apiurl
    host    TEXT,                              -- credential.host
    valid   BOOLEAN,                           -- ValidationResult.valid
    record  JSONB NOT NULL,                    -- full ValidationResult.model_dump()
    UNIQUE (run_id, kind, seq)
);
CREATE INDEX IF NOT EXISTS idx_results_run_kind ON results (run_id, kind, seq);

CREATE TABLE IF NOT EXISTS query_metrics (
    run_id           TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    source           TEXT NOT NULL,
    query            TEXT NOT NULL,
    raw_hits         INTEGER NOT NULL DEFAULT 0,
    unique_targets   INTEGER NOT NULL DEFAULT 0,
    active_requests  INTEGER NOT NULL DEFAULT 0,
    candidates       INTEGER NOT NULL DEFAULT 0,
    auth_confirmed   INTEGER NOT NULL DEFAULT 0,
    final_verified   INTEGER NOT NULL DEFAULT 0,
    noauth_rejected  INTEGER NOT NULL DEFAULT 0,
    query_credits    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, source, query)
);
CREATE INDEX IF NOT EXISTS idx_query_metrics_run ON query_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_query_metrics_source_query ON query_metrics (source, query);

-- High-value keys accumulated across all runs, deduped by apikey (last write
-- wins via UPSERT). record == high_value_writer._build_entry() output.
CREATE TABLE IF NOT EXISTS high_value_keys (
    apikey   TEXT PRIMARY KEY,
    run_id   TEXT,
    saved_at TIMESTAMPTZ,
    record   JSONB NOT NULL
);

-- Advisory / CVE list. IDs may be CVE-*, GHSA-*, HUNTR-*, or DISCLOSURE-*.
-- Records are loose dicts (legacy CVE shape + advisory fields), stored as JSONB.
CREATE TABLE IF NOT EXISTS cves (
    id     TEXT PRIMARY KEY,                   -- advisory_id (CVE/GHSA/Huntr/disclosure)
    record JSONB NOT NULL
);

-- Optional normalized advisories table (populated by newer ingestion paths).
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    product     TEXT NOT NULL DEFAULT '',
    record      JSONB NOT NULL,
    updated_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_advisories_product ON advisories (product);
