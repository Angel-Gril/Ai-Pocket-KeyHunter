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
    metrics_version  INTEGER NOT NULL DEFAULT 2,
    scan_mode        TEXT NOT NULL DEFAULT 'incremental',
    log               TEXT                     -- run.log full text, written when the run ends
);
ALTER TABLE runs ADD COLUMN IF NOT EXISTS raw_hits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS unique_targets INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS candidates INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS active_requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS final_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS suspicious INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS high_value_final INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS metrics_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS scan_mode TEXT NOT NULL DEFAULT 'incremental';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS total_active_http_requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS ledger_complete BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS ledger_incomplete_reason TEXT NOT NULL DEFAULT '';
-- metrics_version: 2 = pre-ledger; 3 = ledger_complete true + real denominator

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
ALTER TABLE results ADD COLUMN IF NOT EXISTS credential_issuer TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE results ADD COLUMN IF NOT EXISTS validation_provider TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS query_metrics (
    run_id           TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    source           TEXT NOT NULL,
    query            TEXT NOT NULL,
    raw_hits         INTEGER NOT NULL DEFAULT 0,
    unique_targets   INTEGER NOT NULL DEFAULT 0,
    active_requests  INTEGER NOT NULL DEFAULT 0,
    candidates       INTEGER NOT NULL DEFAULT 0,
    prefilter_survivors INTEGER NOT NULL DEFAULT 0,
    auth_confirmed   INTEGER NOT NULL DEFAULT 0,
    final_verified   INTEGER NOT NULL DEFAULT 0,
    noauth_rejected  INTEGER NOT NULL DEFAULT 0,
    query_credits    INTEGER NOT NULL DEFAULT 0,
    attribution_version INTEGER NOT NULL DEFAULT 2,
    total_active_http_requests INTEGER NOT NULL DEFAULT 0,
    lane             TEXT NOT NULL DEFAULT '',
    pack_id          TEXT NOT NULL DEFAULT '',
    query_id         TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, source, query)
);
CREATE INDEX IF NOT EXISTS idx_query_metrics_run ON query_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_query_metrics_source_query ON query_metrics (source, query);
ALTER TABLE query_metrics ADD COLUMN IF NOT EXISTS prefilter_survivors INTEGER NOT NULL DEFAULT 0;
ALTER TABLE query_metrics ADD COLUMN IF NOT EXISTS attribution_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE query_metrics ADD COLUMN IF NOT EXISTS total_active_http_requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE query_metrics ADD COLUMN IF NOT EXISTS lane TEXT NOT NULL DEFAULT '';
ALTER TABLE query_metrics ADD COLUMN IF NOT EXISTS pack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE query_metrics ADD COLUMN IF NOT EXISTS query_id TEXT NOT NULL DEFAULT '';
-- When attribution_version=3: query_id stable; active_requests means validation_credentials only

-- Append-only physical HTTP attempt log (metrics v3 denominator).
CREATE TABLE IF NOT EXISTS request_ledger (
    id                    BIGSERIAL PRIMARY KEY,
    request_id            TEXT NOT NULL,
    run_id                TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    stage                 TEXT NOT NULL,
    source                TEXT NOT NULL,
    query_id              TEXT NOT NULL DEFAULT '',
    pack_id               TEXT NOT NULL DEFAULT '',
    credential_fingerprint TEXT,
    target_identity       TEXT NOT NULL DEFAULT '',
    artifact_identity     TEXT NOT NULL DEFAULT '',
    product               TEXT NOT NULL DEFAULT '',
    spec_id               TEXT NOT NULL DEFAULT '',
    provider              TEXT NOT NULL DEFAULT '',
    http_method           TEXT NOT NULL DEFAULT 'GET',
    endpoint_class        TEXT NOT NULL DEFAULT '',
    status_class          TEXT NOT NULL DEFAULT '',
    status_code           INTEGER,
    error_class           TEXT NOT NULL DEFAULT '',
    latency_ms            INTEGER NOT NULL DEFAULT 0,
    request_bytes         INTEGER NOT NULL DEFAULT 0,
    response_bytes        INTEGER NOT NULL DEFAULT 0,
    query_credit          DOUBLE PRECISION NOT NULL DEFAULT 0,
    rate_resource         TEXT NOT NULL DEFAULT 'other',
    attempt               INTEGER NOT NULL DEFAULT 1,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_request_ledger_run ON request_ledger (run_id);
CREATE INDEX IF NOT EXISTS idx_request_ledger_run_stage ON request_ledger (run_id, stage);
CREATE INDEX IF NOT EXISTS idx_request_ledger_run_query
    ON request_ledger (run_id, source, query_id);

-- GitHub source durable checkpoints (shard watermark + cursor).
CREATE TABLE IF NOT EXISTS source_checkpoints (
    source          TEXT NOT NULL,
    lane            TEXT NOT NULL,
    pack_id         TEXT NOT NULL,
    shard_id        TEXT NOT NULL,
    watermark       TEXT NOT NULL DEFAULT '',
    cursor_state    JSONB NOT NULL DEFAULT '{}',
    etag            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'ok',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, lane, pack_id, shard_id)
);

-- GitHub artifact work queue (no plaintext secrets).
CREATE TABLE IF NOT EXISTS github_artifacts (
    repo_id                 TEXT NOT NULL,
    repository_full_name    TEXT NOT NULL,
    commit_sha              TEXT NOT NULL,
    file_path               TEXT NOT NULL DEFAULT '',
    object_sha              TEXT NOT NULL DEFAULT '',
    source_kind             TEXT NOT NULL,
    etag                    TEXT NOT NULL DEFAULT '',
    work_status             TEXT NOT NULL,
    attempts                INTEGER NOT NULL DEFAULT 0,
    last_error_class        TEXT NOT NULL DEFAULT '',
    current_stage           TEXT NOT NULL DEFAULT 'fetch_pending',
    next_retry_at           TIMESTAMPTZ,
    run_id                  TEXT NOT NULL DEFAULT '',
    query_id                TEXT NOT NULL DEFAULT '',
    pack_id                 TEXT NOT NULL DEFAULT '',
    lane                    TEXT NOT NULL DEFAULT '',
    coverage_mode           TEXT NOT NULL DEFAULT 'complete',
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repo_id, commit_sha, file_path, source_kind, object_sha)
);
CREATE INDEX IF NOT EXISTS idx_github_artifacts_status
    ON github_artifacts (work_status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_github_artifacts_run ON github_artifacts (run_id);

CREATE TABLE IF NOT EXISTS extraction_method_aggregates (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (run_id, method)
);

CREATE TABLE IF NOT EXISTS validation_outcome_aggregates (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    query TEXT NOT NULL,
    provider TEXT NOT NULL,
    validation_state TEXT NOT NULL,
    error_class TEXT NOT NULL,
    status_code INTEGER,
    count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validation_outcomes_run
    ON validation_outcome_aggregates (run_id);

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
