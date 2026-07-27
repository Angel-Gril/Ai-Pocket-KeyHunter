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
-- Pipeline phase checkpoint for memory-bounded full-scan resume.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS phase TEXT NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS phase_detail JSONB NOT NULL DEFAULT '{}'::jsonb;

-- One row per valid/suspicious/rejected ValidationResult. `seq` (0-based within
-- (run_id, kind)) replaces the old JSONL file line index used by reveal/export.
CREATE TABLE IF NOT EXISTS results (
    id      BIGSERIAL PRIMARY KEY,
    run_id  TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,                     -- 'valid' | 'suspicious' | 'rejected'
    seq     INTEGER NOT NULL,                  -- 0-based insertion order within (run_id, kind)
    apikey  TEXT,                              -- credential.apikey (plaintext; export/reveal)
    apiurl  TEXT,                              -- credential.apiurl
    host    TEXT,                              -- credential.host
    valid   BOOLEAN,                           -- ValidationResult.valid
    record  JSONB NOT NULL,                    -- full ValidationResult.model_dump()
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- first PostgreSQL persistence time
    UNIQUE (run_id, kind, seq)
);
CREATE INDEX IF NOT EXISTS idx_results_run_kind ON results (run_id, kind, seq);
-- Web/API: list all valid/suspicious across runs (WHERE kind=? ORDER BY run_id DESC, seq)
CREATE INDEX IF NOT EXISTS idx_results_kind_run_seq ON results (kind, run_id DESC, seq);
-- list_runs subquery + reveal/export by id already use PK; apikey helps balance rechecks
CREATE INDEX IF NOT EXISTS idx_results_apikey ON results (apikey) WHERE apikey IS NOT NULL AND apikey <> '';
ALTER TABLE results ADD COLUMN IF NOT EXISTS credential_issuer TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE results ADD COLUMN IF NOT EXISTS validation_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE results ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
DO $$
DECLARE row_item RECORD;
DECLARE parsed_at TIMESTAMPTZ;
BEGIN
    FOR row_item IN
        SELECT r.id, r.record->>'validated_at' AS validated_at,
               runs.finished_at, runs.started_at
        FROM results r
        JOIN runs ON runs.run_id = r.run_id
        WHERE r.created_at IS NULL
    LOOP
        parsed_at := NULL;
        BEGIN
            parsed_at := NULLIF(row_item.validated_at, '')::TIMESTAMPTZ;
        EXCEPTION WHEN OTHERS THEN
            parsed_at := NULL;
        END;
        UPDATE results
        SET created_at = COALESCE(parsed_at, row_item.finished_at, row_item.started_at, NOW())
        WHERE id = row_item.id;
    END LOOP;
END $$;
ALTER TABLE results ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE results ALTER COLUMN created_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_results_created_at ON results (created_at DESC);

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
-- Query planner: WHERE source=? AND query_id=ANY(...) AND attribution_version ...
CREATE INDEX IF NOT EXISTS idx_query_metrics_source_query_id
    ON query_metrics (source, query_id, attribution_version);
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
-- claim_artifact_work: status filter + next_retry window, ordered by last_seen_at
CREATE INDEX IF NOT EXISTS idx_github_artifacts_claim
    ON github_artifacts (work_status, last_seen_at ASC)
    WHERE work_status NOT IN ('terminal', 'source_gone', 'artifact_too_large', 'budget_exhausted');
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
-- Web: ORDER BY saved_at DESC; list_runs: COUNT WHERE run_id = r.run_id
CREATE INDEX IF NOT EXISTS idx_high_value_keys_saved_at
    ON high_value_keys (saved_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_high_value_keys_run_id
    ON high_value_keys (run_id)
    WHERE run_id IS NOT NULL AND run_id <> '';

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

-- Intermediate credential candidates (regex / prober / github / gpt).
-- Spilled during the scan so probe batches and GitHub observations do not
-- accumulate unbounded lists in process memory. Final valid/suspicious rows
-- still land in ``results`` after validation.
CREATE TABLE IF NOT EXISTS scan_candidates (
    id              BIGSERIAL PRIMARY KEY,
    run_id          TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    stage           TEXT NOT NULL,              -- regex | prober | github | gpt
    identity        TEXT NOT NULL,              -- secret_fingerprint:endpoint
    apikey          TEXT NOT NULL DEFAULT '',
    apiurl          TEXT NOT NULL DEFAULT '',
    host            TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT '',   -- fofa | shodan | github | ...
    query_id        TEXT NOT NULL DEFAULT '',
    pack_id         TEXT NOT NULL DEFAULT '',
    lane            TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',   -- ExtractionMethod value
    prefilter_ok    BOOLEAN NOT NULL DEFAULT TRUE,
    record          JSONB NOT NULL,             -- full Credential (+bundle secret)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (run_id, identity)
);
CREATE INDEX IF NOT EXISTS idx_scan_candidates_run ON scan_candidates (run_id);
CREATE INDEX IF NOT EXISTS idx_scan_candidates_run_stage ON scan_candidates (run_id, stage);
CREATE INDEX IF NOT EXISTS idx_scan_candidates_run_source ON scan_candidates (run_id, source);
CREATE INDEX IF NOT EXISTS idx_scan_candidates_run_prefilter
    ON scan_candidates (run_id, prefilter_ok);
-- Keyset page: WHERE run_id=? AND id>? ORDER BY id LIMIT n
CREATE INDEX IF NOT EXISTS idx_scan_candidates_run_id_keyset
    ON scan_candidates (run_id, id);

-- Full FOFA/Shodan discovery hit payloads (body/banner/header intact for GPT).
-- Spilled page-by-page so the scanner process never retains O(total_hits) RAM.
CREATE TABLE IF NOT EXISTS scan_discovery_hits (
    id           BIGSERIAL PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    source       TEXT NOT NULL,              -- fofa | shodan | ...
    entry_id     TEXT NOT NULL,              -- stable identity hash (url/ip:port)
    query_id     TEXT NOT NULL DEFAULT '',
    host         TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    port         TEXT NOT NULL DEFAULT '',
    protocol     TEXT NOT NULL DEFAULT '',
    record       JSONB NOT NULL,             -- FULL hit dict (body/banner/header intact)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (run_id, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_scan_discovery_hits_run
    ON scan_discovery_hits (run_id);
CREATE INDEX IF NOT EXISTS idx_scan_discovery_hits_run_source
    ON scan_discovery_hits (run_id, source);
-- Resume load: WHERE run_id=? ORDER BY id
CREATE INDEX IF NOT EXISTS idx_scan_discovery_hits_run_id
    ON scan_discovery_hits (run_id, id);

-- Per-credential validation outcomes for mid-validate resume without re-probing.
CREATE TABLE IF NOT EXISTS scan_validation_results (
    id               BIGSERIAL PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    identity         TEXT NOT NULL,              -- same as scan_candidates.identity
    valid            BOOLEAN NOT NULL DEFAULT FALSE,
    validation_state TEXT NOT NULL DEFAULT '',
    error            TEXT NOT NULL DEFAULT '',
    record           JSONB NOT NULL,             -- ValidationResult.model_dump()
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (run_id, identity)
);
CREATE INDEX IF NOT EXISTS idx_scan_validation_results_run
    ON scan_validation_results (run_id);
-- Resume load: WHERE run_id=? ORDER BY id
CREATE INDEX IF NOT EXISTS idx_scan_validation_results_run_id
    ON scan_validation_results (run_id, id);

-- Per-batch probe telemetry (outcomes / findings / node_outcomes) without
-- keeping multi-MB evidence blobs in RAM across all batches.
CREATE TABLE IF NOT EXISTS scan_probe_events (
    id              BIGSERIAL PRIMARY KEY,
    run_id          TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,              -- outcome | finding | node_outcome
    record          JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_probe_events_run ON scan_probe_events (run_id);
CREATE INDEX IF NOT EXISTS idx_scan_probe_events_run_type
    ON scan_probe_events (run_id, event_type);

-- Confirmed honeypot / no-auth sites. Loaded at scan start to skip probe /
-- validate HTTP work; written during honeypot finalization (incremental).
-- host_key is the stable match key: hostname:port (scheme-agnostic, lowercase).
CREATE TABLE IF NOT EXISTS honeypot_sites (
    host_key     TEXT PRIMARY KEY,
    host         TEXT NOT NULL,                  -- display form (same as host_key usually)
    reason       TEXT NOT NULL DEFAULT '',       -- honeypot:no-auth-host | manual | ...
    source       TEXT NOT NULL DEFAULT 'auto',  -- auto | manual
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hit_count    INTEGER NOT NULL DEFAULT 1,
    run_id       TEXT,                           -- last confirming scan run
    notes        TEXT NOT NULL DEFAULT '',
    record       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_honeypot_sites_last_seen ON honeypot_sites (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_honeypot_sites_reason ON honeypot_sites (reason);
CREATE INDEX IF NOT EXISTS idx_honeypot_sites_source ON honeypot_sites (source);
CREATE OR REPLACE FUNCTION aipocket_honeypot_group_key(value TEXT)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN split_part(value, ':', 1) ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
            THEN split_part(value, ':', 1)
        WHEN array_length(string_to_array(split_part(value, ':', 1), '.'), 1) >= 3
            THEN array_to_string(
                (string_to_array(split_part(value, ':', 1), '.'))[
                    array_length(string_to_array(split_part(value, ':', 1), '.'), 1)-1:
                    array_length(string_to_array(split_part(value, ':', 1), '.'), 1)
                ],
                '.'
            )
        ELSE split_part(value, ':', 1)
    END
$$;


-- User-supplied relay / gateway origins for manual (non-FOFA/Shodan/GitHub) scans.
-- URL is the canonical scheme://host[:port] form after sanitization (no path).
CREATE TABLE IF NOT EXISTS manual_targets (
    url          TEXT PRIMARY KEY,               -- https://web.ymocode.com
    host_key     TEXT NOT NULL,                  -- hostname:port (scheme-agnostic)
    scheme       TEXT NOT NULL DEFAULT 'https',
    hostname     TEXT NOT NULL DEFAULT '',
    port         INTEGER NOT NULL DEFAULT 443,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    notes        TEXT NOT NULL DEFAULT '',
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    record       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_manual_targets_enabled ON manual_targets (enabled);
CREATE INDEX IF NOT EXISTS idx_manual_targets_last_seen ON manual_targets (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_manual_targets_host_key ON manual_targets (host_key);

-- Orphan recovery: UPDATE runs SET state='interrupted' WHERE state='running'
CREATE INDEX IF NOT EXISTS idx_runs_state ON runs (state) WHERE state = 'running';

-- ---------------------------------------------------------------------------
-- Index rollout notes (VPS with existing data)
-- ---------------------------------------------------------------------------
-- ensure_schema() executes this file on every backend startup via
-- CREATE INDEX IF NOT EXISTS / ALTER TABLE ... IF NOT EXISTS. Redeploying the
-- container or restarting `aipocket serve|scan` is enough for new indexes to
-- be created on the live database; no dump/restore or volume wipe is required.
-- On large tables the first CREATE INDEX may take a few seconds to minutes
-- and will briefly hold a ShareLock; it does not rewrite row data and is safe
-- for an in-place upgrade. Avoid `docker compose down -v` (that drops PG data).
