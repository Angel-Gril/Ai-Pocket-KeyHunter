use crate::RequestLedgerEntry;
use aipocket_core::{HoneypotSite, ManualTarget, RunDay, RunSummary};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct QueryMetricRecord {
    pub source: String,
    pub query: String,
    pub query_id: String,
    pub pack_id: String,
    pub lane: String,
    pub funnel: aipocket_core::QueryFunnel,
    pub query_credits: i64,
    pub attribution_version: i32,
}

#[derive(Clone, Default)]
pub struct Repository {
    pool: Option<Arc<PgPool>>,
}

pub struct BalancePersistence<'a> {
    pub result_id: Option<i64>,
    pub apikey: &'a str,
    pub gateway: &'a str,
    pub balance: &'a str,
    pub tier: &'a str,
    pub detail: &'a Value,
    pub high_value: bool,
}

impl Repository {
    pub fn new(pool: Option<PgPool>) -> Self {
        Self {
            pool: pool.map(Arc::new),
        }
    }
    pub fn pool(&self) -> Option<&PgPool> {
        self.pool.as_deref()
    }
    fn require_pool(&self) -> Result<&PgPool> {
        self.pool().context("DATABASE_URL not configured")
    }

    pub async fn seed_cves(&self) -> Result<u64> {
        let Some(pool) = self.pool() else {
            return Ok(0);
        };
        let records: Vec<Value> = serde_json::from_str(include_str!("../data/cve_seed.json"))?;
        let mut inserted = 0;
        for record in records {
            let Some(id) = record.get("id").and_then(Value::as_str) else {
                continue;
            };
            inserted +=
                sqlx::query("INSERT INTO cves(id,record) VALUES($1,$2) ON CONFLICT(id) DO NOTHING")
                    .bind(id)
                    .bind(&record)
                    .execute(pool)
                    .await?
                    .rows_affected();
        }
        Ok(inserted)
    }

    pub async fn list_runs(&self) -> Result<Vec<RunDay>> {
        let pool = match self.pool() {
            Some(pool) => pool,
            None => return Ok(Vec::new()),
        };
        let rows = sqlx::query(
            r#"SELECT r.run_id, r.started_at, r.total_hosts, r.total_credentials, r.total_valid,
                r.raw_hits, r.unique_targets, r.candidates, r.active_requests, r.final_verified,
                r.suspicious, r.high_value_final, r.metrics_version, r.scan_mode, r.sources,
                r.hits_by_source, (r.log IS NOT NULL AND r.log <> '') AS has_log,
                COUNT(*) FILTER (WHERE x.kind='valid') AS valid_count,
                COUNT(*) FILTER (WHERE x.kind='suspicious') AS suspicious_count,
                COALESCE((SELECT COUNT(*) FROM high_value_keys h WHERE h.run_id=r.run_id),0) AS hv_count
               FROM runs r LEFT JOIN results x ON x.run_id=r.run_id
               GROUP BY r.run_id ORDER BY r.run_id DESC"#,
        ).fetch_all(pool).await?;
        let mut days: Vec<RunDay> = Vec::new();
        for row in rows {
            let run_id: String = row.try_get("run_id")?;
            let day = run_day(&run_id);
            let valid_count: i64 = row.try_get("valid_count")?;
            let suspicious_count: i64 = row.try_get("suspicious_count")?;
            let sources: Option<Value> = row.try_get("sources")?;
            let started: DateTime<Utc> = row.try_get("started_at")?;
            let metrics_version: i32 = row.try_get("metrics_version")?;
            let stored_hv: i32 = row.try_get("high_value_final")?;
            let live_hv: i64 = row.try_get("hv_count")?;
            let entry = RunSummary {
                run_id: run_id.clone(),
                started_at: started.to_rfc3339(),
                valid_count,
                suspicious_count,
                has_log: row.try_get("has_log")?,
                raw_hits: positive(&[
                    row.try_get::<i32, _>("raw_hits")? as i64,
                    json_sum(row.try_get("hits_by_source")?),
                    row.try_get::<Option<i32>, _>("total_hosts")?.unwrap_or(0) as i64,
                    row.try_get::<Option<i32>, _>("total_credentials")?
                        .unwrap_or(0) as i64,
                ]),
                unique_targets: positive(&[
                    row.try_get::<i32, _>("unique_targets")? as i64,
                    row.try_get::<Option<i32>, _>("total_hosts")?.unwrap_or(0) as i64,
                    row.try_get::<i32, _>("candidates")? as i64,
                ]),
                candidates: positive(&[
                    row.try_get::<i32, _>("candidates")? as i64,
                    row.try_get::<Option<i32>, _>("total_credentials")?
                        .unwrap_or(0) as i64,
                ]),
                active_requests: row.try_get::<i32, _>("active_requests")? as i64,
                final_verified: if valid_count > 0 {
                    valid_count
                } else {
                    positive(&[
                        row.try_get::<i32, _>("final_verified")? as i64,
                        row.try_get::<Option<i32>, _>("total_valid")?.unwrap_or(0) as i64,
                    ])
                },
                suspicious: if suspicious_count > 0 {
                    suspicious_count
                } else {
                    row.try_get::<i32, _>("suspicious")? as i64
                },
                sources: json_strings(sources),
                scan_mode: row.try_get("scan_mode")?,
                high_value_final: if metrics_version >= 2 {
                    stored_hv as i64
                } else {
                    positive(&[stored_hv as i64, live_hv])
                },
                deletable: true,
            };
            if let Some(group) = days.last_mut().filter(|group| group.day == day) {
                group.runs.push(entry);
            } else {
                days.push(RunDay {
                    day,
                    runs: vec![entry],
                });
            }
        }
        Ok(days)
    }

    pub async fn run_records(&self, run_id: &str, kind: &str, masked: bool) -> Result<Vec<Value>> {
        validate_kind(kind)?;
        let pool = self.require_pool()?;
        let rows = sqlx::query(
            "SELECT id, created_at, record FROM results WHERE run_id=$1 AND kind=$2 ORDER BY seq",
        )
        .bind(run_id)
        .bind(kind)
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let mut record: Value = row.try_get("record").ok()?;
                let object = record.as_object_mut()?;
                object.insert(
                    "result_id".into(),
                    Value::from(row.try_get::<i64, _>("id").ok()?),
                );
                if let Ok(created_at) = row.try_get::<DateTime<Utc>, _>("created_at") {
                    object.insert("created_at".into(), Value::String(created_at.to_rfc3339()));
                }
                if masked {
                    mask_record(&mut record);
                }
                Some(record)
            })
            .collect())
    }

    pub async fn all_records(&self, kind: &str, masked: bool) -> Result<Vec<Value>> {
        validate_kind(kind)?;
        let pool = self.require_pool()?;
        let rows = sqlx::query("SELECT id, run_id, created_at, record FROM results WHERE kind=$1 ORDER BY run_id DESC, seq")
            .bind(kind).fetch_all(pool).await?;
        let mut seen = std::collections::HashSet::new();
        let mut positions = std::collections::HashMap::<String, usize>::new();
        let mut output = Vec::new();
        for row in rows {
            let mut record: Value = row.try_get("record")?;
            let run_id: String = row.try_get("run_id")?;
            let index = positions.entry(run_id.clone()).or_default();
            let apikey = record
                .pointer("/credential/apikey")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if apikey.is_empty() || !seen.insert(apikey) {
                *index += 1;
                continue;
            }
            if let Some(object) = record.as_object_mut() {
                object.insert(
                    "result_id".into(),
                    Value::from(row.try_get::<i64, _>("id")?),
                );
                object.insert("source_run_id".into(), Value::String(run_id));
                object.insert("source_index".into(), Value::from(*index));
                if let Ok(created_at) = row.try_get::<DateTime<Utc>, _>("created_at") {
                    object.insert("created_at".into(), Value::String(created_at.to_rfc3339()));
                }
            }
            *index += 1;
            if masked {
                mask_record(&mut record);
            }
            output.push(record);
        }
        Ok(output)
    }

    pub async fn high_value(&self, masked: bool) -> Result<Vec<Value>> {
        let pool = self.require_pool()?;
        let rows = sqlx::query("SELECT apikey, run_id, saved_at, record FROM high_value_keys ORDER BY saved_at DESC NULLS LAST")
            .fetch_all(pool).await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let key: String = row.try_get("apikey").ok()?;
                let mut record: Value = row.try_get("record").ok()?;
                let object = record.as_object_mut()?;
                object.entry("apikey").or_insert_with(|| Value::String(key));
                if masked && let Some(value) = object.get_mut("apikey") {
                    *value = Value::String(mask_apikey(value.as_str().unwrap_or_default()));
                }
                Some(record)
            })
            .collect())
    }

    pub async fn cves(&self) -> Result<Vec<Value>> {
        let pool = self.require_pool()?;
        Ok(
            sqlx::query_scalar::<_, Value>("SELECT record FROM cves ORDER BY id")
                .fetch_all(pool)
                .await?,
        )
    }

    pub async fn run_log(&self, run_id: &str) -> Result<Option<String>> {
        let pool = match self.pool() {
            Some(pool) => pool,
            None => return Ok(None),
        };
        Ok(sqlx::query_scalar("SELECT log FROM runs WHERE run_id=$1")
            .bind(run_id)
            .fetch_optional(pool)
            .await?
            .flatten())
    }

    pub async fn list_honeypots(
        &self,
        q: &str,
        source: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<HoneypotSite>, i64)> {
        let pool = self.require_pool()?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM honeypot_sites WHERE ($1='' OR host ILIKE '%'||$1||'%' OR reason ILIKE '%'||$1||'%') AND ($2::text IS NULL OR source=$2)")
            .bind(q).bind(source).fetch_one(pool).await?;
        let rows = sqlx::query("SELECT host_key,host,reason,source,first_seen,last_seen,hit_count,COALESCE(run_id,''),notes FROM honeypot_sites WHERE ($1='' OR host ILIKE '%'||$1||'%' OR reason ILIKE '%'||$1||'%') AND ($2::text IS NULL OR source=$2) ORDER BY last_seen DESC LIMIT $3 OFFSET $4")
            .bind(q).bind(source).bind(limit).bind(offset).fetch_all(pool).await?;
        let items = rows
            .into_iter()
            .map(|r| {
                Ok(HoneypotSite {
                    host_key: r.try_get(0)?,
                    host: r.try_get(1)?,
                    reason: r.try_get(2)?,
                    source: r.try_get(3)?,
                    first_seen: r.try_get::<DateTime<Utc>, _>(4)?.to_rfc3339(),
                    last_seen: r.try_get::<DateTime<Utc>, _>(5)?.to_rfc3339(),
                    hit_count: i64::from(r.try_get::<i32, _>(6)?),
                    run_id: r.try_get(7)?,
                    notes: r.try_get(8)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((items, total))
    }

    pub async fn list_manual_targets(
        &self,
        enabled_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ManualTarget>, i64)> {
        let pool = self.require_pool()?;
        let total =
            sqlx::query_scalar("SELECT COUNT(*) FROM manual_targets WHERE NOT $1 OR enabled")
                .bind(enabled_only)
                .fetch_one(pool)
                .await?;
        let rows=sqlx::query("SELECT url,host_key,scheme,hostname,port,enabled,notes,first_seen,last_seen FROM manual_targets WHERE NOT $1 OR enabled ORDER BY last_seen DESC LIMIT $2 OFFSET $3").bind(enabled_only).bind(limit).bind(offset).fetch_all(pool).await?;
        let items = rows
            .into_iter()
            .map(|r| {
                Ok(ManualTarget {
                    url: r.try_get(0)?,
                    host_key: r.try_get(1)?,
                    scheme: r.try_get(2)?,
                    hostname: r.try_get(3)?,
                    port: r.try_get::<i32, _>(4)? as u16,
                    enabled: r.try_get(5)?,
                    notes: r.try_get(6)?,
                    first_seen: r.try_get::<DateTime<Utc>, _>(7)?.to_rfc3339(),
                    last_seen: r.try_get::<DateTime<Utc>, _>(8)?.to_rfc3339(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((items, total))
    }
    pub async fn create_honeypot(
        &self,
        host: &str,
        host_key: &str,
        reason: &str,
        notes: &str,
    ) -> Result<HoneypotSite> {
        let pool = self.require_pool()?;
        let row = sqlx::query("INSERT INTO honeypot_sites(host_key,host,reason,source,notes) VALUES($1,$2,$3,'manual',$4) ON CONFLICT(host_key) DO UPDATE SET host=EXCLUDED.host, reason=EXCLUDED.reason, notes=EXCLUDED.notes, source='manual', last_seen=NOW(), hit_count=honeypot_sites.hit_count+1 RETURNING host_key,host,reason,source,first_seen,last_seen,hit_count,COALESCE(run_id,''),notes")
            .bind(host_key).bind(host).bind(reason).bind(notes).fetch_one(pool).await?;
        row_to_honeypot(&row)
    }

    pub async fn update_honeypot(
        &self,
        host_key: &str,
        reason: Option<&str>,
        notes: Option<&str>,
    ) -> Result<Option<HoneypotSite>> {
        let pool = self.require_pool()?;
        let row = sqlx::query("UPDATE honeypot_sites SET reason=COALESCE($2,reason),notes=COALESCE($3,notes),last_seen=NOW() WHERE host_key=$1 RETURNING host_key,host,reason,source,first_seen,last_seen,hit_count,COALESCE(run_id,''),notes")
            .bind(host_key).bind(reason).bind(notes).fetch_optional(pool).await?;
        row.as_ref().map(row_to_honeypot).transpose()
    }

    pub async fn delete_honeypots(&self, host_keys: &[String]) -> Result<u64> {
        let pool = self.require_pool()?;
        Ok(
            sqlx::query("DELETE FROM honeypot_sites WHERE host_key = ANY($1)")
                .bind(host_keys)
                .execute(pool)
                .await?
                .rows_affected(),
        )
    }

    pub async fn upsert_manual_target(&self, target: &ManualTarget) -> Result<ManualTarget> {
        let pool = self.require_pool()?;
        let row = sqlx::query("INSERT INTO manual_targets(url,host_key,scheme,hostname,port,enabled,notes) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(url) DO UPDATE SET host_key=EXCLUDED.host_key,scheme=EXCLUDED.scheme,hostname=EXCLUDED.hostname,port=EXCLUDED.port,enabled=EXCLUDED.enabled,notes=EXCLUDED.notes,last_seen=NOW() RETURNING url,host_key,scheme,hostname,port,enabled,notes,first_seen,last_seen")
            .bind(&target.url).bind(&target.host_key).bind(&target.scheme).bind(&target.hostname).bind(i32::from(target.port)).bind(target.enabled).bind(&target.notes).fetch_one(pool).await?;
        row_to_manual_target(&row)
    }

    pub async fn delete_manual_targets(&self, urls: &[String]) -> Result<u64> {
        let pool = self.require_pool()?;
        Ok(
            sqlx::query("DELETE FROM manual_targets WHERE url = ANY($1)")
                .bind(urls)
                .execute(pool)
                .await?
                .rows_affected(),
        )
    }
    pub async fn create_run(
        &self,
        run_id: &str,
        started_at: DateTime<Utc>,
        scan_mode: &str,
    ) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        sqlx::query("INSERT INTO runs(run_id,started_at,state,scan_mode) VALUES($1,$2,'running',$3) ON CONFLICT(run_id) DO NOTHING")
            .bind(run_id).bind(started_at).bind(scan_mode).execute(pool).await?;
        Ok(())
    }

    pub async fn insert_results(&self, run_id: &str, kind: &str, rows: &[Value]) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        let mut transaction = pool.begin().await?;
        for (seq, record) in rows.iter().enumerate() {
            let credential = record.get("credential").and_then(Value::as_object);
            sqlx::query("INSERT INTO results(run_id,kind,seq,apikey,apiurl,host,valid,record) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(run_id,kind,seq) DO UPDATE SET apikey=EXCLUDED.apikey,apiurl=EXCLUDED.apiurl,host=EXCLUDED.host,valid=EXCLUDED.valid,record=EXCLUDED.record")
                .bind(run_id).bind(kind).bind(seq as i32)
                .bind(credential.and_then(|v| v.get("apikey")).and_then(Value::as_str).unwrap_or_default())
                .bind(credential.and_then(|v| v.get("apiurl")).and_then(Value::as_str).unwrap_or_default())
                .bind(credential.and_then(|v| v.get("host")).and_then(Value::as_str).unwrap_or_default())
                .bind(record.get("valid").and_then(Value::as_bool).unwrap_or(false)).bind(record)
                .execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn finish_run(
        &self,
        run_id: &str,
        state: &str,
        progress: &aipocket_core::ScanProgress,
        log: &str,
    ) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        sqlx::query("UPDATE runs SET finished_at=NOW(),state=$2,raw_hits=$3,unique_targets=$4,candidates=$5,active_requests=$6,final_verified=$7,suspicious=$8,high_value_final=$9,log=$10 WHERE run_id=$1")
            .bind(run_id).bind(state).bind(progress.raw_hits as i64).bind(progress.unique_targets as i64).bind(progress.candidates as i64).bind(progress.active_requests as i64).bind(progress.final_verified as i64).bind(progress.suspicious as i64).bind(progress.high_value_final as i64).bind(log).execute(pool).await?;
        Ok(())
    }
    pub async fn set_run_log(&self, run_id: &str, log: &str) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        sqlx::query("UPDATE runs SET log=$2 WHERE run_id=$1")
            .bind(run_id)
            .bind(log)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Most recently started run still marked `running` (for error recovery / fail_run).
    pub async fn latest_running_run_id(&self) -> Result<Option<String>> {
        let Some(pool) = self.pool() else {
            return Ok(None);
        };
        Ok(sqlx::query_scalar(
            "SELECT run_id FROM runs WHERE state='running' ORDER BY started_at DESC LIMIT 1",
        )
        .fetch_optional(pool)
        .await?)
    }

    pub async fn append_ledger(&self, entries: &[RequestLedgerEntry]) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        let mut transaction = pool.begin().await?;
        for entry in entries {
            sqlx::query("INSERT INTO request_ledger(request_id,run_id,stage,source,query_id,pack_id,credential_fingerprint,target_identity,artifact_identity,product,spec_id,provider,http_method,endpoint_class,status_class,status_code,error_class,latency_ms,request_bytes,response_bytes,query_credit,rate_resource,attempt,started_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)")
                .bind(&entry.request_id).bind(&entry.run_id).bind(&entry.stage).bind(&entry.source).bind(&entry.query_id).bind(&entry.pack_id).bind(&entry.credential_fingerprint).bind(&entry.target_identity).bind(&entry.artifact_identity).bind(&entry.product).bind(&entry.spec_id).bind(&entry.provider).bind(&entry.http_method).bind(&entry.endpoint_class).bind(&entry.status_class).bind(entry.status_code).bind(&entry.error_class).bind(entry.latency_ms).bind(entry.request_bytes).bind(entry.response_bytes).bind(entry.query_credit).bind(&entry.rate_resource).bind(entry.attempt).bind(entry.started_at).execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }
    pub async fn persist_query_metrics(
        &self,
        run_id: &str,
        metrics: &[QueryMetricRecord],
    ) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        let mut transaction = pool.begin().await?;
        for metric in metrics {
            let funnel = &metric.funnel;
            sqlx::query("INSERT INTO query_metrics(run_id,source,query,raw_hits,unique_targets,active_requests,candidates,prefilter_survivors,auth_confirmed,final_verified,noauth_rejected,query_credits,attribution_version,total_active_http_requests,lane,pack_id,query_id) VALUES($1,$2,$3,$4,$5,$6,$7,0,0,$8,0,$9,$10,$11,$12,$13,$14) ON CONFLICT(run_id,source,query) DO UPDATE SET raw_hits=EXCLUDED.raw_hits,unique_targets=EXCLUDED.unique_targets,active_requests=EXCLUDED.active_requests,candidates=EXCLUDED.candidates,final_verified=EXCLUDED.final_verified,query_credits=EXCLUDED.query_credits,attribution_version=EXCLUDED.attribution_version,total_active_http_requests=EXCLUDED.total_active_http_requests,lane=EXCLUDED.lane,pack_id=EXCLUDED.pack_id,query_id=EXCLUDED.query_id")
                .bind(run_id).bind(&metric.source).bind(&metric.query).bind(funnel.raw_hits as i64).bind(funnel.unique_targets as i64).bind(funnel.active_requests as i64).bind(funnel.candidates as i64).bind(funnel.final_verified as i64).bind(metric.query_credits).bind(metric.attribution_version).bind(funnel.total_active_http_requests as i64).bind(&metric.lane).bind(&metric.pack_id).bind(&metric.query_id).execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn plan_query_ids(
        &self,
        source: &str,
        query_ids: &[String],
        version: u8,
        budget: usize,
    ) -> Result<Vec<String>> {
        if budget >= query_ids.len() || self.pool().is_none() {
            return Ok(query_ids.iter().take(budget).cloned().collect());
        }
        let pool = self.require_pool()?;
        let rows = if version >= 3 {
            sqlx::query("SELECT qm.query_id,COALESCE(SUM(qm.final_verified),0)::bigint AS verified,COALESCE(SUM(qm.total_active_http_requests),0)::bigint AS requests FROM query_metrics qm JOIN runs r ON r.run_id=qm.run_id WHERE qm.source=$1 AND qm.query_id=ANY($2) AND qm.attribution_version>=3 AND r.ledger_complete GROUP BY qm.query_id")
                .bind(source)
                .bind(query_ids)
                .fetch_all(pool)
                .await?
        } else {
            sqlx::query("SELECT query_id,COALESCE(SUM(final_verified),0)::bigint AS verified,COALESCE(SUM(active_requests),0)::bigint AS requests FROM query_metrics WHERE source=$1 AND query_id=ANY($2) AND attribution_version=2 GROUP BY query_id")
                .bind(source)
                .bind(query_ids)
                .fetch_all(pool)
                .await?
        };
        let history = rows
            .into_iter()
            .map(|row| {
                let requests: i64 = row.try_get("requests")?;
                let verified: i64 = row.try_get("verified")?;
                Ok((
                    row.try_get::<String, _>("query_id")?,
                    (verified as f64) / (requests.max(10) as f64),
                ))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        let mut ranked = query_ids
            .iter()
            .enumerate()
            .map(|(index, query)| (query.clone(), *history.get(query).unwrap_or(&0.0), index))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.2.cmp(&right.2))
        });
        ranked.truncate(budget);
        Ok(ranked.into_iter().map(|row| row.0).collect())
    }

    pub async fn source_checkpoint(
        &self,
        source: &str,
        lane: &str,
        pack_id: &str,
        shard_id: &str,
    ) -> Result<Option<crate::SourceCheckpoint>> {
        let Some(pool) = self.pool() else {
            return Ok(None);
        };
        let row = sqlx::query("SELECT source,lane,pack_id,shard_id,watermark,cursor_state,etag,status FROM source_checkpoints WHERE source=$1 AND lane=$2 AND pack_id=$3 AND shard_id=$4")
            .bind(source)
            .bind(lane)
            .bind(pack_id)
            .bind(shard_id)
            .fetch_optional(pool)
            .await?;
        row.map(|row| {
            Ok(crate::SourceCheckpoint {
                source: row.try_get("source")?,
                lane: row.try_get("lane")?,
                pack_id: row.try_get("pack_id")?,
                shard_id: row.try_get("shard_id")?,
                watermark: row.try_get("watermark")?,
                cursor_state: row.try_get("cursor_state")?,
                etag: row.try_get("etag")?,
                status: row.try_get("status")?,
            })
        })
        .transpose()
    }

    pub async fn ledger_summary(&self, run_id: &str) -> Result<(u64, bool, String)> {
        let Some(pool) = self.pool() else {
            return Ok((0, false, "pg_disabled".into()));
        };
        let rows = sqlx::query("SELECT stage,COUNT(*)::bigint AS count FROM request_ledger WHERE run_id=$1 GROUP BY stage")
            .bind(run_id)
            .fetch_all(pool)
            .await?;
        let total = rows
            .iter()
            .map(|row| row.try_get::<i64, _>("count"))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<i64>() as u64;
        let stages = rows
            .iter()
            .map(|row| row.try_get::<String, _>("stage"))
            .collect::<std::result::Result<std::collections::HashSet<_>, _>>()?;
        let complete = stages.contains("validation");
        Ok((
            total,
            complete,
            if complete {
                String::new()
            } else {
                "validation instrumentation missing".into()
            },
        ))
    }

    pub async fn finish_run_metrics(
        &self,
        run_id: &str,
        total_active_http_requests: u64,
        ledger_complete: bool,
        reason: &str,
    ) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        sqlx::query("UPDATE runs SET total_active_http_requests=$2,ledger_complete=$3,ledger_incomplete_reason=$4,metrics_version=$5 WHERE run_id=$1")
            .bind(run_id).bind(total_active_http_requests as i64).bind(ledger_complete).bind(reason).bind(if ledger_complete { 3 } else { 2 }).execute(pool).await?;
        Ok(())
    }
    pub async fn resumable_run(&self, run_id: &str) -> Result<Option<(String, String)>> {
        let pool = self.require_pool()?;
        Ok(sqlx::query_as::<_, (String, String)>(
            "SELECT COALESCE(state,''), COALESCE(phase,'') FROM runs WHERE run_id=$1",
        )
        .bind(run_id)
        .fetch_optional(pool)
        .await?)
    }

    pub async fn resume_phase(&self, run_id: &str) -> Result<Option<String>> {
        let Some(pool) = self.pool() else {
            return Ok(None);
        };
        Ok(
            sqlx::query_scalar("SELECT NULLIF(phase,'') FROM runs WHERE run_id=$1")
                .bind(run_id)
                .fetch_optional(pool)
                .await?
                .flatten(),
        )
    }

    pub async fn update_phase(&self, run_id: &str, phase: &str, detail: Value) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        sqlx::query("UPDATE runs SET phase=$2,phase_detail=$3 WHERE run_id=$1")
            .bind(run_id)
            .bind(phase)
            .bind(detail)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn mark_orphan_runs_interrupted(&self) -> Result<u64> {
        let Some(pool) = self.pool() else {
            return Ok(0);
        };
        Ok(sqlx::query("UPDATE runs SET state='interrupted',finished_at=COALESCE(finished_at,NOW()) WHERE state='running'").execute(pool).await?.rows_affected())
    }
    pub async fn delete_run(&self, run_id: &str) -> Result<bool> {
        let pool = self.require_pool()?;
        Ok(sqlx::query("DELETE FROM runs WHERE run_id=$1")
            .bind(run_id)
            .execute(pool)
            .await?
            .rows_affected()
            > 0)
    }

    pub async fn promote_results(
        &self,
        result_ids: &[i64],
        note: &str,
    ) -> Result<(Vec<i64>, Vec<i64>)> {
        let pool = self.require_pool()?;
        let rows = sqlx::query(
            "SELECT id,run_id,apikey,record FROM results WHERE id = ANY($1) AND kind='valid'",
        )
        .bind(result_ids)
        .fetch_all(pool)
        .await?;
        let mut promoted = Vec::new();
        let mut found = std::collections::HashSet::new();
        for row in rows {
            let id: i64 = row.try_get("id")?;
            found.insert(id);
            let key: String = row
                .try_get::<Option<String>, _>("apikey")?
                .unwrap_or_default();
            if key.is_empty() {
                continue;
            }
            let mut record: Value = row.try_get("record")?;
            if let Some(object) = record.as_object_mut() {
                object.insert("note".into(), Value::String(note.into()));
                object.insert("saved_at".into(), Value::String(Utc::now().to_rfc3339()));
            }
            sqlx::query("INSERT INTO high_value_keys(apikey,run_id,saved_at,record) VALUES($1,$2,NOW(),$3) ON CONFLICT(apikey) DO UPDATE SET run_id=EXCLUDED.run_id,saved_at=EXCLUDED.saved_at,record=EXCLUDED.record").bind(key).bind(row.try_get::<String,_>("run_id")?).bind(record).execute(pool).await?;
            promoted.push(id);
        }
        let skipped = result_ids
            .iter()
            .copied()
            .filter(|id| !found.contains(id))
            .collect();
        Ok((promoted, skipped))
    }

    pub async fn append_results(&self, run_id: &str, kind: &str, rows: &[Value]) -> Result<()> {
        let Some(pool) = self.pool() else {
            return Ok(());
        };
        let start: Option<i32> =
            sqlx::query_scalar("SELECT MAX(seq)+1 FROM results WHERE run_id=$1 AND kind=$2")
                .bind(run_id)
                .bind(kind)
                .fetch_one(pool)
                .await?;
        let start = start.unwrap_or(0);
        let mut transaction = pool.begin().await?;
        for (seq, record) in rows.iter().enumerate() {
            let credential = record.get("credential").and_then(Value::as_object);
            sqlx::query("INSERT INTO results(run_id,kind,seq,apikey,apiurl,host,valid,record) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(run_id).bind(kind).bind(start+seq as i32).bind(credential.and_then(|v|v.get("apikey")).and_then(Value::as_str).unwrap_or_default()).bind(credential.and_then(|v|v.get("apiurl")).and_then(Value::as_str).unwrap_or_default()).bind(credential.and_then(|v|v.get("host")).and_then(Value::as_str).unwrap_or_default()).bind(record.get("valid").and_then(Value::as_bool).unwrap_or(false)).bind(record).execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn persist_balance(&self, update: BalancePersistence<'_>) -> Result<(bool, bool)> {
        let BalancePersistence {
            result_id,
            apikey,
            gateway,
            balance,
            tier,
            detail,
            high_value,
        } = update;
        let pool = self.require_pool()?;
        let updated = if let Some(id) = result_id {
            sqlx::query("UPDATE results SET record=jsonb_set(jsonb_set(jsonb_set(jsonb_set(record,'{gateway}',to_jsonb($2::text),true),'{balance}',to_jsonb($3::text),true),'{tier}',to_jsonb($4::text),true),'{provider_evidence}',$5,true) WHERE id=$1")
                .bind(id).bind(gateway).bind(balance).bind(tier).bind(detail).execute(pool).await?.rows_affected() > 0
        } else {
            false
        };
        let high_updated = if high_value {
            sqlx::query("UPDATE high_value_keys SET record=jsonb_set(jsonb_set(jsonb_set(jsonb_set(record,'{gateway}',to_jsonb($2::text),true),'{balance}',to_jsonb($3::text),true),'{tier}',to_jsonb($4::text),true),'{provider_evidence}',$5,true) WHERE apikey=$1")
                .bind(apikey).bind(gateway).bind(balance).bind(tier).bind(detail).execute(pool).await?.rows_affected() > 0
        } else {
            false
        };
        Ok((updated, high_updated))
    }

    pub async fn upsert_high_value(&self, run_id: &str, record: &Value) -> Result<bool> {
        let Some(pool) = self.pool() else {
            return Ok(false);
        };
        let apikey = record
            .get("apikey")
            .and_then(Value::as_str)
            .context("high-value apikey missing")?;
        Ok(sqlx::query("INSERT INTO high_value_keys(apikey,run_id,saved_at,record) VALUES($1,$2,NOW(),$3) ON CONFLICT(apikey) DO UPDATE SET run_id=EXCLUDED.run_id,saved_at=EXCLUDED.saved_at,record=EXCLUDED.record")
            .bind(apikey)
            .bind(run_id)
            .bind(record)
            .execute(pool)
            .await?
            .rows_affected() > 0)
    }

    pub async fn upsert_cve(&self, record: &Value) -> Result<bool> {
        let pool = self.require_pool()?;
        let id = record
            .get("id")
            .or_else(|| record.get("cve_id"))
            .or_else(|| record.get("advisory_id"))
            .and_then(Value::as_str)
            .context("CVE id missing")?;
        Ok(
            sqlx::query("INSERT INTO cves(id,record) VALUES($1,$2) ON CONFLICT(id) DO NOTHING")
                .bind(id)
                .bind(record)
                .execute(pool)
                .await?
                .rows_affected()
                > 0,
        )
    }
}

fn row_to_honeypot(row: &sqlx::postgres::PgRow) -> Result<HoneypotSite> {
    Ok(HoneypotSite {
        host_key: row.try_get(0)?,
        host: row.try_get(1)?,
        reason: row.try_get(2)?,
        source: row.try_get(3)?,
        first_seen: row.try_get::<DateTime<Utc>, _>(4)?.to_rfc3339(),
        last_seen: row.try_get::<DateTime<Utc>, _>(5)?.to_rfc3339(),
        hit_count: i64::from(row.try_get::<i32, _>(6)?),
        run_id: row.try_get(7)?,
        notes: row.try_get(8)?,
    })
}

fn row_to_manual_target(row: &sqlx::postgres::PgRow) -> Result<ManualTarget> {
    Ok(ManualTarget {
        url: row.try_get(0)?,
        host_key: row.try_get(1)?,
        scheme: row.try_get(2)?,
        hostname: row.try_get(3)?,
        port: row.try_get::<i32, _>(4)? as u16,
        enabled: row.try_get(5)?,
        notes: row.try_get(6)?,
        first_seen: row.try_get::<DateTime<Utc>, _>(7)?.to_rfc3339(),
        last_seen: row.try_get::<DateTime<Utc>, _>(8)?.to_rfc3339(),
    })
}

pub fn mask_apikey(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    if key.len() <= 8 {
        return "*".repeat(key.len());
    }
    let start = &key[..key
        .char_indices()
        .nth(4)
        .map(|(i, _)| i)
        .unwrap_or(key.len())];
    let tail_start = key.char_indices().rev().nth(3).map(|(i, _)| i).unwrap_or(0);
    format!("{start}****{}", &key[tail_start..])
}
fn mask_record(record: &mut Value) {
    if let Some(key) = record.pointer_mut("/credential/apikey") {
        *key = Value::String(mask_apikey(key.as_str().unwrap_or_default()));
    }
}
fn validate_kind(kind: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(kind, "valid" | "suspicious"),
        "invalid kind: {kind}"
    );
    Ok(())
}
fn positive(values: &[i64]) -> i64 {
    values.iter().copied().find(|v| *v > 0).unwrap_or(0)
}
fn json_sum(value: Option<Value>) -> i64 {
    value
        .and_then(|v| {
            v.as_object()
                .map(|o| o.values().filter_map(Value::as_i64).sum())
        })
        .unwrap_or(0)
}
fn json_strings(value: Option<Value>) -> Vec<String> {
    match value {
        Some(Value::Array(v)) => v
            .into_iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        Some(Value::String(v)) => v
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => vec![],
    }
}
fn run_day(id: &str) -> String {
    let parts: Vec<_> = id.split('_').collect();
    if parts.len() >= 4 {
        format!("{}-{}-{}", parts[1], parts[2], parts[3])
    } else {
        "unknown".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn masks_key_but_keeps_shape() {
        assert_eq!(mask_apikey("sk-1234567890"), "sk-1****7890");
    }
    #[test]
    fn groups_run_day() {
        assert_eq!(run_day("run_2026_07_24_12-00-00"), "2026-07-24");
    }
}
