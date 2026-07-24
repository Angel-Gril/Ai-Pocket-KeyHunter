use aipocket_core::{Credential, QueryFunnel, ValidationResult};
use serde_json::Value;
use sha1::{Digest, Sha1};
use sqlx::{PgPool, Row};

#[derive(Clone, Debug, Default)]
pub struct PlannerCandidate {
    pub query_id: String,
    pub source: String,
    pub pack_id: String,
    pub funnel: QueryFunnel,
    pub query_credit: f64,
}
impl PlannerCandidate {
    pub fn score_v2(&self) -> f64 {
        self.funnel.effective_yield_v2()
    }
    pub fn score_v3(&self) -> f64 {
        self.funnel.effective_yield_v3()
    }
}
pub fn plan_queries(
    mut values: Vec<PlannerCandidate>,
    version: u8,
    budget: usize,
) -> Vec<PlannerCandidate> {
    values.sort_by(|a, b| {
        let sa = if version >= 3 {
            a.score_v3()
        } else {
            a.score_v2()
        };
        let sb = if version >= 3 {
            b.score_v3()
        } else {
            b.score_v2()
        };
        sb.total_cmp(&sa).then_with(|| a.query_id.cmp(&b.query_id))
    });
    values.truncate(budget);
    values
}

pub async fn upsert_candidates(
    pool: &PgPool,
    run_id: &str,
    credentials: &[Credential],
) -> anyhow::Result<u64> {
    let mut written = 0;
    for credential in credentials {
        let identity = format!(
            "{:x}",
            Sha1::digest(format!("{}|{}", credential.apikey, credential.apiurl).as_bytes())
        );
        written+=sqlx::query("INSERT INTO scan_candidates(run_id,stage,identity,apikey,apiurl,host,source,record) VALUES($1,'regex',$2,$3,$4,$5,$6,$7) ON CONFLICT(run_id,identity) DO UPDATE SET record=EXCLUDED.record").bind(run_id).bind(identity).bind(&credential.apikey).bind(&credential.apiurl).bind(&credential.host).bind(&credential.backend).bind(serde_json::to_value(credential)?).execute(pool).await?.rows_affected();
    }
    Ok(written)
}
pub async fn load_candidate_page(
    pool: &PgPool,
    run_id: &str,
    after_id: i64,
    limit: i64,
) -> anyhow::Result<Vec<(i64, Credential)>> {
    let rows = sqlx::query(
        "SELECT id,record FROM scan_candidates WHERE run_id=$1 AND id>$2 ORDER BY id LIMIT $3",
    )
    .bind(run_id)
    .bind(after_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("id")?,
                serde_json::from_value(row.try_get::<Value, _>("record")?)?,
            ))
        })
        .collect()
}
pub async fn upsert_validation_results(
    pool: &PgPool,
    run_id: &str,
    results: &[ValidationResult],
) -> anyhow::Result<u64> {
    let mut written = 0;
    for result in results {
        let identity = format!(
            "{:x}",
            Sha1::digest(
                format!("{}|{}", result.credential.apikey, result.credential.apiurl).as_bytes()
            )
        );
        written+=sqlx::query("INSERT INTO scan_validation_results(run_id,identity,valid,validation_state,error,record) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(run_id,identity) DO UPDATE SET valid=EXCLUDED.valid,validation_state=EXCLUDED.validation_state,error=EXCLUDED.error,record=EXCLUDED.record").bind(run_id).bind(identity).bind(result.valid).bind(&result.validation_state).bind(&result.error).bind(serde_json::to_value(result)?).execute(pool).await?.rows_affected();
    }
    Ok(written)
}
pub async fn upsert_discovery_hits(
    pool: &PgPool,
    run_id: &str,
    hits: &[Value],
) -> anyhow::Result<u64> {
    let mut written = 0;
    for hit in hits {
        let entry_id = format!("{:x}", Sha1::digest(hit.to_string().as_bytes()));
        let source = hit
            .get("_source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let query_id = hit
            .get("_query_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let host = hit
            .get("host")
            .or_else(|| hit.get("url"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ip = hit.get("ip").and_then(Value::as_str).unwrap_or_default();
        let port = hit.get("port").map(value_text).unwrap_or_default();
        let protocol = hit
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default();
        written += sqlx::query("INSERT INTO scan_discovery_hits(run_id,source,entry_id,query_id,host,ip,port,protocol,record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(run_id,entry_id) DO UPDATE SET record=EXCLUDED.record")
            .bind(run_id).bind(source).bind(entry_id).bind(query_id).bind(host).bind(ip).bind(port).bind(protocol).bind(hit)
            .execute(pool).await?.rows_affected();
    }
    Ok(written)
}

fn value_text(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

pub async fn load_discovery_hits(pool: &PgPool, run_id: &str) -> anyhow::Result<Vec<Value>> {
    Ok(
        sqlx::query_scalar("SELECT record FROM scan_discovery_hits WHERE run_id=$1 ORDER BY id")
            .bind(run_id)
            .fetch_all(pool)
            .await?,
    )
}

pub async fn load_validation_results(
    pool: &PgPool,
    run_id: &str,
) -> anyhow::Result<Vec<ValidationResult>> {
    let rows = sqlx::query_scalar::<_, Value>(
        "SELECT record FROM scan_validation_results WHERE run_id=$1 ORDER BY id",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| serde_json::from_value(row).map_err(Into::into))
        .collect()
}

#[derive(Clone, Debug, Default)]
pub struct SourceCheckpoint {
    pub source: String,
    pub lane: String,
    pub pack_id: String,
    pub shard_id: String,
    pub watermark: String,
    pub cursor_state: Value,
    pub etag: String,
    pub status: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArtifactWorkItem {
    pub repo_id: String,
    pub repository_full_name: String,
    pub commit_sha: String,
    pub file_path: String,
    pub object_sha: String,
    pub source_kind: String,
    pub etag: String,
    pub work_status: String,
    pub attempts: i32,
    pub last_error_class: String,
    pub current_stage: String,
    pub run_id: String,
    pub query_id: String,
    pub pack_id: String,
    pub lane: String,
    pub coverage_mode: String,
}

impl ArtifactWorkItem {
    pub fn locator(&self) -> (&str, &str, &str, &str, &str) {
        (
            &self.repo_id,
            &self.commit_sha,
            &self.file_path,
            &self.source_kind,
            &self.object_sha,
        )
    }
}

pub async fn advance_checkpoints_with_work(
    pool: &PgPool,
    checkpoints: &[SourceCheckpoint],
    work: &[ArtifactWorkItem],
) -> anyhow::Result<u64> {
    let mut transaction = pool.begin().await?;
    let mut written = 0;
    for item in work {
        written += sqlx::query("INSERT INTO github_artifacts(repo_id,repository_full_name,commit_sha,file_path,object_sha,source_kind,etag,work_status,attempts,last_error_class,current_stage,run_id,query_id,pack_id,lane,coverage_mode) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(repo_id,commit_sha,file_path,source_kind,object_sha) DO UPDATE SET repository_full_name=EXCLUDED.repository_full_name,etag=COALESCE(NULLIF(EXCLUDED.etag,''),github_artifacts.etag),work_status=CASE WHEN github_artifacts.work_status IN ('terminal','source_gone','artifact_too_large','budget_exhausted') THEN github_artifacts.work_status ELSE EXCLUDED.work_status END,last_seen_at=NOW(),run_id=CASE WHEN EXCLUDED.run_id<>'' THEN EXCLUDED.run_id ELSE github_artifacts.run_id END,query_id=CASE WHEN EXCLUDED.query_id<>'' THEN EXCLUDED.query_id ELSE github_artifacts.query_id END,pack_id=CASE WHEN EXCLUDED.pack_id<>'' THEN EXCLUDED.pack_id ELSE github_artifacts.pack_id END,lane=CASE WHEN EXCLUDED.lane<>'' THEN EXCLUDED.lane ELSE github_artifacts.lane END,coverage_mode=EXCLUDED.coverage_mode")
            .bind(&item.repo_id).bind(&item.repository_full_name).bind(&item.commit_sha).bind(&item.file_path).bind(&item.object_sha).bind(&item.source_kind).bind(&item.etag).bind(&item.work_status).bind(item.attempts).bind(&item.last_error_class).bind(&item.current_stage).bind(&item.run_id).bind(&item.query_id).bind(&item.pack_id).bind(&item.lane).bind(&item.coverage_mode)
            .execute(&mut *transaction).await?.rows_affected();
    }
    for checkpoint in checkpoints {
        written += sqlx::query("INSERT INTO source_checkpoints(source,lane,pack_id,shard_id,watermark,cursor_state,etag,status,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT(source,lane,pack_id,shard_id) DO UPDATE SET watermark=EXCLUDED.watermark,cursor_state=EXCLUDED.cursor_state,etag=EXCLUDED.etag,status=EXCLUDED.status,updated_at=NOW()")
            .bind(&checkpoint.source).bind(&checkpoint.lane).bind(&checkpoint.pack_id).bind(&checkpoint.shard_id).bind(&checkpoint.watermark).bind(&checkpoint.cursor_state).bind(&checkpoint.etag).bind(&checkpoint.status)
            .execute(&mut *transaction).await?.rows_affected();
    }
    transaction.commit().await?;
    Ok(written)
}

pub async fn claim_artifact_work(
    pool: &PgPool,
    limit: i64,
) -> anyhow::Result<Vec<ArtifactWorkItem>> {
    let rows = sqlx::query("SELECT repo_id,repository_full_name,commit_sha,file_path,object_sha,source_kind,etag,work_status,attempts,last_error_class,current_stage,run_id,query_id,pack_id,lane,coverage_mode FROM github_artifacts WHERE work_status = ANY($1) AND (next_retry_at IS NULL OR next_retry_at<=NOW()) ORDER BY last_seen_at ASC LIMIT $2")
        .bind(vec!["fetch_pending", "extract_pending", "validation_pending", "transient"])
        .bind(limit).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(ArtifactWorkItem {
                repo_id: row.try_get("repo_id")?,
                repository_full_name: row.try_get("repository_full_name")?,
                commit_sha: row.try_get("commit_sha")?,
                file_path: row.try_get("file_path")?,
                object_sha: row.try_get("object_sha")?,
                source_kind: row.try_get("source_kind")?,
                etag: row.try_get("etag")?,
                work_status: row.try_get("work_status")?,
                attempts: row.try_get("attempts")?,
                last_error_class: row.try_get("last_error_class")?,
                current_stage: row.try_get("current_stage")?,
                run_id: row.try_get("run_id")?,
                query_id: row.try_get("query_id")?,
                pack_id: row.try_get("pack_id")?,
                lane: row.try_get("lane")?,
                coverage_mode: row.try_get("coverage_mode")?,
            })
        })
        .collect()
}

pub async fn transition_artifact_work(
    pool: &PgPool,
    item: &ArtifactWorkItem,
    new_status: &str,
    error_class: &str,
    max_attempts: i32,
) -> anyhow::Result<String> {
    let attempts = item.attempts + i32::from(new_status == "transient");
    let status = if new_status == "transient" && attempts >= max_attempts {
        "source_gone"
    } else {
        new_status
    };
    let error = if status == "source_gone" && new_status == "transient" {
        format!("max_attempts_exceeded:{error_class}")
    } else {
        error_class.to_owned()
    };
    let retry_seconds = if status == "transient" {
        Some(2_i64.pow(attempts.clamp(1, 10) as u32))
    } else {
        None
    };
    sqlx::query("UPDATE github_artifacts SET work_status=$6,current_stage=$6,attempts=$7,last_error_class=$8,next_retry_at=CASE WHEN $9::bigint IS NULL THEN NULL ELSE NOW()+make_interval(secs=>$9::double precision) END,last_seen_at=NOW() WHERE repo_id=$1 AND commit_sha=$2 AND file_path=$3 AND source_kind=$4 AND object_sha=$5")
        .bind(&item.repo_id).bind(&item.commit_sha).bind(&item.file_path).bind(&item.source_kind).bind(&item.object_sha).bind(status).bind(attempts).bind(error).bind(retry_seconds).execute(pool).await?;
    Ok(status.to_owned())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkItem {
    pub id: i64,
    pub status: String,
    pub attempt: i32,
    pub payload: Value,
}
pub fn next_work_status(current: &str, success: bool, source_gone: bool) -> &'static str {
    if source_gone {
        "source_gone"
    } else if success {
        match current {
            "pending" => "fetched",
            "fetched" => "extracted",
            _ => "done",
        }
    } else {
        "transient"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn planner_uses_selected_metric_version() {
        let a = PlannerCandidate {
            query_id: "a".into(),
            funnel: QueryFunnel {
                active_requests: 1,
                total_active_http_requests: 100,
                final_verified: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let b = PlannerCandidate {
            query_id: "b".into(),
            funnel: QueryFunnel {
                active_requests: 2,
                total_active_http_requests: 2,
                final_verified: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            plan_queries(vec![a.clone(), b.clone()], 2, 2)[0].query_id,
            "a"
        );
        assert_eq!(plan_queries(vec![a, b], 3, 2)[0].query_id, "b");
    }
}
