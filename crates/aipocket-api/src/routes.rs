use crate::{
    auth::{Auth, verify},
    error::ApiError,
    settings::{SettingsUpdate, SettingsView, persist_env},
    state::AppState,
};
use aipocket_core::{Credential, ScanMode, ScanStatus};
use aipocket_db::mask_apikey;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use futures::{StreamExt, stream};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, path::PathBuf, time::Duration};
use tokio_stream::wrappers::BroadcastStream;
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(crate::auth::login))
        .route("/api/auth/logout", post(crate::auth::logout))
        .route("/api/runs", get(runs))
        .route("/api/runs/{id}/{kind}", get(run_results))
        .route("/api/runs/{id}/log", get(run_log))
        .route("/api/runs/{id}", axum::routing::delete(delete_run))
        .route("/api/runs/{id}/gpt-failed", get(gpt_failed))
        .route("/api/runs/{id}/retry-gpt-failed", post(retry_gpt_failed))
        .route("/api/high-value", get(high_value))
        .route("/api/high-value/reveal", post(high_value_reveal))
        .route("/api/keys/{kind}", get(all_keys))
        .route("/api/keys/promote", post(promote_keys))
        .route("/api/key/models", post(key_models))
        .route("/api/key/balance", post(key_balance))
        .route("/api/key/chat", post(key_chat))
        .route("/api/key/reveal", post(key_reveal))
        .route("/api/export", post(export))
        .route("/api/cve", get(cves))
        .route("/api/cve/sync", post(cve_sync))
        .route("/api/cve/add", post(cve_add))
        .route(
            "/api/honeypot",
            get(honeypots)
                .post(create_honeypot)
                .patch(update_honeypot)
                .delete(delete_honeypot),
        )
        .route("/api/honeypot/bulk-delete", post(bulk_delete_honeypots))
        .route(
            "/api/manual-targets",
            get(manual_targets)
                .post(save_manual_targets)
                .delete(delete_manual_target),
        )
        .route(
            "/api/manual-targets/bulk-delete",
            post(bulk_delete_manual_targets),
        )
        .route("/api/settings", get(get_settings).put(update_settings))
        .route("/api/settings/check/fofa", post(check_fofa))
        .route("/api/settings/check/shodan", post(check_shodan))
        .route("/api/settings/check/github", post(check_github))
        .route("/api/scan/start", post(scan_start))
        .route("/api/scan/stop", post(scan_stop))
        .route("/api/scan/status", get(scan_status))
        .route("/api/scan/logs", get(scan_logs))
        .route("/api/scan/logs/stream", get(scan_stream))
        .route("/api/system/restart", post(system_restart))
}
#[derive(Deserialize)]
struct PromoteRequest {
    result_ids: Vec<i64>,
    #[serde(default)]
    note: String,
}
async fn promote_keys(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<PromoteRequest>,
) -> Result<Json<Value>, ApiError> {
    let (promoted, skipped) = s.repository.promote_results(&b.result_ids, &b.note).await?;
    Ok(Json(json!({"promoted":promoted,"skipped":skipped})))
}
async fn delete_run(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let deleted = s.repository.delete_run(&id).await?;
    let disk = s.settings.read().await.results_path().join(&id);
    let disk_removed = if disk.exists() {
        std::fs::remove_dir_all(disk).is_ok()
    } else {
        false
    };
    Ok(Json(
        json!({"run_id":id,"deleted":deleted,"disk_removed":disk_removed}),
    ))
}
async fn gpt_failed(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validate_run_id(&id)?;
    let root = s.settings.read().await.results_path();
    let files = inspect_failed_files(&root, &id);
    let failed_hits = files
        .iter()
        .filter_map(|file| file.get("hits").and_then(Value::as_u64))
        .sum::<u64>();
    let retry = s.retry_manager.0.lock().await.clone();
    let retry = if retry
        .get("run_id")
        .and_then(Value::as_str)
        .is_none_or(|run| run == id)
    {
        retry
    } else {
        idle_retry()
    };
    Ok(Json(
        json!({"run_id":id,"failed_files":files.len(),"failed_hits":failed_hits,"files":files,"retry":retry}),
    ))
}
async fn retry_gpt_failed(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validate_run_id(&id)?;
    if matches!(
        s.scan_manager.status().await.state,
        aipocket_core::ScanState::Running | aipocket_core::ScanState::Stopping
    ) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "cannot retry while a scan is running",
        ));
    }
    let run_dir = s.settings.read().await.results_path().join(&id);
    if !run_dir.is_dir() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "run directory not found",
        ));
    }
    if inspect_failed_files(&s.settings.read().await.results_path(), &id).is_empty() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no gpt_failed_batch_*.jsonl files to retry",
        ));
    }
    let mut status = s.retry_manager.0.lock().await;
    if status.get("state").and_then(Value::as_str) == Some("running") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "a GPT-failed retry is already running",
        ));
    }
    let started = chrono::Utc::now().to_rfc3339();
    *status = json!({"state":"running","run_id":id,"started_at":started,"finished_at":null,"error":null,"report":null});
    let response = status.clone();
    drop(status);
    let manager = s.retry_manager.clone();
    let analyzer = aipocket_services::Analyzer::new(
        std::sync::Arc::new(s.settings.read().await.clone()),
        s.http.clone(),
    );
    let repository = s.repository.clone();
    tokio::spawn(async move {
        let outcome = analyzer.retry_failed(&id, &run_dir, &repository).await;
        let mut status = manager.0.lock().await;
        let finished = chrono::Utc::now().to_rfc3339();
        *status = match outcome {
            Ok(report) => {
                json!({"state":"finished","run_id":id,"started_at":started,"finished_at":finished,"error":null,"report":report})
            }
            Err(error) => {
                json!({"state":"error","run_id":id,"started_at":started,"finished_at":finished,"error":error.to_string(),"report":null})
            }
        };
    });
    Ok(Json(response))
}
fn idle_retry() -> Value {
    json!({"state":"idle","run_id":null,"started_at":null,"finished_at":null,"error":null,"report":null})
}

fn validate_run_id(run_id: &str) -> Result<(), ApiError> {
    let valid = regex::Regex::new(r"^run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}$")
        .expect("run id regex")
        .is_match(run_id);
    if valid {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid run id",
        ))
    }
}

fn inspect_failed_files(root: &std::path::Path, run_id: &str) -> Vec<Value> {
    let dir = root.join(run_id);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            if !(name.starts_with("gpt_failed") || name.starts_with("failed_batch")) {
                return None;
            }
            let (hits, batch_idx) = parse_failed_batch(&path);
            Some(json!({"name":name,"hits":hits,"batch_idx":batch_idx}))
        })
        .collect()
}
fn parse_failed_batch(path: &std::path::Path) -> (usize, Option<i64>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (0, None);
    };
    let mut count = 0;
    let mut batch_idx = None;
    for (index, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if index == 0 && value.get("batch_idx").is_some() {
            batch_idx = value.get("batch_idx").and_then(Value::as_i64);
        } else if let Some(rows) = value.as_array() {
            count += rows.len();
        } else if value.is_object() {
            count += 1;
        }
    }
    (count, batch_idx)
}

async fn cve_sync(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let value = s.tavily().await.search("AI security CVE latest").await?;
    let items = value
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut added = 0;
    for item in &items {
        if s.repository.upsert_cve(item).await.unwrap_or(false) {
            added += 1;
        }
    }
    Ok(Json(
        json!({"total":s.repository.cves().await?.len(),"added":added}),
    ))
}
#[derive(Deserialize)]
struct CveAdd {
    url: Option<String>,
    id: Option<String>,
    product: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    description: Option<String>,
    cvss: Option<f64>,
    huntable: Option<String>,
}
async fn cve_add(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<CveAdd>,
) -> Result<Json<Value>, ApiError> {
    let id =
        b.id.or_else(|| {
            b.url.as_ref().and_then(|v| {
                regex::Regex::new(r"(?i)CVE-\d{4}-\d{4,7}")
                    .ok()?
                    .find(v)
                    .map(|m| m.as_str().to_uppercase())
            })
        })
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "bad_request", "CVE id required"))?;
    let record = json!({"id":id,"url":b.url,"product":b.product,"type":b.kind,"description":b.description,"cvss":b.cvss,"huntable":b.huntable});
    let created = s.repository.upsert_cve(&record).await?;
    Ok(Json(
        json!({"created":created,"total":s.repository.cves().await?.len(),"cve":record}),
    ))
}
async fn health() -> Json<Value> {
    Json(json!({"ok":true}))
}
async fn runs(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({"days":s.repository.list_runs().await?})))
}
async fn run_results(
    _: Auth,
    State(s): State<AppState>,
    Path((id, kind)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(kind.as_str(), "valid" | "suspicious") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid result kind",
        ));
    }
    Ok(Json(
        json!({"run_id":id,"results":s.repository.run_records(&id,&kind,true).await?}),
    ))
}
async fn run_log(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let log = s
        .repository
        .run_log(&id)
        .await?
        .or_else(|| {
            std::fs::read_to_string(
                s.settings
                    .blocking_read()
                    .results_path()
                    .join(&id)
                    .join("run.log"),
            )
            .ok()
        })
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "no log for run"))?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], log).into_response())
}
async fn high_value(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        json!({"results":s.repository.high_value(true).await?}),
    ))
}
#[derive(Deserialize)]
struct HighReveal {
    masked: String,
    apiurl: Option<String>,
}
async fn high_value_reveal(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HighReveal>,
) -> Result<Json<Value>, ApiError> {
    for row in s.repository.high_value(false).await? {
        let key = row
            .get("apikey")
            .and_then(Value::as_str)
            .or_else(|| row.pointer("/credential/apikey").and_then(Value::as_str))
            .unwrap_or_default();
        let url = row
            .get("apiurl")
            .and_then(Value::as_str)
            .or_else(|| row.pointer("/credential/apiurl").and_then(Value::as_str))
            .unwrap_or_default();
        if mask_apikey(key) == b.masked && b.apiurl.as_deref().is_none_or(|v| v == url) {
            return Ok(Json(json!({"apikey":key,"apiurl":url})));
        }
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "key not found",
    ))
}
async fn all_keys(
    _: Auth,
    State(s): State<AppState>,
    Path(kind): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        json!({"kind":kind,"results":s.repository.all_records(&kind,true).await?}),
    ))
}
#[derive(Deserialize)]
struct KeyRef {
    apikey: String,
    #[serde(default)]
    apiurl: String,
}
async fn key_models(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<KeyRef>,
) -> Result<Json<Value>, ApiError> {
    if b.apikey.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "apikey required",
        ));
    }
    let models = s
        .balance
        .models(Credential {
            apikey: b.apikey,
            apiurl: b.apiurl,
            ..Default::default()
        })
        .await?;
    Ok(Json(json!({"models":models})))
}
#[derive(Deserialize)]
struct BalanceRequest {
    apikey: String,
    #[serde(default)]
    apiurl: String,
    result_id: Option<i64>,
    #[serde(default)]
    high_value: bool,
}
async fn key_balance(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<BalanceRequest>,
) -> Result<Json<Value>, ApiError> {
    if b.apikey.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "apikey required",
        ));
    }
    let r = s
        .balance
        .query(&Credential {
            apikey: b.apikey.clone(),
            apiurl: b.apiurl.clone(),
            ..Default::default()
        })
        .await?;
    if !r.matched {
        return Ok(Json(json!({
            "gateway":"unsupported",
            "balance_usd":"",
            "tier":"",
            "detail":serde_json::to_value(&r).map_err(ApiError::internal)?,
            "persisted":false,
            "result_id":b.result_id,
            "high_value_updated":false
        })));
    }
    let mut result = aipocket_core::ValidationResult {
        credential: Credential {
            apikey: b.apikey.clone(),
            apiurl: b.apiurl.clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    aipocket_services::apply_probe_result(&mut result, r.clone());
    let balance_display = result.balance;
    let evidence = serde_json::to_value(&r).map_err(ApiError::internal)?;
    let (persisted, high_value_updated) = if b.result_id.is_some() || b.high_value {
        s.repository
            .persist_balance(aipocket_db::BalancePersistence {
                result_id: b.result_id,
                apikey: &b.apikey,
                gateway: &r.gateway,
                balance: &balance_display,
                tier: &r.tier,
                detail: &evidence,
                high_value: b.high_value,
            })
            .await?
    } else {
        (false, false)
    };
    Ok(Json(
        json!({"gateway":r.gateway,"balance_usd":balance_display,"tier":r.tier,"detail":evidence,"persisted":persisted,"result_id":b.result_id,"high_value_updated":high_value_updated}),
    ))
}
#[derive(Deserialize)]
struct ChatRequest {
    apikey: String,
    #[serde(default)]
    apiurl: String,
    model: String,
}
async fn key_chat(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ChatRequest>,
) -> Result<Json<Value>, ApiError> {
    if b.apikey.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "apikey required",
        ));
    }
    if b.model.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "model required (pick one from /api/key/models first)",
        ));
    }
    let result = s
        .balance
        .test_chat(
            Credential {
                apikey: b.apikey,
                apiurl: b.apiurl,
                ..Default::default()
            },
            &b.model,
        )
        .await?;
    Ok(Json(json!({
        "success":result.success,
        "status_code":result.status_code,
        "model":result.model,
        "snippet":result.snippet,
        "error":result.error,
        "consumes_credit":true
    })))
}
#[derive(Deserialize)]
struct RevealRequest {
    run_id: String,
    #[serde(default = "valid_kind")]
    kind: String,
    masked: Option<String>,
    apiurl: Option<String>,
    index: Option<usize>,
}
fn valid_kind() -> String {
    "valid".into()
}
async fn key_reveal(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<RevealRequest>,
) -> Result<Json<Value>, ApiError> {
    let rows = s.repository.run_records(&b.run_id, &b.kind, false).await?;
    for (i, row) in rows.into_iter().enumerate() {
        let key = row
            .pointer("/credential/apikey")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let url = row
            .pointer("/credential/apiurl")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if b.index == Some(i)
            || (b.index.is_none()
                && b.masked.as_deref() == Some(&mask_apikey(key))
                && b.apiurl.as_deref().is_none_or(|v| v == url))
        {
            return Ok(Json(json!({"apikey":key,"apiurl":url})));
        }
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "key not found",
    ))
}
#[derive(Deserialize)]
struct ExportRequest {
    dataset: String,
    #[serde(default = "json_format")]
    format: String,
    run_id: Option<String>,
    #[serde(default = "valid_kind")]
    kind: String,
    #[serde(default)]
    keys: Vec<KeyRef>,
    #[serde(default)]
    indices: Vec<usize>,
}
fn json_format() -> String {
    "json".into()
}
async fn export(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ExportRequest>,
) -> Result<Response, ApiError> {
    let rows = match b.dataset.as_str() {
        "selected" if b.run_id.is_some() && !b.indices.is_empty() => {
            let all = s
                .repository
                .run_records(b.run_id.as_deref().unwrap_or_default(), &b.kind, false)
                .await?;
            b.indices
                .into_iter()
                .filter_map(|index| all.get(index).cloned())
                .collect()
        }
        "selected" if !b.keys.is_empty() => b
            .keys
            .into_iter()
            .map(|k| json!({"apikey":k.apikey,"apiurl":k.apiurl}))
            .collect(),
        "selected" => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "selected export requires run_id+indices or keys",
            ));
        }
        "run" if b.run_id.is_none() => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "run export requires run_id",
            ));
        }
        "run" => {
            s.repository
                .run_records(b.run_id.as_deref().unwrap_or_default(), &b.kind, false)
                .await?
        }
        "high-value" => s.repository.high_value(false).await?,
        "all" => {
            let all = s.repository.all_records(&b.kind, false).await?;
            if b.indices.is_empty() {
                all
            } else {
                b.indices
                    .into_iter()
                    .filter_map(|index| all.get(index).cloned())
                    .collect()
            }
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "unknown dataset",
            ));
        }
    };
    let (content, media, ext) = if b.format == "csv" {
        let mut w = csv::Writer::from_writer(vec![]);
        w.write_record([
            "apikey", "apiurl", "provider", "valid", "tier", "balance", "gateway",
        ])
        .map_err(ApiError::internal)?;
        for row in rows {
            let key = row
                .get("apikey")
                .and_then(Value::as_str)
                .or_else(|| row.pointer("/credential/apikey").and_then(Value::as_str))
                .unwrap_or_default();
            let url = row
                .get("apiurl")
                .and_then(Value::as_str)
                .or_else(|| row.pointer("/credential/apiurl").and_then(Value::as_str))
                .unwrap_or_default();
            w.write_record([
                key,
                url,
                row.pointer("/provider_info/provider")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                &row.get("valid")
                    .and_then(Value::as_bool)
                    .unwrap_or_default()
                    .to_string(),
                row.get("tier").and_then(Value::as_str).unwrap_or_default(),
                row.get("balance")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                row.get("gateway")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ])
            .map_err(ApiError::internal)?;
        }
        (
            w.into_inner().map_err(ApiError::internal)?,
            "text/csv",
            "csv",
        )
    } else {
        (
            serde_json::to_vec_pretty(&rows).map_err(ApiError::internal)?,
            "application/json",
            "json",
        )
    };
    Ok((
        [
            (header::CONTENT_TYPE, media),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"aipocket-export.{ext}\""),
            ),
        ],
        content,
    )
        .into_response())
}
async fn cves(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let cves = s.repository.cves().await?;
    Ok(Json(json!({"cves":cves,"advisories":cves})))
}
#[derive(Default, Deserialize)]
struct PageQuery {
    #[serde(default)]
    q: String,
    source: Option<String>,
    enabled_only: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
}
async fn honeypots(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let (rows, total) = s
        .repository
        .list_honeypots(&q.q, q.source.as_deref(), limit, offset)
        .await?;
    Ok(Json(
        json!({"results":rows,"total":total,"limit":limit,"offset":offset}),
    ))
}
async fn manual_targets(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let (rows, total) = s
        .repository
        .list_manual_targets(q.enabled_only.unwrap_or(false), limit, offset)
        .await?;
    Ok(Json(
        json!({"results":rows,"total":total,"limit":limit,"offset":offset}),
    ))
}
#[derive(Deserialize)]
struct HoneypotCreate {
    host: String,
    #[serde(default = "manual_reason")]
    reason: String,
    #[serde(default)]
    notes: String,
}
fn manual_reason() -> String {
    "honeypot:manual".into()
}
#[derive(Deserialize)]
struct HoneypotUpdate {
    host_key: String,
    reason: Option<String>,
    notes: Option<String>,
}
#[derive(Deserialize)]
struct HoneypotDeleteQuery {
    host_key: String,
}
#[derive(Deserialize)]
struct HoneypotBulkDelete {
    #[serde(default)]
    host_keys: Vec<String>,
}
async fn create_honeypot(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HoneypotCreate>,
) -> Result<Json<Value>, ApiError> {
    let origin =
        aipocket_core::url_sanitize::sanitize_origin(&b.host).map_err(ApiError::internal)?;
    let key = aipocket_core::url_sanitize::host_key(&origin).map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::to_value(
            s.repository
                .create_honeypot(&origin, &key, &b.reason, &b.notes)
                .await?,
        )
        .map_err(ApiError::internal)?,
    ))
}
async fn update_honeypot(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HoneypotUpdate>,
) -> Result<Json<Value>, ApiError> {
    let row = s
        .repository
        .update_honeypot(&b.host_key, b.reason.as_deref(), b.notes.as_deref())
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "honeypot not found"))?;
    Ok(Json(serde_json::to_value(row).map_err(ApiError::internal)?))
}
async fn delete_honeypot(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<HoneypotDeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    s.repository
        .delete_honeypots(std::slice::from_ref(&q.host_key))
        .await?;
    Ok(Json(json!({"ok":true,"host_key":q.host_key})))
}
async fn bulk_delete_honeypots(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HoneypotBulkDelete>,
) -> Result<Json<Value>, ApiError> {
    let deleted = s.repository.delete_honeypots(&b.host_keys).await?;
    Ok(Json(json!({"deleted":deleted})))
}
#[derive(Deserialize)]
struct ManualTargetsSave {
    urls: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    replace: bool,
}
#[derive(Deserialize)]
struct ManualTargetDeleteQuery {
    url: String,
}
#[derive(Deserialize)]
struct ManualTargetsDelete {
    #[serde(default)]
    urls: Vec<String>,
}
async fn save_manual_targets(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ManualTargetsSave>,
) -> Result<Json<Value>, ApiError> {
    if b.replace {
        let (existing, _) = s.repository.list_manual_targets(false, 10_000, 0).await?;
        let urls: Vec<_> = existing.into_iter().map(|target| target.url).collect();
        s.repository.delete_manual_targets(&urls).await?;
    }
    let mut targets = Vec::new();
    let mut rejected = Vec::new();
    for raw in b
        .urls
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        match aipocket_core::url_sanitize::sanitize_origin(raw) {
            Ok(origin) => {
                let parsed = url::Url::parse(&origin).map_err(ApiError::internal)?;
                let target = aipocket_core::ManualTarget {
                    url: origin.clone(),
                    host_key: aipocket_core::url_sanitize::host_key(&origin)
                        .map_err(ApiError::internal)?,
                    scheme: parsed.scheme().into(),
                    hostname: parsed.host_str().unwrap_or_default().into(),
                    port: parsed.port_or_known_default().unwrap_or(443),
                    enabled: true,
                    notes: b.notes.clone(),
                    ..Default::default()
                };
                targets.push(s.repository.upsert_manual_target(&target).await?);
            }
            Err(_) => rejected.push(raw.to_owned()),
        }
    }
    Ok(Json(
        json!({"added":targets.len(),"updated":0,"rejected":rejected,"targets":targets}),
    ))
}
async fn delete_manual_target(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<ManualTargetDeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    let url = aipocket_core::url_sanitize::sanitize_origin(&q.url).map_err(ApiError::internal)?;
    let deleted = s.repository.delete_manual_targets(&[url]).await?;
    Ok(Json(json!({"deleted":deleted})))
}
async fn bulk_delete_manual_targets(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ManualTargetsDelete>,
) -> Result<Json<Value>, ApiError> {
    let urls: Vec<_> = b
        .urls
        .iter()
        .filter_map(|url| aipocket_core::url_sanitize::sanitize_origin(url).ok())
        .collect();
    let deleted = s.repository.delete_manual_targets(&urls).await?;
    Ok(Json(json!({"deleted":deleted})))
}
async fn get_settings(_: Auth, State(s): State<AppState>) -> Json<SettingsView> {
    let settings = s.settings.read().await;
    Json(SettingsView::from_settings(&settings))
}
async fn update_settings(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<SettingsUpdate>,
) -> Result<Json<Value>, ApiError> {
    let updates = b.env_updates();
    persist_env(&PathBuf::from(".env"), &updates).map_err(ApiError::internal)?;
    let new = aipocket_core::Settings::load().map_err(ApiError::internal)?;
    *s.settings.write().await = new;
    let settings = s.settings.read().await;
    Ok(Json(
        json!({"updated":updates.keys().collect::<Vec<_>>(),"hot_reloaded":updates.keys().collect::<Vec<_>>(),"restart_required":[],"settings":SettingsView::from_settings(&settings)}),
    ))
}
async fn check_fofa(_: Auth, State(s): State<AppState>) -> Json<Value> {
    match s.fofa().await.check().await {
        Ok(_) => Json(json!({"status":"ok","message":"reachable","consumes_quota":true})),
        Err(e) => Json(json!({"status":"invalid","message":e.to_string(),"consumes_quota":true})),
    }
}
async fn check_shodan(_: Auth, State(s): State<AppState>) -> Json<Value> {
    let results = s.shodan().await.info_all().await;
    let keys:Vec<_>=results.iter().map(|(key,r)|match r{Ok(info)=>json!({"key_masked":mask_apikey(key),"plan":info.plan,"query_credits":info.query_credits,"alive":true}),Err(_)=>json!({"key_masked":mask_apikey(key),"plan":"","query_credits":0,"alive":false})}).collect();
    let total = keys
        .iter()
        .filter_map(|v| v.get("query_credits").and_then(Value::as_i64))
        .sum::<i64>();
    let dead = keys
        .iter()
        .filter(|v| v.get("alive") == Some(&Value::Bool(false)))
        .count();
    Json(
        json!({"keys":keys,"total_query_credits":total,"n_keys":results.len(),"n_dead":dead,"consumes_quota":false}),
    )
}
async fn check_github(_: Auth, State(s): State<AppState>) -> Json<Value> {
    let n = s.settings.read().await.github_token_list().len();
    if n == 0 {
        return Json(
            json!({"status":"disabled","message":"no tokens","core_remaining":null,"search_remaining":null,"code_search_remaining":null,"n_tokens":0}),
        );
    }
    match s.github().await.rate_limit().await {
        Ok(v) => Json(
            json!({"status":"ok","message":"reachable","core_remaining":v.pointer("/resources/core/remaining"),"search_remaining":v.pointer("/resources/search/remaining"),"code_search_remaining":v.pointer("/resources/code_search/remaining"),"n_tokens":n}),
        ),
        Err(e) => Json(
            json!({"status":"invalid","message":e.to_string(),"core_remaining":null,"search_remaining":null,"code_search_remaining":null,"n_tokens":n}),
        ),
    }
}
#[derive(Deserialize)]
struct ScanStart {
    #[serde(default = "all_source")]
    source: String,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    mode: ScanMode,
    #[serde(default)]
    github_pack_ids: Vec<String>,
    #[serde(default)]
    manual_enrich: Vec<String>,
    #[serde(default)]
    resume_run_id: String,
}
fn all_source() -> String {
    "all".into()
}
async fn scan_start(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ScanStart>,
) -> Result<Json<ScanStatus>, ApiError> {
    if !b.resume_run_id.is_empty() {
        let Some((state, phase)) = s.repository.resumable_run(&b.resume_run_id).await? else {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "resume run not found",
            ));
        };
        if state == "finished" || phase == "finished" {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "conflict",
                "run already finished",
            ));
        }
    }
    let sources = if b.sources.is_empty() {
        vec![b.source.clone()]
    } else {
        b.sources.clone()
    };
    let (cancel, tx, rx, stopped) = s
        .scan_manager
        .start_channel(sources.join(","), b.mode.clone())
        .await
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "conflict", "scan already running"))?;
    s.scan_manager
        .set_options(b.github_pack_ids.clone(), b.manual_enrich.clone())
        .await;
    let manager = s.scan_manager.clone();
    tokio::spawn(manager.consume(rx));
    let scanner = s.scanner.clone();
    let settings = s.settings.read().await.clone();
    let http = s.http.clone();
    tokio::spawn(async move {
        let _stopped = stopped;
        let registry = aipocket_discovery::packs::registry();
        let selected_packs: Vec<_> =
            if b.github_pack_ids.is_empty() || b.github_pack_ids.iter().any(|v| v == "all") {
                registry.values().copied().collect()
            } else {
                b.github_pack_ids
                    .iter()
                    .filter_map(|id| registry.get(id.as_str()).copied())
                    .collect()
            };
        let mut discovery: Vec<std::sync::Arc<dyn aipocket_discovery::DiscoverySource>> =
            Vec::new();
        if sources.iter().any(|v| v == "all" || v == "fofa") {
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::FofaSource {
                    client: aipocket_clients::FofaClient::new(http.clone(), &settings),
                    queries: selected_packs
                        .iter()
                        .flat_map(|p| p.fofa_queries)
                        .map(|v| v.to_string())
                        .collect(),
                    page_size: settings.fofa_page_size,
                    max_pages: settings.fofa_max_pages,
                    page_delay: settings.fofa_page_delay,
                },
            ));
        }
        if sources.iter().any(|v| v == "all" || v == "shodan") {
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::ShodanSource {
                    client: aipocket_clients::ShodanClient::new(http.clone(), &settings),
                    queries: selected_packs
                        .iter()
                        .flat_map(|p| p.shodan_queries)
                        .map(|v| v.to_string())
                        .collect(),
                    max_pages: settings.shodan_max_pages,
                    page_delay: settings.shodan_page_delay,
                },
            ));
        }
        if sources.iter().any(|v| v == "all" || v == "github")
            && !settings.github_token_list().is_empty()
            && settings.pg_enabled()
        {
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::GithubSource {
                    client: aipocket_clients::GithubClient::new(http.clone(), &settings),
                    queries: selected_packs
                        .iter()
                        .flat_map(|p| p.github_terms)
                        .map(|v| v.to_string())
                        .collect(),
                    per_page: settings.github_search_page_size,
                    run_id: b.resume_run_id.clone(),
                    pack_id: if b.github_pack_ids.len() == 1 {
                        b.github_pack_ids[0].clone()
                    } else {
                        String::new()
                    },
                },
            ));
        }
        if sources.iter().any(|v| v == "manual") {
            let targets = scanner.manual_targets().await.unwrap_or_default();
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::ManualSource { targets },
            ));
        }
        if sources.iter().any(|v| v == "manual") && !b.manual_enrich.is_empty() {
            let targets = scanner.manual_targets().await.unwrap_or_default();
            let engines = b
                .manual_enrich
                .iter()
                .map(|engine| engine.trim().to_ascii_lowercase())
                .filter(|engine| engine == "fofa" || engine == "shodan")
                .collect::<Vec<_>>();
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::ManualEnrichSource {
                    targets,
                    engines,
                    fofa: aipocket_clients::FofaClient::new(http.clone(), &settings),
                    shodan: aipocket_clients::ShodanClient::new(http.clone(), &settings),
                },
            ));
        }
        let resume = (!b.resume_run_id.is_empty()).then_some(b.resume_run_id.clone());
        if let Err(error) = scanner
            .run_resumable(discovery, b.mode, resume.clone(), cancel, tx.clone())
            .await
        {
            let run_id = resume.unwrap_or_else(|| "unknown".into());
            scanner.fail_run(&run_id, error.to_string(), &tx).await;
        }
    });
    Ok(Json(s.scan_manager.status().await))
}
async fn scan_stop(_: Auth, State(s): State<AppState>) -> Result<Json<ScanStatus>, ApiError> {
    if !s.scan_manager.stop().await {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "no scan running",
        ));
    }
    Ok(Json(s.scan_manager.status().await))
}
async fn scan_status(_: Auth, State(s): State<AppState>) -> Json<ScanStatus> {
    Json(s.scan_manager.status().await)
}
#[derive(Default, Deserialize)]
struct Since {
    #[serde(default)]
    since: u64,
    token: Option<String>,
}
async fn scan_logs(_: Auth, State(s): State<AppState>, Query(q): Query<Since>) -> Json<Value> {
    let lines = s.scan_manager.logs_since(q.since).await;
    let last_seq = lines.last().map(|l| l.seq).unwrap_or(q.since);
    Json(json!({"lines":lines,"last_seq":last_seq}))
}
async fn scan_stream(
    State(s): State<AppState>,
    Query(q): Query<Since>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    verify(q.token.as_deref().unwrap_or_default(), &s).await?;
    let replay = s
        .scan_manager
        .logs_since(q.since)
        .await
        .into_iter()
        .map(|line| {
            Ok(Event::default()
                .event("log")
                .id(line.seq.to_string())
                .data(line.line))
        });
    let live = BroadcastStream::new(s.scan_manager.subscribe()).filter_map(|item| async move {
        item.ok().map(|line| {
            Ok(Event::default()
                .event("log")
                .id(line.seq.to_string())
                .data(line.line))
        })
    });
    Ok(Sse::new(stream::iter(replay).chain(live))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
async fn system_restart(_: Auth) -> Json<Value> {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::process::exit(75)
    });
    Json(json!({"restarting":true}))
}
