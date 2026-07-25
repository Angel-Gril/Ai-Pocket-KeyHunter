use crate::{DiscoverySource, QueryUsage, SourceBudgets, SourceFetchResult};
use aipocket_clients::{FofaClient, GithubClient, ShodanClient};
use aipocket_core::ScanMode;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
pub struct FofaSource {
    pub client: FofaClient,
    pub queries: Vec<String>,
    pub page_size: u32,
    pub max_pages: u32,
    pub page_delay: f64,
}
#[async_trait]
impl DiscoverySource for FofaSource {
    fn name(&self) -> &'static str {
        "fofa"
    }
    fn query_ids(&self) -> Vec<String> {
        self.queries.clone()
    }
    fn is_configured(&self) -> bool {
        !self.queries.is_empty()
    }
    async fn fetch(&self, budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let selected = budgets.selected_queries.as_ref();
        let queries = self
            .queries
            .iter()
            .filter(|query| selected.is_none_or(|values| values.contains(query)))
            .collect::<Vec<_>>();
        let limit = budgets.fofa.unwrap_or(queries.len());
        let mut result = SourceFetchResult {
            source: "fofa".into(),
            ..Default::default()
        };
        for query in queries.into_iter().take(limit) {
            for page in 1..=self.max_pages.max(1) {
                match self.client.search(query, page, self.page_size.max(1)).await {
                    Ok(value) => {
                        let rows = value
                            .get("results")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let count = rows.len();
                        result.host_hits.extend(rows);
                        result.query_usage.push(QueryUsage {
                            source: "fofa".into(),
                            query: query.clone(),
                            page_count: 1,
                            result_count: count as u64,
                            ..Default::default()
                        });
                        if count < self.page_size as usize {
                            break;
                        }
                    }
                    Err(error) => {
                        result.errors.push(error.to_string());
                        break;
                    }
                }
                if self.page_delay > 0.0 {
                    tokio::time::sleep(std::time::Duration::from_secs_f64(self.page_delay)).await;
                }
            }
        }
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}

pub struct ShodanSource {
    pub client: ShodanClient,
    pub queries: Vec<String>,
    pub max_pages: u32,
    pub page_delay: f64,
}
#[async_trait]
impl DiscoverySource for ShodanSource {
    fn name(&self) -> &'static str {
        "shodan"
    }
    fn query_ids(&self) -> Vec<String> {
        self.queries.clone()
    }
    fn is_configured(&self) -> bool {
        !self.queries.is_empty()
    }
    async fn fetch(&self, budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let selected = budgets.selected_queries.as_ref();
        let queries = self
            .queries
            .iter()
            .filter(|query| selected.is_none_or(|values| values.contains(query)))
            .collect::<Vec<_>>();
        let limit = budgets.shodan.unwrap_or(queries.len());
        let mut result = SourceFetchResult {
            source: "shodan".into(),
            ..Default::default()
        };
        for query in queries.into_iter().take(limit) {
            for page in 1..=self.max_pages.max(1) {
                match self.client.search(query, page).await {
                    Ok(value) => {
                        let rows = value
                            .get("matches")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let count = rows.len();
                        result.host_hits.extend(rows);
                        result.query_usage.push(QueryUsage {
                            source: "shodan".into(),
                            query: query.clone(),
                            page_count: 1,
                            result_count: count as u64,
                            ..Default::default()
                        });
                        if count < 100 {
                            break;
                        }
                    }
                    Err(error) => {
                        result.errors.push(error.to_string());
                        break;
                    }
                }
                if self.page_delay > 0.0 {
                    tokio::time::sleep(std::time::Duration::from_secs_f64(self.page_delay)).await;
                }
            }
        }
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}

pub struct GithubSource {
    pub client: GithubClient,
    pub queries: Vec<String>,
    pub per_page: usize,
    pub run_id: String,
    pub pack_id: String,
}
#[async_trait]
impl DiscoverySource for GithubSource {
    fn name(&self) -> &'static str {
        "github"
    }
    fn query_ids(&self) -> Vec<String> {
        self.queries.clone()
    }
    fn is_configured(&self) -> bool {
        !self.queries.is_empty()
    }
    async fn fetch(&self, budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let mut result = SourceFetchResult {
            source: "github".into(),
            ..Default::default()
        };
        let selected = budgets.selected_queries.as_ref();
        let queries = self
            .queries
            .iter()
            .filter(|query| selected.is_none_or(|values| values.contains(query)))
            .collect::<Vec<_>>();
        let code_limit = budgets.github_code.unwrap_or(queries.len());
        for query in queries.iter().copied().take(code_limit) {
            let shard_id = checkpoint_shard_id(&self.pack_id, query, "code_snapshot");
            let start_page = budgets
                .checkpoints
                .iter()
                .find(|checkpoint| checkpoint.shard_id == shard_id)
                .and_then(|checkpoint| checkpoint.cursor_state.get("next_page"))
                .and_then(Value::as_u64)
                .unwrap_or(1) as usize;
            for page in start_page..=5 {
                let value = match self.client.search_code(query, page, self.per_page).await {
                    Ok(value) => value,
                    Err(error) => {
                        result.errors.push(error.to_string());
                        break;
                    }
                };
                let items = value
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let count = items.len();
                for item in items {
                    self.process_code_item(&item, query, &mut result).await;
                    if let Some(work) = artifact_work(&item, query, "code_snapshot") {
                        result.artifact_work.push(work);
                    }
                }
                result.query_usage.push(QueryUsage {
                    source: "github".into(),
                    query: query.clone(),
                    page_count: 1,
                    result_count: count as u64,
                    query_id: query.clone(),
                    lane: "code_snapshot".into(),
                    ..Default::default()
                });
                if self.per_page <= 1 {
                    break;
                }
                if count < self.per_page {
                    break;
                }
            }
            result.checkpoint_updates.push(checkpoint(
                &self.pack_id,
                query,
                "code_snapshot",
                serde_json::json!({"next_page": 1}),
            ));
        }
        let commit_limit = budgets.github_commit.unwrap_or(0).min(queries.len());
        for query in queries.iter().copied().take(commit_limit) {
            let value = match self.client.search_commits(query, 1, self.per_page).await {
                Ok(value) => value,
                Err(error) => {
                    result.errors.push(error.to_string());
                    continue;
                }
            };
            let items = value
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for item in &items {
                let private = item.pointer("/repository/private").and_then(Value::as_bool);
                if private != Some(false) {
                    continue;
                }
                let endpoint = item
                    .get("html_url")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let message = item
                    .pointer("/commit/message")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                for secret in crate::github_artifacts::extract_artifact_text(
                    message,
                    endpoint,
                    "commit_message",
                    "context",
                    "",
                    item.get("sha").and_then(Value::as_str).unwrap_or_default(),
                ) {
                    result.credential_observations.push(observation(
                        item,
                        secret,
                        query,
                        "commit_message",
                    ));
                }
                if let Some(work) = artifact_work(item, query, "commit_message") {
                    result.artifact_work.push(work);
                }
                result.host_hits.push(item.clone());
            }
            result.query_usage.push(QueryUsage {
                source: "github".into(),
                query: query.clone(),
                page_count: 1,
                result_count: items.len() as u64,
                query_id: query.clone(),
                lane: "commit_message".into(),
                ..Default::default()
            });
            result.checkpoint_updates.push(checkpoint(
                &self.pack_id,
                query,
                "commit_message",
                serde_json::json!({"next_page": 1}),
            ));
        }
        result.credential_observation_count = Some(result.credential_observations.len() as u64);
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}

impl GithubSource {
    async fn process_code_item(&self, item: &Value, query: &str, result: &mut SourceFetchResult) {
        let public = item.pointer("/repository/private").and_then(Value::as_bool) == Some(false)
            || item
                .pointer("/repository/visibility")
                .and_then(Value::as_str)
                == Some("public");
        if !public {
            return;
        }
        let path = item.get("path").and_then(Value::as_str).unwrap_or_default();
        if crate::github_artifacts::is_noise_artifact_path(path) {
            return;
        }
        let endpoint = item
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut text = item
            .get("text_matches")
            .map(Value::to_string)
            .unwrap_or_default();
        if let Some((owner, repo)) = repository_name(item)
            && let Some(sha) = item.get("sha").and_then(Value::as_str)
            && let Ok(blob) = self.client.blob(owner, repo, sha).await
            && let Some(content) = blob.get("content").and_then(Value::as_str)
        {
            use base64::Engine;
            if let Ok(decoded) =
                base64::engine::general_purpose::STANDARD.decode(content.replace('\n', ""))
                && decoded.len() <= 1_048_576
            {
                text = String::from_utf8_lossy(&decoded).into_owned();
            }
        }
        for secret in crate::github_artifacts::extract_artifact_text(
            &text,
            endpoint,
            "code_snapshot",
            "context",
            path,
            item.get("sha").and_then(Value::as_str).unwrap_or_default(),
        ) {
            result
                .credential_observations
                .push(observation(item, secret, query, "code_snapshot"));
        }
        result.host_hits.push(item.clone());
    }
}
fn checkpoint_shard_id(pack_id: &str, query: &str, lane: &str) -> String {
    use sha1::Digest;
    format!(
        "{:x}",
        sha1::Sha1::digest(format!("{lane}|{pack_id}|{query}").as_bytes())
    )
}

fn checkpoint(
    pack_id: &str,
    query: &str,
    lane: &str,
    cursor_state: Value,
) -> crate::CheckpointUpdate {
    crate::CheckpointUpdate {
        source: "github".into(),
        lane: lane.into(),
        pack_id: pack_id.into(),
        shard_id: checkpoint_shard_id(pack_id, query, lane),
        watermark: chrono::Utc::now().to_rfc3339(),
        cursor_state,
        status: "ok".into(),
        ..Default::default()
    }
}

fn artifact_work(item: &Value, query: &str, lane: &str) -> Option<crate::ArtifactWork> {
    let repository = item.get("repository")?;
    let repo_id = repository.get("id").map(ToString::to_string)?;
    let repository_full_name = repository.get("full_name")?.as_str()?.to_owned();
    let object_sha = item
        .get("sha")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let commit_sha = object_sha.clone();
    let file_path = item
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Some(crate::ArtifactWork {
        repo_id,
        repository_full_name,
        commit_sha,
        file_path,
        object_sha,
        source_kind: lane.to_owned(),
        work_status: "fetch_pending".into(),
        current_stage: "fetch_pending".into(),
        query_id: query.to_owned(),
        lane: lane.to_owned(),
        coverage_mode: "complete".into(),
        ..Default::default()
    })
}

fn repository_name(item: &Value) -> Option<(&str, &str)> {
    item.pointer("/repository/full_name")
        .and_then(Value::as_str)?
        .split_once('/')
}

fn observation(
    item: &Value,
    secret: crate::github_artifacts::ExtractedArtifactSecret,
    query: &str,
    lane: &str,
) -> crate::CredentialObservation {
    crate::CredentialObservation {
        credential: secret.credential,
        provenance: crate::ArtifactProvenance {
            repository_id: item
                .pointer("/repository/id")
                .map(ToString::to_string)
                .unwrap_or_default(),
            repository_full_name: item
                .pointer("/repository/full_name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            commit_sha: item
                .get("sha")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            object_sha: secret.object_sha,
            file_path: secret.file_path,
            source_kind: secret.source_kind,
            change_side: secret.change_side,
            line_start: secret.line_start.map(u64::from),
            line_end: secret.line_end.map(u64::from),
            query_id: query.into(),
            lane: lane.into(),
            ..Default::default()
        },
        query_id: query.into(),
        lane: lane.into(),
        coverage_mode: "complete".into(),
        ..Default::default()
    }
}

pub struct ManualSource {
    pub targets: Vec<String>,
}
#[async_trait]
impl DiscoverySource for ManualSource {
    fn name(&self) -> &'static str {
        "manual"
    }
    fn query_ids(&self) -> Vec<String> {
        Vec::new()
    }
    fn is_configured(&self) -> bool {
        !self.targets.is_empty()
    }
    async fn fetch(&self, _budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let host_hits = self
            .targets
            .iter()
            .map(|url| serde_json::json!({"host":url,"url":url,"_source":"manual"}))
            .collect::<Vec<_>>();
        Ok(SourceFetchResult {
            source: "manual".into(),
            host_hit_count: Some(host_hits.len() as u64),
            host_hits,
            ..Default::default()
        })
    }
}

pub struct ManualEnrichSource {
    pub targets: Vec<String>,
    pub engines: Vec<String>,
    pub fofa: FofaClient,
    pub shodan: ShodanClient,
}

#[async_trait]
impl DiscoverySource for ManualEnrichSource {
    fn name(&self) -> &'static str {
        "manual_enrich"
    }
    fn is_configured(&self) -> bool {
        !self.targets.is_empty() && !self.engines.is_empty()
    }
    async fn fetch(&self, _: &SourceBudgets, _: ScanMode) -> Result<SourceFetchResult> {
        let mut result = SourceFetchResult {
            source: "manual_enrich".into(),
            ..Default::default()
        };
        for target in &self.targets {
            let normalized = if target.contains("://") {
                target.clone()
            } else {
                format!("https://{target}")
            };
            let Ok(url) = url::Url::parse(&normalized) else {
                continue;
            };
            let Some(hostname) = url.host_str() else {
                continue;
            };
            let is_ip = hostname.parse::<std::net::IpAddr>().is_ok();
            if self.engines.iter().any(|engine| engine == "fofa") {
                let query = if is_ip {
                    format!("ip=\"{hostname}\"")
                } else {
                    format!("host=\"{hostname}\" || domain=\"{hostname}\"")
                };
                match self.fofa.search(&query, 1, 50).await {
                    Ok(value) => {
                        let mut rows = value
                            .get("results")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        for row in &mut rows {
                            row["_source"] = "fofa".into();
                            row["_manual_seed_host"] = hostname.into();
                            row["_query_id"] = format!("manual-enrich:fofa:{hostname}").into();
                        }
                        result.query_usage.push(QueryUsage {
                            source: "fofa".into(),
                            query,
                            page_count: 1,
                            result_count: rows.len() as u64,
                            query_id: format!("manual-enrich:fofa:{hostname}"),
                            lane: "manual-enrich".into(),
                            ..Default::default()
                        });
                        result.host_hits.append(&mut rows);
                    }
                    Err(error) => result.errors.push(format!("fofa {hostname}: {error}")),
                }
            }
            if self.engines.iter().any(|engine| engine == "shodan") {
                let query = if is_ip {
                    format!("ip:{hostname}")
                } else {
                    format!("hostname:\"{hostname}\"")
                };
                match self.shodan.search(&query, 1).await {
                    Ok(value) => {
                        let mut rows = value
                            .get("matches")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        for row in &mut rows {
                            row["_source"] = "shodan".into();
                            row["_manual_seed_host"] = hostname.into();
                            row["_query_id"] = format!("manual-enrich:shodan:{hostname}").into();
                        }
                        result.query_usage.push(QueryUsage {
                            source: "shodan".into(),
                            query,
                            page_count: 1,
                            result_count: rows.len() as u64,
                            query_id: format!("manual-enrich:shodan:{hostname}"),
                            lane: "manual-enrich".into(),
                            ..Default::default()
                        });
                        result.host_hits.append(&mut rows);
                    }
                    Err(error) => result.errors.push(format!("shodan {hostname}: {error}")),
                }
            }
        }
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}
