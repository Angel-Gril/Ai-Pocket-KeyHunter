use aipocket_core::{Credential, Settings, ValidationResult};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use tokio::sync::Semaphore;

const EXTRACT_SYSTEM: &str = "Extract real API credentials from each ENTRY. Return only a JSON array. Each item must have entry_id, apikey, apiurl, and type. Never invent a credential or associate it with a different ENTRY.";
const RECHECK_SYSTEM: &str = "Review validation evidence. Return only a JSON array of {idx,valid,reason,gateway}. Reject HTML pages, fake completions, honeypots, and non-provider responses.";

#[derive(Clone, Debug, Default)]
pub struct GptExtractionReport {
    pub credentials: Vec<Credential>,
    pub successful_entry_ids: HashSet<String>,
    pub failed_entry_ids: HashSet<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RetryGptFailedReport {
    pub run_id: String,
    pub failed_files: usize,
    pub failed_hits: usize,
    pub credentials_found: usize,
    pub valid_appended: usize,
    pub suspicious_appended: usize,
    pub high_value_final: usize,
    pub archived_files: Vec<String>,
    pub jsonl_paths: Vec<String>,
    pub message: String,
}

#[derive(Clone)]
pub struct Analyzer {
    settings: std::sync::Arc<Settings>,
    http: reqwest::Client,
}

impl Analyzer {
    pub fn new(settings: std::sync::Arc<Settings>, http: reqwest::Client) -> Self {
        Self { settings, http }
    }

    pub async fn extract(&self, hits: &[Value], run_dir: Option<&Path>) -> GptExtractionReport {
        if self.settings.gpt_key.is_empty() || self.settings.gpt_base_url.is_empty() {
            return GptExtractionReport::default();
        }
        let selected: Vec<_> = hits
            .iter()
            .filter(|hit| {
                ["header", "banner", "cert", "body"]
                    .iter()
                    .any(|field| hit.get(field).is_some_and(non_empty))
            })
            .cloned()
            .collect();
        if selected.is_empty() {
            return GptExtractionReport::default();
        }
        let batch_size = if self.settings.gpt_fast {
            self.settings.gpt_recheck_batch_size.max(40)
        } else {
            self.settings.gpt_recheck_batch_size.max(1)
        };
        let concurrency = if self.settings.gpt_fast {
            self.settings.gpt_recheck_concurrency.max(10)
        } else {
            self.settings.gpt_recheck_concurrency.max(1)
        };
        let semaphore = std::sync::Arc::new(Semaphore::new(concurrency));
        let mut tasks = tokio::task::JoinSet::new();
        for (index, batch) in selected.chunks(batch_size).enumerate() {
            let analyzer = self.clone();
            let batch = batch.to_vec();
            let semaphore = semaphore.clone();
            let run_dir = run_dir.map(Path::to_owned);
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.ok();
                analyzer
                    .extract_batch(batch, index + 1, run_dir.as_deref())
                    .await
            });
        }
        let mut report = GptExtractionReport::default();
        let mut seen = HashSet::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(batch) => {
                    report
                        .successful_entry_ids
                        .extend(batch.successful_entry_ids);
                    report.failed_entry_ids.extend(batch.failed_entry_ids);
                    for credential in batch.credentials {
                        if seen.insert((credential.apikey.clone(), credential.apiurl.clone())) {
                            report.credentials.push(credential);
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "GPT extraction task failed in isolation"),
            }
        }
        report
    }

    async fn extract_batch(
        &self,
        batch: Vec<Value>,
        index: usize,
        run_dir: Option<&Path>,
    ) -> GptExtractionReport {
        let entry_ids: HashSet<String> = batch.iter().filter_map(entry_id).collect();
        let targets: HashMap<String, Value> = batch
            .iter()
            .filter_map(|hit| entry_id(hit).map(|id| (id, hit.clone())))
            .collect();
        let payload = batch
            .iter()
            .filter_map(|hit| {
                let id = entry_id(hit)?;
                let text = ["host", "title", "header", "banner", "cert", "body"]
                    .into_iter()
                    .filter_map(|field| hit.get(field).map(|value| format!("{field}: {value}")))
                    .collect::<Vec<_>>()
                    .join("\n");
                (text.len() >= 30).then(|| format!("--- ENTRY {id} ---\n{text}"))
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        if payload.is_empty() {
            return GptExtractionReport {
                successful_entry_ids: entry_ids,
                ..Default::default()
            };
        }
        let response = self.chat(EXTRACT_SYSTEM, &payload, 8000).await;
        let Ok(content) = response else {
            dump_failed(run_dir, index, &batch);
            return GptExtractionReport {
                failed_entry_ids: entry_ids,
                ..Default::default()
            };
        };
        let Some(items) = parse_json_array(&content) else {
            dump_failed(run_dir, index, &batch);
            return GptExtractionReport {
                failed_entry_ids: entry_ids,
                ..Default::default()
            };
        };
        let credentials = items
            .into_iter()
            .filter_map(|item| credential_from_item(&item, &targets))
            .collect();
        GptExtractionReport {
            credentials,
            successful_entry_ids: entry_ids,
            failed_entry_ids: HashSet::new(),
        }
    }

    pub async fn recheck(&self, results: &mut [ValidationResult]) {
        if !self.settings.gpt_recheck
            || self.settings.gpt_key.is_empty()
            || self.settings.gpt_base_url.is_empty()
        {
            return;
        }
        let batches = results
            .iter()
            .enumerate()
            .filter_map(|(index, result)| result.valid.then_some(index))
            .collect::<Vec<_>>()
            .chunks(self.settings.gpt_recheck_batch_size.max(1))
            .map(<[usize]>::to_vec)
            .collect::<Vec<_>>();
        let semaphore =
            std::sync::Arc::new(Semaphore::new(self.settings.gpt_recheck_concurrency.max(1)));
        let mut tasks = tokio::task::JoinSet::new();
        for indices in batches {
            let analyzer = self.clone();
            let semaphore = semaphore.clone();
            let payload = indices
                .iter()
                .enumerate()
                .map(|(batch_index, result_index)| {
                    let result = &results[*result_index];
                    format!("--- ENTRY {batch_index} ---\nURL: {}\nStatus: {:?}\nRate headers: {}\nResponse body: {}", result.credential.apiurl, result.status_code, Value::Object(result.rate_limit_headers.clone()), result.response_snippet.chars().take(300).collect::<String>())
                })
                .collect::<Vec<_>>()
                .join("\n\n");
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.ok();
                let content = analyzer
                    .chat(RECHECK_SYSTEM, &payload, 200 + 80 * indices.len())
                    .await
                    .ok()?;
                Some((indices, parse_json_array(&content)?))
            });
        }
        while let Some(Ok(Some((indices, verdicts)))) = tasks.join_next().await {
            for verdict in verdicts {
                let Some(result_index) = verdict
                    .get("idx")
                    .and_then(Value::as_u64)
                    .and_then(|index| indices.get(index as usize))
                    .copied()
                else {
                    continue;
                };
                let result = &mut results[result_index];
                if verdict.get("valid").and_then(Value::as_bool) == Some(false) {
                    result.valid = false;
                    result.validation_state = "rejected".into();
                    result.error = format!(
                        "gpt-rejected: {}",
                        verdict
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                    );
                }
                if let Some(gateway) = verdict
                    .get("gateway")
                    .and_then(Value::as_str)
                    .filter(|gateway| !gateway.is_empty() && *gateway != "unknown")
                {
                    result.gateway = gateway.into();
                }
            }
        }
    }

    async fn chat(&self, system: &str, user: &str, max_tokens: usize) -> Result<String> {
        let url = format!(
            "{}/chat/completions",
            self.settings.gpt_base_url.trim_end_matches('/')
        );
        let mut payload = json!({
            "model": self.settings.gpt_model,
            "messages": [{"role":"system","content":system},{"role":"user","content":user}],
            "max_tokens": max_tokens,
            "temperature": 0,
        });
        if !self.settings.gpt_reasoning_effort.is_empty()
            && self.settings.gpt_reasoning_effort != "none"
        {
            payload["reasoning_effort"] = Value::String(self.settings.gpt_reasoning_effort.clone());
        }
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.settings.gpt_key)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        let body: Value = response
            .json()
            .await
            .context("GPT response is not valid JSON")?;
        content_from_chat_response(&body)
    }
    pub async fn retry_failed(
        &self,
        run_id: &str,
        run_dir: &Path,
        repository: &aipocket_db::Repository,
    ) -> Result<RetryGptFailedReport> {
        let failed = failed_batch_paths(run_dir)?;
        let mut report = RetryGptFailedReport {
            run_id: run_id.into(),
            failed_files: failed.len(),
            ..Default::default()
        };
        if failed.is_empty() {
            report.message = "No gpt_failed_batch_*.jsonl files found — nothing to retry.".into();
            return Ok(report);
        }
        let mut hits = Vec::new();
        for path in &failed {
            hits.extend(read_failed_batch(path)?);
        }
        report.failed_hits = hits.len();
        if hits.is_empty() {
            report.archived_files = archive_failed_batches(&failed)?;
            report.message = "Failed batch files were empty; archived.".into();
            return Ok(report);
        }
        for (index, hit) in hits.iter_mut().enumerate() {
            if hit
                .get("_entry_id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                hit["_entry_id"] = Value::String(format!("retry-{index}"));
            }
        }
        let mut credentials = crate::extract_credentials(&hits);
        let mut seen = credentials
            .iter()
            .map(|item| (item.apikey.clone(), item.apiurl.clone()))
            .collect::<HashSet<_>>();
        for credential in self.extract(&hits, Some(run_dir)).await.credentials {
            if seen.insert((credential.apikey.clone(), credential.apiurl.clone())) {
                credentials.push(credential);
            }
        }
        report.credentials_found = credentials.len();
        let existing = existing_result_identities(repository, run_id).await?;
        credentials.retain(|item| !existing.contains(&(item.apikey.clone(), item.apiurl.clone())));
        let validator = aipocket_prober::Validator::new(self.http.clone());
        let mut outcomes = Vec::new();
        for credential in credentials {
            match validator.validate(credential).await {
                Ok(result) => outcomes.push(result),
                Err(error) => tracing::warn!(%error, "GPT retry validation failed in isolation"),
            }
        }
        self.recheck(&mut outcomes).await;
        let (mut valid, suspicious) = crate::finalize_results(outcomes);
        let balance = crate::BalanceService::new(self.http.clone());
        for result in &mut valid {
            if let Ok(enriched) = balance.query_for_result(result).await {
                crate::balance::apply_probe_result(result, enriched);
            }
        }
        let valid_json = valid
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let suspicious_json = suspicious
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        repository
            .append_results(run_id, "valid", &valid_json)
            .await?;
        repository
            .append_results(run_id, "suspicious", &suspicious_json)
            .await?;
        report.valid_appended = valid.len();
        report.suspicious_appended = suspicious.len();
        for result in &valid {
            if let Some(record) = crate::high_value_record(result, run_id)
                && repository.upsert_high_value(run_id, &record).await?
            {
                report.high_value_final += 1;
            }
        }
        report.archived_files = archive_failed_batches(&failed)?;
        report.message = format!(
            "Appended {} valid + {} suspicious credential(s) to PostgreSQL results table.",
            report.valid_appended, report.suspicious_appended
        );
        Ok(report)
    }
}

fn content_from_chat_response(body: &Value) -> Result<String> {
    let choices = body
        .get("choices")
        .and_then(Value::as_array)
        .context("GPT response missing choices")?;
    let first = choices
        .first()
        .context("GPT response missing non-empty choices")?;
    let message = first.get("message");
    if message.is_none() || message == Some(&Value::Null) {
        return Ok(String::new());
    }
    let content = message.and_then(|value| value.get("content"));
    match content {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(content)) => Ok(content.clone()),
        _ => anyhow::bail!("GPT content expected string"),
    }
}

fn parse_json_array(content: &str) -> Option<Vec<Value>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(items) = serde_json::from_str::<Vec<Value>>(trimmed) {
        return Some(items.into_iter().filter(Value::is_object).collect());
    }
    let start = trimmed.find('[')?;
    let end = trimmed.rfind(']')?;
    serde_json::from_str::<Vec<Value>>(&trimmed[start..=end])
        .ok()
        .map(|items| items.into_iter().filter(Value::is_object).collect())
}

fn credential_from_item(item: &Value, targets: &HashMap<String, Value>) -> Option<Credential> {
    let id = item.get("entry_id")?.as_str()?;
    let target = targets.get(id)?;
    let apikey = item.get("apikey")?.as_str()?.trim();
    if apikey.is_empty() {
        return None;
    }
    let host = target
        .get("host")
        .or_else(|| target.get("url"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let explicit_apiurl = item
        .get("apiurl")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let provider = item
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| provider_hint("", apikey));
    let apiurl = explicit_apiurl
        .or_else(|| {
            let host_is_discovery_artifact =
                host.contains("github.com") || host.contains("fofa") || host.contains("shodan");
            (host.is_empty() || host_is_discovery_artifact)
                .then(|| provider_default(&provider))
                .flatten()
        })
        .unwrap_or(host);
    Some(Credential {
        apikey: apikey.into(),
        apiurl: apiurl.into(),
        source: provider,
        source_type: "body".into(),
        backend: target
            .get("_source")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        host: host.into(),
        ip: target
            .get("ip")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        port: target
            .get("port")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string())
            })
            .unwrap_or_default(),
        raw_context: target.to_string().chars().take(500).collect(),
        ..Default::default()
    })
}

fn failed_batch_paths(run_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = std::fs::read_dir(run_dir)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("gpt_failed")
                        && !name.ends_with(".done")
                        && !name.contains(".bak")
                })
        })
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn read_failed_batch(path: &Path) -> Result<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    let mut rows = Vec::new();
    for (index, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if index == 0 && value.get("batch_idx").is_some() {
            continue;
        }
        if value.is_array() {
            rows.extend(value.as_array().cloned().unwrap_or_default());
        } else if value.is_object() {
            rows.push(value);
        }
    }
    Ok(rows)
}

fn archive_failed_batches(paths: &[PathBuf]) -> Result<Vec<String>> {
    let mut archived = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("failed batch filename")?;
        let mut destination = path.with_file_name(format!("{name}.done"));
        if destination.exists() {
            destination = path.with_file_name(format!(
                "{name}.{}.done",
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
            ));
        }
        std::fs::rename(path, &destination)?;
        archived.push(
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .into(),
        );
    }
    Ok(archived)
}

async fn existing_result_identities(
    repository: &aipocket_db::Repository,
    run_id: &str,
) -> Result<HashSet<(String, String)>> {
    let mut identities = HashSet::new();
    for kind in ["valid", "suspicious"] {
        for row in repository.run_records(run_id, kind, false).await? {
            let key = row
                .pointer("/credential/apikey")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let url = row
                .pointer("/credential/apiurl")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !key.is_empty() {
                identities.insert((key.into(), url.into()));
            }
        }
    }
    Ok(identities)
}

fn entry_id(hit: &Value) -> Option<String> {
    hit.get("_entry_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
fn non_empty(value: &Value) -> bool {
    value.as_str().is_some_and(|value| !value.is_empty()) || !value.is_null()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfigCredentialBundle {
    pub secret: String,
    pub secret_fingerprint: String,
    pub credential_kind: String,
    pub endpoint_candidates: Vec<String>,
    pub provider_hint: String,
    pub confidence: String,
    pub context: Value,
    pub evidence: Value,
}

pub fn extract_config_bundles(content: &str, format_hint: &str) -> Vec<ConfigCredentialBundle> {
    let entries = parse_config_entries(content, format_hint);
    if entries
        .get("type")
        .is_some_and(|value| value == "service_account")
        && entries.contains_key("private_key")
    {
        let secret = entries["private_key"].clone();
        return vec![bundle(
            secret,
            "google_service_account",
            "vertex",
            vec!["https://aiplatform.googleapis.com".into()],
            "high",
            json!({"project":entries.get("project_id"),"location":entries.get("location").or_else(||entries.get("VERTEX_LOCATION")),"service_account_email":entries.get("client_email")}),
        )];
    }
    let endpoints: Vec<_> = entries
        .iter()
        .filter(|(name, value)| endpoint_name(name) && value.starts_with("http"))
        .map(|(name, value)| (name.clone(), value.trim_end_matches('/').to_owned()))
        .collect();
    entries.iter().filter(|(name, value)| secret_name(name) && value.len() >= 15).map(|(name, secret)| {
        let provider = provider_hint(name, secret);
        let prefix = variable_prefix(name);
        let matched: Vec<_> = endpoints.iter().filter(|(endpoint_name, _)| !prefix.is_empty() && variable_prefix(endpoint_name) == prefix).map(|(_, value)| value.clone()).collect();
        let urls = if matched.is_empty() { endpoints.iter().map(|(_, value)| value.clone()).collect::<Vec<_>>() } else { matched };
        let urls = if urls.is_empty() { provider_default(&provider).into_iter().map(str::to_owned).collect() } else { urls };
        let confidence = if urls.len() > 1 { "ambiguous" } else if !prefix.is_empty() { "high" } else { "medium" };
        let azure_resource = urls.first().and_then(|value| url::Url::parse(value).ok()).and_then(|url| url.host_str().map(|host| host.split('.').next().unwrap_or_default().to_owned())).unwrap_or_default();
        bundle(secret.clone(), "api_key", &provider, urls, confidence, json!({"azure_resource":azure_resource,"deployment":entries.get("AZURE_OPENAI_DEPLOYMENT").or_else(||entries.get("AZURE_OPENAI_DEPLOYMENT_NAME")),"api_version":entries.get("AZURE_OPENAI_API_VERSION").or_else(||entries.get("OPENAI_API_VERSION"))}))
    }).collect()
}

fn parse_config_entries(content: &str, hint: &str) -> HashMap<String, String> {
    let hint = hint.trim_start_matches('.').to_ascii_lowercase();
    if hint == "json"
        && let Ok(value) = serde_json::from_str::<Value>(content)
    {
        return flatten(&value);
    }
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches("export ");
            let (key, value) = line.split_once('=').or_else(|| line.split_once(':'))?;
            let key = key.trim().trim_matches(['\"', '\'']).to_owned();
            let value = value.trim().trim_matches(['\"', '\'', ',']).to_owned();
            (!key.is_empty() && !value.is_empty()).then_some((key, value))
        })
        .collect()
}
fn flatten(value: &Value) -> HashMap<String, String> {
    fn visit(value: &Value, output: &mut HashMap<String, String>) {
        match value {
            Value::Object(fields) => {
                for (name, value) in fields {
                    if let Some(text) = value.as_str() {
                        output.insert(name.clone(), text.into());
                    } else {
                        visit(value, output);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    visit(item, output);
                }
            }
            _ => {}
        }
    }
    let mut output = HashMap::new();
    visit(value, &mut output);
    output
}
fn bundle(
    secret: String,
    kind: &str,
    provider: &str,
    urls: Vec<String>,
    confidence: &str,
    context: Value,
) -> ConfigCredentialBundle {
    use sha1::{Digest, Sha1};
    ConfigCredentialBundle {
        secret_fingerprint: format!("{:x}", Sha1::digest(secret.as_bytes())),
        secret,
        credential_kind: kind.into(),
        endpoint_candidates: urls,
        provider_hint: provider.into(),
        confidence: confidence.into(),
        context,
        evidence: json!({"source":"config"}),
    }
}
fn secret_name(name: &str) -> bool {
    ["api_key", "apikey", "token", "secret", "private_key"]
        .iter()
        .any(|suffix| name.to_ascii_lowercase().ends_with(suffix))
}
fn endpoint_name(name: &str) -> bool {
    ["base_url", "api_url", "endpoint", "api_base"]
        .iter()
        .any(|suffix| name.to_ascii_lowercase().ends_with(suffix))
}
fn variable_prefix(name: &str) -> String {
    let upper = name.to_ascii_uppercase();
    [
        "_API_KEY",
        "_KEY",
        "_TOKEN",
        "_SECRET",
        "_BASE_URL",
        "_API_URL",
        "_ENDPOINT",
        "_API_BASE",
    ]
    .iter()
    .find_map(|suffix| upper.strip_suffix(suffix).map(str::to_owned))
    .unwrap_or_default()
}
fn provider_hint(name: &str, secret: &str) -> String {
    let text = name.to_ascii_lowercase();
    [
        ("aws_bearer_token_bedrock", "aws_bedrock"),
        ("bedrock", "aws_bedrock"),
        ("windsurf", "windsurf"),
        ("codeium", "windsurf"),
        ("cursor", "cursor"),
        ("kiro", "kiro"),
        ("qoder", "qoder"),
        ("xai", "xai"),
        ("grok", "xai"),
        ("gemini", "gemini"),
        ("azure_openai", "azure_openai"),
        ("zhipu", "glm"),
        ("bigmodel", "glm"),
        ("glm", "glm"),
        ("moonshot", "kimi"),
        ("kimi", "kimi"),
        ("dashscope", "qwen"),
        ("qwen", "qwen"),
        ("cohere", "cohere"),
        ("replicate", "replicate"),
        ("together", "together"),
        ("fireworks", "fireworks"),
        ("minimax", "minimax"),
        ("nvidia", "nvidia"),
        ("ksyun", "ksyun"),
        ("longcat", "longcat"),
        ("openai", "openai"),
        ("anthropic", "anthropic"),
        ("google", "google"),
        ("vertex", "vertex"),
    ]
    .iter()
    .find_map(|(token, provider)| text.contains(token).then_some((*provider).to_owned()))
    .unwrap_or_else(|| {
        if secret.starts_with("xai-") {
            "xai".into()
        } else if secret.starts_with("ksk_") {
            "kiro".into()
        } else if secret.starts_with("crsr_") {
            "cursor".into()
        } else if secret.starts_with("pt-") {
            "qoder".into()
        } else if secret.starts_with("sk-ant-") {
            "anthropic".into()
        } else if secret.starts_with("r8_") {
            "replicate".into()
        } else if secret.starts_with("AIza") {
            "gemini".into()
        } else if secret.starts_with("sk-") {
            "openai".into()
        } else {
            "unknown".into()
        }
    })
}
fn dump_failed(run_dir: Option<&Path>, index: usize, batch: &[Value]) {
    let Some(directory) = run_dir else { return };
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let path: PathBuf = directory.join(format!("gpt_failed_batch_{stamp}_{index}.jsonl"));
    let mut lines = Vec::with_capacity(batch.len() + 1);
    lines.push(
        json!({"batch_idx":index,"total_hits":batch.len(),"dumped_at":stamp.to_string()})
            .to_string(),
    );
    lines.extend(batch.iter().map(Value::to_string));
    let _ = std::fs::create_dir_all(directory);
    let _ = std::fs::write(path, format!("{}\n", lines.join("\n")));
}

fn provider_default(provider: &str) -> Option<&'static str> {
    Some(match provider {
        "aws_bedrock" => "https://bedrock.us-east-1.amazonaws.com",
        "xai" => "https://api.x.ai/v1",
        "qoder" => "https://api.qoder.com",
        "kiro" => "https://app.kiro.dev",
        "cursor" => "https://api.cursor.com",
        "windsurf" => "https://server.codeium.com/api/v1",
        "gemini" => "https://generativelanguage.googleapis.com",
        "openai" => "https://api.openai.com/v1",
        "anthropic" => "https://api.anthropic.com/v1",
        "google" => "https://generativelanguage.googleapis.com",
        "vertex" => "https://aiplatform.googleapis.com",
        "glm" => "https://open.bigmodel.cn/api/paas/v4",
        "kimi" => "https://api.moonshot.cn/v1",
        "qwen" => "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "cohere" => "https://api.cohere.com/v1",
        "replicate" => "https://api.replicate.com/v1",
        "together" => "https://api.together.xyz/v1",
        "fireworks" => "https://api.fireworks.ai/inference/v1",
        "minimax" => "https://api.minimax.io/v1",
        "nvidia" => "https://integrate.api.nvidia.com/v1",
        "ksyun" => "https://kspmas.ksyun.com/v1",
        "longcat" => "https://api.longcat.chat/openai",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_fenced_json_and_rejects_unknown_attribution() {
        assert_eq!(
            parse_json_array("```json\n[{\"x\":1}]\n```").unwrap().len(),
            1
        );
        let targets = HashMap::from([("known".into(), json!({"host":"https://a"}))]);
        assert!(
            credential_from_item(
                &json!({"entry_id":"other","apikey":"sk-proj-abcdefghijklmnopqrstuv"}),
                &targets
            )
            .is_none()
        );
    }
    #[test]
    fn attributed_provider_keys_receive_official_endpoints() {
        let targets = HashMap::from([(
            "known".into(),
            json!({"host":"https://github.com/acme/repo/blob/main/.env","_source":"github"}),
        )]);
        for (key, provider, endpoint) in [
            ("xai-abcdefghijklmnop", "xai", "https://api.x.ai/v1"),
            ("ksk_abcdefghijklmnop", "kiro", "https://app.kiro.dev"),
            (
                "crsr_abcdefghijklmnopqrstuvwxyz123456",
                "cursor",
                "https://api.cursor.com",
            ),
            ("pt-abcdefghijklmnop", "qoder", "https://api.qoder.com"),
            (
                "AIzaSyabcdefghijklmnopqrst",
                "gemini",
                "https://generativelanguage.googleapis.com",
            ),
        ] {
            let credential = credential_from_item(
                &json!({"entry_id":"known","apikey":key,"type":provider}),
                &targets,
            )
            .unwrap();
            assert_eq!(credential.apiurl, endpoint, "{provider}");
        }
    }

    #[test]
    fn config_pairs_provider_prefix_and_default() {
        let rows = extract_config_bundles(
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuv\nOPENAI_BASE_URL=https://relay.example/v1",
            "env",
        );
        assert_eq!(rows[0].provider_hint, "openai");
        assert_eq!(
            rows[0].endpoint_candidates,
            vec!["https://relay.example/v1"]
        );
        let defaults = extract_config_bundles(
            "GLM_API_KEY=f7638a0d932046079d9900bda54cdde9.79EtThsVS0IEdssm",
            "env",
        );
        assert_eq!(
            defaults[0].endpoint_candidates,
            vec!["https://open.bigmodel.cn/api/paas/v4"]
        );
    }

    #[test]
    fn failed_batch_files_parse_archive_and_ignore_metadata() {
        let root = std::env::temp_dir().join(format!("aipocket-analyzer-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("gpt_failed_batch_fixture.jsonl");
        std::fs::write(
            &path,
            "{\"batch_idx\":3,\"total_hits\":2}\n[{\"host\":\"a\"},{\"host\":\"b\"}]\nnot-json\n",
        )
        .unwrap();
        assert_eq!(failed_batch_paths(&root).unwrap(), vec![path.clone()]);
        assert_eq!(read_failed_batch(&path).unwrap().len(), 2);
        let archived = archive_failed_batches(std::slice::from_ref(&path)).unwrap();
        assert_eq!(archived.len(), 1);
        assert!(!path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_parses_service_accounts_nested_json_and_ambiguous_endpoints() {
        let service = extract_config_bundles(
            r#"{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----fixture","project_id":"p","client_email":"svc@example.test"}"#,
            "json",
        );
        assert_eq!(service[0].credential_kind, "google_service_account");
        assert_eq!(service[0].provider_hint, "vertex");
        let rows = extract_config_bundles(
            "CUSTOM_API_KEY=abcdefghijklmnopqrst\nONE_BASE_URL=https://one.test\nTWO_ENDPOINT=https://two.test",
            "yaml",
        );
        assert_eq!(rows[0].confidence, "ambiguous");
        assert_eq!(rows[0].endpoint_candidates.len(), 2);
        assert_eq!(
            provider_hint("MYSTERY_KEY", "AIzaSyabcdefghijklmnopqrst"),
            "gemini"
        );
        assert!(provider_default("missing").is_none());
    }

    #[tokio::test]
    async fn extraction_failures_dump_retryable_batches_and_empty_payloads_succeed() {
        let root = std::env::temp_dir().join(format!(
            "aipocket-analyzer-failure-{}",
            uuid::Uuid::new_v4()
        ));
        let analyzer = Analyzer::new(
            std::sync::Arc::new(Settings {
                gpt_key: "fixture".into(),
                gpt_base_url: "http://127.0.0.1:1/v1".into(),
                ..Settings::default()
            }),
            reqwest::Client::new(),
        );
        let failed = analyzer
            .extract(
                &[json!({"_entry_id":"failure","host":"https://failure.example","body":"OPENAI_API_KEY=sk-failure-abcdefghijkl"})],
                Some(&root),
            )
            .await;
        assert!(failed.failed_entry_ids.contains("failure"));
        let paths = failed_batch_paths(&root).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(read_failed_batch(&paths[0]).unwrap().len(), 1);

        let empty = analyzer
            .extract(&[json!({"_entry_id":"empty","body":"x"})], None)
            .await;
        assert!(empty.successful_entry_ids.contains("empty"));
        assert!(empty.credentials.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn chat_and_config_parsers_fail_closed_on_malformed_shapes() {
        assert!(content_from_chat_response(&json!({})).is_err());
        assert!(content_from_chat_response(&json!({"choices":[]})).is_err());
        assert_eq!(
            content_from_chat_response(&json!({"choices":[{"message":null}]})).unwrap(),
            ""
        );
        assert!(
            content_from_chat_response(&json!({"choices":[{"message":{"content":3}}]})).is_err()
        );
        assert!(parse_json_array("").is_none());
        assert!(parse_json_array("no array").is_none());

        let nested = extract_config_bundles(
            r#"{"nested":[{"OPENAI_API_KEY":"sk-nested-abcdefghijkl","OPENAI_BASE_URL":"https://nested.example/v1"}]}"#,
            "json",
        );
        assert_eq!(
            nested[0].endpoint_candidates,
            vec!["https://nested.example/v1"]
        );
        assert_eq!(
            provider_hint("MYSTERY_KEY", "sk-ant-api03-abcdefghijkl"),
            "anthropic"
        );
        assert_eq!(
            provider_hint("MYSTERY_KEY", "r8_abcdefghijklmnop"),
            "replicate"
        );
        assert_eq!(
            provider_hint("MYSTERY_KEY", "sk-abcdefghijklmnop"),
            "openai"
        );
    }
}
