use aipocket_core::Settings;
use aipocket_db::mask_apikey;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};
#[derive(Clone, Debug, Serialize)]
pub struct SettingsView {
    pub fofa_keys: String,
    pub fofa_base_url: String,
    pub fofa_page_size: u32,
    pub fofa_max_pages: u32,
    pub fofa_timeout: f64,
    pub shodan_keys: String,
    pub shodan_base_url: String,
    pub shodan_max_pages: u32,
    pub shodan_timeout: f64,
    pub shodan_page_delay: f64,
    pub github_tokens: String,
    pub github_api_base_url: String,
    pub github_hunter_enabled: bool,
    pub validate_concurrency: usize,
    pub prober_concurrency: usize,
}
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SettingsUpdate {
    pub fofa_keys: Option<String>,
    pub fofa_base_url: Option<String>,
    pub fofa_page_size: Option<u32>,
    pub fofa_max_pages: Option<u32>,
    pub fofa_timeout: Option<f64>,
    pub shodan_keys: Option<String>,
    pub shodan_base_url: Option<String>,
    pub shodan_max_pages: Option<u32>,
    pub shodan_timeout: Option<f64>,
    pub shodan_page_delay: Option<f64>,
    pub github_tokens: Option<String>,
    pub github_api_base_url: Option<String>,
    pub github_hunter_enabled: Option<bool>,
    pub validate_concurrency: Option<usize>,
    pub prober_concurrency: Option<usize>,
    pub prober_batch_timeout_secs: Option<u64>,
}
impl SettingsView {
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            fofa_keys: mask_list(&s.fofa_keys),
            fofa_base_url: s.fofa_base_url.clone(),
            fofa_page_size: s.fofa_page_size,
            fofa_max_pages: s.fofa_max_pages,
            fofa_timeout: s.fofa_timeout,
            shodan_keys: mask_list(&s.shodan_keys),
            shodan_base_url: s.shodan_base_url.clone(),
            shodan_max_pages: s.shodan_max_pages,
            shodan_timeout: s.shodan_timeout,
            shodan_page_delay: s.shodan_page_delay,
            github_tokens: mask_list(&s.github_tokens),
            github_api_base_url: s.github_api_base_url.clone(),
            github_hunter_enabled: s.github_hunter_enabled,
            validate_concurrency: s.validate_concurrency,
            prober_concurrency: s.prober_concurrency,
        }
    }
}
impl SettingsUpdate {
    pub fn env_updates(&self) -> BTreeMap<&'static str, String> {
        let mut out = BTreeMap::new();
        macro_rules! put {
            ($field:ident,$key:literal) => {
                if let Some(v) = &self.$field {
                    out.insert($key, v.to_string());
                }
            };
        }
        macro_rules! secret {
            ($field:ident,$key:literal) => {
                if let Some(v) = &self.$field {
                    if !v.contains("****") {
                        out.insert($key, v.to_string());
                    }
                }
            };
        }
        secret!(fofa_keys, "FOFA_KEYS");
        put!(fofa_base_url, "FOFA_BASE_URL");
        put!(fofa_page_size, "FOFA_PAGE_SIZE");
        put!(fofa_max_pages, "FOFA_MAX_PAGES");
        put!(fofa_timeout, "FOFA_TIMEOUT");
        secret!(shodan_keys, "SHODAN_KEYS");
        put!(shodan_base_url, "SHODAN_BASE_URL");
        put!(shodan_max_pages, "SHODAN_MAX_PAGES");
        put!(shodan_timeout, "SHODAN_TIMEOUT");
        put!(shodan_page_delay, "SHODAN_PAGE_DELAY");
        secret!(github_tokens, "GITHUB_TOKENS");
        put!(github_api_base_url, "GITHUB_API_BASE_URL");
        put!(github_hunter_enabled, "GITHUB_HUNTER_ENABLED");
        put!(validate_concurrency, "VALIDATE_CONCURRENCY");
        put!(prober_concurrency, "PROBER_CONCURRENCY");
        put!(prober_batch_timeout_secs, "PROBER_BATCH_TIMEOUT_SECS");
        out
    }
}
pub fn persist_env(path: &Path, updates: &BTreeMap<&str, String>) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let mut lines = Vec::new();
    for line in existing.lines() {
        if let Some((key, _)) = line.split_once('=')
            && let Some(value) = updates.get(key.trim())
        {
            lines.push(format!("{}={value}", key.trim()));
            seen.insert(key.trim().to_owned());
            continue;
        }
        lines.push(line.to_owned());
    }
    for (key, value) in updates {
        if !seen.contains(*key) {
            lines.push(format!("{key}={value}"));
        }
    }
    fs::write(path, format!("{}\n", lines.join("\n"))).context("write .env")
}
fn mask_list(value: &str) -> String {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(mask_apikey)
        .collect::<Vec<_>>()
        .join(",")
}
