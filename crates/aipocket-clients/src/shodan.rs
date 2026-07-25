use aipocket_core::Settings;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone)]
pub struct ShodanClient {
    http: Client,
    base_url: String,
    keys: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShodanInfo {
    pub plan: String,
    pub query_credits: i64,
    #[serde(default)]
    pub scan_credits: i64,
}
impl ShodanClient {
    pub fn new(http: Client, settings: &Settings) -> Self {
        Self {
            http,
            base_url: settings.shodan_base_url.trim_end_matches('/').into(),
            keys: settings
                .shodan_key_list()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
    pub async fn info_all(&self) -> Vec<(String, Result<ShodanInfo, String>)> {
        let mut out = Vec::new();
        for key in &self.keys {
            let result = self
                .http
                .get(format!("{}/api-info", self.base_url))
                .query(&[("key", key)])
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| e.to_string());
            let parsed = match result {
                Ok(r) => r.json::<ShodanInfo>().await.map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            out.push((key.clone(), parsed));
        }
        out
    }
    pub async fn search(&self, query: &str, page: u32) -> Result<Value> {
        let key = self.keys.first().context("SHODAN_KEYS not configured")?;
        let response = self
            .http
            .get(format!("{}/shodan/host/search", self.base_url))
            .query(&[
                ("key", key.as_str()),
                ("query", query),
                ("page", &page.to_string()),
            ])
            .send()
            .await?;
        crate::parse_json_response("shodan", response).await
    }
    pub async fn count(&self, query: &str) -> Result<i64> {
        let key = self.keys.first().context("SHODAN_KEYS not configured")?;
        let value: Value = self
            .http
            .get(format!("{}/shodan/host/count", self.base_url))
            .query(&[("key", key.as_str()), ("query", query)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        value
            .get("total")
            .and_then(Value::as_i64)
            .context("Shodan count response missing total")
    }
}
