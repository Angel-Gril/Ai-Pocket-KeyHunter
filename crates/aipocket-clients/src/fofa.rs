use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::Client;
use serde_json::Value;

use aipocket_core::Settings;

#[derive(Clone)]
pub struct FofaClient {
    http: Client,
    base_url: String,
    keys: Vec<String>,
}
impl FofaClient {
    pub fn new(http: Client, settings: &Settings) -> Self {
        Self {
            http,
            base_url: settings.fofa_base_url.trim_end_matches('/').into(),
            keys: settings
                .fofa_key_list()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
    pub async fn search(&self, query: &str, page: u32, size: u32) -> Result<Value> {
        let key = self.keys.first().context("FOFA_KEYS not configured")?;
        let qbase64 = STANDARD.encode(query);
        let response = self
            .http
            .get(format!("{}/api/v1/search/all", self.base_url))
            .query(&[
                ("key", key.as_str()),
                ("qbase64", qbase64.as_str()),
                ("page", &page.to_string()),
                ("size", &size.to_string()),
                ("fields", "host,ip,port,protocol,title,header,body,cert"),
            ])
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }
    pub async fn check(&self) -> Result<Value> {
        self.search("title=\"123\"", 1, 1).await
    }
}
