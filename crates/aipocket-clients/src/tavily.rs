use aipocket_core::Settings;
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{Value, json};
#[derive(Clone)]
pub struct TavilyClient {
    http: Client,
    base_url: String,
    key: String,
}
impl TavilyClient {
    pub fn new(http: Client, settings: &Settings) -> Self {
        Self {
            http,
            base_url: settings.tavily_base_url.trim_end_matches('/').into(),
            key: settings.tavily_key.clone(),
        }
    }
    pub async fn search(&self, query: &str) -> Result<Value> {
        if self.key.is_empty() {
            anyhow::bail!("TAVILY_KEY not configured")
        }
        let response = self
            .http
            .post(format!("{}/search", self.base_url))
            .json(&json!({"api_key":self.key,"query":query,"search_depth":"advanced"}))
            .send()
            .await
            .context("Tavily request")?
            .error_for_status()?;
        Ok(response.json().await?)
    }
}
