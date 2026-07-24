use aipocket_core::Settings;
use anyhow::{Context, Result};
use reqwest::{Client, header};
use serde_json::Value;
#[derive(Clone)]
pub struct GithubClient {
    http: Client,
    base_url: String,
    version: String,
    tokens: Vec<String>,
}
impl GithubClient {
    pub fn new(http: Client, settings: &Settings) -> Self {
        Self {
            http,
            base_url: settings.github_api_base_url.trim_end_matches('/').into(),
            version: settings.github_api_version.clone(),
            tokens: settings
                .github_token_list()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
    fn request(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self
            .tokens
            .first()
            .context("GITHUB_TOKENS not configured")?;
        Ok(self
            .http
            .get(format!("{}{}", self.base_url, path))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("X-GitHub-Api-Version", &self.version)
            .header(header::ACCEPT, "application/vnd.github+json"))
    }
    pub async fn rate_limit(&self) -> Result<Value> {
        Ok(self
            .request("/rate_limit")?
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn search_code(&self, query: &str, page: usize, per_page: usize) -> Result<Value> {
        Ok(self
            .request("/search/code")?
            .query(&[
                ("q", query),
                ("page", &page.to_string()),
                ("per_page", &per_page.to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn search_commits(&self, query: &str, page: usize, per_page: usize) -> Result<Value> {
        Ok(self
            .request("/search/commits")?
            .query(&[
                ("q", query),
                ("page", &page.to_string()),
                ("per_page", &per_page.to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn commit(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        page: usize,
        per_page: usize,
    ) -> Result<Value> {
        Ok(self
            .request(&format!("/repos/{owner}/{repo}/commits/{sha}"))?
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn blob(&self, owner: &str, repo: &str, sha: &str) -> Result<Value> {
        Ok(self
            .request(&format!("/repos/{owner}/{repo}/git/blobs/{sha}"))?
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn file_history(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        page: usize,
        per_page: usize,
    ) -> Result<Value> {
        Ok(self
            .request(&format!("/repos/{owner}/{repo}/commits"))?
            .query(&[
                ("path", path),
                ("page", &page.to_string()),
                ("per_page", &per_page.to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
