use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::Client;
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use aipocket_core::Settings;

/// FOFA client.
///
/// Supports two deployment styles:
/// - Official / API-compatible relays: `FOFA_BASE_URL` + `FOFA_KEYS`
///   (plain `GET {base}/api/v1/search/all?key=&qbase64=&page=&size=&fields=`).
/// - Session-gated relays (e.g. map.shenxd.top card login): additionally
///   configure `FOFA_LOGIN_URL` (e.g. `http://host/login.php`) and
///   `FOFA_API_PATH` (e.g. `/fofa/test_fofa/fofa1_api.php`). The client
///   lazily logs in once with the first key as `user_key` (web-session card
///   login), stores the session cookie via the cookie jar, and then queries
///   the configured API path with the same key parameter.
#[derive(Clone)]
pub struct FofaClient {
    http: Client,
    base_url: String,
    login_url: Option<String>,
    api_path: String,
    keys: Vec<String>,
    logged_in: Arc<AtomicBool>,
}
impl FofaClient {
    pub fn new(http: Client, settings: &Settings) -> Self {
        let login_url = settings.fofa_login_url.trim();
        Self {
            http,
            base_url: settings.fofa_base_url.trim_end_matches('/').into(),
            login_url: if login_url.is_empty() {
                None
            } else {
                Some(login_url.to_owned())
            },
            api_path: {
                let path = settings.fofa_api_path.trim();
                if path.is_empty() {
                    "/api/v1/search/all".into()
                } else {
                    path.trim_start_matches('/').to_owned()
                }
            },
            keys: settings
                .fofa_key_list()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            logged_in: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Some relays require a web-session login (card number as `user_key`)
    /// before the API path accepts the key. Lazy, once per process.
    async fn ensure_logged_in(&self) -> Result<()> {
        if self.logged_in.load(Ordering::Relaxed) {
            return Ok(());
        }
        let Some(login_url) = &self.login_url else {
            self.logged_in.store(true, Ordering::Relaxed);
            return Ok(());
        };
        let key = self.keys.first().context("FOFA_KEYS not configured")?;
        self.http
            .post(login_url)
            .form(&[("user_key", key.as_str())])
            .send()
            .await
            .context("FOFA session login request")?;
        self.logged_in.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub async fn search(&self, query: &str, page: u32, size: u32) -> Result<Value> {
        self.ensure_logged_in().await?;
        let key = self.keys.first().context("FOFA_KEYS not configured")?;
        let qbase64 = STANDARD.encode(query);
        let response = self
            .http
            .get(format!("{}/{}", self.base_url, self.api_path))
            .query(&[
                ("key", key.as_str()),
                ("qbase64", qbase64.as_str()),
                ("page", &page.to_string()),
                ("size", &size.to_string()),
                // Keep field list aligned with Python DEFAULT_FIELDS / discovery FOFA_FIELDS.
                (
                    "fields",
                    "host,ip,port,protocol,title,header,banner,server,product,link,domain,cert",
                ),
            ])
            .send()
            .await?;
        crate::parse_json_response("fofa", response).await
    }
    pub async fn check(&self) -> Result<Value> {
        self.search("title=\"123\"", 1, 1).await
    }
}
