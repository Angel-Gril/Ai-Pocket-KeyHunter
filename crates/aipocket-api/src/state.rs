use crate::scan_manager::ScanManager;
use aipocket_clients::{FofaClient, GithubClient, ShodanClient, TavilyClient};
use aipocket_core::Settings;
use aipocket_db::Repository;
use aipocket_services::{BalanceService, Scanner};
use std::sync::Arc;
use tokio::sync::RwLock;
#[derive(Clone, Debug, Default)]
pub struct LoginFailures(
    pub Arc<tokio::sync::Mutex<std::collections::HashMap<String, Vec<std::time::Instant>>>>,
);
#[derive(Clone, Debug)]
pub struct RetryManager(pub Arc<tokio::sync::Mutex<serde_json::Value>>);

impl Default for RetryManager {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(serde_json::json!({
            "state":"idle","run_id":null,"started_at":null,"finished_at":null,"error":null,"report":null
        }))))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<RwLock<Settings>>,
    pub repository: Repository,
    pub http: reqwest::Client,
    pub scan_manager: Arc<ScanManager>,
    pub balance: BalanceService,
    pub scanner: Scanner,
    pub login_failures: LoginFailures,
    pub retry_manager: RetryManager,
}
impl AppState {
    pub async fn new(settings: Settings, repository: Repository) -> anyhow::Result<Self> {
        settings.validate_server()?;
        let settings = Arc::new(RwLock::new(settings));
        let timeout = settings.read().await.validate_timeout;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs_f64(timeout))
            .redirect(reqwest::redirect::Policy::limited(2))
            .no_proxy()
            .build()?;
        let scanner = Scanner::new(
            Arc::new(settings.read().await.clone()),
            repository.clone(),
            http.clone(),
        );
        let balance = BalanceService::new(http.clone());
        Ok(Self {
            settings,
            repository,
            http,
            scan_manager: Arc::new(ScanManager::new(2000)),
            balance,
            scanner,
            login_failures: LoginFailures::default(),
            retry_manager: RetryManager::default(),
        })
    }
    pub async fn fofa(&self) -> FofaClient {
        let settings = self.settings.read().await;
        FofaClient::new(self.http.clone(), &settings)
    }
    pub async fn shodan(&self) -> ShodanClient {
        let settings = self.settings.read().await;
        ShodanClient::new(self.http.clone(), &settings)
    }
    pub async fn github(&self) -> GithubClient {
        let settings = self.settings.read().await;
        GithubClient::new(self.http.clone(), &settings)
    }
    pub async fn tavily(&self) -> TavilyClient {
        let settings = self.settings.read().await;
        TavilyClient::new(self.http.clone(), &settings)
    }
}
