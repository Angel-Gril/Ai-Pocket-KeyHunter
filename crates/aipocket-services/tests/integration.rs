use aipocket_core::{Credential, ScanMode, Settings};
use aipocket_db::{Repository, connect_pg, ensure_schema};
use aipocket_discovery::{DiscoverySource, SourceBudgets, SourceFetchResult};
use aipocket_services::{BalanceService, ScanEvent, Scanner, Scheduler};
use anyhow::Result;
use async_trait::async_trait;
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

struct FixtureSource {
    base: String,
}
#[async_trait]
impl DiscoverySource for FixtureSource {
    fn name(&self) -> &'static str {
        "manual"
    }
    fn is_configured(&self) -> bool {
        true
    }
    async fn fetch(&self, _: &SourceBudgets, _: ScanMode) -> Result<SourceFetchResult> {
        Ok(SourceFetchResult {
            source: "manual".into(),
            host_hits: vec![
                json!({"host":self.base,"body":"OPENAI_API_KEY=sk-integration-secret"}),
            ],
            host_hit_count: Some(1),
            ..Default::default()
        })
    }
}
async fn models() -> Json<Value> {
    Json(json!({"data":[{"id":"fixture-model"}]}))
}
async fn fixture_server() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/v1/models", get(models))
        .route(
            "/v1/chat/completions",
            axum::routing::post(|Json(body): Json<Value>| async move {
                Json(json!({"id":"chatcmpl-fixture","model":body["model"],"choices":[{"message":{"content":"ok"}}]}))
            }),
        )
        .route("/api/paas/v4/models", get(models))
        .route(
            "/api/paas/v4/chat/completions",
            axum::routing::post(|Json(body): Json<Value>| async move {
                Json(json!({"id":"chatcmpl-glm-fixture","model":body["model"],"choices":[{"message":{"content":"ok"}}]}))
            }),
        )
        .route(
            "/v1/messages",
            axum::routing::post(|Json(body): Json<Value>| async move {
                Json(json!({"id":"msg-fixture","model":body["model"],"content":[{"type":"text","text":"ok"}]}))
            }),
        )
        .route(
            "/v1beta/models/gemini-2.0-flash:generateContent",
            axum::routing::post(|| async { Json(json!({"candidates":[{"content":{"parts":[{"text":"ok"}]}}]})) }),
        )
        .route(
            "/user/balance",
            get(|| async { Json(json!({"balance":"12.5"})) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), task)
}
fn settings() -> Settings {
    Settings {
        database_url: std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://aipocket:aipocket@127.0.0.1:15432/aipocket".into()),
        dedup_redis_url: std::env::var("TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:16379/0".into()),
        pg_pool_min: 1,
        pg_pool_max: 3,
        validate_batch_size: 1,
        scan_lock_ttl: 10,
        ..Settings::default()
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis integration services"]
async fn scanner_persists_valid_result_ledger_and_resume_phase() {
    let settings = settings();
    let pool = connect_pg(&settings).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let repo = Repository::new(Some(pool.clone()));
    let (base, server) = fixture_server().await;
    let scanner = Scanner::new(
        Arc::new(settings.clone()),
        repo.clone(),
        reqwest::Client::new(),
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let run_id = scanner
        .run(
            vec![Arc::new(FixtureSource { base: base.clone() })],
            ScanMode::Incremental,
            CancellationToken::new(),
            tx,
        )
        .await
        .unwrap();
    let mut finished = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, ScanEvent::Finished { .. }) {
            finished = true;
        }
    }
    assert!(finished);
    let rows = repo.run_records(&run_id, "valid", false).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        repo.resume_phase(&run_id).await.unwrap().as_deref(),
        Some("finished")
    );
    let metrics: (i32, bool, String) = sqlx::query_as(
        "SELECT metrics_version,ledger_complete,ledger_incomplete_reason FROM runs WHERE run_id=$1",
    )
    .bind(&run_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(metrics.0, 3);
    assert!(metrics.1);
    assert!(metrics.2.is_empty());
    let dedup = aipocket_db::DedupStore::connect(&settings).await;
    assert!(dedup.target_seen("probe", &base).await);
    let cached_credential: Credential =
        serde_json::from_value(rows[0]["credential"].clone()).unwrap();
    assert!(
        dedup
            .get_success::<aipocket_core::ValidationResult>(&cached_credential)
            .await
            .is_some()
    );
    assert!(repo.delete_run(&run_id).await.unwrap());
    server.abort();
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis integration services"]
async fn scanner_cancellation_interrupts_run_and_jsonl_artifacts_are_written() {
    let mut settings = settings();
    settings.dedup_enabled = false;
    settings.pg_dual_write = true;
    let root = std::env::temp_dir().join(format!(
        "aipocket-scanner-integration-{}",
        uuid::Uuid::new_v4()
    ));
    settings.results_dir = root.to_string_lossy().into();
    let pool = connect_pg(&settings).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let repo = Repository::new(Some(pool));
    let scanner = Scanner::new(Arc::new(settings), repo.clone(), reqwest::Client::new());

    let cancel = CancellationToken::new();
    cancel.cancel();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let interrupted_id = scanner
        .run(
            vec![Arc::new(FixtureSource {
                base: String::new(),
            })],
            ScanMode::Full,
            cancel,
            tx,
        )
        .await
        .unwrap();
    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, ScanEvent::Phase(_)))
    );
    assert!(events.iter().any(
        |event| matches!(event, ScanEvent::Interrupted { error, .. } if error == "cancelled")
    ));
    let interrupted: (String, String) =
        sqlx::query_as("SELECT state,COALESCE(log,'') FROM runs WHERE run_id=$1")
            .bind(&interrupted_id)
            .fetch_one(repo.pool().unwrap())
            .await
            .unwrap();
    assert_eq!(interrupted.0, "interrupted");

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let (base, server) = fixture_server().await;
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let completed_id = scanner
        .run(
            vec![Arc::new(FixtureSource { base })],
            ScanMode::Full,
            CancellationToken::new(),
            tx,
        )
        .await
        .unwrap();
    let run_dir = root.join(&completed_id);
    for name in ["raw_hits.jsonl", "valid.jsonl", "suspicious.jsonl"] {
        assert!(run_dir.join(name).is_file(), "{name}");
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    scanner
        .fail_run(&completed_id, "fixture failure", &tx)
        .await;
    assert!(
        matches!(rx.try_recv(), Ok(ScanEvent::Interrupted { error, .. }) if error == "fixture failure")
    );

    assert!(repo.delete_run(&completed_id).await.unwrap());
    std::fs::remove_dir_all(root).unwrap();

    server.abort();
}
#[tokio::test]
async fn models_and_chat_use_provider_protocol_endpoints() {
    let (base, server) = fixture_server().await;
    let address: std::net::SocketAddr = base.trim_start_matches("http://").parse().unwrap();
    let service = BalanceService::new(
        reqwest::Client::builder()
            .resolve("api.anthropic.com", address)
            .resolve("generativelanguage.googleapis.com", address)
            .resolve("open.bigmodel.cn", address)
            .build()
            .unwrap(),
    );
    let openai = Credential {
        apikey: "sk-generic-fixture".into(),
        apiurl: base.clone(),
        ..Default::default()
    };
    assert_eq!(
        service.models(openai.clone()).await.unwrap(),
        vec!["fixture-model"]
    );
    let chat = service.test_chat(openai, "fixture-model").await.unwrap();
    assert!(chat.success);
    assert_eq!(chat.status_code, Some(200));
    assert_eq!(chat.model, "fixture-model");

    let anthropic = Credential {
        apikey: "sk-ant-api03-fixture".into(),
        apiurl: format!(
            "http://api.anthropic.com:{}/v1",
            url::Url::parse(&base).unwrap().port().unwrap()
        ),
        ..Default::default()
    };
    let messages = service
        .test_chat(anthropic, "claude-sonnet-fixture")
        .await
        .unwrap();
    assert!(messages.success);
    assert_eq!(messages.model, "claude-sonnet-fixture");

    let google = service
        .test_chat(
            Credential {
                apikey: "AIzaSyDaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                apiurl: format!(
                    "http://generativelanguage.googleapis.com:{}",
                    url::Url::parse(&base).unwrap().port().unwrap()
                ),
                ..Default::default()
            },
            "gemini-2.0-flash",
        )
        .await
        .unwrap();
    assert!(google.success);
    assert_eq!(google.model, "gemini-2.0-flash");

    let glm = Credential {
        apikey: "glm-fixture-key".into(),
        apiurl: format!("http://open.bigmodel.cn:{}/api/paas/v4", address.port()),
        ..Default::default()
    };
    assert_eq!(
        service.models(glm.clone()).await.unwrap(),
        vec!["fixture-model"]
    );
    let glm_chat = service.test_chat(glm, "glm-4-flash").await.unwrap();
    assert!(glm_chat.success);
    assert_eq!(glm_chat.status_code, Some(200));
    assert_eq!(glm_chat.model, "glm-4-flash");
    let empty = service
        .test_chat(
            Credential {
                apikey: "sk-generic-fixture".into(),
                ..Default::default()
            },
            "fixture-model",
        )
        .await
        .unwrap();
    assert_eq!(empty.error, "no apiurl");
    server.abort();
}
#[tokio::test]
async fn scheduler_ticks_and_cancels() {
    let settings = Arc::new(Settings {
        scheduler_interval: 1,
        ..Settings::default()
    });
    let scheduler = Scheduler::new(settings);
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let count = Arc::new(tokio::sync::Mutex::new(0));
    let seen = count.clone();
    scheduler
        .run_forever(cancel, move || {
            let seen = seen.clone();
            let stop = stop.clone();
            async move {
                let mut count = seen.lock().await;
                *count += 1;
                stop.cancel();
                Ok(())
            }
        })
        .await
        .unwrap();
    assert_eq!(*count.lock().await, 1);
}

#[tokio::test]
async fn balance_and_models_use_provider_routes() {
    let (base, server) = fixture_server().await;
    let service = BalanceService::new(reqwest::Client::new());
    let credential = Credential {
        apikey: "sk-test".into(),
        apiurl: base,
        ..Default::default()
    };
    assert_eq!(
        service.models(credential.clone()).await.unwrap(),
        vec!["fixture-model"]
    );
    let balance = service.query(&credential).await.unwrap();
    assert!(!balance.matched);
    server.abort();
}

#[tokio::test]
async fn balance_and_validation_cover_provider_protocols_and_statuses() {
    use axum::{
        Router,
        http::{HeaderMap, StatusCode},
        routing::get,
    };
    async fn models(headers: HeaderMap) -> (StatusCode, axum::Json<serde_json::Value>) {
        if headers.contains_key("x-api-key") {
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({"models":[{"name":"claude-fixture"}]})),
            )
        } else {
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error":"denied"})),
            )
        }
    }
    async fn gemini() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({"models":[{"name":"gemini-fixture"}]}))
    }
    async fn balance() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({"balance_infos":[{"currency":"USD","total_balance":12.5}]}))
    }
    let app = Router::new()
        .route("/v1/models", get(models))
        .route("/v1beta/models", get(gemini))
        .route("/user/balance", get(balance))
        .route("/deepseek/user/balance", get(balance));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}");
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let validator = aipocket_prober::Validator::new(
        reqwest::Client::builder()
            .resolve("api.anthropic.com", address)
            .resolve("generativelanguage.googleapis.com", address)
            .build()
            .unwrap(),
    );
    let port = address.port();
    let anthropic = validator
        .validate(Credential {
            apikey: "local-anthropic-fixture".into(),
            apiurl: format!("http://api.anthropic.com:{port}"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(anthropic.valid);
    assert_eq!(
        anthropic.provider_info.models_available,
        vec!["claude-fixture"]
    );
    let gemini = validator
        .validate(Credential {
            apikey: "local-gemini-fixture".into(),
            apiurl: format!("http://generativelanguage.googleapis.com:{port}"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(gemini.valid);
    let rejected = validator
        .validate(Credential {
            apikey: "sk-fixture".into(),
            apiurl: base.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(rejected.validation_state, "rejected");
    let no_url = validator.validate(Credential::default()).await.unwrap();
    assert_eq!(no_url.validation_state, "rejected");
    let deepseek = BalanceService::new(reqwest::Client::new())
        .query(&Credential {
            apikey: "fixture".into(),
            apiurl: format!("{base}/deepseek"),
            host: "https://api.deepseek.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(deepseek.balance_usd, "12.5");
    assert!(deepseek.matched);
    server.abort();
}

#[tokio::test]
async fn analyzer_extracts_attributed_credentials_and_rechecks_verdicts() {
    use axum::{Json, Router, extract::State, routing::post};
    use std::sync::atomic::{AtomicUsize, Ordering};
    async fn chat(State(calls): State<Arc<AtomicUsize>>) -> Json<Value> {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        let content = if call == 0 {
            r#"[{"entry_id":"entry-1","apikey":"sk-analyzer-abcdefghijkl","apiurl":"https://api.openai.com/v1","type":"openai"}]"#
        } else {
            r#"[{"idx":0,"valid":false,"reason":"fixture rejection","gateway":"relay"}]"#
        };
        Json(json!({"choices":[{"message":{"content":content}}]}))
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/chat/completions", post(chat))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let settings = Arc::new(Settings {
        gpt_key: "fixture".into(),
        gpt_base_url: base,
        gpt_recheck: true,
        gpt_recheck_batch_size: 1,
        ..Settings::default()
    });
    let analyzer = aipocket_services::Analyzer::new(settings, reqwest::Client::new());
    let report = analyzer.extract(&[json!({"_entry_id":"entry-1","host":"https://relay.example","_source":"fofa","body":"OPENAI_API_KEY=sk-analyzer-abcdefghijkl with enough surrounding evidence"})], None).await;
    assert_eq!(report.credentials.len(), 1);
    assert_eq!(report.credentials[0].backend, "fofa");
    let mut result = aipocket_core::ValidationResult {
        credential: report.credentials[0].clone(),
        valid: true,
        status_code: Some(200),
        response_snippet: "fixture".into(),
        ..Default::default()
    };
    analyzer.recheck(std::slice::from_mut(&mut result)).await;
    assert!(!result.valid);
    assert_eq!(result.validation_state, "rejected");
    assert_eq!(result.gateway, "relay");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn balance_routes_cover_gateway_and_provider_payload_shapes() {
    use axum::{Json, Router, extract::Request, routing::get};
    async fn fixture(request: Request) -> Json<Value> {
        let path = request.uri().path();
        let value = match path {
            "/deepseek/user/balance" => {
                json!({"balance_infos":[{"currency":"USD","total_balance":"9.5"}],"is_available":true})
            }
            "/kimi/v1/users/me/balance" => json!({"data":{"available_balance":"8"}}),
            "/minimax/token_plan/remains" => {
                json!({"base_resp":{"status_code":0},"model_remains":[{"model":"x"}]})
            }
            "/api/status" => {
                json!({"success":true,"data":{"quota_per_unit":1,"stripe_unit_price":1,"self_use_mode_enabled":true}})
            }
            "/api/user/self" => json!({"success":true,"data":{"quota":100.0,"used_quota":25.0}}),
            "/v1/models" | "/kimi/v1/models" => json!({"data":[{"id":"fixture-model"}]}),
            "/litellm/key/info" => {
                json!({"key_info":{"spend":3.0,"max_budget":10.0,"tier":"paid"}})
            }
            _ => json!({}),
        };
        Json(value)
    }
    let app = Router::new().fallback(get(fixture));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let service = BalanceService::new(reqwest::Client::new());
    let query = |apikey: &str, path: &str, host: &str| Credential {
        apikey: apikey.into(),
        apiurl: if path.is_empty() {
            base.clone()
        } else {
            format!("{base}{path}")
        },
        host: host.into(),
        ..Default::default()
    };
    let deepseek = service
        .query(&query("fixture", "/deepseek", "https://api.deepseek.com"))
        .await
        .unwrap();
    assert_eq!(deepseek.balance_usd, "9.5");
    assert_eq!(deepseek.evidence_kind, "cash_balance");
    let kimi = service
        .query(&query("fixture", "/kimi", "https://api.moonshot.cn"))
        .await
        .unwrap();
    assert_eq!(kimi.balance_native, "8");
    let minimax = service
        .query(&query("fixture", "/minimax", "https://api.minimax.io"))
        .await
        .unwrap();
    assert_eq!(minimax.evidence_kind, "quota");
    let gateway = service
        .query(&query("sk-fixture", "", "https://relay.example"))
        .await
        .unwrap();
    assert_eq!(gateway.gateway, "newapi");
    assert_eq!(gateway.balance_usd, "");
    assert_eq!(gateway.quota, json!({"quota":100.0,"used_quota":25.0}));
    server.abort();
}
