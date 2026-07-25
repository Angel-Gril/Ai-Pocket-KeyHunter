use aipocket_clients::{FofaClient, GithubClient, ShodanClient};
use aipocket_core::{ScanMode, Settings};
use aipocket_discovery::{
    DiscoveryProgress, DiscoverySource, SourceBudgets,
    sources::{FofaSource, GithubSource, ManualSource, ShodanSource},
};
use axum::{Json, Router, extract::Query, routing::get};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::sync::Arc;
async fn fixture(Query(q): Query<std::collections::HashMap<String, String>>) -> Json<Value> {
    if q.contains_key("qbase64") {
        Json(json!({"results":[{"host":"https://fofa"}]}))
    } else if q.contains_key("query") {
        Json(json!({"matches":[{"host":"https://shodan"}]}))
    } else {
        let private = q.get("q").is_some_and(|value| value.contains("private"));
        Json(json!({"items":[{
            "host":"https://github",
            "html_url":"https://github.example/fixture/public/blob/sha/.env",
            "path":if private {"vendor/bundle.js"} else {".env"},
            "sha":"blob-sha",
            "text_matches":[{"fragment":"OPENAI_API_KEY=sk-github-abcdefghijkl"}],
            "commit":{"message":"ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnop"},
            "repository":{"private":private,"visibility":if private {"private"} else {"public"},"id":1,"full_name":"fixture/public"}
        }]}))
    }
}
async fn server() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/v1/search/all", get(fixture))
        .route("/shodan/host/search", get(fixture))
        .route("/search/code", get(fixture))
        .route("/search/commits", get(fixture));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), task)
}
#[tokio::test]
async fn all_source_adapters_return_contract_shape() {
    let (base, task) = server().await;
    let settings = Settings {
        fofa_keys: "x".into(),
        shodan_keys: "x".into(),
        github_tokens: "x".into(),
        fofa_base_url: base.clone(),
        shodan_base_url: base.clone(),
        github_api_base_url: base.clone(),
        ..Settings::default()
    };
    let http = reqwest::Client::new();
    let sources: Vec<Arc<dyn DiscoverySource>> = vec![
        Arc::new(FofaSource {
            client: FofaClient::new(http.clone(), &settings),
            queries: vec!["q".into()],
            page_size: 100,
            max_pages: 1,
            page_delay: 0.0,
        }),
        Arc::new(ShodanSource {
            client: ShodanClient::new(http.clone(), &settings),
            queries: vec!["q".into()],
            max_pages: 1,
            page_delay: 0.0,
        }),
        Arc::new(GithubSource {
            client: GithubClient::new(http, &settings),
            queries: vec!["q".into()],
            per_page: 1,
            run_id: "run_fixture".into(),
            pack_id: "fixture".into(),
        }),
        Arc::new(ManualSource {
            targets: vec!["https://manual".into()],
        }),
    ];
    for source in sources {
        let source_name = source.name();
        let budgets = if source_name == "github" {
            SourceBudgets {
                github_code: Some(1),
                github_commit: Some(1),
                ..Default::default()
            }
        } else {
            SourceBudgets::default()
        };
        let result = source.fetch(&budgets, ScanMode::Incremental).await.unwrap();
        assert!(!result.host_hits.is_empty());
        assert_eq!(result.source, source_name);
        if source_name == "fofa" || source_name == "shodan" || source_name == "manual" {
            for hit in &result.host_hits {
                assert!(
                    hit.get("host")
                        .and_then(Value::as_str)
                        .is_some_and(|h| !h.is_empty()),
                    "{source_name} hit missing host: {hit}"
                );
                assert_eq!(
                    hit.get("_source").and_then(Value::as_str),
                    Some(source_name),
                    "{source_name} hit missing _source: {hit}"
                );
            }
        }
        if source_name == "github" {
            assert_eq!(result.artifact_work.len(), 2);
            assert!(
                result
                    .artifact_work
                    .iter()
                    .all(|work| work.work_status == "fetch_pending")
            );
            assert_eq!(result.checkpoint_updates.len(), 2);
            assert!(
                result
                    .checkpoint_updates
                    .iter()
                    .any(|row| row.lane == "code_snapshot")
            );
            assert!(
                result
                    .checkpoint_updates
                    .iter()
                    .any(|row| row.lane == "commit_message")
            );
            assert_eq!(result.query_usage.len(), 2);
            assert!(result.credential_observations.len() >= 2);
        }
    }
    task.abort();
}

#[tokio::test]
async fn source_selection_errors_and_manual_enrichment_cover_boundaries() {
    let (base, task) = server().await;
    let settings = Settings {
        fofa_keys: "x".into(),
        shodan_keys: "x".into(),
        github_tokens: "x".into(),
        fofa_base_url: base.clone(),
        shodan_base_url: base.clone(),
        github_api_base_url: base.clone(),
        ..Settings::default()
    };
    let http = reqwest::Client::new();
    let progress = Arc::new(Mutex::new(Vec::<DiscoveryProgress>::new()));
    let progress_sink = progress.clone();
    let fofa = FofaSource {
        client: FofaClient::new(http.clone(), &settings),
        queries: vec!["keep".into(), "drop".into()],
        page_size: 1,
        max_pages: 2,
        page_delay: 0.001,
    };
    assert_eq!(fofa.query_ids().len(), 2);
    assert!(fofa.is_configured());
    let selected = fofa
        .fetch(
            &SourceBudgets {
                fofa: Some(1),
                selected_queries: Some(vec!["keep".into()]),
                progress: Some(Arc::new(move |event| {
                    progress_sink.lock().push(event);
                })),
                ..Default::default()
            },
            ScanMode::Full,
        )
        .await
        .unwrap();
    assert_eq!(selected.query_usage.len(), 2);
    {
        let progress = progress.lock();
        assert_eq!(progress.first().unwrap().query_index, 1);
        assert_eq!(progress.last().unwrap().page, 2);
        assert_eq!(progress.last().unwrap().hits, 2);
    }

    let shodan = ShodanSource {
        client: ShodanClient::new(http.clone(), &settings),
        queries: vec!["keep".into(), "drop".into()],
        max_pages: 2,
        page_delay: 0.001,
    };
    assert_eq!(shodan.query_ids().len(), 2);
    assert!(shodan.is_configured());
    let selected = shodan
        .fetch(
            &SourceBudgets {
                shodan: Some(1),
                selected_queries: Some(vec!["keep".into()]),
                ..Default::default()
            },
            ScanMode::Full,
        )
        .await
        .unwrap();
    assert_eq!(selected.query_usage.len(), 1);

    let github = GithubSource {
        client: GithubClient::new(http.clone(), &settings),
        queries: vec!["private".into()],
        per_page: 1,
        run_id: "run_fixture".into(),
        pack_id: "fixture".into(),
    };
    assert_eq!(github.query_ids(), vec!["private"]);
    assert!(github.is_configured());
    let private = github
        .fetch(
            &SourceBudgets {
                github_code: Some(1),
                github_commit: Some(1),
                ..Default::default()
            },
            ScanMode::Incremental,
        )
        .await
        .unwrap();
    assert!(private.host_hits.is_empty());
    assert!(private.credential_observations.is_empty());

    let manual = aipocket_discovery::sources::ManualEnrichSource {
        targets: vec!["example.com".into(), "127.0.0.1".into(), "://bad".into()],
        engines: vec!["fofa".into(), "shodan".into()],
        fofa: FofaClient::new(http.clone(), &settings),
        shodan: ShodanClient::new(http, &settings),
    };
    assert!(manual.is_configured());
    let enriched = manual
        .fetch(&SourceBudgets::default(), ScanMode::Incremental)
        .await
        .unwrap();
    assert_eq!(enriched.query_usage.len(), 4);
    assert_eq!(enriched.host_hits.len(), 4);
    assert!(
        enriched
            .host_hits
            .iter()
            .all(|row| row.get("_manual_seed_host").is_some())
    );
    task.abort();
}
