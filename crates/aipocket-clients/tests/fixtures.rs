use aipocket_clients::{FofaClient, GithubClient, ShodanClient};
use aipocket_core::Settings;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};

async fn fixture(Query(query): Query<std::collections::HashMap<String, String>>) -> Json<Value> {
    if query.contains_key("qbase64") {
        return Json(json!({"results":[["https://example.com","1.2.3.4","443"]]}));
    }
    if query.contains_key("query") {
        return if query.contains_key("page") {
            Json(json!({"matches":[{"ip_str":"1.2.3.4","port":443}]}))
        } else {
            Json(json!({"total":42}))
        };
    }
    if query.contains_key("key") {
        return Json(json!({"plan":"dev","query_credits":7,"scan_credits":3}));
    }
    Json(
        json!({"items":[{"name":".env","repository":{"full_name":"owner/repo"}}],"resources":{"core":{"remaining":10}},"files":[{"filename":".env"}],"content":"Zml4dHVyZQ=="}),
    )
}

async fn server() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/v1/search/all", get(fixture))
        .route("/shodan/host/search", get(fixture))
        .route("/shodan/host/count", get(fixture))
        .route("/api-info", get(fixture))
        .route("/search/code", get(fixture))
        .route("/search/commits", get(fixture))
        .route("/rate_limit", get(fixture))
        .route("/repos/{owner}/{repo}/commits", get(fixture))
        .route("/repos/{owner}/{repo}/commits/{sha}", get(fixture))
        .route("/repos/{owner}/{repo}/git/blobs/{sha}", get(fixture));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), task)
}

async fn rotating_search(
    State(tokens): State<Arc<Mutex<Vec<String>>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    tokens.lock().push(authorization.clone());
    if authorization == "Bearer exhausted" {
        (
            StatusCode::FORBIDDEN,
            [("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1")],
            Json(json!({"message":"API rate limit exceeded"})),
        )
            .into_response()
    } else {
        Json(json!({"items":[{"name":".env"}]})).into_response()
    }
}

#[tokio::test]
async fn github_search_rotates_tokens_after_rate_limit() {
    let tokens = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/search/code", get(rotating_search))
        .with_state(tokens.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let github = GithubClient::new(
        reqwest::Client::new(),
        &Settings {
            github_tokens: "exhausted,healthy".into(),
            github_api_base_url: format!("http://{address}"),
            github_rate_limit_max_wait_seconds: 0.0,
            ..Settings::default()
        },
    );
    assert_eq!(
        github.search_code("test", 1, 1).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        tokens.lock().as_slice(),
        ["Bearer exhausted", "Bearer healthy"]
    );
    task.abort();
}

#[tokio::test]
async fn github_rate_limit_rotates_past_forbidden_tokens() {
    let tokens = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/rate_limit", get(rotating_search))
        .with_state(tokens.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let github = GithubClient::new(
        reqwest::Client::new(),
        &Settings {
            github_tokens: "exhausted,healthy".into(),
            github_api_base_url: format!("http://{address}"),
            ..Settings::default()
        },
    );
    assert_eq!(
        github.rate_limit().await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        tokens.lock().as_slice(),
        ["Bearer exhausted", "Bearer healthy"]
    );
    task.abort();
}

#[tokio::test]
async fn clients_parse_recorded_fixture_shapes() {
    let (base, task) = server().await;
    let settings = Settings {
        fofa_keys: "fofa".into(),
        shodan_keys: "shodan".into(),
        github_tokens: "github".into(),
        fofa_base_url: base.clone(),
        shodan_base_url: base.clone(),
        github_api_base_url: base,
        ..Settings::default()
    };
    let http = reqwest::Client::new();
    assert_eq!(
        FofaClient::new(http.clone(), &settings)
            .search("test", 1, 1)
            .await
            .unwrap()["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        ShodanClient::new(http.clone(), &settings)
            .search("test", 1)
            .await
            .unwrap()["matches"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let shodan = ShodanClient::new(http.clone(), &settings);
    assert_eq!(shodan.count("test").await.unwrap(), 42);
    let info = shodan.info_all().await;
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].1.as_ref().unwrap().query_credits, 7);
    let github = GithubClient::new(http, &settings);
    assert_eq!(
        github.search_code("test", 1, 1).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        github.search_commits("test", 1, 1).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        github.rate_limit().await.unwrap()["resources"]["core"]["remaining"],
        10
    );
    assert_eq!(
        github.commit("owner", "repo", "sha", 1, 10).await.unwrap()["files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        github.blob("owner", "repo", "sha").await.unwrap()["content"],
        "Zml4dHVyZQ=="
    );
    assert_eq!(
        github
            .file_history("owner", "repo", ".env", 1, 10)
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    task.abort();
}
