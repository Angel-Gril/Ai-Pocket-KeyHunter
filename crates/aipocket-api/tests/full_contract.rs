use aipocket_api::{AppState, create_app};
use aipocket_core::{ScanProgress, Settings};
use aipocket_db::{Repository, connect_pg, ensure_schema};
use axum::{
    Json, Router,
    body::Body,
    extract::Query,
    http::{Request, StatusCode},
    routing::{get, post},
};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn mock(Query(q): Query<std::collections::HashMap<String, String>>) -> Json<Value> {
    if q.contains_key("qbase64") {
        Json(json!({"results":[]}))
    } else if q.contains_key("key") {
        Json(json!({"plan":"dev","query_credits":7,"matches":[]}))
    } else {
        Json(
            json!({"data":[{"id":"model-a"}],"items":[],"resources":{"core":{"remaining":10},"search":{"remaining":9},"code_search":{"remaining":8}}}),
        )
    }
}
async fn mock_post() -> Json<Value> {
    Json(
        json!({"results":[{"id":"CVE-2099-9999","title":"fixture"}],"choices":[{"message":{"content":"OK"}}]}),
    )
}
async fn gateway_status() -> Json<Value> {
    Json(json!({"success":true,"data":{
        "quota_per_unit":1,"stripe_unit_price":1,"self_use_mode_enabled":true
    }}))
}
async fn gateway_user() -> Json<Value> {
    Json(json!({"success":true,"data":{"quota":100,"used_quota":25}}))
}
async fn fixture_server() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/v1/search/all", get(mock))
        .route("/api-info", get(mock))
        .route("/rate_limit", get(mock))
        .route("/v1/models", get(mock))
        .route("/api/status", get(gateway_status))
        .route("/api/user/self", get(gateway_user))
        .route(
            "/dashboard/billing/subscription",
            get(|| async { Json(json!({})) }),
        )
        .route("/key/info", get(|| async { Json(json!({})) }))
        .route("/search", post(mock_post))
        .route("/v1/chat/completions", post(mock_post));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), task)
}

async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let payload = if let Some(value) = body {
        builder = builder.header("content-type", "application/json");
        Body::from(value.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(builder.body(payload).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)}));
    (status, value, headers)
}

#[tokio::test]
#[ignore = "requires PostgreSQL on TEST_DATABASE_URL"]
async fn complete_frontend_api_contract_smoke() {
    let (base, mock_task) = fixture_server().await;
    let mut settings = Settings {
        database_url: std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://aipocket:aipocket@127.0.0.1:15432/aipocket".into()),
        pg_pool_min: 1,
        pg_pool_max: 4,
        dedup_enabled: false,
        web_password: "test".into(),
        web_jwt_secret: "integration-secret".into(),
        fofa_keys: "fofa-secret".into(),
        shodan_keys: "shodan-secret".into(),
        github_tokens: "github-secret".into(),
        tavily_key: "tavily-secret".into(),
        fofa_base_url: base.clone(),
        shodan_base_url: base.clone(),
        github_api_base_url: base.clone(),
        tavily_base_url: base.clone(),
        ..Settings::default()
    };
    settings.results_dir = std::env::temp_dir()
        .join("aipocket-api-contract")
        .to_string_lossy()
        .into();
    let pool = connect_pg(&settings).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let repo = Repository::new(Some(pool));
    let run_id = "run_2099_02_02_00-00-00";
    let _ = repo.delete_run(run_id).await;
    repo.create_run(run_id, Utc::now(), "incremental", &[])
        .await
        .unwrap();
    let record = json!({"credential":{"apikey":"sk-contract-plaintext","apiurl":base,"host":"fixture","backend":"manual"},"valid":true,"validation_state":"final_verified","provider_info":{"provider":"unknown"},"tier":"paid","balance":"1"});
    repo.insert_results(run_id, "valid", std::slice::from_ref(&record))
        .await
        .unwrap();
    repo.finish_run(
        run_id,
        "finished",
        &ScanProgress {
            raw_hits: 1,
            unique_targets: 1,
            candidates: 1,
            active_requests: 1,
            final_verified: 1,
            ..Default::default()
        },
        "run log",
    )
    .await
    .unwrap();
    let state = AppState::new(settings, repo.clone()).await.unwrap();
    let app = create_app(state).await;
    let (_, login, _) = request(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({"password":"test"})),
    )
    .await;
    let token = login["token"].as_str().unwrap();
    assert_eq!(
        request(&app, "POST", "/api/auth/logout", Some(token), None)
            .await
            .0,
        StatusCode::OK
    );
    for path in [
        "/api/runs",
        &format!("/api/runs/{run_id}/valid"),
        &format!("/api/runs/{run_id}/suspicious"),
        &format!("/api/runs/{run_id}/log"),
        &format!("/api/runs/{run_id}/gpt-failed"),
        "/api/high-value",
        "/api/keys/valid",
        "/api/keys/suspicious",
        "/api/cve",
        "/api/honeypot",
        "/api/manual-targets",
        "/api/settings",
        "/api/scan/status",
        "/api/scan/logs?since=0",
    ] {
        let (status, value, _) = request(&app, "GET", path, Some(token), None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {value}");
    }
    let (_, run_rows, _) = request(
        &app,
        "GET",
        &format!("/api/runs/{run_id}/valid"),
        Some(token),
        None,
    )
    .await;
    let result_id = run_rows["results"][0]["result_id"].as_i64().unwrap();
    let masked = run_rows["results"][0]["credential"]["apikey"]
        .as_str()
        .unwrap();
    assert_ne!(masked, "sk-contract-plaintext");
    let (_, revealed, _) = request(
        &app,
        "POST",
        "/api/key/reveal",
        Some(token),
        Some(json!({"run_id":run_id,"kind":"valid","index":0})),
    )
    .await;
    assert_eq!(revealed["apikey"], "sk-contract-plaintext");
    let (_, models, _) = request(
        &app,
        "POST",
        "/api/key/models",
        Some(token),
        Some(json!({"apikey":"sk-contract-plaintext","apiurl":base})),
    )
    .await;
    assert_eq!(models["models"][0], "model-a");
    let (_, revealed_by_mask, _) = request(
        &app,
        "POST",
        "/api/key/reveal",
        Some(token),
        Some(json!({"run_id":run_id,"masked":masked,"apiurl":base})),
    )
    .await;
    assert_eq!(revealed_by_mask["apikey"], "sk-contract-plaintext");
    let (balance_status, balance_persisted, _) = request(
        &app,
        "POST",
        "/api/key/balance",
        Some(token),
        Some(json!({"apikey":"sk-contract-plaintext","apiurl":base,"result_id":result_id})),
    )
    .await;
    assert_eq!(balance_status, StatusCode::OK, "{balance_persisted}");
    assert_eq!(balance_persisted["persisted"], true);
    let (_, chat_failure, _) = request(
        &app,
        "POST",
        "/api/key/chat",
        Some(token),
        Some(json!({"apikey":"sk-contract-plaintext","apiurl":"http://127.0.0.1:1","model":"model-a"})),
    )
    .await;
    assert_eq!(chat_failure["success"], false);
    for (path, body) in [
        (
            "/api/key/balance",
            json!({"apikey":"sk-contract-plaintext","apiurl":base}),
        ),
        (
            "/api/key/chat",
            json!({"apikey":"sk-contract-plaintext","apiurl":base,"model":"model-a"}),
        ),
    ] {
        assert_eq!(
            request(&app, "POST", path, Some(token), Some(body)).await.0,
            StatusCode::OK
        );
    }
    for format in ["json", "csv"] {
        let (status, _, headers) = request(
            &app,
            "POST",
            "/api/export",
            Some(token),
            Some(json!({"dataset":"run","run_id":run_id,"kind":"valid","format":format})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.contains_key("content-disposition"));
    }
    for (dataset, body) in [
        (
            "selected",
            json!({"dataset":"selected","keys":[{"apikey":"sk-selected","apiurl":base}],"format":"json"}),
        ),
        (
            "high-value",
            json!({"dataset":"high-value","format":"json"}),
        ),
        (
            "all",
            json!({"dataset":"all","kind":"valid","format":"json"}),
        ),
    ] {
        assert_eq!(
            request(&app, "POST", "/api/export", Some(token), Some(body))
                .await
                .0,
            StatusCode::OK,
            "{dataset}"
        );
    }
    for body in [
        json!({"dataset":"selected","run_id":run_id,"indices":[0],"format":"json"}),
        json!({"dataset":"all","kind":"valid","indices":[0],"format":"json"}),
    ] {
        assert_eq!(
            request(&app, "POST", "/api/export", Some(token), Some(body))
                .await
                .0,
            StatusCode::OK
        );
    }
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/export",
            Some(token),
            Some(json!({"dataset":"bogus"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, promoted, _) = request(
        &app,
        "POST",
        "/api/keys/promote",
        Some(token),
        Some(json!({"result_ids":[result_id],"note":"fixture"})),
    )
    .await;
    assert_eq!(promoted["promoted"][0], result_id);
    let (_, high, _) = request(&app, "GET", "/api/high-value", Some(token), None).await;
    let high_masked = high["results"][0]["apikey"]
        .as_str()
        .or_else(|| high["results"][0]["credential"]["apikey"].as_str())
        .unwrap();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/high-value/reveal",
            Some(token),
            Some(json!({"masked":high_masked}))
        )
        .await
        .0,
        StatusCode::OK
    );
    for path in [
        "/api/settings/check/fofa",
        "/api/settings/check/shodan",
        "/api/settings/check/github",
        "/api/cve/sync",
    ] {
        assert_eq!(
            request(&app, "POST", path, Some(token), None).await.0,
            StatusCode::OK
        );
    }
    let (_, github_disabled, _) = request(
        &app,
        "POST",
        "/api/settings/check/github",
        Some(token),
        None,
    )
    .await;
    assert_eq!(github_disabled["status"], "ok");
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/cve/add",
            Some(token),
            Some(json!({"id":"CVE-2099-9998","product":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/cve/add",
            Some(token),
            Some(json!({"url":"https://nvd.example/CVE-2099-9997","product":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (site_status, site, _) = request(
        &app,
        "POST",
        "/api/honeypot",
        Some(token),
        Some(json!({"host":"https://trap.example","notes":"fixture"})),
    )
    .await;
    assert_eq!(site_status, StatusCode::OK, "{site}");
    let host_key = site["host_key"].as_str().unwrap();
    assert_eq!(
        request(
            &app,
            "PATCH",
            "/api/honeypot",
            Some(token),
            Some(json!({"host_key":host_key,"notes":"updated"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/honeypot?host_key={host_key}"),
            Some(token),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, replacement, _) = request(
        &app,
        "POST",
        "/api/honeypot",
        Some(token),
        Some(json!({"host":"https://trap.example","notes":"fixture"})),
    )
    .await;
    let host_key = replacement["host_key"].as_str().unwrap();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/honeypot/bulk-delete",
            Some(token),
            Some(json!({"host_keys":[host_key]}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/manual-targets",
            Some(token),
            Some(json!({"urls":"https://manual.example/path","notes":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            "/api/manual-targets?url=https%3A%2F%2Fmanual.example",
            Some(token),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/manual-targets",
            Some(token),
            Some(json!({"urls":"https://manual.example/path\nnot-a-url","notes":"fixture","replace":true}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/manual-targets/bulk-delete",
            Some(token),
            Some(json!({"urls":["https://manual.example"]}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("/api/runs/{run_id}/retry-gpt-failed"),
            Some(token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for (method, path, body, expected) in [
        (
            "GET",
            format!("/api/runs/{run_id}/rejected"),
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "GET",
            "/api/runs/not-a-run/gpt-failed".into(),
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "GET",
            format!("/api/runs/{run_id}/missing-log"),
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/export".into(),
            Some(json!({"dataset":"selected"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/export".into(),
            Some(json!({"dataset":"run"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/cve/add".into(),
            Some(json!({"product":"fixture"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/key/reveal".into(),
            Some(json!({"run_id":run_id,"kind":"valid","index":999})),
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            "/api/high-value/reveal".into(),
            Some(json!({"masked":"missing"})),
            StatusCode::NOT_FOUND,
        ),
        (
            "PATCH",
            "/api/honeypot".into(),
            Some(json!({"host_key":"missing","notes":"x"})),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, value, _) = request(&app, method, &path, Some(token), body).await;
        assert_eq!(status, expected, "{method} {path}: {value}");
        assert!(value.get("error").is_some());
    }
    for (body, expected) in [
        (
            json!({"resume_run_id":"run_2099_12_31_00-00-00"}),
            StatusCode::NOT_FOUND,
        ),
        (json!({"resume_run_id":run_id}), StatusCode::CONFLICT),
    ] {
        assert_eq!(
            request(&app, "POST", "/api/scan/start", Some(token), Some(body))
                .await
                .0,
            expected
        );
    }
    assert_eq!(
        request(&app, "POST", "/api/scan/stop", Some(token), None)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/scan/start",
            Some(token),
            Some(json!({"sources":["manual"],"mode":"incremental","github_pack_ids":["all"]}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let mut stopped = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let status = request(&app, "POST", "/api/scan/stop", Some(token), None)
            .await
            .0;
        if status == StatusCode::OK {
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/runs/{run_id}"),
            Some(token),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    mock_task.abort();
}
