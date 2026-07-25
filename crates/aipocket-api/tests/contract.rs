use aipocket_api::{AppState, auth::verify, create_app, error::ApiError};
use aipocket_core::{ScanMode, Settings};
use aipocket_db::Repository;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::IntoResponse,
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::Value;
use std::time::Instant;
use tower::ServiceExt;

async fn app() -> axum::Router {
    let settings = Settings {
        web_password: "test-password".into(),
        web_jwt_secret: "test-secret-that-is-long-enough".into(),
        ..Settings::default()
    };
    create_app(
        AppState::new(settings, Repository::default())
            .await
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn health_is_public() {
    let response = app()
        .await
        .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body, serde_json::json!({"ok": true}));
}

#[tokio::test]
async fn login_contract_and_protected_error_shape() {
    let app = app().await;
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"test-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(
        body["token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert_eq!(body["token_type"], "bearer");
    assert_eq!(body["expires_in"], 86400);

    let response = app
        .oneshot(Request::get("/api/runs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"]["code"], "unauthorized");
    assert!(body["error"]["message"].is_string());
}

#[tokio::test]
async fn wrong_password_returns_frozen_error_contract() {
    let response = app()
        .await
        .oneshot(
            Request::post("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"wrong"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"error":{"code":"unauthorized","message":"invalid password"}})
    );
}

#[tokio::test]
async fn login_rate_limit_and_forwarded_client_contract() {
    let app = app().await;
    for attempt in 0..11 {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/auth/login")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "203.0.113.8, 10.0.0.1")
                    .body(Body::from(r#"{"password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let expected = if attempt < 10 {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(response.status(), expected);
        if attempt == 10 {
            let body: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["error"]["code"], "rate_limited");
        }
    }
}

#[tokio::test]
async fn successful_login_clears_only_that_clients_failures() {
    let state = AppState::new(
        Settings {
            web_password: "test-password".into(),
            web_jwt_secret: "test-secret-that-is-long-enough".into(),
            ..Settings::default()
        },
        Repository::default(),
    )
    .await
    .unwrap();
    state
        .login_failures
        .0
        .lock()
        .await
        .insert("198.51.100.7".into(), vec![Instant::now()]);
    let app = create_app(state.clone()).await;
    let response = app
        .oneshot(
            Request::post("/api/auth/login")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "198.51.100.7")
                .body(Body::from(r#"{"password":"test-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !state
            .login_failures
            .0
            .lock()
            .await
            .contains_key("198.51.100.7")
    );
}

#[tokio::test]
async fn auth_rejects_malformed_token_and_wrong_subject() {
    let state = AppState::new(
        Settings {
            web_password: "test-password".into(),
            web_jwt_secret: "test-secret-that-is-long-enough".into(),
            ..Settings::default()
        },
        Repository::default(),
    )
    .await
    .unwrap();
    let malformed = verify("not-a-jwt", &state).await.unwrap_err();
    assert_eq!(malformed.status, StatusCode::UNAUTHORIZED);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({"sub":"someone-else","iat":now,"exp":now + 60}),
        &EncodingKey::from_secret(b"test-secret-that-is-long-enough"),
    )
    .unwrap();
    let wrong_subject = verify(&token, &state).await.unwrap_err();
    assert_eq!(wrong_subject.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_requires_bearer_token_and_error_conversions_are_stable() {
    let app = app().await;
    let login = app
        .clone()
        .oneshot(
            Request::post("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"test-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&login.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["token"].as_str().unwrap();
    let response = app
        .oneshot(
            Request::post("/api/auth/logout")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body, serde_json::json!({"ok": true}));

    let internal = ApiError::internal("fixture failure").into_response();
    assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let converted: ApiError = anyhow::anyhow!("fixture failure").into();
    assert_eq!(converted.code, "internal_error");
}

#[tokio::test]
async fn active_run_log_endpoint_serves_the_in_memory_transcript() {
    let settings = Settings {
        web_password: "test-password".into(),
        web_jwt_secret: "test-secret-that-is-long-enough".into(),
        ..Settings::default()
    };
    let state = AppState::new(settings, Repository::default())
        .await
        .unwrap();
    let (_cancel, tx, rx, stopped) = state
        .scan_manager
        .start_channel("fofa".into(), ScanMode::Incremental)
        .await
        .unwrap();
    let consumer = tokio::spawn(state.scan_manager.clone().consume(
        rx,
        Repository::default(),
        stopped,
    ));
    tx.send(aipocket_services::ScanEvent::Started {
        run_id: "run_live_log".into(),
    })
    .unwrap();
    tx.send(aipocket_services::ScanEvent::Log(
        "发现 · 进度 · fofa · 查询 1/23 · 第 1 页".into(),
    ))
    .unwrap();
    for _ in 0..20 {
        if state.scan_manager.status().await.run_id.as_deref() == Some("run_live_log") {
            break;
        }
        tokio::task::yield_now().await;
    }
    let app = create_app(state).await;
    let login = app
        .clone()
        .oneshot(
            Request::post("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"test-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let login: Value =
        serde_json::from_slice(&login.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let response = app
        .oneshot(
            Request::get("/api/runs/run_live_log/log")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", login["token"].as_str().unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("扫描请求已接受"));
    drop(tx);
    consumer.await.unwrap();
}

#[tokio::test]
async fn app_serves_static_fallback_and_specific_cors_origins() {
    let root = std::env::temp_dir().join(format!("aipocket-static-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("index.html"), "<main>fixture</main>").unwrap();
    let settings = Settings {
        web_password: "test-password".into(),
        web_jwt_secret: "test-secret-that-is-long-enough".into(),
        web_cors_origins: "https://allowed.example,invalid header".into(),
        web_static_dir: root.to_string_lossy().into(),
        ..Settings::default()
    };
    let app = create_app(
        AppState::new(settings, Repository::default())
            .await
            .unwrap(),
    )
    .await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/missing-route")
                .header("origin", "https://allowed.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://allowed.example"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("fixture"));
    std::fs::remove_dir_all(root).unwrap();
}
