use aipocket_api::{AppState, create_app};
use aipocket_core::Settings;
use aipocket_db::Repository;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
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
