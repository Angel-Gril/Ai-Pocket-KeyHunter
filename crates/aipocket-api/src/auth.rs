use crate::{error::ApiError, state::AppState};
use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}
#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: u64,
    exp: u64,
}
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let client = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_owned();
    let now = Instant::now();
    {
        let mut failures = state.login_failures.0.lock().await;
        let recent = failures.entry(client.clone()).or_default();
        recent.retain(|failure| now.duration_since(*failure) < Duration::from_secs(300));
        if recent.len() >= 10 {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many login attempts, try again later",
            ));
        }
    }
    let settings = state.settings.read().await;
    if settings
        .web_password
        .as_bytes()
        .ct_eq(body.password.as_bytes())
        .unwrap_u8()
        != 1
    {
        state
            .login_failures
            .0
            .lock()
            .await
            .entry(client)
            .or_default()
            .push(now);
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid password",
        ));
    }
    state.login_failures.0.lock().await.remove(&client);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ApiError::internal)?
        .as_secs();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &Claims {
            sub: "aipocket".into(),
            iat: now,
            exp: now + settings.web_token_ttl,
        },
        &EncodingKey::from_secret(settings.web_jwt_secret.as_bytes()),
    )
    .map_err(ApiError::internal)?;
    Ok(Json(LoginResponse {
        token,
        token_type: "bearer",
        expires_in: settings.web_token_ttl,
    }))
}
pub async fn logout(_: Auth) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok":true}))
}
#[derive(Clone, Debug)]
pub struct Auth;
impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(ApiError::unauthorized)?;
        verify(token, state).await?;
        Ok(Auth)
    }
}
pub async fn verify(token: &str, state: &AppState) -> Result<(), ApiError> {
    let settings = state.settings.read().await;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(settings.web_jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| ApiError::unauthorized())?
    .claims;
    if claims.sub != "aipocket" {
        return Err(ApiError::unauthorized());
    }
    Ok(())
}
