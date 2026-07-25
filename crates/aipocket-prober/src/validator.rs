use crate::{ProtocolFamily, ProviderRegistry};
use aipocket_core::{Credential, ProviderInfo, ValidationResult};
use anyhow::Result;
use serde_json::{Value, json};
#[derive(Clone)]
pub struct Validator {
    http: reqwest::Client,
    registry: std::sync::Arc<ProviderRegistry>,
}
impl Validator {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            registry: std::sync::Arc::new(ProviderRegistry),
        }
    }
    pub async fn validate(&self, credential: Credential) -> Result<ValidationResult> {
        let resolution = self
            .registry
            .resolve(&credential.apiurl, &credential.apikey);
        let base = if credential.apiurl.is_empty() {
            resolution.spec.official_api_url
        } else {
            &credential.apiurl
        };
        let mut result = ValidationResult {
            credential: credential.clone(),
            provider_info: ProviderInfo {
                provider: resolution.spec.name.into(),
                validation_provider: resolution.spec.name.into(),
                category: resolution.spec.category.into(),
                models_available: vec![],
                models_verified: vec![],
                balance_provider: String::new(),
                credential_issuer: resolution.spec.name.into(),
                issuer_evidence: resolution.reason.into(),
                served_model_families: vec![],
                evidence_source: "validation".into(),
                evidence_kind: "models".into(),
                evidence_observed_at: chrono::Utc::now().to_rfc3339(),
            },
            validated_at: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        };
        if base.is_empty() {
            result.error = "no API URL".into();
            result.validation_state = "rejected".into();
            return Ok(result);
        }
        if let Some(specialized) =
            crate::specialized::validate_specialized(&self.http, &credential, resolution.spec.name)
                .await?
        {
            result.status_code = specialized.status_code;
            result.valid = specialized.valid;
            result.credential_kind = specialized.credential_kind;
            result.scope = specialized.scope;
            result.tier_evidence = specialized.tier_evidence;
            result.error = specialized.error;
            result.provider_evidence = specialized.evidence;
            result.provider_info.models_available = specialized.models;
            result.validation_state = if result.valid {
                "final_verified".into()
            } else if matches!(result.status_code, Some(401 | 403)) {
                "rejected".into()
            } else {
                "transient".into()
            };
            return Ok(result);
        }
        let response = match resolution.spec.protocol {
            ProtocolFamily::Anthropic => {
                self.http
                    .get(format!("{}/v1/models", base.trim_end_matches('/')))
                    .header("x-api-key", &credential.apikey)
                    .header("anthropic-version", "2023-06-01")
                    .send()
                    .await?
            }
            ProtocolFamily::Gemini => {
                let origin = base
                    .split("/v1beta")
                    .next()
                    .unwrap_or(base)
                    .trim_end_matches('/');
                self.http
                    .get(format!("{origin}/v1beta/models"))
                    .query(&[("key", &credential.apikey)])
                    .send()
                    .await?
            }
            ProtocolFamily::AwsBedrock => {
                let base = base.trim_end_matches('/');
                self.http
                    .get(if base.ends_with("/foundation-models") {
                        base.to_owned()
                    } else {
                        format!("{base}/foundation-models")
                    })
                    .bearer_auth(&credential.apikey)
                    .send()
                    .await?
            }
            _ => {
                let base = base.trim_end_matches('/');
                self.http
                    .get(if base.ends_with("/v1") {
                        format!("{base}/models")
                    } else {
                        format!("{base}/v1/models")
                    })
                    .bearer_auth(&credential.apikey)
                    .send()
                    .await?
            }
        };
        result.status_code = Some(response.status().as_u16());
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(json!({}));
        let models = extract_models(&body);
        result.valid = status.is_success() && !models.is_empty();
        result.validation_state = if result.valid {
            "final_verified".into()
        } else if status.as_u16() == 401 || status.as_u16() == 403 || status.is_success() {
            "rejected".into()
        } else {
            "transient".into()
        };
        if status.is_success() && models.is_empty() {
            result.error = "invalid-response-schema".into();
        }
        result.response_snippet = body.to_string().chars().take(512).collect();
        result.provider_info.models_available = models;
        Ok(result)
    }
}
fn extract_models(value: &Value) -> Vec<String> {
    value
        .get("data")
        .or_else(|| value.get("models"))
        .or_else(|| value.get("modelSummaries"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.get("id")
                .or_else(|| item.get("name"))
                .or_else(|| item.get("modelId"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::Query,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use std::collections::HashMap;

    async fn fixture_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/v1/models",
                get(|headers: HeaderMap| async move {
                    if headers.get("x-api-key").is_some() {
                        Json(json!({"models":[{"name":"claude-fixture"}]})).into_response()
                    } else {
                        Json(json!({"data":[{"id":"openai-fixture"}]})).into_response()
                    }
                }),
            )
            .route(
                "/v1beta/models",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    if query.contains_key("key") {
                        Json(json!({"models":[{"name":"gemini-fixture"}]})).into_response()
                    } else {
                        (StatusCode::UNAUTHORIZED, Json(json!({"error":"bad key"}))).into_response()
                    }
                }),
            )
            .route(
                "/foundation-models",
                get(|| async { Json(json!({"modelSummaries":[{"modelId":"bedrock-fixture"}]})) }),
            )
            .route(
                "/forbidden/v1/models",
                get(|| async { (StatusCode::FORBIDDEN, Json(json!({"error":"forbidden"}))) }),
            )
            .route(
                "/transient/v1/models",
                get(|| async {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error":"busy"})),
                    )
                }),
            )
            .route(
                "/html/v1/models",
                get(|| async { (StatusCode::OK, "<!doctype html><title>not an API</title>") }),
            )
            .route(
                "/empty/v1/models",
                get(|| async { Json(json!({"data":[]})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address, task)
    }

    fn credential(apikey: &str, apiurl: String) -> Credential {
        Credential {
            apikey: apikey.into(),
            apiurl,
            ..Default::default()
        }
    }

    #[test]
    fn parses_all_supported_model_shapes() {
        assert_eq!(extract_models(&json!({"data":[{"id":"a"}]})), vec!["a"]);
        assert_eq!(extract_models(&json!({"models":[{"name":"b"}]})), vec!["b"]);
        assert_eq!(
            extract_models(&json!({"modelSummaries":[{"modelId":"c"}]})),
            vec!["c"]
        );
        assert!(extract_models(&json!({"data":[{"unknown":"d"}]})).is_empty());
    }

    #[tokio::test]
    async fn validates_protocol_routes_and_classifies_http_failures() {
        let (address, server) = fixture_server().await;
        let base = format!("http://127.0.0.1:{}", address.port());
        let validator = Validator::new(
            reqwest::Client::builder()
                .resolve("api.anthropic.com", address)
                .resolve("generativelanguage.googleapis.com", address)
                .resolve("bedrock.us-east-1.amazonaws.com", address)
                .build()
                .unwrap(),
        );
        for (apikey, apiurl, model) in [
            (
                "local-anthropic-key",
                format!("http://api.anthropic.com:{}", address.port()),
                "claude-fixture",
            ),
            (
                "AI-test-gemini-key",
                format!(
                    "http://generativelanguage.googleapis.com:{}",
                    address.port()
                ),
                "gemini-fixture",
            ),
            (
                "local-bedrock-key",
                format!("http://bedrock.us-east-1.amazonaws.com:{}", address.port()),
                "bedrock-fixture",
            ),
            ("sk-generic-abcdefghijkl", base.clone(), "openai-fixture"),
        ] {
            let result = validator
                .validate(credential(apikey, apiurl))
                .await
                .unwrap();
            assert!(
                result.valid,
                "provider={} status={:?} error={} body={}",
                result.provider_info.provider,
                result.status_code,
                result.error,
                result.response_snippet
            );
            assert_eq!(result.validation_state, "final_verified");
            assert_eq!(result.provider_info.models_available, vec![model]);
        }

        let rejected = validator
            .validate(credential(
                "sk-generic-abcdefghijkl",
                format!("{base}/forbidden"),
            ))
            .await
            .unwrap();
        assert!(!rejected.valid);
        assert_eq!(rejected.status_code, Some(403));
        assert_eq!(rejected.validation_state, "rejected");

        let transient = validator
            .validate(credential(
                "sk-generic-abcdefghijkl",
                format!("{base}/transient"),
            ))
            .await
            .unwrap();
        assert!(!transient.valid);
        assert_eq!(transient.status_code, Some(503));
        assert_eq!(transient.validation_state, "transient");
        for path in ["html", "empty"] {
            let invalid = validator
                .validate(credential(
                    "sk-generic-abcdefghijkl",
                    format!("{base}/{path}"),
                ))
                .await
                .unwrap();
            assert!(!invalid.valid, "{path}");
            assert_eq!(invalid.status_code, Some(200));
            assert_eq!(invalid.validation_state, "rejected");
            assert_eq!(invalid.error, "invalid-response-schema");
        }

        server.abort();
    }
}
