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
                self.http
                    .get(format!("{}/v1beta/models", base.trim_end_matches('/')))
                    .query(&[("key", &credential.apikey)])
                    .send()
                    .await?
            }
            _ => {
                self.http
                    .get(format!("{}/v1/models", base.trim_end_matches('/')))
                    .bearer_auth(&credential.apikey)
                    .send()
                    .await?
            }
        };
        result.status_code = Some(response.status().as_u16());
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(json!({}));
        result.valid = status.is_success();
        result.validation_state = if result.valid {
            "final_verified".into()
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            "rejected".into()
        } else {
            "transient".into()
        };
        result.response_snippet = body.to_string().chars().take(512).collect();
        result.provider_info.models_available = extract_models(&body);
        Ok(result)
    }
}
fn extract_models(value: &Value) -> Vec<String> {
    value
        .get("data")
        .or_else(|| value.get("models"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.get("id")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_models() {
        assert_eq!(extract_models(&json!({"data":[{"id":"a"}]})), vec!["a"]);
    }
}
