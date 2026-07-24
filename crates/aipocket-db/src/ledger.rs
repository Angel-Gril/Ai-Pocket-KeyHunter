use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestLedgerEntry {
    pub request_id: String,
    pub run_id: String,
    pub stage: String,
    pub source: String,
    pub query_id: String,
    pub pack_id: String,
    pub credential_fingerprint: Option<String>,
    pub target_identity: String,
    pub artifact_identity: String,
    pub product: String,
    pub spec_id: String,
    pub provider: String,
    pub http_method: String,
    pub endpoint_class: String,
    pub status_class: String,
    pub status_code: Option<i32>,
    pub error_class: String,
    pub latency_ms: i64,
    pub request_bytes: i64,
    pub response_bytes: i64,
    pub query_credit: f64,
    pub rate_resource: String,
    pub attempt: i32,
    pub started_at: DateTime<Utc>,
}

impl RequestLedgerEntry {
    pub fn new(run_id: impl Into<String>, stage: impl Into<String>) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            run_id: run_id.into(),
            stage: stage.into(),
            source: String::new(),
            query_id: String::new(),
            pack_id: String::new(),
            credential_fingerprint: None,
            target_identity: String::new(),
            artifact_identity: String::new(),
            product: String::new(),
            spec_id: String::new(),
            provider: String::new(),
            http_method: "GET".into(),
            endpoint_class: String::new(),
            status_class: String::new(),
            status_code: None,
            error_class: String::new(),
            latency_ms: 0,
            request_bytes: 0,
            response_bytes: 0,
            query_credit: 0.0,
            rate_resource: "other".into(),
            attempt: 1,
            started_at: Utc::now(),
        }
    }
}
