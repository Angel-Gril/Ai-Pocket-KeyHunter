use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderInfo {
    pub provider: String,
    pub validation_provider: String,
    pub category: String,
    pub models_available: Vec<String>,
    pub models_verified: Vec<String>,
    pub balance_provider: String,
    pub credential_issuer: String,
    pub issuer_evidence: String,
    pub served_model_families: Vec<String>,
    pub evidence_source: String,
    pub evidence_kind: String,
    pub evidence_observed_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Credential {
    pub apikey: String,
    pub apiurl: String,
    pub source: String,
    pub source_type: String,
    pub backend: String,
    pub host: String,
    pub ip: String,
    pub port: String,
    pub product: String,
    pub raw_context: String,
    pub leak_host: String,
    pub routed_to_official: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidationResult {
    pub credential: Credential,
    pub valid: bool,
    pub validation_state: String,
    pub credential_kind: String,
    pub scope: String,
    pub tier_evidence: String,
    pub status_code: Option<u16>,
    pub error: String,
    pub tier: String,
    pub gateway: String,
    pub balance: String,
    pub rate_limit_headers: Map<String, Value>,
    pub model_available: String,
    pub response_snippet: String,
    pub provider_info: ProviderInfo,
    pub provider_evidence: Value,
    pub result_id: Option<i64>,
    pub created_at: String,
    pub saved_at: String,
    pub validated_at: String,
    pub suspicious: bool,
    pub suspicious_reason: String,
    pub source_run_id: String,
    pub source_index: Option<usize>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanProgress {
    pub raw_hits: u64,
    pub unique_targets: u64,
    pub candidates: u64,
    pub active_requests: u64,
    pub final_verified: u64,
    pub suspicious: u64,
    pub high_value_final: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Full,
    #[default]
    Incremental,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanState {
    #[default]
    Idle,
    Running,
    Stopping,
    Finished,
    Interrupted,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanStatus {
    pub state: ScanState,
    pub source: Option<String>,
    pub mode: ScanMode,
    pub github_pack_ids: Vec<String>,
    pub manual_enrich: Vec<String>,
    pub run_id: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub progress: ScanProgress,
    pub phase: String,
    pub error: Option<String>,
    pub log_seq: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanLogLine {
    pub seq: u64,
    pub line: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub started_at: String,
    pub valid_count: i64,
    pub suspicious_count: i64,
    pub has_log: bool,
    pub raw_hits: i64,
    pub unique_targets: i64,
    pub candidates: i64,
    pub active_requests: i64,
    pub final_verified: i64,
    pub suspicious: i64,
    pub sources: Vec<String>,
    pub scan_mode: String,
    pub high_value_final: i64,
    pub deletable: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDay {
    pub day: String,
    pub runs: Vec<RunSummary>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HoneypotSite {
    pub host_key: String,
    pub host: String,
    pub reason: String,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub hit_count: i64,
    pub run_id: String,
    pub notes: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ManualTarget {
    pub url: String,
    pub host_key: String,
    pub scheme: String,
    pub hostname: String,
    pub port: u16,
    pub enabled: bool,
    pub notes: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation_result_accepts_extra_fields() {
        let result: ValidationResult = serde_json::from_value(serde_json::json!({
            "credential": {"apikey": "sk-test", "apiurl": "https://example.com"},
            "unknown_future_field": 7
        }))
        .unwrap();
        assert_eq!(result.extra["unknown_future_field"], 7);
    }
    #[test]
    fn scan_progress_has_exact_authoritative_fields() {
        let value = serde_json::to_value(ScanProgress::default()).unwrap();
        assert!(value.get("valid").is_none());
        assert_eq!(value.as_object().unwrap().len(), 7);
    }
}
