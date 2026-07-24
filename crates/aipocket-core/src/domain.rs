use crate::{Credential, ScanMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationState {
    Candidate,
    Authenticated,
    FinalVerified,
    Suspicious,
    Rejected,
    Transient,
    NoAuthEndpoint,
}
impl ValidationState {
    pub fn is_authenticated(self) -> bool {
        matches!(self, Self::Authenticated | Self::FinalVerified)
    }
    pub fn is_final_positive(self) -> bool {
        matches!(self, Self::FinalVerified)
    }
    pub fn is_quarantined(self) -> bool {
        matches!(self, Self::Suspicious | Self::NoAuthEndpoint)
    }
    pub fn can_transition(self, next: Self) -> bool {
        use ValidationState::*;
        self == next
            || matches!(
                (self, next),
                (
                    Candidate,
                    Authenticated | Rejected | Transient | NoAuthEndpoint
                ) | (Authenticated, FinalVerified | Suspicious | Rejected)
                    | (Transient, Authenticated | Rejected)
                    | (Suspicious, FinalVerified | Rejected)
            )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetIdentity {
    pub scheme: String,
    pub hostname: String,
    pub port: u16,
}
impl TargetIdentity {
    pub fn url(&self) -> String {
        let host = if self.hostname.starts_with('[') && self.hostname.ends_with(']') {
            self.hostname.clone()
        } else if self.hostname.contains(':') {
            format!("[{}]", self.hostname)
        } else {
            self.hostname.clone()
        };
        let default = if self.scheme == "https" { 443 } else { 80 };
        format!(
            "{}://{}{}",
            self.scheme,
            host,
            if self.port == default {
                String::new()
            } else {
                format!(":{}", self.port)
            }
        )
    }
    pub fn identity_hash(&self) -> String {
        format!(
            "{:x}",
            Sha1::digest(format!("{}://{}:{}", self.scheme, self.hostname, self.port).as_bytes())
        )
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiscoveryTarget {
    pub identity: TargetIdentity,
    pub sources: BTreeSet<String>,
    pub query_ids: BTreeSet<String>,
    pub advisory_ids: BTreeSet<String>,
    pub product_hints: BTreeSet<String>,
    pub aliases: BTreeSet<String>,
    pub content_evidence: Vec<String>,
    pub hit: Value,
}
impl Default for TargetIdentity {
    fn default() -> Self {
        Self {
            scheme: "https".into(),
            hostname: String::new(),
            port: 443,
        }
    }
}
pub fn canonicalize_hits(hits: &[Value]) -> Vec<DiscoveryTarget> {
    let mut merged: BTreeMap<(String, String, u16), DiscoveryTarget> = BTreeMap::new();
    for hit in hits {
        let raw = hit
            .get("host")
            .or_else(|| hit.get("link"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let hint = hit
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("https");
        let value = if raw.contains("://") {
            raw.to_owned()
        } else {
            format!("{hint}://{raw}")
        };
        let Ok(url) = Url::parse(&value) else {
            continue;
        };
        let Some(host) = url.host_str() else { continue };
        let scheme = if url.scheme() == "http" {
            "http"
        } else {
            "https"
        };
        let port = url
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let key = (scheme.into(), host.to_ascii_lowercase(), port);
        let target = merged
            .entry(key.clone())
            .or_insert_with(|| DiscoveryTarget {
                identity: TargetIdentity {
                    scheme: key.0.clone(),
                    hostname: key.1.clone(),
                    port,
                },
                hit: hit.clone(),
                ..Default::default()
            });
        insert_values(&mut target.sources, hit, "_source");
        insert_values(&mut target.query_ids, hit, "_query_id");
        insert_values(&mut target.query_ids, hit, "_query_ids");
        insert_values(&mut target.advisory_ids, hit, "_cve");
        insert_values(&mut target.advisory_ids, hit, "_cves");
        insert_values(&mut target.product_hints, hit, "_product");
        insert_values(&mut target.product_hints, hit, "_product_hints");
        for key in ["header", "banner", "body", "cert", "title"] {
            if let Some(text) = hit
                .get(key)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
            {
                target.content_evidence.push(text.into());
            }
        }
    }
    merged.into_values().collect()
}
fn insert_values(set: &mut BTreeSet<String>, value: &Value, key: &str) {
    if let Some(text) = value.get(key).and_then(Value::as_str) {
        for part in text.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            set.insert(part.into());
        }
    }
    if let Some(items) = value.get(key).and_then(Value::as_array) {
        set.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Discovery,
    Extract,
    Probe,
    Validate,
    Balance,
    Finalize,
    Finished,
}
impl ScanPhase {
    pub fn rank(self) -> u8 {
        match self {
            Self::Discovery => 0,
            Self::Extract => 1,
            Self::Probe => 2,
            Self::Validate => 3,
            Self::Balance => 4,
            Self::Finalize => 5,
            Self::Finished => 6,
        }
    }
    pub fn at_least(self, other: Self) -> bool {
        self.rank() >= other.rank()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanPolicy {
    pub mode: ScanMode,
    pub discovery_scope: String,
    pub use_cross_run_dedup: bool,
    pub require_fresh_verification: bool,
    pub require_fresh_balance: bool,
    pub write_checkpoints: bool,
}
impl ScanPolicy {
    pub fn from_mode(mode: ScanMode) -> Self {
        match mode {
            ScanMode::Full => Self {
                mode,
                discovery_scope: "full".into(),
                use_cross_run_dedup: true,
                require_fresh_verification: false,
                require_fresh_balance: false,
                write_checkpoints: true,
            },
            ScanMode::Incremental => Self {
                mode,
                discovery_scope: "incremental".into(),
                use_cross_run_dedup: true,
                require_fresh_verification: false,
                require_fresh_balance: false,
                write_checkpoints: true,
            },
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialIdentity {
    pub apikey: String,
    pub apiurl: String,
}
impl CredentialIdentity {
    pub fn fingerprint(&self) -> String {
        format!(
            "{:x}",
            Sha1::digest(format!("{}|{}", self.apikey, self.apiurl).as_bytes())
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalCredentialObservation {
    pub identity: CredentialIdentity,
    pub credential: Credential,
    pub methods: BTreeSet<String>,
    pub sources: BTreeSet<String>,
    pub evidence: Vec<String>,
}
#[derive(Default)]
pub struct ObservationRegistry {
    observations: HashMap<CredentialIdentity, CanonicalCredentialObservation>,
}
impl ObservationRegistry {
    pub fn observe(&mut self, credential: Credential, method: &str, source: &str, evidence: &str) {
        let identity = CredentialIdentity {
            apikey: credential.apikey.clone(),
            apiurl: credential.apiurl.clone(),
        };
        let item = self
            .observations
            .entry(identity.clone())
            .or_insert_with(|| CanonicalCredentialObservation {
                identity,
                credential,
                methods: BTreeSet::new(),
                sources: BTreeSet::new(),
                evidence: vec![],
            });
        item.methods.insert(method.into());
        item.sources.insert(source.into());
        if !evidence.is_empty() {
            item.evidence.push(evidence.into());
        }
    }
    pub fn into_values(self) -> Vec<CanonicalCredentialObservation> {
        self.observations.into_values().collect()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QueryFunnel {
    pub raw_hits: u64,
    pub unique_targets: u64,
    pub candidates: u64,
    pub active_requests: u64,
    pub total_active_http_requests: u64,
    pub final_verified: u64,
    pub suspicious: u64,
    pub high_value_final: u64,
}
impl QueryFunnel {
    pub fn effective_yield_v2(&self) -> f64 {
        ratio(self.final_verified, self.active_requests)
    }
    pub fn effective_yield_v3(&self) -> f64 {
        ratio(self.final_verified, self.total_active_http_requests)
    }
}
fn ratio(n: u64, d: u64) -> f64 {
    if d == 0 { 0.0 } else { n as f64 / d as f64 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_merge_and_state_machine_are_stable() {
        let targets = canonicalize_hits(&[
            serde_json::json!({"host":"example.com","_source":"fofa"}),
            serde_json::json!({"host":"https://example.com","_source":"shodan"}),
        ]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].sources.len(), 2);
        assert!(ValidationState::Candidate.can_transition(ValidationState::Authenticated));
        assert!(!ValidationState::Rejected.can_transition(ValidationState::FinalVerified));
    }
    #[test]
    fn phases_policies_observations_and_fingerprints_are_stable() {
        assert!(ScanPhase::Finished.at_least(ScanPhase::Discovery));
        assert!(!ScanPhase::Extract.at_least(ScanPhase::Validate));
        for mode in [ScanMode::Full, ScanMode::Incremental] {
            let policy = ScanPolicy::from_mode(mode);
            assert!(policy.use_cross_run_dedup);
            assert!(policy.write_checkpoints);
            assert!(!policy.require_fresh_verification);
        }
        let full = ScanPolicy::from_mode(ScanMode::Full);
        let incremental = ScanPolicy::from_mode(ScanMode::Incremental);
        assert_eq!(full.discovery_scope, "full");
        assert_eq!(incremental.discovery_scope, "incremental");
        assert!(!full.require_fresh_balance);
        let identity = CredentialIdentity {
            apikey: "sk-fixture".into(),
            apiurl: "https://api.example/v1".into(),
        };
        assert_eq!(identity.fingerprint().len(), 40);
        let mut observations = ObservationRegistry::default();
        let credential = Credential {
            apikey: identity.apikey.clone(),
            apiurl: identity.apiurl.clone(),
            ..Default::default()
        };
        observations.observe(credential.clone(), "regex", "fofa", "header");
        observations.observe(credential, "gpt", "shodan", "");
        let row = observations.into_values().pop().unwrap();
        assert_eq!(row.methods.len(), 2);
        assert_eq!(row.sources.len(), 2);
        assert_eq!(row.evidence, vec!["header"]);
        assert_eq!(
            QueryFunnel {
                final_verified: 1,
                active_requests: 2,
                total_active_http_requests: 4,
                ..Default::default()
            }
            .effective_yield_v2(),
            0.5
        );
        assert_eq!(QueryFunnel::default().effective_yield_v3(), 0.0);
    }

    #[test]
    fn canonicalization_keeps_ipv6_default_ports_and_provenance_arrays() {
        let rows = canonicalize_hits(&[
            serde_json::json!({"host":"http://[::1]:80/path","_source":"fofa,manual","_query_ids":["q1","q2"],"_cves":["CVE-1"],"_product_hints":["dify"],"title":"fixture"}),
            serde_json::json!({"host":"http://[::1]","_source":"shodan","body":"body"}),
            serde_json::json!({"host":"not a url"}),
        ]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity.url(), "http://[::1]");
        assert_eq!(rows[0].identity.identity_hash().len(), 40);
        assert_eq!(rows[0].sources.len(), 3);
        assert_eq!(rows[0].query_ids.len(), 2);
        assert_eq!(rows[0].content_evidence.len(), 2);
    }
}
