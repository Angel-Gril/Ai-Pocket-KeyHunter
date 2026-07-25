pub mod github_artifacts;
pub mod legacy_queries;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

use aipocket_core::{Credential, ScanMode};

pub mod packs;
pub mod sources;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub repository_id: String,
    pub repository_full_name: String,
    pub commit_sha: String,
    pub object_sha: String,
    pub file_path: String,
    pub source_kind: String,
    pub change_side: String,
    pub line_start: Option<u64>,
    pub line_end: Option<u64>,
    pub query_id: String,
    pub pack_id: String,
    pub lane: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CredentialObservation {
    pub credential: Credential,
    pub provenance: ArtifactProvenance,
    pub query_id: String,
    pub pack_id: String,
    pub lane: String,
    pub coverage_mode: String,
    pub coverage_gap: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QueryUsage {
    pub source: String,
    pub query: String,
    pub page_count: u64,
    pub result_count: u64,
    pub query_id: String,
    pub pack_id: String,
    pub lane: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryProgress {
    pub source: String,
    pub query_index: usize,
    pub query_total: usize,
    pub page: u32,
    pub hits: u64,
    pub errors: usize,
}

pub type DiscoveryProgressReporter = Arc<dyn Fn(DiscoveryProgress) + Send + Sync>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckpointUpdate {
    pub source: String,
    pub lane: String,
    pub pack_id: String,
    pub shard_id: String,
    pub watermark: String,
    pub cursor_state: Value,
    pub etag: String,
    pub status: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ArtifactWork {
    pub repo_id: String,
    pub repository_full_name: String,
    pub commit_sha: String,
    pub file_path: String,
    pub object_sha: String,
    pub source_kind: String,
    pub etag: String,
    pub work_status: String,
    pub attempts: i32,
    pub last_error_class: String,
    pub current_stage: String,
    pub run_id: String,
    pub query_id: String,
    pub pack_id: String,
    pub lane: String,
    pub coverage_mode: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceFetchResult {
    pub source: String,
    pub host_hits: Vec<Value>,
    pub credential_observations: Vec<CredentialObservation>,
    pub query_usage: Vec<QueryUsage>,
    pub checkpoint_updates: Vec<CheckpointUpdate>,
    pub artifact_work: Vec<ArtifactWork>,
    pub errors: Vec<String>,
    pub host_hit_count: Option<u64>,
    pub credential_observation_count: Option<u64>,
    pub spilled: bool,
}
#[derive(Clone, Default)]
pub struct SourceBudgets {
    pub fofa: Option<usize>,
    pub shodan: Option<usize>,
    pub github_commit: Option<usize>,
    pub github_code: Option<usize>,
    pub selected_queries: Option<Vec<String>>,
    pub checkpoints: Vec<CheckpointUpdate>,
    pub progress: Option<DiscoveryProgressReporter>,
}
#[async_trait]
pub trait DiscoverySource: Send + Sync {
    fn name(&self) -> &'static str;
    fn query_ids(&self) -> Vec<String> {
        Vec::new()
    }
    fn is_configured(&self) -> bool;
    async fn fetch(&self, budgets: &SourceBudgets, mode: ScanMode) -> Result<SourceFetchResult>;
}
