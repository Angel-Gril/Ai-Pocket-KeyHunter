use aipocket_core::Credential;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}
#[derive(Clone, Debug)]
pub struct ProbeContext {
    pub target: String,
    pub product: String,
    pub max_risk: RiskLevel,
    pub intrusive_checks: bool,
    pub allowed_classes: Vec<String>,
    pub request_budget: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProbeFinding {
    pub product: String,
    pub vuln_class: String,
    pub risk: u8,
    pub evidence: Value,
    pub credentials: Vec<Credential>,
}
impl ProbeContext {
    pub fn allows(&self, class: &str, risk: RiskLevel) -> bool {
        if risk > self.max_risk {
            return false;
        }
        if risk > RiskLevel::L0 && !self.intrusive_checks {
            return false;
        }
        self.allowed_classes
            .iter()
            .any(|v| v == "*" || v == "all" || v == class)
    }
}
#[async_trait]
pub trait Prober: Send + Sync {
    fn product(&self) -> &'static str;
    async fn probe(
        &self,
        http: &reqwest::Client,
        context: &ProbeContext,
    ) -> Result<Vec<ProbeFinding>>;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_risk_fails_closed() {
        let context = ProbeContext {
            target: String::new(),
            product: String::new(),
            max_risk: RiskLevel::L3,
            intrusive_checks: false,
            allowed_classes: vec!["*".into()],
            request_budget: 1,
        };
        assert!(!context.allows("rce", RiskLevel::L3));
        assert!(context.allows("unauth_read", RiskLevel::L0));
    }
}
