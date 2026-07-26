use aipocket_core::{CoreError, Settings};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnClass {
    UnauthRead,
    WeakPassword,
    Idor,
    Ssrf,
    Sqli,
    Rce,
}

impl VulnClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnauthRead => "unauth_read",
            Self::WeakPassword => "weak_password",
            Self::Idor => "idor",
            Self::Ssrf => "ssrf",
            Self::Sqli => "sqli",
            Self::Rce => "rce",
        }
    }
}

impl std::str::FromStr for VulnClass {
    type Err = CoreError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "unauth_read" => Ok(Self::UnauthRead),
            "weak_password" => Ok(Self::WeakPassword),
            "idor" => Ok(Self::Idor),
            "ssrf" => Ok(Self::Ssrf),
            "sqli" => Ok(Self::Sqli),
            "rce" => Ok(Self::Rce),
            other => Err(CoreError::Config(format!(
                "unknown probe vulnerability class: {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeSpec {
    pub id: String,
    pub product: String,
    pub vuln_class: VulnClass,
    pub risk_level: crate::RiskLevel,
    #[serde(default)]
    pub cve_ids: Vec<String>,
    #[serde(default)]
    pub requires_auth: bool,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub entry: Value,
    #[serde(default = "default_max_requests")]
    pub max_requests: usize,
}
fn default_max_requests() -> usize {
    5
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Executed,
    SkippedGate,
    SkippedBudget,
    SkippedNoAuth,
    SkippedDependency,
    SkippedClass,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeOutcome {
    pub spec_id: String,
    pub vuln_class: VulnClass,
    pub risk_level: crate::RiskLevel,
    pub status: NodeStatus,
    #[serde(default)]
    pub requests_used: usize,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub credentials_found: usize,
}

#[derive(Clone, Debug)]
pub struct RiskPolicy {
    pub enabled_classes: HashSet<VulnClass>,
    pub max_risk: crate::RiskLevel,
    pub intrusive_checks: bool,
    pub authorized_scope: Vec<String>,
    pub ssrf_enabled: bool,
    pub sqli_enabled: bool,
    pub rce_enabled: bool,
}

impl RiskPolicy {
    pub fn from_settings(settings: &Settings) -> Result<Self, CoreError> {
        let enabled_classes = if settings.probe_vuln_classes.trim().is_empty()
            || matches!(
                settings
                    .probe_vuln_classes
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "*" | "all"
            ) {
            [
                VulnClass::UnauthRead,
                VulnClass::WeakPassword,
                VulnClass::Idor,
                VulnClass::Ssrf,
                VulnClass::Sqli,
                VulnClass::Rce,
            ]
            .into_iter()
            .collect()
        } else {
            settings
                .probe_vuln_classes
                .split(',')
                .map(str::parse)
                .collect::<Result<_, _>>()?
        };
        let max_risk = match settings.probe_max_risk {
            0 => crate::RiskLevel::L0,
            1 => crate::RiskLevel::L1,
            2 => crate::RiskLevel::L2,
            3 => crate::RiskLevel::L3,
            value => {
                return Err(CoreError::Config(format!(
                    "PROBE_MAX_RISK must be 0..=3, got {value}"
                )));
            }
        };
        let authorized_scope: Vec<String> = settings
            .authorized_probe_scope
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        Ok(Self {
            enabled_classes,
            max_risk,
            intrusive_checks: settings.intrusive_checks && !authorized_scope.is_empty(),
            authorized_scope,
            ssrf_enabled: settings.probe_ssrf_enabled,
            sqli_enabled: settings.probe_sqli_enabled,
            rce_enabled: settings.probe_rce_enabled,
        })
    }

    pub fn allows(&self, spec: &ProbeSpec, target: &str) -> bool {
        if !self.enabled_classes.contains(&spec.vuln_class) || spec.risk_level > self.max_risk {
            return false;
        }
        if spec.vuln_class == VulnClass::Ssrf && !self.ssrf_enabled
            || spec.vuln_class == VulnClass::Sqli && !self.sqli_enabled
            || spec.vuln_class == VulnClass::Rce && !self.rce_enabled
        {
            return false;
        }
        if spec.risk_level == crate::RiskLevel::L0 {
            return true;
        }
        if !self.intrusive_checks {
            return false;
        }
        if self.authorized_scope.is_empty() {
            return true;
        }
        normalized_origin(target).is_some_and(|origin| {
            self.authorized_scope
                .iter()
                .any(|allowed| allowed == &origin)
        })
    }
}

pub fn plan_specs(
    product: &str,
    specs: &[ProbeSpec],
    target: &str,
    policy: &RiskPolicy,
    advisory_ids: &[String],
) -> Vec<ProbeSpec> {
    let advisory: HashSet<_> = advisory_ids
        .iter()
        .map(|value| value.to_ascii_uppercase())
        .collect();
    let mut selected: Vec<_> = specs
        .iter()
        .filter(|spec| {
            normalize_product(&spec.product) == normalize_product(product)
                && policy.allows(spec, target)
        })
        .cloned()
        .collect();
    selected.sort_by_key(|spec| {
        (
            class_order(spec.vuln_class),
            !spec
                .cve_ids
                .iter()
                .any(|id| advisory.contains(&id.to_ascii_uppercase())),
            spec.id.clone(),
        )
    });
    selected
}

fn class_order(class: VulnClass) -> u8 {
    match class {
        VulnClass::UnauthRead => 0,
        VulnClass::WeakPassword => 1,
        VulnClass::Idor => 2,
        VulnClass::Ssrf => 3,
        VulnClass::Sqli => 4,
        VulnClass::Rce => 5,
    }
}
fn normalize_product(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', "-")
}
fn normalized_origin(target: &str) -> Option<String> {
    let parsed = Url::parse(target).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port();
    Some(match port {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_classes_fail_closed_and_active_scope_is_exact() {
        let mut settings = Settings {
            probe_vuln_classes: "rcee".into(),
            ..Settings::default()
        };
        assert!(RiskPolicy::from_settings(&settings).is_err());
        settings.probe_vuln_classes = "rce".into();
        settings.probe_max_risk = 3;
        settings.intrusive_checks = true;
        settings.probe_rce_enabled = true;
        settings.authorized_probe_scope = "https://allowed.example".into();
        let policy = RiskPolicy::from_settings(&settings).unwrap();
        let spec = ProbeSpec {
            id: "rce".into(),
            product: "x".into(),
            vuln_class: VulnClass::Rce,
            risk_level: crate::RiskLevel::L3,
            cve_ids: vec![],
            requires_auth: false,
            depends_on: vec![],
            entry: Value::Null,
            max_requests: 1,
        };
        assert!(policy.allows(&spec, "https://allowed.example/path"));
        assert!(!policy.allows(&spec, "https://evil.example"));
        settings.authorized_probe_scope.clear();
        let unrestricted = RiskPolicy::from_settings(&settings).unwrap();
        assert!(!unrestricted.allows(&spec, "https://allowed.example/path"));
    }
}
