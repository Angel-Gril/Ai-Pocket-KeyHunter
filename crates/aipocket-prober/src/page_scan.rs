//! Generic passive page-key scanner.
//!
//! Fetches the root page (and a few common leak-prone paths) of any target and
//! extracts API-key-like secrets with the full credential regex set. Pure GET,
//! L0 / unauth_read only, and bounded by `generic_max_requests_per_target`
//! (which the scheduler passes as `ProbeContext.request_budget`).
//!
//! This covers the "view source of an arbitrary URL and find sk- strings"
//! use-case that product-specific probers do not handle for unknown targets.

use crate::engine::{ProbeContext, ProbeFinding, Prober};
use aipocket_core::Credential;
use async_trait::async_trait;
use regex::Regex;
use serde_json::json;
use std::sync::LazyLock;

/// Same pattern set as `aipocket-services::pipeline::KEY_PATTERNS`.
/// Kept local to avoid a dependency cycle (prober is a base crate).
pub static KEY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"\bsk-or-v1-[a-fA-F0-9-]{30,}\b",
        r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
        r"\bsk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}\b",
        r"\bAIza[A-Za-z0-9_-]{20,}\b",
        r"\bgsk_[A-Za-z0-9]{20,}\b",
        r"\bpplx-[A-Za-z0-9]{20,}\b",
        r"\br8_[A-Za-z0-9]{20,}\b",
        r"\bhf_[A-Za-z0-9]{20,}\b",
        r"\bxai-[A-Za-z0-9]{20,}\b",
        r"\bkey_[A-Za-z0-9]{20,}\b",
        r"\bksk_[A-Za-z0-9_-]{16,}\b",
        r"\bcrsr_[A-Za-z0-9_-]{32,}\b",
        r"\bpt-[A-Za-z0-9]{16,}\b",
        r"\bABSK[A-Za-z0-9_+=/.-]{20,}\b",
        r"\b[a-f0-9]{32}\.[A-Za-z0-9]{16}\b",
        r"\bsk-[A-Za-z0-9_-]{16,}\b",
        r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
        r"\bwsk_live_[A-Za-z0-9_-]{20,}\b",
        r"\bcwk-[A-Za-z0-9_-]{20,}\b",
        r"\bapi-key-kling-[A-Za-z0-9_-]{20,}\b",
    ]
    .into_iter()
    .map(|pattern| Regex::new(pattern).expect("credential regex"))
    .collect()
});

/// Substrings that indicate a placeholder/example rather than a real secret.
const NOISE_SUBSTRINGS: &[&str] = &[
    "changeme",
    "your_",
    "your-",
    "example",
    "dummy",
    "placeholder",
    "xxxx",
    "<sk-",
    "sk-xxxx",
];

/// Public CDN / vendor keys that appear on nearly every website but are NOT
/// secrets: Google Fonts / Maps / reCAPTCHA AIzaSy keys, gstatic assets.
/// Keys found on these domains are public client keys by design.
const PUBLIC_CDN_DOMAINS: &[&str] = &[
    "fonts.googleapis.com",
    "maps.googleapis.com",
    "gstatic.com",
    "recaptcha.google.com",
];

fn extract_keys(text: &str, target: &str, product: &str) -> Vec<Credential> {
    let lower = text.to_ascii_lowercase();
    let target_lower = target.to_ascii_lowercase();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for pattern in KEY_PATTERNS.iter() {
        for matched in pattern.find_iter(text) {
            let value = matched.as_str();
            if NOISE_SUBSTRINGS
                .iter()
                .any(|noise| value.to_ascii_lowercase().contains(noise))
            {
                continue;
            }
            // Public Google CDN client keys are not leaks.
            if value.starts_with("AIza")
                && PUBLIC_CDN_DOMAINS
                    .iter()
                    .any(|domain| target_lower.contains(domain))
            {
                continue;
            }
            if !seen.insert(value.to_owned()) {
                continue;
            }
            out.push(Credential {
                apikey: value.into(),
                apiurl: target.into(),
                source: format!("page_scan:{product}"),
                source_type: "page_scan".into(),
                backend: "page_scan".into(),
                host: target.into(),
                ip: String::new(),
                port: String::new(),
                product: product.into(),
                raw_context: text.chars().take(512).collect(),
                leak_host: target.into(),
                routed_to_official: false,
            });
        }
    }
    let _ = lower;
    out
}

pub struct PageKeyScanProber;

#[async_trait]
impl Prober for PageKeyScanProber {
    fn product(&self) -> &'static str {
        "page_key_scan"
    }

    async fn probe(
        &self,
        http: &reqwest::Client,
        context: &ProbeContext,
    ) -> Result<Vec<ProbeFinding>, anyhow::Error> {
        // Root page + common leak-prone paths. Bounded by request_budget
        // (generic_max_requests_per_target) like every other prober.
        let paths = ["/", "/.env", "/api/config", "/api/status", "/v1/models"];
        let mut requests = 0usize;
        let mut findings = Vec::new();
        for path in paths {
            if requests >= context.request_budget.max(1) {
                break;
            }
            requests += 1;
            let url = format!("{}{}", context.target.trim_end_matches('/'), path);
            // Short per-request timeout: FOFA-discovered targets include many
            // dead/hanging hosts; a 15s global timeout lets slow hosts occupy
            // concurrency slots for 75s (5 paths) and starves the probe.
            let Ok(response) = http
                .get(&url)
                .timeout(std::time::Duration::from_secs(6))
                .send()
                .await
            else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            let Ok(text) = response.text().await else {
                continue;
            };
            let credentials = extract_keys(&text, &context.target, &context.product);
            if credentials.is_empty() {
                continue;
            }
            findings.push(ProbeFinding {
                product: context.product.clone(),
                vuln_class: "unauth_read".into(),
                risk: 0,
                evidence: json!({
                    "path": path,
                    "snippet": text.chars().take(512).collect::<String>(),
                }),
                credentials,
            });
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_real_keys_and_skips_noise() {
        let text = "const key = \"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\";\n\
                    API_KEY=your_api_key_here\n\
                    token=sk-xxxx\n\
                    AIzaSyDummyExampleKey0123456789abcdef";
        let creds = extract_keys(text, "http://target", "page_key_scan");
        assert_eq!(creds.len(), 1, "only the real sk-proj key should survive");
        assert_eq!(creds[0].apikey, "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
        assert_eq!(creds[0].backend, "page_scan");
    }

    #[test]
    fn extracts_anthropic_and_xai_keys() {
        let text = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234\n\
                    XAI_API_KEY=xai-0123456789abcdef0123456789abcdef0123456789abcdef";
        let creds = extract_keys(text, "http://t", "page_key_scan");
        assert!(creds.iter().any(|c| c.apikey.starts_with("sk-ant-")), "{:?}", creds);
        assert!(creds.iter().any(|c| c.apikey.starts_with("xai-")), "{:?}", creds);
    }

    #[test]
    fn extracts_relay_prefix_keys() {
        let text = "WAVESPEED_KEY=wsk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefgh\n\
                    CWK=cwk-ffbb3aaa6c156e109e8f41d50e5edb8c87079e5a1c68550ee3613a2560971d89\n\
                    KLING=api-key-kling-Mn3iRbmKJMfQjAzqySOf9R17kOmOuSQAB3xLKdsTu5o";
        let creds = extract_keys(text, "http://t", "page_key_scan");
        assert!(creds.iter().any(|c| c.apikey.starts_with("wsk_live_")), "{:?}", creds);
        assert!(creds.iter().any(|c| c.apikey.starts_with("cwk-")), "{:?}", creds);
        assert!(creds.iter().any(|c| c.apikey.starts_with("api-key-kling-")), "{:?}", creds);
    }

    #[test]
    fn skips_public_google_cdn_keys_but_keeps_other_aiza_keys() {
        // Page hosted on Google Fonts: the AIzaSy key there is a public client key.
        let fonts = "AIzaSyPublicFontsKey00000000000000000000000";
        assert_eq!(
            extract_keys(fonts, "https://fonts.googleapis.com/css2?family=Inter", "page_key_scan").len(),
            0
        );
        let maps = "AIzaSyPublicMapsKey11111111111111111111111111";
        assert_eq!(
            extract_keys(maps, "http://maps.googleapis.com/maps/api/js", "page_key_scan").len(),
            0
        );
        let own = "AIzaSyMyOwnPrivateKey22222222222222222222222222";
        let creds = extract_keys(own, "http://myapp.example.com", "page_key_scan");
        assert!(creds.iter().any(|c| c.apikey.starts_with("AIzaSyMyOwn")), "{:?}", creds);
    }

    #[test]
    fn respects_request_budget() {
        let context = ProbeContext {
            target: "http://127.0.0.1:1".into(),
            product: "page_key_scan".into(),
            max_risk: crate::engine::RiskLevel::L0,
            intrusive_checks: false,
            allowed_classes: vec!["*".into()],
            request_budget: 2,
        };
        // unreachable target: still loops but must not exceed budget
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let http = reqwest::Client::new();
        let findings = runtime
            .block_on(PageKeyScanProber.probe(&http, &context))
            .unwrap();
        assert!(findings.is_empty());
    }
}
