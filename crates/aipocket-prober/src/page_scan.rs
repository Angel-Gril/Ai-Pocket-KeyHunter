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
        r"\bsk-[A-Za-z0-9]{20,}\b",
        r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
        r"\bwsk_live_[A-Za-z0-9_-]{20,}\b",
        r"\bcwk-[A-Za-z0-9_-]{20,}\b",
        r"\bapi-key-kling-[A-Za-z0-9_-]{20,}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
        r"\bAKIA[A-Z0-9]{16}\b",
        r"\bLTAI[A-Za-z0-9]{12,}\b",
        r"\b[0-9]{8,10}:[A-Za-z0-9_-]{30,35}\b",
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

/// One-click provider-import links (AI as Workspace set-provider, AMA
/// set-api-key, OpenCat team/join) expose keys *intentionally*: the site
/// owner publishes them so users can import the gateway. These keys are
/// maintained by the owner and stay alive far longer than accidental
/// leaks, so flag them for priority validation / high-value marking.
const SHARED_KEY_MARKERS: &[&str] = &[
    "set-provider",
    "set-api-key",
    "opencat://",
    "ama://",
    "team/join",
];

fn is_shared_key_context(text: &str, value: &str) -> bool {
    let Some(pos) = text.find(value) else {
        return false;
    };
    // Byte-safe window: walk back 300 chars and forward 200 chars from the
    // match, staying on UTF-8 char boundaries (text may contain CJK/emoji).
    let before: usize = text[..pos]
        .chars()
        .rev()
        .take(300)
        .map(char::len_utf8)
        .sum();
    let window_start = pos - before;
    let after: usize = text[pos..]
        .chars()
        .take(value.len() + 200)
        .map(char::len_utf8)
        .sum();
    let window_end = (pos + after).min(text.len());
    let window = &text[window_start..window_end];
    SHARED_KEY_MARKERS.iter().any(|m| window.contains(m))
}

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
                source: if is_shared_key_context(text, &value) {
                    format!("page_scan:{product}:shared")
                } else {
                    format!("page_scan:{product}")
                },
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
        let paths = [
            "/",
            "/.env",
            "/api/config",
            "/api/status",
            "/v1/models",
            // Swagger/OpenAPI endpoints: FastAPI-based gateways (LiteLLM,
            // new-api, sub2api) expose /docs + /openapi.json where devs
            // leave Authorization header default values in Try-it-out boxes.
            "/docs",
            "/openapi.json",
            "/redoc",
        ];
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
        let text = "wsk_live_abcdefghijklmnopqrstuvwxyz12345678 cwk-abcdefghijklmnopqrstuvwxyz12345678 api-key-kling-abcdefghijklmnopqrstuvwxyz123456";
        let creds = extract_keys(text, "http://example.com", "page_key_scan");
        let kinds: Vec<_> = creds.iter().map(|c| c.apikey.split('-').next().unwrap()).collect();
        assert!(kinds.contains(&"wsk_live_abcdefghijklmnopqrstuvwxyz12345678"), "{creds:?}");
        assert!(creds.iter().any(|c| c.apikey.starts_with("wsk_live_")), "{creds:?}");
        assert!(creds.iter().any(|c| c.apikey.starts_with("cwk-")), "{creds:?}");
        assert!(creds.iter().any(|c| c.apikey.starts_with("api-key-kling-")), "{creds:?}");
    }

    #[test]
    fn extracts_github_cloud_telegram_keys() {
        for (sample, ok) in [
            ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", true),
            ("github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", true),
            ("AKIAIOSFODNN7EXAMPLE", false), // contains "example" noise substring
            ("AKIAABCDEFGHIJKLMNOP", true),
            ("LTAI5tABCDEFGHIJKLMN", true),
            ("123456789:AAabcdefghijklmnopqrstuvwxyz012345", true),
            ("ghp_short", false),
            ("AKIA123", false),
            ("AKIAABCDEFGHIJKLMNOP", true),
            ("plaintext", false),
        ] {
            let creds = extract_keys(sample, "http://example.com", "page_key_scan");
            assert_eq!(!creds.is_empty(), ok, "match mismatch for {sample}");
        }
    }

    #[test]
    fn marks_owner_shared_keys() {
        // One-click import links publish keys intentionally.
        let import_link = "https://aiaw.app/set-provider?provider=\"{\"type\":\"openai\",\"settings\":{\"apiKey\":\"{sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}\",\"baseURL\":\"{https://relay.example:445}/v1\"}}";
        let shared = extract_keys(import_link, "https://api.relay.example", "page_key_scan");
        assert!(
            shared.iter().any(|c| c.source.ends_with(":shared")),
            "expected shared marker, got {:?}",
            shared.iter().map(|c| &c.source).collect::<Vec<_>>()
        );
        // Accidental leak on a normal page stays unmarked.
        let plain = "const KEY = \"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\";";
        let leak = extract_keys(plain, "https://example.com", "page_key_scan");
        assert!(
            leak.iter().all(|c| !c.source.ends_with(":shared")),
            "plain leak should not be marked shared"
        );
    }

    #[test]
    fn shared_marker_is_utf8_safe() {
        // CJK text before the key: byte slicing must stay on char boundaries.
        let text = format!(
            "{}开屏公告：本站提供 OpenAI 兼容 API 服务，欢迎使用！点此一键导入：https://aiaw.app/set-provider?provider={{\"settings\":{{\"apiKey\":\"{{sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}}\"}}}}",
            "站" .repeat(400)
        );
        let creds = extract_keys(&text, "https://api.example.com", "page_key_scan");
        assert!(
            creds.iter().any(|c| c.source.ends_with(":shared")),
            "expected shared marker with CJK context"
        );
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
