use crate::CoreError;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalEndpoint {
    pub api_base: String,
    pub origin: String,
}

const OPERATION_SUFFIXES: &[&str] = &[
    "/chat/completions",
    "/messages",
    "/models",
    "/user/balance",
    "/users/me/balance",
    "/token_plan/remains",
];

pub fn canonicalize_endpoint(raw: &str, provider: &str) -> Result<CanonicalEndpoint, CoreError> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(CanonicalEndpoint {
            api_base: String::new(),
            origin: String::new(),
        });
    }
    let value = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let parsed = Url::parse(&value).map_err(|error| CoreError::InvalidInput(error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| CoreError::InvalidInput("URL has no host".into()))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let scheme = match parsed.scheme() {
        "http" => "http",
        _ => "https",
    };
    let mut authority = host.clone();
    if let Some(port) = parsed.port()
        && !((scheme == "https" && port == 443) || (scheme == "http" && port == 80))
    {
        authority = format!("{authority}:{port}");
    }
    let origin = format!("{scheme}://{authority}");
    let provider = provider.to_ascii_lowercase();
    let official = match (provider.as_str(), host.as_str()) {
        ("openai", "api.openai.com") | ("anthropic", "api.anthropic.com") => Some("/v1"),
        ("deepseek", "api.deepseek.com") => Some(""),
        ("kimi", "api.moonshot.cn" | "api.moonshot.ai") => Some("/v1"),
        ("glm", "open.bigmodel.cn") => Some("/api/paas/v4"),
        ("nvidia", "integrate.api.nvidia.com") | ("ksyun", "kspmas.ksyun.com") => Some("/v1"),
        ("xai", "api.x.ai") => Some("/v1"),
        ("openrouter", "openrouter.ai") => Some("/api"),
        ("qoder", "api.qoder.com") | ("cursor", "api.cursor.com") => Some(""),
        ("windsurf", "server.codeium.com") => Some("/api/v1"),
        ("minimax", "api.minimax.io" | "api.minimaxi.com" | "api.minimax.chat") => Some("/v1"),
        ("longcat", "api.longcat.chat") => Some(
            if parsed.path().to_ascii_lowercase().starts_with("/anthropic") {
                "/anthropic"
            } else {
                "/openai"
            },
        ),
        _ => None,
    };
    let path = official
        .map(str::to_owned)
        .unwrap_or_else(|| strip_operation_path(parsed.path()));
    Ok(CanonicalEndpoint {
        api_base: format!("{origin}{path}"),
        origin,
    })
}

fn strip_operation_path(path: &str) -> String {
    let normalized = format!(
        "/{}",
        path.split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    );
    if normalized == "/" {
        return String::new();
    }
    let lowered = normalized.to_ascii_lowercase();
    for suffix in OPERATION_SUFFIXES {
        if lowered.ends_with(suffix) {
            let base = normalized[..normalized.len() - suffix.len()].trim_end_matches('/');
            if *suffix == "/models" && base.eq_ignore_ascii_case("/v1") {
                return String::new();
            }
            return base.to_owned();
        }
    }
    normalized.trim_end_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_official_and_gateway_endpoints() {
        let openai = canonicalize_endpoint("https://api.openai.com/v1/models", "openai").unwrap();
        assert_eq!(openai.api_base, "https://api.openai.com/v1");
        assert_eq!(openai.origin, "https://api.openai.com");
        let gateway =
            canonicalize_endpoint("relay.example:8443/v1/chat/completions", "gateway").unwrap();
        assert_eq!(gateway.api_base, "https://relay.example:8443/v1");
    }

    #[test]
    fn normalizes_official_provider_matrix_and_operation_suffixes() {
        for (raw, provider, expected) in [
            (
                "api.deepseek.com/user/balance",
                "deepseek",
                "https://api.deepseek.com",
            ),
            (
                "https://api.moonshot.cn/v1/users/me/balance",
                "kimi",
                "https://api.moonshot.cn/v1",
            ),
            (
                "https://open.bigmodel.cn/api/paas/v4/models",
                "glm",
                "https://open.bigmodel.cn/api/paas/v4",
            ),
            (
                "https://api.minimax.io:443/v1/models",
                "minimax",
                "https://api.minimax.io/v1",
            ),
            (
                "http://relay.example:80/v1/models",
                "gateway",
                "http://relay.example",
            ),
            (
                "https://api.longcat.chat/anthropic/messages",
                "longcat",
                "https://api.longcat.chat/anthropic",
            ),
            ("https://api.x.ai/v1/models", "xai", "https://api.x.ai/v1"),
            (
                "https://openrouter.ai/v1/models",
                "openrouter",
                "https://openrouter.ai/api",
            ),
            (
                "https://server.codeium.com/api/v1/GetTeamCreditBalance",
                "windsurf",
                "https://server.codeium.com/api/v1",
            ),
        ] {
            assert_eq!(
                canonicalize_endpoint(raw, provider).unwrap().api_base,
                expected
            );
        }
        assert_eq!(canonicalize_endpoint("", "unknown").unwrap().origin, "");
        assert!(canonicalize_endpoint("://", "unknown").is_err());
    }
}
