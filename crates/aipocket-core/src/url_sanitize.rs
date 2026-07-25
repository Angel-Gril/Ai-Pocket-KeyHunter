use url::Url;

use crate::CoreError;

pub fn sanitize_origin(raw: &str) -> Result<String, CoreError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput("empty URL".into()));
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&candidate).map_err(|e| CoreError::InvalidInput(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| CoreError::InvalidInput("URL has no hostname".into()))?;
    let port = parsed.port();
    let mut output = format!(
        "{}://{}",
        parsed.scheme().to_ascii_lowercase(),
        host.to_ascii_lowercase()
    );
    if let Some(port) = port {
        output.push_str(&format!(":{port}"));
    }
    Ok(output)
}

pub fn host_key(raw: &str) -> Result<String, CoreError> {
    let origin = sanitize_origin(raw)?;
    let parsed = Url::parse(&origin).expect("sanitized URL parses");
    let host = parsed.host_str().unwrap_or_default();
    let port = parsed.port_or_known_default().unwrap_or(443);
    Ok(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_path_and_normalizes_host() {
        assert_eq!(
            sanitize_origin("Example.COM/path?q=1").unwrap(),
            "https://example.com"
        );
        assert_eq!(host_key("http://example.com").unwrap(), "example.com:80");
    }
}
