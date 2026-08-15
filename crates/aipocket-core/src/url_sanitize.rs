use url::Url;

use crate::CoreError;

/// Returns true when `host` is a loopback, link-local, private (RFC1918),
/// or cloud-metadata reserved address. These must never be probed or
/// validated from the backend (SSRF surface).
fn is_reserved_host(host: &str) -> bool {
    // Url::host_str() returns bracketed IPv6 like "[::1]"; strip them.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_private()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    // belt-and-suspenders: cloud metadata 169.254.169.254
                    || v4.octets() == [169, 254, 169, 254]
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
            }
        };
    }
    // Resolve nothing at sanitize time; block obvious reserved literals only.
    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "metadata.google.internal"
        || lower == "metadata"
        || lower.ends_with(".internal")
}

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
    if is_reserved_host(host) {
        return Err(CoreError::InvalidInput(format!(
            "reserved/internal host not allowed: {host}"
        )));
    }
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
pub fn honeypot_group_key(raw: &str) -> Result<String, CoreError> {
    let origin = sanitize_origin(raw)?;
    let parsed = Url::parse(&origin).expect("sanitized URL parses");
    let host = parsed.host_str().unwrap_or_default();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.into());
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() >= 3 {
        Ok(labels[labels.len() - 2..].join("."))
    } else {
        Ok(host.into())
    }
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
    #[test]
    fn rejects_reserved_hosts() {
        for bad in [
            "http://127.0.0.1:8000",
            "http://localhost/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://[::1]/",
            "http://fd00::1/",
        ] {
            assert!(sanitize_origin(bad).is_err(), "should reject {bad}");
        }
    }
    #[test]
    fn allows_public_hosts() {
        for good in [
            "https://example.com",
            "http://45.202.199.163:3080",
            "https://8.8.8.8/",
        ] {
            assert!(sanitize_origin(good).is_ok(), "should allow {good}");
        }
    }
    #[test]
    fn groups_honeypot_subdomains_but_not_ips() {
        assert_eq!(
            honeypot_group_key("https://a.b.ip.linodeusercontent.com:8443").unwrap(),
            "linodeusercontent.com"
        );
        assert_eq!(
            honeypot_group_key("https://192.0.2.8:8443").unwrap(),
            "192.0.2.8"
        );
    }
}
