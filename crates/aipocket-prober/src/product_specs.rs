use crate::{ProbeSpec, RiskLevel, VulnClass};
use serde_json::json;

struct ProductSurface {
    product: &'static str,
    unauth: &'static [&'static str],
    login: Option<&'static str>,
    idor: Option<&'static str>,
    ssrf: Option<(&'static str, &'static str)>,
    sqli: Option<(&'static str, &'static str)>,
    rce: Option<(&'static str, &'static str)>,
}

const SURFACES: &[ProductSurface] = &[
    ProductSurface {
        product: "anythingllm",
        unauth: &["/api/system", "/api/v1/system"],
        login: Some("/api/request-token"),
        idor: None,
        ssrf: Some(("/api/workspace/upload-link", "link")),
        sqli: Some(("/api/workspaces", "slug")),
        rce: Some(("/api/system/run-command", "command")),
    },
    ProductSurface {
        product: "chatgpt_next_web",
        unauth: &["/api/config"],
        login: Some("/api/auth"),
        idor: None,
        ssrf: Some(("/api/proxy", "url")),
        sqli: Some(("/api/openai", "path")),
        rce: Some(("/api/run", "command")),
    },
    ProductSurface {
        product: "dify",
        unauth: &["/console/api/system-features", "/v1/info"],
        login: Some("/console/api/login"),
        idor: None,
        ssrf: Some(("/console/api/files/upload/for-image", "url")),
        sqli: Some(("/console/api/apps", "id")),
        rce: Some((
            "/console/api/workspaces/current/tool-provider/api/test/pre",
            "schema",
        )),
    },
    ProductSurface {
        product: "fastgpt",
        unauth: &["/api/system/getInitData"],
        login: Some("/api/support/user/account/login"),
        idor: None,
        ssrf: Some(("/api/common/file/uploadLink", "url")),
        sqli: Some(("/api/core/dataset/list", "searchText")),
        rce: Some(("/api/core/plugin/run", "code")),
    },
    ProductSurface {
        product: "flowise",
        unauth: &["/api/v1/credentials", "/api/v1/chatflows"],
        login: Some("/api/v1/login"),
        idor: Some("/api/v1/credentials/{id}"),
        ssrf: Some(("/api/v1/fetch-links", "url")),
        sqli: Some(("/api/v1/chatflows", "name")),
        rce: Some(("/api/v1/node-load-method/customFunction", "code")),
    },
    ProductSurface {
        product: "langflow",
        unauth: &["/api/v1/variables", "/api/v1/flows"],
        login: Some("/api/v1/login"),
        idor: None,
        ssrf: Some(("/api/v1/files/download", "url")),
        sqli: Some(("/api/v1/flows", "name")),
        rce: Some(("/api/v1/custom_component", "code")),
    },
    ProductSurface {
        product: "librechat",
        unauth: &["/api/config"],
        login: Some("/api/auth/login"),
        idor: Some("/api/keys/{id}"),
        ssrf: Some(("/api/files/download", "url")),
        sqli: Some(("/api/messages", "conversationId")),
        rce: Some(("/api/run/code", "code")),
    },
    ProductSurface {
        product: "litellm",
        unauth: &["/health/readiness", "/v1/models"],
        login: Some("/login"),
        idor: Some("/key/info?key={id}"),
        ssrf: Some(("/health/test_connection", "api_base")),
        sqli: Some(("/key/info", "key")),
        rce: Some(("/utils/dotproduct", "code")),
    },
    ProductSurface {
        product: "lobechat",
        unauth: &["/api/config"],
        login: None,
        idor: None,
        ssrf: Some(("/api/proxy", "url")),
        sqli: Some(("/api/user/list", "q")),
        rce: Some(("/api/debug/exec", "command")),
    },
    ProductSurface {
        product: "newapi",
        unauth: &["/api/status", "/v1/models"],
        login: Some("/api/user/login"),
        idor: Some("/api/token/{id}"),
        ssrf: Some(("/api/channel/test", "base_url")),
        sqli: Some(("/api/log/", "username")),
        rce: Some(("/api/system/test", "cmd")),
    },
    ProductSurface {
        product: "openrouter",
        unauth: &["/api/v1/models"],
        login: Some("/api/auth/login"),
        idor: None,
        ssrf: Some(("/api/v1/fetch", "url")),
        sqli: Some(("/api/v1/keys", "name")),
        rce: Some(("/api/admin/exec", "command")),
    },
    ProductSurface {
        product: "openwebui",
        unauth: &["/api/config", "/api/version"],
        login: Some("/api/v1/auths/signin"),
        idor: Some("/api/v1/users/{id}"),
        ssrf: Some(("/api/v1/tools/fetch", "url")),
        sqli: Some(("/api/v1/users/", "query")),
        rce: Some(("/api/v1/pipelines/upload", "code")),
    },
    ProductSurface {
        product: "portkey",
        unauth: &["/v1/models"],
        login: Some("/v1/login"),
        idor: None,
        ssrf: Some(("/v1/proxy", "url")),
        sqli: Some(("/v1/logs", "q")),
        rce: Some(("/v1/debug/exec", "command")),
    },
];

pub fn specs_for(product: &str) -> Vec<ProbeSpec> {
    let migrated = crate::migrated_specs::migrated_specs(product);
    let normalized = product.to_ascii_lowercase().replace('-', "_");
    let Some(surface) = SURFACES
        .iter()
        .find(|surface| surface.product == normalized)
    else {
        return Vec::new();
    };
    let mut specs = vec![ProbeSpec {
        id: format!("{}.unauth", surface.product),
        product: surface.product.into(),
        vuln_class: VulnClass::UnauthRead,
        risk_level: RiskLevel::L0,
        cve_ids: vec![],
        requires_auth: false,
        depends_on: vec![],
        entry: json!({"paths":surface.unauth}),
        max_requests: surface.unauth.len().max(1),
    }];
    if let Some(login) = surface.login {
        specs.push(ProbeSpec {
            id: format!("{}.weak_password", surface.product),
            product: surface.product.into(),
            vuln_class: VulnClass::WeakPassword,
            risk_level: RiskLevel::L1,
            cve_ids: vec![],
            requires_auth: false,
            depends_on: vec![],
            entry: json!({"login":login,"body":{"username":"{user}","password":"{pass}"}}),
            max_requests: 12,
        });
    }
    if let Some(path) = surface.idor {
        specs.push(ProbeSpec {
            id: format!("{}.idor", surface.product),
            product: surface.product.into(),
            vuln_class: VulnClass::Idor,
            risk_level: RiskLevel::L1,
            cve_ids: vec![],
            requires_auth: true,
            depends_on: vec![format!("{}.weak_password", surface.product)],
            entry: json!({"object":path,"predictable_ids":["1","2","3"]}),
            max_requests: 6,
        });
    }
    if let Some((path, param)) = surface.ssrf {
        specs.push(active(
            surface.product,
            VulnClass::Ssrf,
            RiskLevel::L2,
            "ssrf",
            path,
            param,
            3,
        ));
    }
    if let Some((path, param)) = surface.sqli {
        specs.push(active(
            surface.product,
            VulnClass::Sqli,
            RiskLevel::L2,
            "sqli",
            path,
            param,
            4,
        ));
    }
    if let Some((path, param)) = surface.rce {
        specs.push(active(
            surface.product,
            VulnClass::Rce,
            RiskLevel::L3,
            "rce",
            path,
            param,
            2,
        ));
    }
    for spec in migrated {
        if let Some(existing) = specs.iter_mut().find(|item| item.id == spec.id) {
            *existing = spec;
        } else {
            specs.push(spec);
        }
    }
    specs
}

fn active(
    product: &str,
    class: VulnClass,
    risk: RiskLevel,
    suffix: &str,
    path: &str,
    param: &str,
    max_requests: usize,
) -> ProbeSpec {
    let key = if class == VulnClass::Ssrf {
        "url_param"
    } else {
        "param"
    };
    ProbeSpec {
        id: format!("{product}.{suffix}"),
        product: product.into(),
        vuln_class: class,
        risk_level: risk,
        cve_ids: vec![],
        requires_auth: false,
        depends_on: vec![],
        entry: json!({"path":path,key:param,"payloads":["' OR '1'='1","'"]}),
        max_requests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_product_has_l0_l2_l3_specs() {
        for surface in SURFACES {
            let specs = specs_for(surface.product);
            assert!(
                specs
                    .iter()
                    .any(|spec| spec.vuln_class == VulnClass::UnauthRead)
            );
            assert!(specs.iter().any(|spec| spec.vuln_class == VulnClass::Ssrf));
            assert!(specs.iter().any(|spec| spec.vuln_class == VulnClass::Sqli));
            assert!(specs.iter().any(|spec| spec.vuln_class == VulnClass::Rce));
        }
    }
}
