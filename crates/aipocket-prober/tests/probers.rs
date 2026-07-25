use aipocket_core::{Credential, Settings};
use aipocket_prober::{ProbeContext, RiskLevel, products::default_probers};
use axum::{Router, routing::get};
#[tokio::test]
async fn every_registered_product_prober_executes_passive_paths() {
    let app = Router::new().fallback(get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let context = ProbeContext {
        target: format!("http://{address}"),
        product: "fixture".into(),
        max_risk: RiskLevel::L0,
        intrusive_checks: false,
        allowed_classes: vec!["*".into()],
        request_budget: 2,
    };
    for prober in default_probers() {
        assert!(
            !prober
                .probe(&reqwest::Client::new(), &context)
                .await
                .unwrap()
                .is_empty(),
            "{}",
            prober.product()
        );
    }
    task.abort();
}
#[test]
fn provider_registry_resolves_domain_prefix_and_unknown() {
    let registry = aipocket_prober::ProviderRegistry;
    assert_eq!(
        registry.resolve("https://api.openai.com", "x").spec.name,
        "openai"
    );
    assert_eq!(registry.resolve("", "AIza123").spec.name, "gemini");
    assert_eq!(
        registry.resolve("https://example.com", "x").spec.name,
        "unknown"
    );
    assert!(registry.specs().contains_key("anthropic"));
    assert_eq!(
        registry.resolve("", "xai-abcdefghijklmnop").spec.name,
        "xai"
    );
    assert_eq!(
        registry.resolve("", "ksk_abcdefghijklmnop").spec.name,
        "kiro"
    );
    assert_eq!(
        registry
            .resolve("", "crsr_abcdefghijklmnopqrstuvwxyz123456")
            .spec
            .name,
        "cursor"
    );
    assert_eq!(
        registry.resolve("", "pt-abcdefghijklmnop").spec.name,
        "qoder"
    );
    assert_eq!(
        registry
            .resolve("https://bedrock-runtime.us-east-1.amazonaws.com", "token")
            .spec
            .name,
        "aws_bedrock"
    );
    assert!(registry.specs()["xai"].models.contains(&"grok-4.7"));
}
#[tokio::test]
async fn coding_agent_and_bedrock_credentials_use_official_read_only_routes() {
    use axum::{Json, extract::Request};
    use serde_json::{Value, json};
    async fn fixture(request: Request) -> Json<Value> {
        Json(match request.uri().path() {
            "/api/v1/cloud/models" => json!({"data":[{"id":"cantus"}]}),
            "/v1/me" => json!({"apiKeyName":"scanner","userEmail":"dev@example.test"}),
            "/foundation-models" => {
                json!({"modelSummaries":[{"modelId":"amazon.nova-lite-v1:0"}]})
            }
            _ => json!({}),
        })
    }
    let app = Router::new().fallback(get(fixture));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let port = address.port();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let validator = aipocket_prober::Validator::new(
        reqwest::Client::builder()
            .resolve("api.qoder.com", address)
            .resolve("api.cursor.com", address)
            .resolve("bedrock.us-east-1.amazonaws.com", address)
            .build()
            .unwrap(),
    );
    for (key, provider, models) in [
        ("pt-abcdefghijklmnop", "qoder", vec!["cantus"]),
        ("crsr_abcdefghijklmnopqrstuvwxyz123456", "cursor", vec![]),
        (
            "ABSKabcdefghijklmnopqrstuvwxyz",
            "aws_bedrock",
            vec!["amazon.nova-lite-v1:0"],
        ),
    ] {
        let expected = aipocket_prober::ProviderRegistry.resolve("", key).spec.name;
        let result = validator
            .validate(Credential {
                apikey: key.into(),
                apiurl: match provider {
                    "qoder" => format!("http://api.qoder.com:{port}"),
                    "cursor" => format!("http://api.cursor.com:{port}"),
                    _ => format!("http://bedrock.us-east-1.amazonaws.com:{port}"),
                },
                product: provider.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(result.valid, "{provider}");
        assert_eq!(expected, provider);
        assert_eq!(result.provider_info.models_available, models, "{provider}");
    }
    task.abort();
}

#[test]
fn defaults_construct_credential() {
    let credential = Credential::default();
    assert!(credential.apikey.is_empty());
    assert_eq!(Settings::default().probe_max_risk, 1);
}

#[tokio::test]
async fn engine_executes_safe_read_proofs_and_enforces_gates() {
    use aipocket_prober::{
        EngineContext, NodeStatus, ProbeSpec, RiskLevel, RiskPolicy, VulnClass, execute_plan,
    };
    use axum::{
        Json, Router,
        http::StatusCode,
        routing::{get, post},
    };
    use serde_json::{Value, json};
    use std::collections::HashSet;
    async fn public() -> &'static str {
        "OPENAI_API_KEY=sk-abcdefghijklmnop"
    }
    async fn login(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        if body["username"] == "admin" && body["password"] == "admin" {
            (StatusCode::OK, Json(json!({"token":"fixture"})))
        } else {
            (StatusCode::UNAUTHORIZED, Json(json!({})))
        }
    }
    async fn secret() -> &'static str {
        "sk-qrstuvwxyzabcdefgh"
    }
    async fn ssrf(Json(_): Json<Value>) -> &'static str {
        "localhost OPENAI_API_KEY=sk-ssrfabcdefghijkl"
    }
    async fn sqli() -> (StatusCode, &'static str) {
        (StatusCode::INTERNAL_SERVER_ERROR, "SQL syntax error")
    }
    async fn rce(Json(body): Json<Value>) -> String {
        body["command"].as_str().unwrap_or_default().to_owned()
    }
    let app = Router::new()
        .route("/public", get(public))
        .route("/login", post(login))
        .route("/secret", get(secret))
        .route("/fetch", post(ssrf))
        .route("/item", get(sqli))
        .route("/exec", post(rce));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mk = |id: &str, class, risk, entry| ProbeSpec {
        id: id.into(),
        product: "fixture".into(),
        vuln_class: class,
        risk_level: risk,
        cve_ids: vec![],
        requires_auth: false,
        depends_on: vec![],
        entry,
        max_requests: 6,
    };
    let specs = vec![
        mk(
            "read",
            VulnClass::UnauthRead,
            RiskLevel::L0,
            json!({"paths":["/public"]}),
        ),
        mk(
            "weak",
            VulnClass::WeakPassword,
            RiskLevel::L1,
            json!({"login":"/login","body":{"username":"{user}","password":"admin"},"post_auth_paths":["/secret"]}),
        ),
        mk(
            "ssrf",
            VulnClass::Ssrf,
            RiskLevel::L2,
            json!({"path":"/fetch","target_urls":["http://localhost"]}),
        ),
        mk(
            "sqli",
            VulnClass::Sqli,
            RiskLevel::L2,
            json!({"path":"/item","payloads":["' OR '1'='1"]}),
        ),
        mk(
            "rce",
            VulnClass::Rce,
            RiskLevel::L3,
            json!({"path":"/exec"}),
        ),
    ];
    let policy = RiskPolicy {
        enabled_classes: HashSet::from([
            VulnClass::UnauthRead,
            VulnClass::WeakPassword,
            VulnClass::Idor,
            VulnClass::Ssrf,
            VulnClass::Sqli,
            VulnClass::Rce,
        ]),
        max_risk: RiskLevel::L3,
        intrusive_checks: true,
        authorized_scope: vec![base.clone()],
        ssrf_enabled: true,
        sqli_enabled: true,
        rce_enabled: true,
    };
    let result = execute_plan(
        &reqwest::Client::new(),
        EngineContext {
            target: base.clone(),
            product: "fixture".into(),
            ..Default::default()
        },
        &specs,
        &policy,
        20,
    )
    .await;
    assert!(result.credentials.len() >= 2, "{:#?}", result.outcomes);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.vuln_class == "unauth_read")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.vuln_class == "weak_password")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.vuln_class == "ssrf")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.vuln_class == "sqli")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.vuln_class == "rce")
    );
    assert!(
        result
            .outcomes
            .iter()
            .all(|outcome| outcome.status == NodeStatus::Executed)
    );

    let idor = mk(
        "idor",
        VulnClass::Idor,
        RiskLevel::L1,
        json!({"object":"/secret","predictable_ids":["1"]}),
    );
    let idor_result = execute_plan(
        &reqwest::Client::new(),
        EngineContext {
            target: base.clone(),
            product: "fixture".into(),
            auth_headers: std::collections::HashMap::from([(
                "authorization".into(),
                "Bearer fixture".into(),
            )]),
            ..Default::default()
        },
        std::slice::from_ref(&idor),
        &policy,
        2,
    )
    .await;
    assert_eq!(idor_result.outcomes[0].status, NodeStatus::Executed);
    assert_eq!(idor_result.findings[0].vuln_class, "idor");

    let unauth_only = RiskPolicy {
        enabled_classes: HashSet::from([VulnClass::UnauthRead]),
        max_risk: RiskLevel::L0,
        intrusive_checks: false,
        authorized_scope: vec![],
        ssrf_enabled: false,
        sqli_enabled: false,
        rce_enabled: false,
    };
    let gated = execute_plan(
        &reqwest::Client::new(),
        EngineContext {
            target: base.clone(),
            product: "fixture".into(),
            ..Default::default()
        },
        &[
            ProbeSpec {
                id: "class-disabled".into(),
                vuln_class: VulnClass::Idor,
                ..idor.clone()
            },
            ProbeSpec {
                id: "risk-gated".into(),
                vuln_class: VulnClass::UnauthRead,
                risk_level: RiskLevel::L1,
                ..idor.clone()
            },
        ],
        &unauth_only,
        2,
    )
    .await;
    assert!(
        gated
            .outcomes
            .iter()
            .any(|row| row.status == NodeStatus::SkippedClass)
    );
    assert!(
        gated
            .outcomes
            .iter()
            .any(|row| row.status == NodeStatus::SkippedGate)
    );

    let no_auth = ProbeSpec {
        id: "no-auth".into(),
        requires_auth: true,
        vuln_class: VulnClass::UnauthRead,
        risk_level: RiskLevel::L0,
        entry: json!({"paths":["/public"]}),
        ..idor.clone()
    };
    let exhausted = ProbeSpec {
        id: "exhausted".into(),
        vuln_class: VulnClass::UnauthRead,
        risk_level: RiskLevel::L0,
        requires_auth: false,
        entry: json!({"paths":["/public"]}),
        ..idor.clone()
    };
    let skipped = execute_plan(
        &reqwest::Client::new(),
        EngineContext {
            target: base.clone(),
            product: "fixture".into(),
            ..Default::default()
        },
        &[no_auth, exhausted],
        &unauth_only,
        0,
    )
    .await;
    assert!(
        skipped
            .outcomes
            .iter()
            .any(|row| row.status == NodeStatus::SkippedNoAuth)
    );
    assert!(
        skipped
            .outcomes
            .iter()
            .any(|row| row.status == NodeStatus::SkippedBudget)
    );

    let dependency = ProbeSpec {
        id: "dependency".into(),
        vuln_class: VulnClass::UnauthRead,
        risk_level: RiskLevel::L0,
        depends_on: vec!["missing".into()],
        entry: json!({"paths":["/public"]}),
        ..idor
    };
    let unresolved = execute_plan(
        &reqwest::Client::new(),
        EngineContext {
            target: base,
            product: "fixture".into(),
            ..Default::default()
        },
        &[dependency],
        &unauth_only,
        1,
    )
    .await;
    assert_eq!(unresolved.outcomes[0].status, NodeStatus::SkippedDependency);
    task.abort();
}
