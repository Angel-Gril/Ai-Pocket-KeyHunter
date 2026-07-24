use aipocket_core::Credential;
use aipocket_prober::ProviderRegistry;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BalanceResult {
    pub gateway: String,
    pub balance_usd: String,
    pub tier: String,
    pub detail: Value,
    pub matched: bool,
    pub provider: String,
    pub source: String,
    pub evidence_kind: String,
    pub balance_native: String,
    pub currency: String,
    pub plan: String,
    pub account_type: String,
    pub quota: Value,
    pub usage: Value,
    pub entitlements: Value,
    pub identity: Value,
    pub alive: Option<bool>,
}

#[derive(Clone)]
pub struct BalanceService {
    http: reqwest::Client,
    registry: std::sync::Arc<ProviderRegistry>,
    official_base_override: Option<String>,
}

impl BalanceService {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            registry: std::sync::Arc::new(ProviderRegistry),
            official_base_override: None,
        }
    }

    #[cfg(test)]
    fn with_official_base(mut self, base: impl Into<String>) -> Self {
        self.official_base_override = Some(base.into());
        self
    }
    fn endpoint(&self, official: &str) -> String {
        self.official_base_override
            .as_ref()
            .map(|base| {
                let path = url::Url::parse(official)
                    .map(|url| url.path().to_owned())
                    .unwrap_or_default();
                format!("{}{path}", base.trim_end_matches('/'))
            })
            .unwrap_or_else(|| official.to_owned())
    }

    pub async fn query(&self, credential: &Credential) -> Result<BalanceResult> {
        self.query_with_context(credential, None).await
    }

    pub async fn query_for_result(
        &self,
        result: &aipocket_core::ValidationResult,
    ) -> Result<BalanceResult> {
        self.query_with_context(&result.credential, Some(result))
            .await
    }

    async fn query_with_context(
        &self,
        credential: &Credential,
        context: Option<&aipocket_core::ValidationResult>,
    ) -> Result<BalanceResult> {
        if !header_safe(&credential.apikey) {
            return Ok(Default::default());
        }
        let provider_hint = if credential.host.is_empty() {
            &credential.apiurl
        } else {
            &credential.host
        };
        let resolution = self.registry.resolve(provider_hint, &credential.apikey);
        let contextual_provider = context
            .map(|result| result.provider_info.validation_provider.as_str())
            .filter(|provider| !matches!(*provider, "" | "unknown" | "ambiguous"));
        let provider = contextual_provider.unwrap_or(resolution.spec.name);
        let canonical = aipocket_core::endpoint::canonicalize_endpoint(
            if credential.apiurl.is_empty() {
                resolution.spec.official_api_url
            } else {
                &credential.apiurl
            },
            provider,
        )
        .unwrap_or_else(|_| aipocket_core::endpoint::CanonicalEndpoint {
            api_base: String::new(),
            origin: String::new(),
        });
        let base = canonical.api_base.as_str();
        match provider {
            "google" | "gemini" => Ok(Default::default()),
            "glm" => {
                if let Some(result) = context {
                    let passive = glm_passive(result);
                    if passive.matched {
                        return Ok(passive);
                    }
                }
                self.models_liveness(credential, provider, "").await
            }
            "longcat" => Ok(context.map(longcat_liveness).unwrap_or_default()),
            "deepseek" => self.deepseek(credential, base).await,
            "kimi" => self.kimi(credential, base).await,
            "minimax" => self.minimax(credential, base).await,
            "cohere" => self.cohere(credential).await,
            "together" => self.together(credential).await,
            "replicate" => self.replicate(credential).await,
            "fireworks" => self.fireworks(credential).await,
            "openrouter" => self.openrouter(credential).await,
            "anthropic" => self.anthropic(credential).await,
            "openai" => self.openai(credential).await,
            "azure_openai" | "vertex" => Ok(context
                .map(|result| validated_liveness(result, provider))
                .unwrap_or_default()),
            "unknown" | "gateway" | "ambiguous" => {
                self.gateway(credential, &canonical.origin).await
            }
            _ => self.models_liveness(credential, provider, "").await,
        }
    }

    async fn deepseek(&self, credential: &Credential, base: &str) -> Result<BalanceResult> {
        let (status, payload, _) = self
            .get_json(format!("{}/user/balance", strip_v1(base)), credential, &[])
            .await?;
        if status != 200 {
            return Ok(Default::default());
        }
        let Some(infos) = payload.get("balance_infos").and_then(Value::as_array) else {
            return Ok(Default::default());
        };
        let mut totals = serde_json::Map::new();
        for item in infos {
            let Some(item) = item.as_object() else {
                return Ok(Default::default());
            };
            let Some(amount) = item.get("total_balance").and_then(number) else {
                return Ok(Default::default());
            };
            let currency = item
                .get("currency")
                .and_then(Value::as_str)
                .unwrap_or("CNY")
                .to_ascii_uppercase();
            let total = totals.get(&currency).and_then(Value::as_f64).unwrap_or(0.0) + amount;
            totals.insert(currency, json!(total));
        }
        if totals.is_empty() {
            totals.insert("CNY".into(), json!(0.0));
        }
        let cny = totals.get("CNY").and_then(Value::as_f64);
        let usd = totals.get("USD").and_then(Value::as_f64);
        let mut result = probe_result(
            "deepseek",
            "deepseek:user_balance",
            "cash_balance",
            usd.map(number_string).unwrap_or_default(),
            json!({"balance_infos":infos,"totals":totals}),
        );
        result.balance_native = cny.map(number_string).unwrap_or_default();
        result.currency = if cny.is_some() { "CNY" } else { "USD" }.into();
        result.alive = Some(true);
        Ok(result)
    }

    async fn kimi(&self, credential: &Credential, base: &str) -> Result<BalanceResult> {
        let origin = origin(base);
        let domestic = origin.contains("moonshot.cn") || base.contains("/kimi");
        let international = origin.contains("moonshot.ai");
        if !domestic && !international {
            return self.models_liveness(credential, "kimi", "").await;
        }
        let endpoint = if base.contains("/kimi") {
            format!("{}/v1/users/me/balance", base.trim_end_matches('/'))
        } else {
            format!("{origin}/v1/users/me/balance")
        };
        let (status, payload, _) = self.get_json(endpoint, credential, &[]).await?;
        let Some(data) = payload.get("data").and_then(Value::as_object) else {
            return Ok(Default::default());
        };
        if status != 200
            || payload.get("status") == Some(&Value::Bool(false))
            || payload
                .get("code")
                .is_some_and(|value| value.as_i64() != Some(0) && value.as_str() != Some("0"))
        {
            return Ok(Default::default());
        }
        let Some(available) = data.get("available_balance").and_then(number) else {
            return Ok(Default::default());
        };
        let mut result = probe_result(
            "kimi",
            "kimi:users_me_balance",
            "cash_balance",
            if domestic {
                String::new()
            } else {
                number_string(available)
            },
            json!({
                "data":data,
                "host":if domestic{"api.moonshot.cn"}else{"api.moonshot.ai"},
                "voucher_balance":data.get("voucher_balance").and_then(number),
                "cash_balance":data.get("cash_balance").and_then(number)
            }),
        );
        if domestic {
            result.balance_native = number_string(available);
            result.currency = "CNY".into();
        } else {
            result.currency = "USD".into();
        }
        result.alive = Some(true);
        Ok(result)
    }

    async fn minimax(&self, credential: &Credential, base: &str) -> Result<BalanceResult> {
        let (status, payload, _) = self
            .get_json(
                format!("{}/token_plan/remains", strip_v1(base)),
                credential,
                &[],
            )
            .await?;
        let remains = payload.get("model_remains").and_then(Value::as_array);
        let ok = payload
            .pointer("/base_resp/status_code")
            .is_some_and(|value| value.as_i64() == Some(0) || value.as_str() == Some("0"));
        if status != 200 || !ok || remains.is_none() {
            return Ok(Default::default());
        }
        let mut result = probe_result(
            "minimax",
            "minimax:token_plan_remains",
            "quota",
            "",
            json!({"base_resp":payload.get("base_resp")}),
        );
        result.quota = json!({"model_remains":remains});
        result.alive = Some(true);
        Ok(result)
    }

    async fn cohere(&self, credential: &Credential) -> Result<BalanceResult> {
        let response = self
            .http
            .post(self.endpoint("https://api.cohere.com/v1/check-api-key"))
            .bearer_auth(&credential.apikey)
            .send()
            .await?;
        let status = response.status().as_u16();
        let payload: Value = response.json().await.unwrap_or(Value::Null);
        if status != 200 || payload.get("valid").and_then(Value::as_bool) != Some(true) {
            return Ok(Default::default());
        }
        let identity = string_fields(&payload, &["organization_id", "owner_id"]);
        let evidence_kind = if identity.as_object().is_some_and(|value| !value.is_empty()) {
            "identity"
        } else {
            "liveness"
        };
        let mut result = probe_result(
            "cohere",
            "cohere:check_api_key",
            evidence_kind,
            "",
            json!({"valid":true}),
        );
        result.identity = identity;
        result.alive = Some(true);
        Ok(result)
    }

    async fn together(&self, credential: &Credential) -> Result<BalanceResult> {
        let (status, payload, headers) = self
            .get_json(
                self.endpoint("https://api.together.ai/v1/whoami"),
                credential,
                &[],
            )
            .await?;
        if status != 200 || !payload.is_object() {
            return Ok(Default::default());
        }
        let identity = string_fields(
            &payload,
            &["id", "name", "email", "project_id", "organization_id"],
        );
        if identity.as_object().is_none_or(|value| value.is_empty()) {
            return Ok(Default::default());
        }
        let rate_limits = rate_headers(&headers);
        let has_rate_limits = rate_limits
            .as_object()
            .is_some_and(|value| !value.is_empty());
        let mut result = probe_result(
            "together",
            "together:whoami",
            if has_rate_limits { "quota" } else { "identity" },
            "",
            json!({}),
        );
        result.identity = identity;
        result.quota = if has_rate_limits {
            json!({"rate_limits":rate_limits})
        } else {
            json!({})
        };
        result.alive = Some(true);
        Ok(result)
    }

    async fn replicate(&self, credential: &Credential) -> Result<BalanceResult> {
        let (status, payload, _) = self
            .get_json(
                self.endpoint("https://api.replicate.com/v1/account"),
                credential,
                &[],
            )
            .await?;
        if status != 200 || !payload.is_object() {
            return Ok(Default::default());
        }
        let identity = string_fields(&payload, &["type", "username", "name", "github_url"]);
        if identity.as_object().is_none_or(|value| value.is_empty()) {
            return Ok(Default::default());
        }
        let mut result = probe_result("replicate", "replicate:account", "identity", "", json!({}));
        result.account_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into();
        result.identity = identity;
        result.alive = Some(true);
        Ok(result)
    }

    async fn fireworks(&self, credential: &Credential) -> Result<BalanceResult> {
        let (status, payload, _) = self
            .get_json(
                self.endpoint("https://api.fireworks.ai/v1/accounts"),
                credential,
                &[],
            )
            .await?;
        let Some(accounts) = payload.get("accounts").and_then(Value::as_array) else {
            return Ok(Default::default());
        };
        if status != 200 {
            return Ok(Default::default());
        }
        let official = self
            .official_base_override
            .as_deref()
            .unwrap_or("https://api.fireworks.ai")
            .trim_end_matches('/');
        let mut summaries = Vec::new();
        let mut matched_quota = json!({});
        let mut account_type = String::new();
        let mut suspend_state = String::new();
        let mut tier = String::new();
        for item in accounts {
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            let name = name.trim_matches('/');
            if !name.starts_with("accounts/") || name.matches('/').count() != 1 {
                continue;
            }
            let (account_status, account, _) = self
                .get_json(format!("{official}/v1/{name}"), credential, &[])
                .await?;
            if account_status == 200 && account.is_object() {
                account_type = account
                    .get("accountType")
                    .and_then(Value::as_str)
                    .unwrap_or(&account_type)
                    .into();
                suspend_state = account
                    .get("suspendState")
                    .and_then(Value::as_str)
                    .unwrap_or(&suspend_state)
                    .into();
            }
            let (quota_status, quotas, _) = self
                .get_json(format!("{official}/v1/{name}/quotas"), credential, &[])
                .await?;
            if quota_status != 200 {
                continue;
            }
            let Some(rows) = quotas.get("quotas").and_then(Value::as_array) else {
                continue;
            };
            for quota in rows
                .iter()
                .filter(|row| row.get("name").and_then(Value::as_str) == Some("monthly-spend-usd"))
            {
                let Some(maximum) = quota.get("maxValue").and_then(strict_number) else {
                    continue;
                };
                tier = fireworks_tier(maximum, &account_type).into();
                matched_quota = quota.clone();
                summaries.push(json!({"account":name,"quota":quota}));
            }
        }
        let has_quota = matched_quota
            .as_object()
            .is_some_and(|value| !value.is_empty());
        if !has_quota && account_type.is_empty() {
            return Ok(Default::default());
        }
        let mut result = probe_result(
            "fireworks",
            "fireworks:accounts_quotas",
            if has_quota { "quota" } else { "identity" },
            "N/A",
            json!({"accounts":summaries}),
        );
        result.tier = tier;
        result.account_type = account_type;
        result.quota = matched_quota;
        if !suspend_state.is_empty() {
            result.identity = json!({"suspend_state":suspend_state});
        }
        result.alive = Some(true);
        Ok(result)
    }

    async fn openrouter(&self, credential: &Credential) -> Result<BalanceResult> {
        let (status, payload, _) = self
            .get_json(
                self.endpoint("https://openrouter.ai/api/v1/auth/key"),
                credential,
                &[],
            )
            .await?;
        let Some(data) = payload.get("data").and_then(Value::as_object) else {
            return Ok(Default::default());
        };
        if status != 200 {
            return Ok(Default::default());
        }
        let usage = data.get("usage").and_then(number).unwrap_or(0.0);
        let limit = data.get("limit").and_then(number);
        let limit_remaining = data.get("limit_remaining").and_then(number);
        let free = data.get("is_free_tier").and_then(Value::as_bool) == Some(true);
        let mut source = "openrouter:key";
        let mut balance = limit_remaining.or_else(|| limit.map(|value| (value - usage).max(0.0)));
        let mut detail = json!({"key":data});
        let mut quota = json!({"limit":limit,"limit_remaining":limit_remaining});
        let mut usage_evidence = json!({"usage":usage});
        if balance.is_none() {
            let (credits_status, credits_payload, _) = self
                .get_json(
                    self.endpoint("https://openrouter.ai/api/v1/credits"),
                    credential,
                    &[],
                )
                .await?;
            if credits_status == 200
                && let Some(credits) = credits_payload.get("data").and_then(Value::as_object)
                && (credits.contains_key("total_credits") || credits.contains_key("total_usage"))
            {
                let total_credits = credits.get("total_credits").and_then(number).unwrap_or(0.0);
                let total_usage = credits.get("total_usage").and_then(number).unwrap_or(0.0);
                balance = Some((total_credits - total_usage).max(0.0));
                source = "openrouter:credits";
                quota = json!({"total_credits":total_credits});
                usage_evidence = json!({"total_usage":total_usage});
                detail = json!({"key":data,"credits":credits});
            } else if free {
                balance = Some(0.0);
                source = "openrouter:free_tier";
            } else {
                source = "openrouter:key_no_limit";
            }
        }
        let mut result = probe_result(
            "openrouter",
            source,
            "quota",
            balance.map(number_string).unwrap_or_default(),
            detail,
        );
        result.quota = quota;
        result.usage = usage_evidence;
        result.alive = Some(true);
        Ok(result)
    }
    async fn openai(&self, credential: &Credential) -> Result<BalanceResult> {
        let key = credential.apikey.as_str();
        let kind = if key.starts_with("sk-proj-") {
            "project"
        } else if key.starts_with("sk-svcacct-") {
            "service_account"
        } else if key.starts_with("sk-admin-") {
            "admin"
        } else if key.starts_with("sess-") {
            "session"
        } else {
            "ordinary"
        };
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))?,
        );
        for path in [
            "/dashboard/billing/credit_grants",
            "/v1/dashboard/billing/credit_grants",
        ] {
            let (status, payload, _) = self
                .get_json_with_headers(
                    format!(
                        "{}{}",
                        self.endpoint("https://api.openai.com/"),
                        path.trim_start_matches('/')
                    ),
                    headers.clone(),
                    &[],
                )
                .await?;
            if status == 200
                && let Some(remaining) = openai_credit_remaining(&payload)
            {
                let mut result = probe_result(
                    "openai",
                    "openai:credit_grants",
                    "cash_balance",
                    number_string(remaining),
                    payload,
                );
                result.account_type = kind.into();
                result.alive = Some(true);
                return Ok(result);
            }
        }
        let mut subscription = None;
        for path in [
            "/dashboard/billing/subscription",
            "/v1/dashboard/billing/subscription",
        ] {
            let (status, payload, _) = self
                .get_json_with_headers(
                    format!(
                        "{}{}",
                        self.endpoint("https://api.openai.com/"),
                        path.trim_start_matches('/')
                    ),
                    headers.clone(),
                    &[],
                )
                .await?;
            if status == 200
                && (payload.get("object").and_then(Value::as_str) == Some("billing_subscription")
                    || payload.get("hard_limit_usd").and_then(number).is_some()
                    || payload
                        .get("system_hard_limit_usd")
                        .and_then(number)
                        .is_some())
            {
                subscription = Some(payload);
                break;
            }
        }
        if let Some(subscription) = subscription {
            let hard_limit = subscription
                .get("hard_limit_usd")
                .or_else(|| subscription.get("system_hard_limit_usd"))
                .and_then(number)
                .unwrap_or(0.0);
            let mut usage_payload = Value::Null;
            let mut used_usd = 0.0;
            for path in [
                "/dashboard/billing/usage",
                "/v1/dashboard/billing/usage",
                "/v1/usage",
            ] {
                let (status, payload, _) = self
                    .get_json_with_headers(
                        format!(
                            "{}{}",
                            self.endpoint("https://api.openai.com/"),
                            path.trim_start_matches('/')
                        ),
                        headers.clone(),
                        &[],
                    )
                    .await?;
                if status != 200 || !payload.is_object() {
                    continue;
                }
                used_usd = payload
                    .get("total_usage")
                    .and_then(number)
                    .map(|value| value / 100.0)
                    .or_else(|| payload.get("total_usage_usd").and_then(number))
                    .unwrap_or(0.0);
                usage_payload = payload;
                break;
            }
            let balance = if hard_limit > 0.0 {
                number_string((hard_limit - used_usd).max(0.0))
            } else {
                "N/A".into()
            };
            let mut result = probe_result(
                "openai",
                if hard_limit > 0.0 {
                    "openai:subscription_budget"
                } else {
                    "openai:subscription"
                },
                "quota",
                balance,
                json!({"subscription":subscription,"usage":usage_payload}),
            );
            result.account_type = kind.into();
            result.plan = subscription
                .get("plan")
                .and_then(Value::as_object)
                .and_then(|plan| plan.get("id").or_else(|| plan.get("title")))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into();
            result.tier = openai_budget_tier(hard_limit).into();
            result.quota = json!({"hard_limit_usd":hard_limit});
            result.usage = json!({"used_usd":used_usd});
            result.alive = Some(true);
            return Ok(result);
        }
        let (status, payload, response_headers) = self
            .get_json_with_headers(
                format!("{}v1/models", self.endpoint("https://api.openai.com/")),
                headers,
                &[],
            )
            .await?;
        if !matches!(status, 200 | 401 | 403 | 429) {
            return Ok(Default::default());
        }
        let source = match status {
            200 => "openai:api_key_no_balance",
            429 => "openai:rate_limited",
            _ => "openai:unauthorized",
        };
        let rate_limits = rate_headers(&response_headers);
        let mut result = probe_result(
            "openai",
            source,
            "liveness",
            "N/A",
            json!({"status_code":status,"models":model_ids(&payload),"rate_limits":rate_limits}),
        );
        result.account_type = kind.into();
        result.tier = if status == 200 {
            openai_tier(&response_headers)
        } else if status == 429 {
            "rate_limited".into()
        } else {
            String::new()
        };
        result.alive = Some(matches!(status, 200 | 429));
        Ok(result)
    }

    async fn anthropic(&self, credential: &Credential) -> Result<BalanceResult> {
        let kind = if credential.apikey.starts_with("sk-ant-admin") {
            "admin"
        } else if credential.apikey.starts_with("sk-ant-oat")
            || credential.apikey.starts_with("sk-ant-sid")
        {
            "oauth"
        } else {
            "api"
        };
        if matches!(kind, "admin" | "oauth") {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "anthropic-version",
                reqwest::header::HeaderValue::from_static("2023-06-01"),
            );
            let auth = if kind == "oauth" {
                format!("Bearer {}", credential.apikey)
            } else {
                credential.apikey.clone()
            };
            let auth_header = if kind == "oauth" {
                "authorization"
            } else {
                "x-api-key"
            };
            headers.insert(
                reqwest::header::HeaderName::from_static(auth_header),
                reqwest::header::HeaderValue::from_str(&auth)?,
            );
            let (status, organization, _) = self
                .get_json_with_headers(
                    self.endpoint("https://api.anthropic.com/v1/organizations/me"),
                    headers.clone(),
                    &[],
                )
                .await?;
            if status != 200 {
                let source = if matches!(status, 401 | 403) {
                    "anthropic:unauthorized"
                } else if status == 429 {
                    "anthropic:rate_limited"
                } else {
                    "anthropic:admin_org_error"
                };
                let mut result = probe_result(
                    "anthropic",
                    source,
                    "liveness",
                    "N/A",
                    json!({"status_code":status}),
                );
                result.account_type = kind.into();
                result.alive = Some(status == 429);
                return Ok(result);
            }
            let (cost_status, cost_report, _) = self
                .get_json_with_headers(
                    self.endpoint("https://api.anthropic.com/v1/organizations/cost_report"),
                    headers.clone(),
                    &[("bucket_width", "1d")],
                )
                .await?;
            let spend = (cost_status == 200)
                .then(|| anthropic_cost_usd(&cost_report))
                .flatten();
            let (limits_status, rate_limits, _) = self
                .get_json_with_headers(
                    self.endpoint("https://api.anthropic.com/v1/organizations/rate_limits"),
                    headers,
                    &[],
                )
                .await?;
            let tier = if limits_status == 200 {
                anthropic_rate_limits_tier(&rate_limits)
            } else {
                String::new()
            };
            let identity = string_fields(&organization, &["id", "organization_id", "name"]);
            let mut result = probe_result(
                "anthropic",
                if spend.is_some() {
                    "anthropic:admin_cost_report"
                } else {
                    "anthropic:admin_org_alive"
                },
                if spend.is_some() { "quota" } else { "identity" },
                "N/A",
                json!({"organization":organization,"cost_report":cost_report,"rate_limits":rate_limits}),
            );
            result.account_type = kind.into();
            result.identity = identity;
            result.tier = if tier.is_empty() {
                "org:admin".into()
            } else {
                tier
            };
            if let Some(spend) = spend {
                result.usage = json!({"spend_usd_30d":spend});
            }
            result.alive = Some(true);
            return Ok(result);
        }
        let mut request = self
            .http
            .get(self.endpoint("https://api.anthropic.com/v1/models"))
            .header("anthropic-version", "2023-06-01");
        request = request.header("x-api-key", &credential.apikey);
        let response = request.send().await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let payload: Value = response.json().await.unwrap_or(Value::Null);
        if !matches!(status, 200 | 401 | 403 | 429) {
            return Ok(Default::default());
        }
        let source = match status {
            200 => "anthropic:api_key_no_balance",
            429 => "anthropic:rate_limited",
            _ => "anthropic:unauthorized",
        };
        let mut result = probe_result(
            "anthropic",
            source,
            "liveness",
            "N/A",
            json!({"status_code":status,"models":model_ids(&payload),"rate_limits":rate_headers(&headers)}),
        );
        result.account_type = "api".into();
        result.tier = if status == 200 {
            anthropic_tier(&headers, &payload)
        } else if status == 429 {
            "rate_limited".into()
        } else {
            String::new()
        };
        result.alive = Some(matches!(status, 200 | 429));
        Ok(result)
    }

    async fn models_liveness(
        &self,
        credential: &Credential,
        provider: &str,
        balance: &str,
    ) -> Result<BalanceResult> {
        let response = self.models_response(credential.clone()).await?;
        let Some((status, payload, headers)) = response else {
            return Ok(Default::default());
        };
        if status == 429 {
            let mut result = probe_result(
                provider,
                &format!("{provider}:models"),
                "liveness",
                balance,
                json!({"status_code":429,"rate_limits":rate_headers(&headers)}),
            );
            result.alive = Some(true);
            return Ok(result);
        }
        let models = model_ids(&payload);
        if status != 200 || models.is_empty() {
            return Ok(Default::default());
        }
        let rate_limits = rate_headers(&headers);
        let has_rate_limits = rate_limits
            .as_object()
            .is_some_and(|value| !value.is_empty());
        let entitlement = provider == "ksyun";
        let mut result = probe_result(
            provider,
            &format!("{provider}:models"),
            if entitlement {
                "entitlement"
            } else if has_rate_limits {
                "quota"
            } else {
                "liveness"
            },
            balance,
            json!({"models":models.iter().take(100).collect::<Vec<_>>() }),
        );
        if has_rate_limits {
            result.quota = json!({"rate_limits":rate_limits});
        }
        if entitlement {
            result.entitlements = json!({"models":models});
        }
        result.alive = Some(true);
        Ok(result)
    }
    async fn gateway(&self, credential: &Credential, base: &str) -> Result<BalanceResult> {
        let endpoint = origin(base);
        if endpoint.is_empty() {
            return Ok(Default::default());
        }
        let (status_code, status, _) = self
            .get_json(format!("{endpoint}/api/status"), credential, &[])
            .await?;
        let (self_code, user, _) = self
            .get_json(format!("{endpoint}/api/user/self"), credential, &[])
            .await?;
        let (billing_code, subscription, _) = self
            .get_json(
                format!("{endpoint}/dashboard/billing/subscription"),
                credential,
                &[],
            )
            .await?;
        let status_data = status.get("data").and_then(Value::as_object);
        let user_data = user.get("data").and_then(Value::as_object);
        let status_signal = status_code == 200
            && status.get("success").and_then(Value::as_bool) == Some(true)
            && status_data.is_some_and(|data| {
                [
                    "quota_per_unit",
                    "stripe_unit_price",
                    "self_use_mode_enabled",
                    "system_name",
                    "version",
                ]
                .iter()
                .filter(|key| data.contains_key(**key))
                .count()
                    >= 3
            });
        let self_signal = self_code == 200
            && user.get("success").and_then(Value::as_bool) == Some(true)
            && user_data.is_some_and(|data| {
                data.get("quota").and_then(strict_number).is_some()
                    && data.get("used_quota").and_then(strict_number).is_some()
            });
        let billing_signal = billing_code == 200
            && subscription.get("object").and_then(Value::as_str) == Some("billing_subscription")
            && subscription
                .get("hard_limit_usd")
                .and_then(strict_number)
                .is_some();
        let oneapi_signal = status_code == 200
            && status.get("success").and_then(Value::as_bool) == Some(true)
            && status_data.is_some_and(|data| {
                data.get("system_name").and_then(Value::as_str).is_some()
                    && data.get("version").and_then(Value::as_str).is_some()
            })
            && !status_signal;
        if status_signal && (self_signal || billing_signal) {
            let mut quota = serde_json::Map::new();
            let mut usage = json!({});
            if self_signal && let Some(data) = user_data {
                quota.insert("quota".into(), data["quota"].clone());
                quota.insert("used_quota".into(), data["used_quota"].clone());
            }
            if billing_signal {
                quota.insert(
                    "hard_limit_usd".into(),
                    subscription["hard_limit_usd"].clone(),
                );
                let (usage_code, usage_payload, _) = self
                    .get_json(
                        format!("{endpoint}/dashboard/billing/usage"),
                        credential,
                        &[("start_date", "2024-01-01"), ("end_date", "2099-12-31")],
                    )
                    .await?;
                if usage_code == 200
                    && usage_payload.get("object").and_then(Value::as_str) == Some("list")
                    && usage_payload
                        .get("total_usage")
                        .and_then(strict_number)
                        .is_some()
                {
                    usage = json!({"total_usage":usage_payload["total_usage"],"unit":"cents"});
                }
            }
            let mut result = probe_result(
                "newapi",
                "newapi:fingerprint",
                "quota",
                "",
                json!({"signals":{"status":status_signal,"self":self_signal,"billing":billing_signal}}),
            );
            result.quota = Value::Object(quota);
            result.usage = usage;
            result.alive = Some(true);
            return Ok(result);
        }
        if oneapi_signal && self_signal {
            let mut result = probe_result(
                "oneapi",
                "oneapi:fingerprint",
                "quota",
                "",
                json!({"signals":{"status":true,"self":true}}),
            );
            result.quota =
                json!({"quota":user["data"]["quota"],"used_quota":user["data"]["used_quota"]});
            result.alive = Some(true);
            return Ok(result);
        }
        self.litellm(credential, &endpoint).await
    }

    async fn litellm(&self, credential: &Credential, endpoint: &str) -> Result<BalanceResult> {
        let (status, payload, _) = self
            .get_json(
                format!("{endpoint}/key/info"),
                credential,
                &[("key", credential.apikey.as_str())],
            )
            .await?;
        if status != 200
            || payload.get("success") == Some(&Value::Bool(false))
            || payload.get("error").is_some()
        {
            return Ok(Default::default());
        }
        let Some(info) = payload
            .get("key_info")
            .or_else(|| payload.get("info"))
            .and_then(Value::as_object)
        else {
            return Ok(Default::default());
        };
        let spend_value = info.get("spend");
        let has_spend = spend_value.and_then(strict_number).is_some()
            || spend_value.is_none()
                && (info.contains_key("max_budget") || info.contains_key("models"));
        let has_budget_signal = ["spend", "max_budget", "max_budget_soft"]
            .iter()
            .any(|field| info.get(*field).and_then(strict_number).is_some());
        let unlimited_envelope = info.contains_key("max_budget")
            && info.get("models").and_then(Value::as_array).is_some();
        if (!has_budget_signal && !unlimited_envelope) || (!has_spend && !has_budget_signal) {
            return Ok(Default::default());
        }
        let spend = spend_value.and_then(strict_number).unwrap_or(0.0);
        let maximum = info
            .get("max_budget")
            .and_then(strict_number)
            .or_else(|| info.get("max_budget_soft").and_then(strict_number));
        let models = info
            .get("models")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut result = probe_result(
            "litellm",
            if maximum.is_some() {
                "litellm:key_info"
            } else {
                "litellm:key_no_limit"
            },
            "quota",
            maximum
                .map(|value| number_string((value - spend).max(0.0)))
                .unwrap_or_else(|| "N/A".into()),
            json!({"models":models}),
        );
        result.tier = info
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into();
        result.quota = if let Some(maximum) = maximum {
            json!({"spend":spend,"max_budget":maximum,"remaining":(maximum-spend).max(0.0)})
        } else {
            json!({"spend":spend,"max_budget":null,"unlimited":true})
        };
        if maximum.is_none() {
            result.usage = json!({"spend":spend});
        }
        result.alive = Some(true);
        Ok(result)
    }

    async fn get_json(
        &self,
        url: String,
        credential: &Credential,
        params: &[(&str, &str)],
    ) -> Result<(u16, Value, reqwest::header::HeaderMap)> {
        if !header_safe(&credential.apikey) {
            return Ok((0, Value::Null, reqwest::header::HeaderMap::new()));
        }
        let response = self
            .http
            .get(url)
            .bearer_auth(&credential.apikey)
            .query(params)
            .send()
            .await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let payload = response.json().await.unwrap_or(Value::Null);
        Ok((status, payload, headers))
    }

    async fn get_json_with_headers(
        &self,
        url: String,
        headers: reqwest::header::HeaderMap,
        params: &[(&str, &str)],
    ) -> Result<(u16, Value, reqwest::header::HeaderMap)> {
        let response = self
            .http
            .get(url)
            .headers(headers)
            .query(params)
            .send()
            .await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let payload = response.json().await.unwrap_or(Value::Null);
        Ok((status, payload, headers))
    }

    async fn models_response(
        &self,
        credential: Credential,
    ) -> Result<Option<(u16, Value, reqwest::header::HeaderMap)>> {
        if !header_safe(&credential.apikey) {
            return Ok(None);
        }
        let resolution = self
            .registry
            .resolve(&credential.apiurl, &credential.apikey);
        let routed = routed_credential(credential, &resolution);
        let canonical = match aipocket_core::endpoint::canonicalize_endpoint(
            &routed.apiurl,
            resolution.spec.name,
        ) {
            Ok(endpoint) => endpoint,
            Err(_) => return Ok(None),
        };
        let url = models_url(&canonical, resolution.spec.protocol);
        if url.is_empty() {
            return Ok(None);
        }
        let response = match resolution.spec.protocol {
            aipocket_prober::ProtocolFamily::Anthropic => {
                self.http
                    .get(url)
                    .header("x-api-key", &routed.apikey)
                    .header("anthropic-version", "2023-06-01")
                    .send()
                    .await?
            }
            aipocket_prober::ProtocolFamily::Gemini => {
                self.http
                    .get(url)
                    .query(&[("key", &routed.apikey)])
                    .send()
                    .await?
            }
            _ => {
                self.http
                    .get(url)
                    .bearer_auth(&routed.apikey)
                    .send()
                    .await?
            }
        };
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let payload = response.json().await.unwrap_or(Value::Null);
        Ok(Some((status, payload, headers)))
    }

    pub async fn models(&self, credential: Credential) -> Result<Vec<String>> {
        let Some((status, payload, _)) = self.models_response(credential).await? else {
            return Ok(Vec::new());
        };
        if !(200..300).contains(&status) {
            return Ok(Vec::new());
        }
        Ok(model_ids(&payload))
    }

    pub async fn test_chat(&self, credential: Credential, model: &str) -> Result<ChatProbeResult> {
        if model.is_empty() {
            return Ok(ChatProbeResult::failure(None, model, "model required"));
        }
        if !header_safe(&credential.apikey) {
            return Ok(ChatProbeResult::failure(None, model, "invalid apikey"));
        }
        let resolution = self
            .registry
            .resolve(&credential.apiurl, &credential.apikey);
        if resolution.spec.protocol == aipocket_prober::ProtocolFamily::Gemini {
            return Ok(ChatProbeResult::failure(
                None,
                model,
                "excluded:google_generative_language",
            ));
        }
        let routed = routed_credential(credential, &resolution);
        let canonical = match aipocket_core::endpoint::canonicalize_endpoint(
            &routed.apiurl,
            resolution.spec.name,
        ) {
            Ok(endpoint) if !endpoint.api_base.is_empty() => endpoint,
            _ => return Ok(ChatProbeResult::failure(None, model, "no apiurl")),
        };
        let url = chat_url(&canonical, resolution.spec.protocol);
        if url.is_empty() {
            return Ok(ChatProbeResult::failure(None, model, "no apiurl"));
        }
        let request = match resolution.spec.protocol {
            aipocket_prober::ProtocolFamily::Anthropic => self
                .http
                .post(url)
                .header("x-api-key", &routed.apikey)
                .header("anthropic-version", "2023-06-01")
                .json(&json!({"model":model,"max_tokens":4,"messages":[{"role":"user","content":"Reply OK"}]})),
            _ => self
                .http
                .post(url)
                .bearer_auth(&routed.apikey)
                .json(&json!({"model":model,"messages":[{"role":"user","content":"Reply OK"}],"max_tokens":4})),
        };
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => return Ok(ChatProbeResult::failure(None, model, &error.to_string())),
        };
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        if status == 200 {
            return Ok(ChatProbeResult {
                success: true,
                status_code: Some(status),
                model: model.into(),
                snippet: format!("model={model}"),
                error: String::new(),
            });
        }
        let error = match status {
            401 | 403 => "unauthorized",
            429 => "rate_limited",
            _ => text.as_str(),
        };
        Ok(ChatProbeResult {
            success: false,
            status_code: Some(status),
            model: model.into(),
            snippet: String::new(),
            error: error.into(),
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChatProbeResult {
    pub success: bool,
    pub status_code: Option<u16>,
    pub model: String,
    pub snippet: String,
    pub error: String,
}

impl ChatProbeResult {
    fn failure(status_code: Option<u16>, model: &str, error: &str) -> Self {
        Self {
            success: false,
            status_code,
            model: model.into(),
            snippet: String::new(),
            error: error.into(),
        }
    }
}
fn routed_credential(
    mut credential: Credential,
    resolution: &aipocket_prober::ProviderResolution,
) -> Credential {
    if resolution.reason == "key_prefix"
        && !resolution.spec.official_api_url.is_empty()
        && !credential.apiurl.contains(
            resolution
                .spec
                .domain_suffixes
                .first()
                .copied()
                .unwrap_or_default(),
        )
    {
        credential.apiurl = resolution.spec.official_api_url.into();
    }
    credential
}

fn validated_liveness(result: &aipocket_core::ValidationResult, provider: &str) -> BalanceResult {
    let authenticated = is_authenticated(result);
    if !authenticated {
        return Default::default();
    }
    let mut probe = probe_result(
        provider,
        &format!("{provider}:validated_liveness"),
        "liveness",
        "N/A",
        json!({
            "models":result.provider_info.models_available,
            "validation_state":result.validation_state,
            "passive_error":result.error
        }),
    );
    probe.alive = Some(true);
    probe
}

fn glm_passive(result: &aipocket_core::ValidationResult) -> BalanceResult {
    const CODES: &[&str] = &[
        "1308", "1310", "1311", "1314", "1315", "1316", "1317", "1318", "1319", "1320", "1321",
    ];
    let evidence = format!("{} {}", result.error, result.response_snippet);
    let Some(code) = CODES
        .iter()
        .find(|code| contains_standalone_code(&evidence, code))
    else {
        return Default::default();
    };
    let reset_at = regex::Regex::new(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b")
        .ok()
        .and_then(|pattern| {
            pattern
                .find(&evidence)
                .map(|value| value.as_str().to_owned())
        });
    let mut quota = serde_json::Map::new();
    quota.insert("business_code".into(), Value::String((*code).into()));
    if let Some(reset_at) = reset_at {
        quota.insert("reset_at".into(), Value::String(reset_at));
    }
    let mut probe = probe_result(
        "glm",
        "glm:passive_error",
        "quota",
        "",
        json!({"business_code":code,"message":evidence.chars().take(500).collect::<String>()}),
    );
    probe.quota = Value::Object(quota);
    probe.alive = Some(true);
    probe
}

fn longcat_liveness(result: &aipocket_core::ValidationResult) -> BalanceResult {
    if !is_authenticated(result) {
        return Default::default();
    }
    let evidence = format!("{} {}", result.error, result.response_snippet);
    let lowered = evidence.to_ascii_lowercase();
    let depleted = [
        "credit balance",
        "insufficient balance",
        "insufficient quota",
        "余额不足",
        "额度不足",
        "欠费",
    ]
    .iter()
    .any(|marker| lowered.contains(marker));
    let mut detail = json!({
        "models":result.provider_info.models_available,
        "validation_state":result.validation_state,
        "passive_error":result.error
    });
    if depleted {
        detail["cash_balance_state"] = Value::String("depleted".into());
    }
    let mut probe = probe_result(
        "longcat",
        "longcat:validated_liveness",
        "liveness",
        "N/A",
        detail,
    );
    probe.alive = Some(true);
    probe
}

fn is_authenticated(result: &aipocket_core::ValidationResult) -> bool {
    result.valid
        || matches!(
            result.validation_state.as_str(),
            "authentication_confirmed" | "inference_verified" | "final_verified"
        )
}

fn contains_standalone_code(text: &str, code: &str) -> bool {
    text.match_indices(code).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + code.len()..].chars().next();
        before.is_none_or(|value| !value.is_ascii_digit())
            && after.is_none_or(|value| !value.is_ascii_digit())
    })
}

fn string_fields(value: &Value, fields: &[&str]) -> Value {
    let mut result = serde_json::Map::new();
    for field in fields {
        if let Some(value) = value.get(*field).and_then(Value::as_str)
            && !value.is_empty()
        {
            result.insert((*field).into(), Value::String(value.into()));
        }
    }
    Value::Object(result)
}

fn strict_number(value: &Value) -> Option<f64> {
    if value.is_boolean() {
        None
    } else {
        value.as_f64()
    }
}

fn fireworks_tier(maximum: f64, account_type: &str) -> &'static str {
    if account_type.eq_ignore_ascii_case("ENTERPRISE") {
        return "enterprise";
    }
    match maximum as i64 {
        50 if maximum == 50.0 => "tier1",
        500 if maximum == 500.0 => "tier2",
        5000 if maximum == 5000.0 => "tier3",
        50000 if maximum == 50000.0 => "tier4",
        _ => "",
    }
}

fn models_url(
    endpoint: &aipocket_core::endpoint::CanonicalEndpoint,
    protocol: aipocket_prober::ProtocolFamily,
) -> String {
    match protocol {
        aipocket_prober::ProtocolFamily::Anthropic => {
            format!("{}/models", endpoint.api_base.trim_end_matches('/'))
        }
        aipocket_prober::ProtocolFamily::Gemini => {
            format!("{}/v1beta/models", endpoint.origin.trim_end_matches('/'))
        }
        _ => openai_operation_url(&endpoint.api_base, "models"),
    }
}

fn chat_url(
    endpoint: &aipocket_core::endpoint::CanonicalEndpoint,
    protocol: aipocket_prober::ProtocolFamily,
) -> String {
    match protocol {
        aipocket_prober::ProtocolFamily::Anthropic => {
            format!("{}/messages", endpoint.api_base.trim_end_matches('/'))
        }
        aipocket_prober::ProtocolFamily::Gemini => String::new(),
        _ => openai_operation_url(&endpoint.api_base, "chat/completions"),
    }
}

fn openai_operation_url(base: &str, operation: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        String::new()
    } else if base.ends_with("/v1") {
        format!("{base}/{operation}")
    } else {
        format!("{base}/v1/{operation}")
    }
}

fn probe_result(
    provider: &str,
    source: &str,
    evidence_kind: &str,
    balance_usd: impl Into<String>,
    detail: Value,
) -> BalanceResult {
    BalanceResult {
        matched: true,
        provider: provider.into(),
        gateway: provider.into(),
        source: source.into(),
        evidence_kind: evidence_kind.into(),
        balance_usd: balance_usd.into(),
        detail,
        ..Default::default()
    }
}

pub fn apply_probe_result(result: &mut aipocket_core::ValidationResult, probe: BalanceResult) {
    if !probe.matched {
        return;
    }
    let provider = if probe.provider.is_empty() {
        probe.gateway.clone()
    } else {
        probe.provider.clone()
    };
    result.provider_info.validation_provider = provider.clone();
    result.provider_info.provider = provider.clone();
    if matches!(
        result.provider_info.credential_issuer.as_str(),
        "" | "unknown" | "gateway"
    ) {
        result.provider_info.credential_issuer = provider.clone();
    }
    let observed_at = chrono::Utc::now().to_rfc3339();
    result.provider_info.evidence_source = probe.source.clone();
    result.provider_info.evidence_kind = probe.evidence_kind.clone();
    result.provider_info.evidence_observed_at = observed_at.clone();
    if probe.evidence_kind == "cash_balance" {
        result.provider_info.balance_provider = provider.clone();
    }
    if !probe.balance_usd.is_empty() {
        result.balance = probe.balance_usd.clone();
    } else if !probe.balance_native.is_empty() {
        result.balance = match probe.currency.to_ascii_uppercase().as_str() {
            "CNY" => format!("¥{}", probe.balance_native),
            "" | "USD" => probe.balance_native.clone(),
            currency => format!("{} {currency}", probe.balance_native),
        };
    }
    if !probe.tier.is_empty() {
        result.tier = probe.tier.clone();
    }
    result.gateway = provider;
    result.provider_evidence = serde_json::to_value(&probe).unwrap_or(probe.detail);
    if let Some(evidence) = result.provider_evidence.as_object_mut() {
        evidence.remove("matched");
        evidence.insert("observed_at".into(), Value::String(observed_at));
    }
}
fn openai_budget_tier(hard_limit: f64) -> &'static str {
    if hard_limit >= 200_000.0 {
        "tier5_candidate"
    } else if hard_limit >= 5_000.0 {
        "tier4_candidate"
    } else if hard_limit >= 1_000.0 {
        "tier3_candidate"
    } else if hard_limit >= 100.0 {
        "tier1+_candidate"
    } else {
        ""
    }
}

fn strip_v1(value: &str) -> String {
    value.trim_end_matches('/').trim_end_matches("/v1").into()
}
fn origin(value: &str) -> String {
    url::Url::parse(value)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            })
        })
        .unwrap_or_else(|| strip_v1(value))
}
fn number(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str()?.replace(',', "").parse().ok())
}
fn number_string(value: f64) -> String {
    let text = format!("{value:.4}");
    text.trim_end_matches('0').trim_end_matches('.').into()
}
fn anthropic_cost_usd(payload: &Value) -> Option<f64> {
    let rows = payload.get("data").and_then(Value::as_array)?;
    let mut cents = 0.0;
    let mut found = false;
    for bucket in rows {
        let Some(results) = bucket.get("results").and_then(Value::as_array) else {
            continue;
        };
        for row in results {
            if let Some(amount) = row.get("amount").and_then(number) {
                cents += amount;
                found = true;
            }
        }
    }
    found.then_some(cents / 100.0)
}

fn anthropic_rate_limits_tier(payload: &Value) -> String {
    let Some(entries) = payload.get("data").and_then(Value::as_array) else {
        return String::new();
    };
    let mut rpm = 0_u64;
    let mut itpm = 0_u64;
    for entry in entries {
        if entry
            .get("group_type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind != "model_group")
        {
            continue;
        }
        let Some(limits) = entry.get("limits").and_then(Value::as_array) else {
            continue;
        };
        for limit in limits {
            let value = limit.get("value").and_then(number).unwrap_or(0.0) as u64;
            match limit
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
            {
                "requests_per_minute" => rpm = rpm.max(value),
                "input_tokens_per_minute" | "tokens_per_minute" => itpm = itpm.max(value),
                _ => {}
            }
        }
    }
    anthropic_usage_tier(rpm, itpm).into()
}

fn anthropic_usage_tier(rpm: u64, itpm: u64) -> &'static str {
    if rpm >= 10_000 || itpm >= 10_000_000 {
        "usage_tier:scale"
    } else if rpm >= 5_000 || itpm >= 5_000_000 {
        "usage_tier:build"
    } else if rpm >= 1_000 || itpm >= 500_000 {
        "usage_tier:start"
    } else {
        ""
    }
}

fn header_safe(value: &str) -> bool {
    !value.contains(['\r', '\n']) && value.is_ascii()
}
fn model_ids(payload: &Value) -> Vec<String> {
    payload
        .get("data")
        .or_else(|| payload.get("models"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.get("id")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}
fn rate_headers(headers: &reqwest::header::HeaderMap) -> Value {
    Value::Object(
        headers
            .iter()
            .filter_map(|(key, value)| {
                let name = key.as_str();
                (name.starts_with("x-ratelimit-") || name.starts_with("ratelimit-")).then(|| {
                    (
                        name.into(),
                        Value::String(value.to_str().unwrap_or_default().into()),
                    )
                })
            })
            .collect(),
    )
}

fn openai_credit_remaining(payload: &Value) -> Option<f64> {
    if let Some(total) = payload.get("total_available").and_then(number) {
        return Some(total.max(0.0));
    }
    let rows = payload
        .pointer("/grants/data")
        .or_else(|| payload.get("data"))
        .and_then(Value::as_array)?;
    let mut total = 0.0;
    let mut found = false;
    for row in rows {
        let Some(row) = row.as_object() else {
            continue;
        };
        if !row.contains_key("grant_amount")
            && !row.contains_key("used_amount")
            && !row.contains_key("used")
        {
            continue;
        }
        total += row.get("grant_amount").and_then(number).unwrap_or(0.0)
            - row
                .get("used_amount")
                .or_else(|| row.get("used"))
                .and_then(number)
                .unwrap_or(0.0);
        found = true;
    }
    found.then_some(total.max(0.0))
}

fn openai_tier(headers: &reqwest::header::HeaderMap) -> String {
    let rpm = headers
        .get("x-ratelimit-limit-requests")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let tpm = headers
        .get("x-ratelimit-limit-tokens")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if rpm.is_some_and(|value| value >= 10_000) {
        "tier5_candidate".into()
    } else if rpm.is_some_and(|value| value >= 5_000) {
        "tier4_candidate".into()
    } else if rpm.is_some_and(|value| value >= 500) {
        "tier1+_candidate".into()
    } else if tpm.is_some_and(|value| value >= 2_000_000) {
        "tier5_candidate".into()
    } else if tpm.is_some_and(|value| value >= 450_000) {
        "tier3+_candidate".into()
    } else {
        let mut parts = Vec::new();
        if let Some(rpm) = rpm {
            parts.push(format!("rpm:{rpm}"));
        }
        if let Some(tpm) = tpm {
            parts.push(format!("tpm:{tpm}"));
        }
        if parts.is_empty() {
            "api:payg".into()
        } else {
            parts.join(" ")
        }
    }
}
fn anthropic_tier(headers: &reqwest::header::HeaderMap, payload: &Value) -> String {
    let rpm = headers
        .get("anthropic-ratelimit-requests-limit")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let itpm = headers
        .get("anthropic-ratelimit-input-tokens-limit")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if rpm >= 10_000 || itpm >= 10_000_000 {
        "usage_tier:scale".into()
    } else if rpm >= 5_000 || itpm >= 5_000_000 {
        "usage_tier:build".into()
    } else if rpm >= 1_000 || itpm >= 500_000 {
        "usage_tier:start".into()
    } else if model_ids(payload)
        .iter()
        .any(|model| model.contains("opus"))
    {
        "api:usage_tier_frontier".into()
    } else {
        "api:payg".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numbers_origins_and_headers_safely() {
        assert_eq!(number(&json!("110.00")), Some(110.0));
        assert_eq!(number_string(12.5000), "12.5");
        assert_eq!(
            origin("https://relay.example:8443/v1"),
            "https://relay.example:8443"
        );
        assert!(!header_safe("x\r\ny"));
        assert_eq!(number(&json!("not-a-number")), None);
        assert_eq!(origin("not-a-url/v1"), "not-a-url");
        assert!(header_safe("ascii-key"));
        assert_eq!(
            model_ids(&json!({"models":[{"name":"named-model"}]})),
            vec!["named-model"]
        );
        assert_eq!(fireworks_tier(1234.0, "STANDARD"), "");
        assert_eq!(fireworks_tier(1234.0, "ENTERPRISE"), "enterprise");
        assert_eq!(openai_credit_remaining(&json!({"data":[]})), None);
        assert_eq!(openai_budget_tier(100.0), "tier1+_candidate");
        assert_eq!(anthropic_rate_limits_tier(&json!({})), "");
        assert_eq!(
            anthropic_rate_limits_tier(&json!({"data":[
                {"group_type":"other","limits":[{"type":"requests_per_minute","value":99999}]},
                {"group_type":"model_group"},
                {"group_type":"model_group","limits":[
                    {"type":"requests_per_minute","value":"1000"},
                    {"type":"tokens_per_minute","value":500000},
                    {"type":"ignored","value":99999}
                ]}
            ]})),
            "usage_tier:start"
        );
        assert_eq!(
            anthropic_cost_usd(&json!({"data":[{}, {"results":[
                {"amount":"bad"}, {"amount":"100"}
            ]}]})),
            Some(1.0)
        );
        let mut unmatched = aipocket_core::ValidationResult::default();
        apply_probe_result(&mut unmatched, BalanceResult::default());
        assert!(unmatched.gateway.is_empty());
        let mut native = aipocket_core::ValidationResult::default();
        native.provider_info.credential_issuer = "gateway".into();
        apply_probe_result(
            &mut native,
            BalanceResult {
                matched: true,
                gateway: "native-provider".into(),
                evidence_kind: "cash_balance".into(),
                balance_native: "10".into(),
                currency: "EUR".into(),
                tier: "paid".into(),
                ..Default::default()
            },
        );
        assert_eq!(native.balance, "10 EUR");
        assert_eq!(native.tier, "paid");
        assert_eq!(native.provider_info.balance_provider, "native-provider");
        assert_eq!(native.provider_info.credential_issuer, "native-provider");
    }

    #[tokio::test]
    async fn official_provider_payloads_are_parsed() {
        use axum::{
            Json, Router,
            extract::Request,
            http::{HeaderMap, HeaderValue},
            routing::get,
        };
        async fn fixture(request: Request) -> (HeaderMap, Json<Value>) {
            let path = request.uri().path();
            let body = match path {
                "/v1/check-api-key" => json!({"valid":true,"organization_id":"org"}),
                "/v1/whoami" => json!({"id":"user"}),
                "/v1/account" => json!({"type":"team"}),
                "/v1/accounts" => json!({"accounts":[{"name":"accounts/acme"}]}),
                "/v1/accounts/acme" => json!({"accountType":"STANDARD","suspendState":"ACTIVE"}),
                "/v1/accounts/acme/quotas" => {
                    json!({"quotas":[{"name":"monthly-spend-usd","maxValue":500}]})
                }
                "/api/v1/auth/key" => json!({"data":{"limit":100,"usage":30,"is_free_tier":false}}),
                "/v1/models" => json!({"data":[{"id":"claude-opus-fixture"}]}),
                _ => json!({}),
            };
            let mut headers = HeaderMap::new();
            headers.insert(
                "anthropic-ratelimit-requests-limit",
                HeaderValue::from_static("10000"),
            );
            (headers, Json(body))
        }
        let app = Router::new().fallback(get(fixture).post(fixture));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service = BalanceService::new(reqwest::Client::new()).with_official_base(&base);
        for (host, key, gateway) in [
            ("https://api.cohere.com", "fixture", "cohere"),
            ("https://api.together.ai", "fixture", "together"),
            (
                "https://api.replicate.com",
                "r8_fixtureabcdefghijkl",
                "replicate",
            ),
            ("https://api.fireworks.ai", "fixture", "fireworks"),
            ("https://openrouter.ai", "sk-or-v1-fixture", "openrouter"),
            ("https://api.anthropic.com", "sk-ant-fixture", "anthropic"),
        ] {
            let result = service
                .query(&Credential {
                    apikey: key.into(),
                    host: host.into(),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(result.gateway, gateway, "{host}");
        }
        assert_eq!(openai_budget_tier(200_000.0), "tier5_candidate");
        assert_eq!(openai_budget_tier(5_000.0), "tier4_candidate");
        assert_eq!(openai_budget_tier(1_000.0), "tier3_candidate");
        assert_eq!(openai_budget_tier(99.0), "");
        assert_eq!(anthropic_usage_tier(10_000, 0), "usage_tier:scale");
        assert_eq!(anthropic_usage_tier(1_000, 0), "usage_tier:start");
        let fireworks = service
            .query(&Credential {
                apikey: "fixture".into(),
                host: "https://api.fireworks.ai".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(fireworks.tier, "tier2");
        let openrouter = service
            .query(&Credential {
                apikey: "sk-or-v1-fixture".into(),
                host: "https://openrouter.ai".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(openrouter.balance_usd, "70");
        let anthropic = service
            .query(&Credential {
                apikey: "sk-ant-fixture".into(),
                host: "https://api.anthropic.com".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(anthropic.tier, "usage_tier:scale");
        server.abort();
    }
    #[test]
    fn passive_context_and_apply_match_python_contract() {
        let glm = aipocket_core::ValidationResult {
            valid: true,
            validation_state: "authentication_confirmed".into(),
            error: "429: code 1314 reset 2026-07-23T00:00:00Z".into(),
            ..Default::default()
        };
        let probe = glm_passive(&glm);
        assert!(probe.matched);
        assert_eq!(probe.source, "glm:passive_error");
        assert_eq!(probe.quota["business_code"], "1314");
        assert_eq!(probe.quota["reset_at"], "2026-07-23T00:00:00Z");
        assert!(
            !glm_passive(&aipocket_core::ValidationResult {
                error: "code 1309".into(),
                ..Default::default()
            })
            .matched
        );

        let longcat = longcat_liveness(&aipocket_core::ValidationResult {
            valid: true,
            error: "余额不足，请充值".into(),
            ..Default::default()
        });
        assert_eq!(longcat.detail["cash_balance_state"], "depleted");

        let mut result = aipocket_core::ValidationResult {
            provider_info: aipocket_core::ProviderInfo {
                credential_issuer: "gateway".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        apply_probe_result(
            &mut result,
            BalanceResult {
                matched: true,
                provider: "deepseek".into(),
                source: "deepseek:user_balance".into(),
                evidence_kind: "cash_balance".into(),
                balance_native: "6.5".into(),
                currency: "CNY".into(),
                tier: "provider-returned-tier".into(),
                ..Default::default()
            },
        );
        assert_eq!(result.balance, "¥6.5");
        assert_eq!(result.provider_info.balance_provider, "deepseek");
        assert_eq!(result.provider_info.credential_issuer, "deepseek");
        assert!(result.provider_evidence["observed_at"].is_string());
        assert!(result.provider_evidence.get("matched").is_none());
    }

    #[tokio::test]
    async fn provider_dispatch_preserves_typed_balance_semantics() {
        use axum::{Json, Router, extract::Request, http::StatusCode, routing::get};
        async fn fixture(request: Request) -> (StatusCode, Json<Value>) {
            let path = request.uri().path();
            let body = match path {
                "/deepseek/user/balance" => json!({
                    "is_available":true,
                    "balance_infos":[
                        {"currency":"cny","total_balance":"2.75"},
                        {"currency":"CNY","total_balance":1.25}
                    ]
                }),
                "/kimi/v1/users/me/balance" => json!({
                    "code":0,"status":true,
                    "data":{"available_balance":"8.50","voucher_balance":2.5,"cash_balance":6.0}
                }),
                "/kimi-fail/v1/users/me/balance" => json!({
                    "code":401,"status":false,"data":{"available_balance":99}
                }),
                _ => json!({}),
            };
            (StatusCode::OK, Json(body))
        }
        let app = Router::new().fallback(get(fixture));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service = BalanceService::new(reqwest::Client::new());

        let deepseek = service
            .deepseek(
                &Credential {
                    apikey: "fixture".into(),
                    ..Default::default()
                },
                &format!("{base}/deepseek"),
            )
            .await
            .unwrap();
        assert!(deepseek.matched);
        assert_eq!(deepseek.balance_native, "4");
        assert_eq!(deepseek.balance_usd, "");
        assert_eq!(deepseek.currency, "CNY");

        let domestic = service
            .kimi(
                &Credential {
                    apikey: "fixture".into(),
                    ..Default::default()
                },
                &format!("{base}/kimi"),
            )
            .await
            .unwrap();
        assert_eq!(domestic.balance_native, "8.5");
        assert_eq!(domestic.detail["voucher_balance"], 2.5);

        let failed = service
            .kimi(
                &Credential {
                    apikey: "fixture".into(),
                    ..Default::default()
                },
                &format!("{base}/kimi-fail"),
            )
            .await
            .unwrap();
        assert!(!failed.matched);
        server.abort();
    }

    #[tokio::test]
    async fn gateway_requires_strict_independent_signals() {
        use axum::{Json, Router, extract::Request, routing::get};
        async fn fixture(request: Request) -> Json<Value> {
            Json(match request.uri().path() {
                "/api/status" => json!({"success":true,"data":{
                    "quota_per_unit":1,"stripe_unit_price":1,"self_use_mode_enabled":true
                }}),
                "/api/user/self" => json!({"success":true,"data":{"quota":100,"used_quota":25}}),
                "/dashboard/billing/subscription" => json!({}),
                "/key/info" => json!({"success":false,"key_info":{"spend":0,"max_budget":10}}),
                _ => json!({}),
            })
        }
        let app = Router::new().fallback(get(fixture));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service = BalanceService::new(reqwest::Client::new());
        let newapi = service
            .query(&Credential {
                apikey: "sk-fixture".into(),
                apiurl: format!("{base}/v1"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(newapi.provider, "newapi");
        assert_eq!(newapi.quota, json!({"quota":100,"used_quota":25}));
        assert_eq!(newapi.balance_usd, "");
        server.abort();
    }
    #[tokio::test]
    async fn openai_credit_and_liveness_contracts_are_typed() {
        use axum::{Json, Router, extract::Request, http::HeaderMap, routing::get};
        async fn fixture(request: Request) -> (HeaderMap, Json<Value>) {
            let mut headers = HeaderMap::new();
            headers.insert("x-ratelimit-limit-requests", "5000".parse().unwrap());
            let payload = match request.uri().path() {
                "/dashboard/billing/credit_grants" => json!({"total_available":"12.5"}),
                "/v1/dashboard/billing/credit_grants" => json!({}),
                "/v1/models" => json!({"data":[{"id":"gpt-fixture"}]}),
                _ => json!({}),
            };
            (headers, Json(payload))
        }
        let app = Router::new().fallback(get(fixture));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service = BalanceService::new(reqwest::Client::new()).with_official_base(&base);
        let credit = service
            .query(&Credential {
                apikey: "sk-proj-fixture".into(),
                host: "https://api.openai.com".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(credit.balance_usd, "12.5");
        assert_eq!(credit.evidence_kind, "cash_balance");
        assert_eq!(credit.account_type, "project");
        assert_eq!(
            openai_credit_remaining(
                &json!({"grants":{"data":[{"grant_amount":5,"used_amount":2}]}})
            ),
            Some(3.0)
        );
        assert_eq!(openai_tier(&HeaderMap::new()), "api:payg");
        server.abort();
    }
    #[tokio::test]
    async fn gateway_variants_enforce_schema_and_preserve_quota_evidence() {
        use axum::{Json, Router, extract::Request, routing::get};
        async fn fixture(request: Request) -> Json<Value> {
            let key = request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let path = request.uri().path();
            Json(match (key, path) {
                ("Bearer sk-oneapi", "/api/status") => {
                    json!({"success":true,"data":{"system_name":"One API","version":"0.6"}})
                }
                ("Bearer sk-oneapi", "/api/user/self") => {
                    json!({"success":true,"data":{"quota":9,"used_quota":2}})
                }
                ("Bearer sk-litellm", "/key/info") => json!({
                    "success":true,
                    "key_info":{"spend":3,"max_budget":10,"tier":"team","models":["gpt"]}
                }),
                ("Bearer sk-unlimited", "/key/info") => json!({
                    "info":{"spend":0,"max_budget":null,"models":["qwen"],"budget_duration":"30d"}
                }),
                ("Bearer sk-invalid", "/key/info") => json!({
                    "success":false,"key_info":{"spend":0,"max_budget":10}
                }),
                ("Bearer sk-billing", "/api/status") => json!({"success":true,"data":{
                    "quota_per_unit":1,"stripe_unit_price":1,"self_use_mode_enabled":true
                }}),
                ("Bearer sk-billing", "/dashboard/billing/subscription") => {
                    json!({"object":"billing_subscription","hard_limit_usd":20})
                }
                ("Bearer sk-billing", "/dashboard/billing/usage") => {
                    json!({"object":"list","total_usage":250})
                }
                _ => json!({}),
            })
        }
        let app = Router::new().fallback(get(fixture));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service = BalanceService::new(reqwest::Client::new());
        let credential = |key: &str| Credential {
            apikey: key.into(),
            apiurl: format!("{base}/v1"),
            ..Default::default()
        };

        let oneapi = service.query(&credential("sk-oneapi")).await.unwrap();
        assert_eq!(oneapi.provider, "oneapi");
        assert_eq!(oneapi.quota, json!({"quota":9,"used_quota":2}));

        let litellm = service.query(&credential("sk-litellm")).await.unwrap();
        assert_eq!(litellm.balance_usd, "7");
        assert_eq!(litellm.tier, "team");
        assert_eq!(litellm.quota["remaining"], 7.0);

        let unlimited = service.query(&credential("sk-unlimited")).await.unwrap();
        assert_eq!(unlimited.source, "litellm:key_no_limit");
        assert_eq!(unlimited.balance_usd, "N/A");
        assert_eq!(unlimited.quota["unlimited"], true);
        assert_eq!(unlimited.usage["spend"], 0.0);

        assert!(
            !service
                .query(&credential("sk-invalid"))
                .await
                .unwrap()
                .matched
        );

        let billing = service.query(&credential("sk-billing")).await.unwrap();
        assert_eq!(billing.provider, "newapi");
        assert_eq!(billing.quota["hard_limit_usd"], 20);
        assert_eq!(billing.usage, json!({"total_usage":250,"unit":"cents"}));
        server.abort();
    }

    #[tokio::test]
    async fn openrouter_models_and_context_edges_match_python_semantics() {
        use axum::{
            Json, Router, extract::Request, http::StatusCode, response::IntoResponse, routing::get,
        };
        async fn fixture(request: Request) -> impl IntoResponse {
            let key = request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let path = request.uri().path();
            match (key, path) {
                ("Bearer sk-or-v1-credits", "/api/v1/auth/key") => (
                    StatusCode::OK,
                    Json(
                        json!({"data":{"usage":12.5,"limit":null,"limit_remaining":null,"is_free_tier":false}}),
                    ),
                ),
                ("Bearer sk-or-v1-credits", "/api/v1/credits") => (
                    StatusCode::OK,
                    Json(json!({"data":{"total_credits":50,"total_usage":12.5}})),
                ),
                ("Bearer sk-or-v1-free", "/api/v1/auth/key") => (
                    StatusCode::OK,
                    Json(
                        json!({"data":{"usage":0,"limit":null,"limit_remaining":null,"is_free_tier":true}}),
                    ),
                ),
                ("Bearer sk-or-v1-free", "/api/v1/credits") => {
                    (StatusCode::UNAUTHORIZED, Json(json!({"error":"denied"})))
                }
                ("Bearer rate", "/v1/models") => {
                    (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error":"rate"})))
                }
                ("Bearer ksyun", "/v1/models") => {
                    (StatusCode::OK, Json(json!({"data":[{"id":"deepseek-v3"}]})))
                }
                _ => (StatusCode::NOT_FOUND, Json(json!({}))),
            }
        }
        let app = Router::new().fallback(get(fixture));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service = BalanceService::new(reqwest::Client::new()).with_official_base(&base);

        let credits = service
            .query(&Credential {
                apikey: "sk-or-v1-credits".into(),
                host: "https://openrouter.ai".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(credits.balance_usd, "37.5");
        assert_eq!(credits.source, "openrouter:credits");
        let free = service
            .query(&Credential {
                apikey: "sk-or-v1-free".into(),
                host: "https://openrouter.ai".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(free.balance_usd, "0");
        assert_eq!(free.source, "openrouter:free_tier");

        let rate = service
            .query_for_result(&aipocket_core::ValidationResult {
                credential: Credential {
                    apikey: "rate".into(),
                    apiurl: base.clone(),
                    ..Default::default()
                },
                provider_info: aipocket_core::ProviderInfo {
                    validation_provider: "nvidia".into(),
                    ..Default::default()
                },
                valid: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(rate.matched);
        assert_eq!(rate.evidence_kind, "liveness");
        assert_eq!(rate.alive, Some(true));

        let entitlement = service
            .query_for_result(&aipocket_core::ValidationResult {
                credential: Credential {
                    apikey: "ksyun".into(),
                    apiurl: base.clone(),
                    ..Default::default()
                },
                provider_info: aipocket_core::ProviderInfo {
                    validation_provider: "ksyun".into(),
                    ..Default::default()
                },
                valid: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(entitlement.evidence_kind, "entitlement");
        assert_eq!(entitlement.entitlements, json!({"models":["deepseek-v3"]}));

        for provider in ["azure_openai", "vertex"] {
            let result = service
                .query_for_result(&aipocket_core::ValidationResult {
                    valid: true,
                    validation_state: "final_verified".into(),
                    provider_info: aipocket_core::ProviderInfo {
                        validation_provider: provider.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(result.source, format!("{provider}:validated_liveness"));
        }
        assert!(
            !service
                .query(&Credential {
                    apikey: "bad\nkey".into(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .matched
        );
        server.abort();
    }
    #[tokio::test]
    async fn openai_subscription_and_anthropic_admin_keep_distinct_evidence() {
        use axum::{Json, Router, extract::Request, routing::get};
        async fn fixture(request: Request) -> Json<Value> {
            let key = request
                .headers()
                .get("authorization")
                .or_else(|| request.headers().get("x-api-key"))
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            Json(match (key, request.uri().path()) {
                ("Bearer sk-proj-subscription", "/dashboard/billing/subscription") => json!({
                    "object":"billing_subscription",
                    "hard_limit_usd":100,
                    "plan":{"id":"payg"}
                }),
                ("Bearer sk-proj-subscription", "/dashboard/billing/usage") => {
                    json!({"total_usage":250})
                }
                ("sk-ant-admin-fixture", "/v1/organizations/me") => {
                    json!({"id":"org-1","name":"Acme"})
                }
                ("sk-ant-admin-fixture", "/v1/organizations/cost_report") => json!({
                    "data":[{"results":[{"amount":"1250"},{"amount":"50.5"}]}]
                }),
                ("sk-ant-admin-fixture", "/v1/organizations/rate_limits") => json!({
                    "data":[{"group_type":"model_group","limits":[
                        {"type":"requests_per_minute","value":5000},
                        {"type":"input_tokens_per_minute","value":5000000}
                    ]}]
                }),
                _ => json!({}),
            })
        }
        let app = Router::new().fallback(get(fixture));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service = BalanceService::new(reqwest::Client::new()).with_official_base(&base);

        let subscription = service
            .query(&Credential {
                apikey: "sk-proj-subscription".into(),
                host: "https://api.openai.com".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(subscription.source, "openai:subscription_budget");
        assert_eq!(subscription.balance_usd, "97.5");
        assert_eq!(subscription.plan, "payg");
        assert_eq!(subscription.tier, "tier1+_candidate");
        assert_eq!(subscription.usage["used_usd"], 2.5);

        let admin = service
            .query(&Credential {
                apikey: "sk-ant-admin-fixture".into(),
                host: "https://api.anthropic.com".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(admin.source, "anthropic:admin_cost_report");
        assert_eq!(admin.balance_usd, "N/A");
        assert_eq!(admin.account_type, "admin");
        assert_eq!(admin.identity["id"], "org-1");
        assert_eq!(admin.usage["spend_usd_30d"], 13.005);
        assert_eq!(admin.tier, "usage_tier:build");
        assert_eq!(anthropic_cost_usd(&json!({"data":[]})), None);
        assert_eq!(anthropic_usage_tier(0, 0), "");
        server.abort();
    }
}
