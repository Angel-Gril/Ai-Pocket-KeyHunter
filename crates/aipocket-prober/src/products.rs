use crate::{ProbeContext, ProbeFinding, Prober};
use anyhow::Result;
use async_trait::async_trait;
macro_rules! passive_prober{($name:ident,$product:literal,$paths:expr)=>{pub struct $name;#[async_trait]impl Prober for $name{fn product(&self)->&'static str{$product}async fn probe(&self,http:&reqwest::Client,context:&ProbeContext)->Result<Vec<ProbeFinding>>{let mut findings=Vec::new();for path in $paths{if findings.len()>=context.request_budget{break}let url=format!("{}{}",context.target.trim_end_matches('/'),path);if let Ok(response)=http.get(url).send().await{if response.status().is_success(){let text=response.text().await.unwrap_or_default();findings.push(ProbeFinding{product:$product.into(),vuln_class:"unauth_read".into(),risk:0,evidence:serde_json::json!({"path":path,"snippet":text.chars().take(512).collect::<String>()}),credentials:vec![]});}}}Ok(findings)}}};}
passive_prober!(
    DifyProber,
    "dify",
    &["/console/api/system-features", "/v1/info"]
);
passive_prober!(
    LiteLlmProber,
    "litellm",
    &["/health/readiness", "/v1/models"]
);
passive_prober!(
    OpenWebUiProber,
    "openwebui",
    &["/api/config", "/api/version"]
);
passive_prober!(FlowiseProber, "flowise", &["/api/v1/version"]);
passive_prober!(LangflowProber, "langflow", &["/api/v1/version"]);
passive_prober!(NewApiProber, "newapi", &["/api/status", "/v1/models"]);
passive_prober!(GenericProber, "generic", &["/v1/models", "/api/status"]);
// Sub2API / One-API quota panels — passive path probing only (GET).
// Login route is probed for existence (status != 404), never exercised.
passive_prober!(
    Sub2ApiProber,
    "sub2api",
    &["/api/v1/auth/login", "/api/status", "/v1/models"]
);
passive_prober!(
    OneApiProber,
    "oneapi",
    &["/api/status", "/v1/models"]
);
passive_prober!(
    AnythingLlmProber,
    "anythingllm",
    &["/api/system", "/api/v1/system"]
);
passive_prober!(ChatGptNextWebProber, "chatgpt_next_web", &["/api/config"]);
passive_prober!(FastGptProber, "fastgpt", &["/api/system/getInitData"]);
passive_prober!(LibreChatProber, "librechat", &["/api/config"]);
passive_prober!(LobeChatProber, "lobechat", &["/api/config"]);
passive_prober!(OpenRouterProber, "openrouter", &["/api/v1/models"]);
passive_prober!(PortkeyProber, "portkey", &["/v1/models"]);
pub fn default_probers() -> Vec<Box<dyn Prober>> {
    vec![
        Box::new(DifyProber),
        Box::new(LiteLlmProber),
        Box::new(OpenWebUiProber),
        Box::new(FlowiseProber),
        Box::new(LangflowProber),
        Box::new(NewApiProber),
        Box::new(Sub2ApiProber),
        Box::new(OneApiProber),
        Box::new(GenericProber),
        Box::new(AnythingLlmProber),
        Box::new(ChatGptNextWebProber),
        Box::new(FastGptProber),
        Box::new(LibreChatProber),
        Box::new(LobeChatProber),
        Box::new(OpenRouterProber),
        Box::new(PortkeyProber),
    ]
}
