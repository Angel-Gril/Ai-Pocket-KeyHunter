pub const DIRECT_CREDENTIAL_QUERIES: &[&str] = &[
    "header=\"authorization: bearer sk-\"",
    "header=\"authorization: bearer sk-proj\"",
    "header=\"authorization: bearer sk-ant-\"",
    "header=\"x-api-key: sk-\"",
    "header=\"x-api-key: sk-ant-\"",
    "header=\"api-key: sk-\"",
    "header=\"apikey: sk-\"",
    "banner=\"authorization: bearer sk-\"",
    "banner=\"authorization: bearer sk-proj\"",
    "banner=\"authorization: bearer sk-ant-\"",
    "banner=\"OPENAI_API_KEY=sk-\"",
    "banner=\"ANTHROPIC_API_KEY=sk-ant-\"",
    "body=\"sk-proj-\"",
    "body=\"sk-ant-api\"",
    "body=\"OPENAI_API_KEY\" && body=\"sk-\"",
    "body=\"ANTHROPIC_API_KEY\" && body=\"sk-ant-\"",
    "body=\"DEEPSEEK_API_KEY\" && body=\"sk-\"",
    "body=\".env\" && body=\"sk-\"",
    "body=\"docker-compose\" && body=\"sk-\"",
    "body=\"api_key\" && body=\"sk-proj-\"",
    "body=\"moonshot\" && body=\"sk-\"",
    "body=\"deepseek\" && body=\"sk-\"",
    "body=\"master_key\" && body=\"sk-\"",
    "body=\"DANGEROUSLY_DISABLE_AUTH\" && body=\"sk-\"",
    "body=\"GEMINI_API_KEY\" && body=\"AIza\"",
    "body=\"XAI_API_KEY\" && body=\"xai-\"",
    "body=\"QODER_PAT\" && body=\"pt-\"",
    "body=\"KIRO_API_KEY\" && body=\"ksk_\"",
    "body=\"AWS_BEARER_TOKEN_BEDROCK\"",
    "body=\"CURSOR_API_KEY\" && body=\"crsr_\"",
    "body=\"WINDSURF_SERVICE_KEY\" || body=\"CODEIUM_SERVICE_KEY\"",
];

pub const PRODUCT_QUERIES: &[(&str, &[&str])] = &[
    (
        "LiteLLM",
        &[
            "body=\"litellm\" && body=\"sk-\"",
            "body=\"litellm_proxy\" && body=\"api_key\"",
            "body=\"LiteLLM Proxy\" && body=\"master_key\"",
        ],
    ),
    (
        "Flowise",
        &[
            "body=\"Flowise\" && body=\"sk-\"",
            "body=\"flowise\" && body=\"apiKey\"",
        ],
    ),
    (
        "Dify",
        &[
            "body=\"dify\" && body=\"sk-\"",
            "body=\"dify\" && body=\"OPENAI_API_KEY\"",
            "body=\"dify\" && body=\"ANTHROPIC_API_KEY\"",
        ],
    ),
    (
        "LibreChat",
        &[
            "body=\"librechat\" && body=\"sk-\"",
            "body=\"librechat\" && body=\"OPENAI_API_KEY\"",
            "body=\"librechat\" && body=\"ANTHROPIC_API_KEY\"",
        ],
    ),
    (
        "OpenWebUI",
        &[
            "body=\"Open WebUI\" && body=\"sk-\"",
            "body=\"open-webui\" && body=\"api_key\"",
        ],
    ),
    (
        "Langflow",
        &[
            "body=\"langflow\" && body=\"sk-\"",
            "body=\"langflow\" && body=\"OPENAI_API_KEY\"",
        ],
    ),
    (
        "MLflow",
        &[
            "body=\"mlflow\" && body=\"sk-\"",
            "body=\"mlflow\" && body=\"api_key\"",
        ],
    ),
    (
        "Portkey AI Gateway",
        &[
            "body=\"portkey\" && body=\"sk-\"",
            "body=\"portkey\" && body=\"api_key\"",
        ],
    ),
    (
        "LangChain",
        &[
            "body=\"langchain\" && body=\"OPENAI_API_KEY\"",
            "body=\"langchain\" && body=\"sk-\"",
        ],
    ),
    ("PraisonAI", &["body=\"praisonai\" && body=\"sk-\""]),
    (
        "GitLab AI Gateway",
        &["body=\"ai-gateway\" && body=\"sk-\""],
    ),
    (
        "FastGPT",
        &[
            "body=\"fastgpt\" && body=\"sk-\"",
            "body=\"fastgpt\" && body=\"OPENAI_API_KEY\"",
        ],
    ),
    (
        "New-API",
        &[
            "body=\"new-api\" && body=\"sk-\"",
            "body=\"new-api\" && body=\"token\"",
        ],
    ),
    (
        "One-API",
        &[
            "body=\"one-api\" && body=\"sk-\"",
            "body=\"one-api\" && body=\"token\"",
            "body=\"oneapi\" && body=\"sk-\"",
        ],
    ),
    (
        "AnythingLLM",
        &[
            "body=\"anythingllm\" && body=\"sk-\"",
            "body=\"anythingllm\" && body=\"OPENAI_API_KEY\"",
        ],
    ),
    (
        "ChatGPT-Next-Web",
        &[
            "body=\"nextchat\" && body=\"sk-\"",
            "body=\"chatgpt-next-web\" && body=\"OPENAI_API_KEY\"",
        ],
    ),
    (
        "OpenRouter",
        &[
            "body=\"openrouter\" && body=\"sk-or-\"",
            "body=\"openrouter\" && body=\"sk-\"",
            "body=\"OpenRouter\" && body=\"api_key\"",
        ],
    ),
    (
        "vLLM",
        &[
            "body=\"vllm\" && body=\"sk-\"",
            "body=\"vllm\" && body=\"api_key\"",
        ],
    ),
    ("Ollama", &["body=\"ollama\" && body=\"sk-\""]),
    ("LocalAI", &["body=\"localai\" && body=\"sk-\""]),
    (
        "Text-Generation-WebUI",
        &["body=\"text-generation-webui\" && body=\"sk-\""],
    ),
    (
        "LobeChat",
        &[
            "body=\"lobe-chat\" && body=\"sk-\"",
            "body=\"lobechat\" && body=\"OPENAI_API_KEY\"",
        ],
    ),
    ("Jan", &["body=\"jan.ai\" && body=\"sk-\""]),
    (
        "Claude",
        &[
            "body=\"claude\" && body=\"sk-ant-\"",
            "body=\"ANTHROPIC_API_KEY\" && body=\"sk-ant-\"",
            "body=\"anthropic\" && body=\"api_key\" && body=\"sk-\"",
        ],
    ),
    ("Codex CLI", &["body=\"codex\" && body=\"OPENAI_API_KEY\""]),
];

pub fn fofa_queries() -> Vec<String> {
    let mut out: Vec<String> = DIRECT_CREDENTIAL_QUERIES
        .iter()
        .map(|value| (*value).into())
        .collect();
    for (_, queries) in PRODUCT_QUERIES {
        out.extend(
            queries
                .iter()
                .map(|value| format!("{value} && status_code=\"200\"")),
        );
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_covers_runtime_queries() {
        assert_eq!(DIRECT_CREDENTIAL_QUERIES.len(), 31);
        assert_eq!(PRODUCT_QUERIES.len(), 25);
        assert!(fofa_queries().len() > 60);
    }
}
