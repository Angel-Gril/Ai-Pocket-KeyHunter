use std::collections::BTreeMap;
#[derive(Clone, Debug)]
pub struct ProviderPack {
    pub id: &'static str,
    pub fofa_queries: &'static [&'static str],
    pub shodan_queries: &'static [&'static str],
    pub github_terms: &'static [&'static str],
}
pub const PACKS: &[ProviderPack] = &[
    ProviderPack {
        id: "openai",
        fofa_queries: &["body=\"sk-\""],
        shodan_queries: &["http.html:sk-"],
        github_terms: &["sk- filename:.env"],
    },
    ProviderPack {
        id: "anthropic",
        fofa_queries: &["body=\"sk-ant-\""],
        shodan_queries: &["http.html:sk-ant-"],
        github_terms: &["sk-ant- filename:.env"],
    },
    ProviderPack {
        id: "azure_openai",
        fofa_queries: &["body=\"openai.azure.com\""],
        shodan_queries: &["http.html:openai.azure.com"],
        github_terms: &["AZURE_OPENAI_API_KEY"],
    },
    ProviderPack {
        id: "cohere",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["COHERE_API_KEY"],
    },
    ProviderPack {
        id: "deepseek",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["DEEPSEEK_API_KEY"],
    },
    ProviderPack {
        id: "fireworks",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["FIREWORKS_API_KEY"],
    },
    ProviderPack {
        id: "glm",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["ZHIPUAI_API_KEY"],
    },
    ProviderPack {
        id: "kimi",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["MOONSHOT_API_KEY"],
    },
    ProviderPack {
        id: "longcat",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["LONGCAT_API_KEY"],
    },
    ProviderPack {
        id: "minimax",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["MINIMAX_API_KEY"],
    },
    ProviderPack {
        id: "qwen",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["DASHSCOPE_API_KEY"],
    },
    ProviderPack {
        id: "replicate",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["REPLICATE_API_TOKEN"],
    },
    ProviderPack {
        id: "together",
        fofa_queries: &[],
        shodan_queries: &[],
        github_terms: &["TOGETHER_API_KEY"],
    },
];
pub fn registry() -> BTreeMap<&'static str, &'static ProviderPack> {
    PACKS.iter().map(|pack| (pack.id, pack)).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pack_ids_are_unique() {
        assert_eq!(registry().len(), PACKS.len());
    }
}
