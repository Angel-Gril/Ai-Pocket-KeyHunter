pub mod fofa;
pub mod github;
pub mod shodan;
pub mod tavily;

pub use fofa::FofaClient;
pub use github::GithubClient;
pub use shodan::ShodanClient;
pub use tavily::TavilyClient;

async fn parse_json_response(
    source: &str,
    response: reqwest::Response,
) -> anyhow::Result<serde_json::Value> {
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        anyhow::bail!(
            "{source} response status={status}: {}",
            response_preview(&bytes)
        );
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "{source} invalid JSON response status={status}: {}: {error}",
            response_preview(&bytes)
        )
    })
}

fn response_preview(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(200)
        .collect::<String>()
        .replace(['\r', '\n'], " ")
}
