mod maintenance;

use aipocket_core::{ScanMode, Settings};
use aipocket_db::{Repository, connect_pg, ensure_schema};
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::{net::IpAddr, sync::Arc};
#[derive(Parser)]
#[command(
    name = "aipocket",
    about = "Scan and validate exposed AI infrastructure",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Scan {
        #[arg(long, default_value = "all")]
        source: String,
        #[arg(long, value_enum, default_value = "incremental")]
        mode: Mode,
        #[arg(long)]
        resume_run: Option<String>,
    },
    Serve {
        #[arg(long, default_value = "0.0.0.0")]
        host: IpAddr,
        #[arg(long, default_value_t = 8000)]
        port: u16,
    },
    Watch,
    Queries,
    Config,
    #[command(name = "shodan-info")]
    ShodanInfo,
    #[command(name = "cve-sync")]
    CveSync,
    Balance,
    Maintenance {
        #[command(subcommand)]
        command: maintenance::MaintenanceCommand,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Full,
    Incremental,
}
impl From<Mode> for ScanMode {
    fn from(v: Mode) -> Self {
        match v {
            Mode::Full => Self::Full,
            Mode::Incremental => Self::Incremental,
        }
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aipocket=info,tower_http=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let settings = Settings::load()?;
    match cli.command {
        Command::Serve { host, port } => serve(settings, host, port).await,
        Command::Config => {
            let mut value = serde_json::to_value(&settings)?;
            for key in [
                "fofa_keys",
                "shodan_keys",
                "github_tokens",
                "gpt_key",
                "tavily_key",
                "web_password",
                "web_jwt_secret",
            ] {
                if let Some(v) = value.get_mut(key) {
                    *v = serde_json::Value::String(mask(v.as_str().unwrap_or_default()));
                }
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        Command::Queries => {
            for pack in aipocket_discovery::packs::PACKS {
                println!(
                    "{}\tfofa={} shodan={} github={}",
                    pack.id,
                    pack.fofa_queries.len(),
                    pack.shodan_queries.len(),
                    pack.github_terms.len()
                );
            }
            Ok(())
        }
        Command::ShodanInfo => {
            let http = http_client(&settings)?;
            let client = aipocket_clients::ShodanClient::new(http, &settings);
            println!("{}",serde_json::to_string_pretty(&client.info_all().await.into_iter().map(|(key,result)|serde_json::json!({"key":mask(&key),"result":result.ok()})).collect::<Vec<_>>())?);
            Ok(())
        }
        Command::CveSync => {
            let value = aipocket_clients::TavilyClient::new(http_client(&settings)?, &settings)
                .search("AI security CVE latest")
                .await?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        Command::Balance => {
            let pool = connect_pg(&settings).await?;
            let repo = Repository::new(pool);
            let rows = repo.all_records("valid", false).await?;
            let svc = aipocket_services::BalanceService::new(http_client(&settings)?);
            for row in rows {
                let credential: aipocket_core::Credential =
                    serde_json::from_value(row.get("credential").cloned().unwrap_or_default())?;
                println!("{}", serde_json::to_string(&svc.query(&credential).await?)?);
            }
            Ok(())
        }
        Command::Maintenance { command } => maintenance::run(command, settings).await,
        Command::Scan {
            source,
            mode,
            resume_run,
        } => run_scan(settings, source, mode.into(), resume_run).await,
        Command::Watch => run_watch(settings).await,
    }
}
fn http_client(settings: &Settings) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs_f64(
            settings.validate_timeout,
        ))
        .redirect(reqwest::redirect::Policy::limited(
            settings.max_probe_redirects,
        ))
        .no_proxy()
        .build()?)
}
async fn serve(settings: Settings, host: IpAddr, port: u16) -> Result<()> {
    settings.validate_server()?;
    let pool = connect_pg(&settings).await?;
    if let Some(pool) = &pool {
        ensure_schema(pool).await?;
    }
    let repository = Repository::new(pool);
    repository.mark_orphan_runs_interrupted().await?;
    if let Err(error) = repository.seed_cves().await {
        tracing::warn!(%error, "CVE seed backfill skipped");
    }
    aipocket_db::scan_lock::clear_stale_scan_lock(&settings).await;
    let state = aipocket_api::AppState::new(settings.clone(), repository).await?;
    let app = aipocket_api::create_app(state).await;
    let scheduler_task = if settings.scheduler_enabled {
        tracing::info!(interval = settings.scheduler_interval, "scheduler enabled");
        let scheduler_settings = settings.clone();
        Some(tokio::spawn(async move {
            let _ = run_watch(scheduler_settings).await;
        }))
    } else {
        None
    };
    let listener = tokio::net::TcpListener::bind((host, port)).await?;
    tracing::info!(%host,%port,"aipocket listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    if let Some(task) = scheduler_task {
        task.abort();
    }
    Ok(())
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {_=ctrl_c=>{},_=terminate=>{}}
}
async fn run_watch(settings: Settings) -> Result<()> {
    let settings = Arc::new(settings);
    let scheduler = aipocket_services::Scheduler::new(settings.clone());
    let cancel = tokio_util::sync::CancellationToken::new();
    let signal = cancel.clone();
    tokio::spawn(async move {
        shutdown().await;
        signal.cancel();
    });
    scheduler
        .run_forever(cancel, move || {
            let settings = settings.clone();
            async move {
                if let Err(error) = run_scan(
                    (*settings).clone(),
                    "all".into(),
                    ScanMode::Incremental,
                    None,
                )
                .await
                {
                    tracing::error!(%error, "scheduled scan failed");
                }
                Ok(())
            }
        })
        .await
}

async fn run_scan(
    settings: Settings,
    source: String,
    mode: ScanMode,
    resume: Option<String>,
) -> Result<()> {
    let pool = connect_pg(&settings).await?;
    if let Some(pool) = &pool {
        ensure_schema(pool).await?;
    }
    let repository = Repository::new(pool);
    let http = http_client(&settings)?;
    let scanner =
        aipocket_services::Scanner::new(Arc::new(settings.clone()), repository, http.clone());
    let mut sources: Vec<Arc<dyn aipocket_discovery::DiscoverySource>> = Vec::new();
    let registry = aipocket_discovery::packs::registry();
    let mut fofa_queries = aipocket_discovery::legacy_queries::fofa_queries();
    fofa_queries.extend(
        registry
            .values()
            .flat_map(|p| p.fofa_queries)
            .map(|q| q.to_string()),
    );
    fofa_queries.sort();
    fofa_queries.dedup();
    let shodan_queries = registry
        .values()
        .flat_map(|p| p.shodan_queries)
        .map(|q| q.to_string())
        .collect();
    if source == "all" || source == "fofa" {
        sources.push(Arc::new(aipocket_discovery::sources::FofaSource {
            client: aipocket_clients::FofaClient::new(http.clone(), &settings),
            queries: fofa_queries,
            page_size: settings.fofa_page_size,
            max_pages: settings.fofa_max_pages,
            page_delay: settings.fofa_page_delay,
        }));
    }
    if source == "all" || source == "shodan" {
        sources.push(Arc::new(aipocket_discovery::sources::ShodanSource {
            client: aipocket_clients::ShodanClient::new(http.clone(), &settings),
            queries: shodan_queries,
            max_pages: settings.shodan_max_pages,
            page_delay: settings.shodan_page_delay,
        }));
    }
    if (source == "all" || source == "github")
        && !settings.github_token_list().is_empty()
        && settings.pg_enabled()
    {
        sources.push(Arc::new(aipocket_discovery::sources::GithubSource {
            client: aipocket_clients::GithubClient::new(http.clone(), &settings),
            queries: registry
                .values()
                .flat_map(|p| p.github_terms)
                .map(|q| q.to_string())
                .collect(),
            per_page: settings.github_search_page_size,
            run_id: resume.clone().unwrap_or_default(),
            pack_id: String::new(),
        }));
    }
    if source == "manual" {
        let targets = scanner.manual_targets().await?;
        sources.push(Arc::new(aipocket_discovery::sources::ManualSource {
            targets,
        }));
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            tracing::info!(?event);
        }
    });
    let run_id = scanner
        .run_resumable(
            sources,
            mode,
            resume,
            tokio_util::sync::CancellationToken::new(),
            tx,
        )
        .await?;
    println!("{run_id}");
    Ok(())
}
fn mask(value: &str) -> String {
    aipocket_db::mask_apikey(value)
}
