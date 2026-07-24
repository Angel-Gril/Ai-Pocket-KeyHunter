use aipocket_core::{Credential, Settings, endpoint::canonicalize_endpoint, url_sanitize};
use aipocket_prober::ProviderRegistry;
use aipocket_services::BalanceService;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const ADVISORY_LOCK_KEY: i64 = 0xA1_20260721;

#[derive(Subcommand)]
pub enum MaintenanceCommand {
    #[command(name = "canonicalize-endpoints")]
    CanonicalizeEndpoints(CommonArgs),
    #[command(name = "reclassify-providers")]
    ReclassifyProviders(CommonArgs),
    #[command(name = "purge-google-generative-language")]
    PurgeGoogleGenerativeLanguage(CommonArgs),
    #[command(name = "backfill-honeypot-sites")]
    BackfillHoneypotSites(CommonArgs),
    #[command(name = "delete-empty-runs")]
    DeleteEmptyRuns(CommonArgs),
    #[command(name = "backfill-run-funnel-metrics")]
    BackfillRunFunnelMetrics(CommonArgs),
    #[command(name = "clean-false-valid")]
    CleanFalseValid(CleanArgs),
    #[command(name = "reprobe-balance")]
    ReprobeBalance(ReprobeArgs),
    #[command(name = "dedup-stats")]
    DedupStats,
    #[command(name = "import-jsonl-to-pg")]
    ImportJsonl(ImportArgs),
    #[command(name = "verify-high-value")]
    VerifyHighValue(ReprobeArgs),
    #[command(name = "verify-honeypot-replay")]
    VerifyHoneypotReplay(VerifyHoneypotArgs),
    #[command(name = "retry-failed-batches")]
    RetryFailedBatches { run_id: String },
    #[command(name = "backfill-unknown-provider")]
    BackfillUnknownProvider(CommonArgs),
    #[command(name = "backfill-routing-fields")]
    BackfillRoutingFields(CommonArgs),
    #[command(name = "fix-gateway-provider-hosts")]
    FixGatewayProviderHosts(CommonArgs),
    #[command(name = "run-balance-only")]
    RunBalanceOnly(ReprobeArgs),
    #[command(name = "reconcile-high-value")]
    ReconcileHighValue(CommonArgs),
    #[command(name = "resume-from-rawhits")]
    ResumeFromRawhits {
        path: PathBuf,
        #[arg(long)]
        database_url: Option<String>,
    },
    #[command(name = "carve-realtest")]
    CarveRealtest {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long)]
        apply: bool,
    },
    #[command(name = "shodan-filter-probe")]
    ShodanFilterProbe {
        #[arg(long)]
        query: Option<String>,
    },
    #[command(name = "verify-gpt")]
    VerifyGpt(VerifyGptArgs),
}

#[derive(Clone, Debug, Args)]
pub struct CommonArgs {
    #[arg(long)]
    pub database_url: Option<String>,
    #[arg(long)]
    pub run_id: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub limit: i64,
    #[arg(long, default_value_t = false)]
    pub apply: bool,
}
#[derive(Clone, Debug, Args)]
pub struct CleanArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long, default_value_t = false)]
    pub aggressive: bool,
    #[arg(long, default_value_t = false)]
    pub drop_gemini_free: bool,
    #[arg(long, default_value_t = false)]
    pub delete: bool,
}
#[derive(Clone, Debug, Args)]
pub struct ReprobeArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long, default_value_t = false)]
    pub force: bool,
    #[arg(long, default_value_t = false)]
    pub only_anthropic: bool,
}
#[derive(Clone, Debug, Args)]
pub struct ImportArgs {
    #[arg(long)]
    pub database_url: Option<String>,
    #[arg(long)]
    pub results: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub apply: bool,
}
#[derive(Clone, Debug, Args)]
pub struct VerifyHoneypotArgs {
    #[arg(long)]
    pub database_url: Option<String>,
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    pub limit: i64,
    #[arg(long, default_value_t = false)]
    pub apply: bool,
}
#[derive(Clone, Debug, Args)]
pub struct VerifyGptArgs {
    #[arg(long)]
    pub database_url: Option<String>,
    #[arg(long)]
    pub run_id: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub limit: i64,
    #[arg(long, value_delimiter = ',', default_values_t = ["gpt-5.5".to_owned(), "gpt-5.5-pro".to_owned(), "gpt-5.5-2026-04-23".to_owned()])]
    pub models: Vec<String>,
    #[arg(long, default_value_t = false)]
    pub apply: bool,
}

pub async fn run(command: MaintenanceCommand, mut settings: Settings) -> Result<()> {
    match command {
        MaintenanceCommand::DedupStats => return dedup_stats(&settings).await,
        MaintenanceCommand::ImportJsonl(args) => {
            if let Some(url) = args.database_url {
                settings.database_url = url;
            }
            let pool = pool(&settings).await?;
            return import_jsonl(
                &pool,
                args.results.unwrap_or_else(|| settings.results_path()),
                args.apply,
            )
            .await;
        }
        MaintenanceCommand::VerifyHoneypotReplay(args) => {
            if let Some(url) = args.database_url.as_ref() {
                settings.database_url = url.clone();
            }
            if let Some(input) = args.input.as_ref() {
                let pool = if args.apply {
                    Some(pool(&settings).await?)
                } else {
                    None
                };
                return verify_honeypot_jsonl(
                    input,
                    pool.as_ref(),
                    &settings,
                    args.limit,
                    args.apply,
                )
                .await;
            }
            let pool = pool(&settings).await?;
            return verify_honeypots(&pool, &settings, args.limit, args.apply).await;
        }
        MaintenanceCommand::RetryFailedBatches { run_id } => {
            return retry_failed_batches(&settings, &run_id).await;
        }
        MaintenanceCommand::CarveRealtest {
            input,
            output,
            limit,
            apply,
        } => return carve_realtest(&input, &output, limit, apply),
        MaintenanceCommand::ShodanFilterProbe { query } => {
            return shodan_filter_probe(&settings, query.as_deref()).await;
        }
        MaintenanceCommand::ResumeFromRawhits { path, database_url } => {
            if let Some(url) = database_url {
                settings.database_url = url;
            }
            return resume_raw_hits(path, settings).await;
        }
        MaintenanceCommand::VerifyGpt(args) => {
            if let Some(url) = args.database_url.as_ref() {
                settings.database_url = url.clone();
            }
            let pool = pool(&settings).await?;
            return verify_gpt(&pool, &settings, &args).await;
        }
        _ => {}
    }
    let common = match &command {
        MaintenanceCommand::CanonicalizeEndpoints(args)
        | MaintenanceCommand::ReclassifyProviders(args)
        | MaintenanceCommand::PurgeGoogleGenerativeLanguage(args)
        | MaintenanceCommand::BackfillHoneypotSites(args)
        | MaintenanceCommand::DeleteEmptyRuns(args)
        | MaintenanceCommand::BackfillRunFunnelMetrics(args) => args.clone(),
        MaintenanceCommand::BackfillUnknownProvider(args)
        | MaintenanceCommand::BackfillRoutingFields(args)
        | MaintenanceCommand::FixGatewayProviderHosts(args)
        | MaintenanceCommand::ReconcileHighValue(args) => args.clone(),
        MaintenanceCommand::RunBalanceOnly(args) => args.common.clone(),
        MaintenanceCommand::CleanFalseValid(args) => args.common.clone(),
        MaintenanceCommand::ReprobeBalance(args) | MaintenanceCommand::VerifyHighValue(args) => {
            args.common.clone()
        }
        _ => unreachable!(),
    };
    if let Some(url) = &common.database_url {
        settings.database_url = url.clone();
    }
    let pool = pool(&settings).await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ADVISORY_LOCK_KEY)
        .execute(&pool)
        .await?;
    let result = match command {
        MaintenanceCommand::CanonicalizeEndpoints(args) => canonicalize(&pool, &args).await,
        MaintenanceCommand::ReclassifyProviders(args) => reclassify(&pool, &args).await,
        MaintenanceCommand::PurgeGoogleGenerativeLanguage(args) => purge_google(&pool, &args).await,
        MaintenanceCommand::BackfillHoneypotSites(args) => backfill_honeypots(&pool, &args).await,
        MaintenanceCommand::DeleteEmptyRuns(args) => delete_empty_runs(&pool, &args).await,
        MaintenanceCommand::BackfillRunFunnelMetrics(args) => backfill_funnel(&pool, &args).await,
        MaintenanceCommand::CleanFalseValid(args) => clean_false_valid(&pool, &args).await,
        MaintenanceCommand::ReprobeBalance(args) => {
            reprobe_balance(&pool, &settings, &args, false).await
        }
        MaintenanceCommand::VerifyHighValue(args) => {
            verify_high_value(&pool, &settings, &args).await
        }
        MaintenanceCommand::BackfillUnknownProvider(args) => {
            backfill_unknown_provider(&pool, &args).await
        }
        MaintenanceCommand::BackfillRoutingFields(args) => {
            backfill_routing_fields(&pool, &args).await
        }
        MaintenanceCommand::FixGatewayProviderHosts(args) => {
            fix_gateway_provider_hosts(&pool, &args).await
        }
        MaintenanceCommand::RunBalanceOnly(args) => {
            reprobe_balance(&pool, &settings, &args, false).await
        }
        MaintenanceCommand::ReconcileHighValue(args) => reconcile_high_value(&pool, &args).await,
        _ => unreachable!(),
    };
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(ADVISORY_LOCK_KEY)
        .execute(&pool)
        .await
        .ok();
    result
}

async fn pool(settings: &Settings) -> Result<PgPool> {
    let pool = aipocket_db::connect_pg(settings)
        .await?
        .context("DATABASE_URL or --database-url is required")?;
    aipocket_db::ensure_schema(&pool).await?;
    Ok(pool)
}
fn print_summary(mode: &str, values: Value) -> Result<()> {
    println!("mode={mode}\n{}", serde_json::to_string_pretty(&values)?);
    Ok(())
}
fn credential(record: &Value) -> &Value {
    record.get("credential").unwrap_or(record)
}
fn provider_of(record: &Value, apiurl: &str, apikey: &str) -> String {
    record
        .pointer("/provider_info/validation_provider")
        .or_else(|| record.pointer("/provider_info/provider"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| ProviderRegistry.resolve(apiurl, apikey).spec.name.into())
}

async fn canonicalize(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let tables = [
        ("results", "id", true),
        ("high_value_keys", "apikey", false),
        ("scan_candidates", "id", true),
        ("scan_validation_results", "id", false),
    ];
    let mut scanned = 0usize;
    let mut changed = 0usize;
    for (table, key, lifted) in tables {
        let sql = format!(
            "SELECT {key}::text AS key,record FROM {table} WHERE ($1::text IS NULL OR run_id=$1) ORDER BY {key} LIMIT NULLIF($2,0)"
        );
        let rows = sqlx::query(&sql)
            .bind(&args.run_id)
            .bind(args.limit)
            .fetch_all(pool)
            .await?;
        for row in rows {
            scanned += 1;
            let key_value: String = row.try_get("key")?;
            let mut record: Value = row.try_get("record")?;
            let cred = credential(&record);
            let apiurl = cred
                .get("apiurl")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let apikey = cred
                .get("apikey")
                .or_else(|| record.get("apikey"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let endpoint = canonicalize_endpoint(&apiurl, &provider_of(&record, &apiurl, &apikey))?;
            let old_host = cred.get("host").and_then(Value::as_str).unwrap_or_default();
            if endpoint.api_base.is_empty()
                || (apiurl == endpoint.api_base && old_host == endpoint.origin)
            {
                continue;
            }
            changed += 1;
            if !args.apply {
                continue;
            }
            let target = if record.get("credential").is_some() {
                record
                    .get_mut("credential")
                    .and_then(Value::as_object_mut)
                    .context("credential must be object")?
            } else {
                record.as_object_mut().context("record must be object")?
            };
            target.insert("apiurl".into(), endpoint.api_base.clone().into());
            target.insert("host".into(), endpoint.origin.clone().into());
            let sql = if lifted {
                format!("UPDATE {table} SET apiurl=$2,host=$3,record=$4 WHERE {key}::text=$1")
            } else {
                format!("UPDATE {table} SET record=$4 WHERE {key}::text=$1")
            };
            sqlx::query(&sql)
                .bind(key_value)
                .bind(endpoint.api_base)
                .bind(endpoint.origin)
                .bind(record)
                .execute(pool)
                .await?;
        }
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"scanned":scanned,"changed":changed}),
    )
}

async fn reclassify(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let rows=sqlx::query("SELECT id,apiurl,apikey,record FROM results WHERE ($1::text IS NULL OR run_id=$1) ORDER BY id LIMIT NULLIF($2,0)").bind(&args.run_id).bind(args.limit).fetch_all(pool).await?;
    let mut changed = 0;
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let apiurl: String = row
            .try_get::<Option<String>, _>("apiurl")?
            .unwrap_or_default();
        let apikey: String = row
            .try_get::<Option<String>, _>("apikey")?
            .unwrap_or_default();
        let mut record: Value = row.try_get("record")?;
        let resolved = ProviderRegistry.resolve(&apiurl, &apikey);
        let provider = if resolved.spec.name == "unknown" && !apiurl.is_empty() {
            "gateway"
        } else {
            resolved.spec.name
        };
        let old = record
            .pointer("/provider_info/validation_provider")
            .or_else(|| record.pointer("/provider_info/provider"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if old == provider {
            continue;
        }
        changed += 1;
        if args.apply {
            let info = record
                .as_object_mut()
                .unwrap()
                .entry("provider_info")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .unwrap();
            info.insert("provider".into(), provider.into());
            info.insert("validation_provider".into(), provider.into());
            info.insert("category".into(), resolved.spec.category.into());
            sqlx::query("UPDATE results SET validation_provider=$2,credential_issuer=CASE WHEN credential_issuer IN ('','unknown','gateway') THEN $2 ELSE credential_issuer END,record=$3 WHERE id=$1").bind(id).bind(provider).bind(record).execute(pool).await?;
        }
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"scanned":rows.len(),"changed":changed}),
    )
}

fn newapi_contract(value: &Value) -> bool {
    match value {
        Value::Object(fields) => {
            let signals = [
                fields
                    .keys()
                    .filter(|key| {
                        [
                            "quota_per_unit",
                            "stripe_unit_price",
                            "self_use_mode_enabled",
                            "system_name",
                            "version",
                        ]
                        .contains(&key.as_str())
                    })
                    .count()
                    >= 3,
                fields
                    .get("object")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == "billing_subscription" || value == "list"),
                fields.get("success").and_then(Value::as_bool) == Some(true)
                    && fields
                        .get("data")
                        .and_then(|data| data.get("quota"))
                        .is_some_and(Value::is_number),
            ]
            .into_iter()
            .filter(|signal| *signal)
            .count();
            signals >= 2 || fields.values().any(newapi_contract)
        }
        Value::Array(items) => items.iter().any(newapi_contract),
        _ => false,
    }
}

fn gateway_provider_hint(
    record: &Value,
    apiurl: &str,
    apikey: &str,
) -> Option<(&'static str, &'static str)> {
    let lower = apiurl.to_ascii_lowercase();
    if lower.contains("llm.alem.ai") {
        return Some(("litellm", "litellm"));
    }
    if lower.contains("dashscope") {
        return Some(("qwen", "dashscope"));
    }
    if lower.contains("apinet.cloud") || lower.contains("142.171.135.205") {
        return Some(("newapi", "newapi"));
    }
    if lower.contains("213.142.134.36") || apikey.starts_with("sk-vxia-") {
        return Some(("gateway", "voxia"));
    }
    let gateway = record
        .get("gateway")
        .or_else(|| record.pointer("/provider_info/balance_provider"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    Some(match gateway {
        "newapi" | "newapi_billing" => ("newapi", "newapi"),
        "oneapi" => ("oneapi", "oneapi"),
        "litellm" => ("litellm", "litellm"),
        "dashscope" => ("qwen", "dashscope"),
        "openai" => ("openai", "openai"),
        "openrouter" => ("openrouter", "openrouter"),
        "deepseek" => ("deepseek", "deepseek"),
        "moonshot" => ("kimi", "moonshot"),
        "glm" => ("glm", "glm"),
        "siliconflow" => ("siliconflow", "siliconflow"),
        _ => return None,
    })
}

async fn patch_provider_rows(pool: &PgPool, args: &CommonArgs, mode: &str) -> Result<()> {
    let tables = [("results", "id"), ("high_value_keys", "apikey")];
    let mut scanned = 0usize;
    let mut changed = 0usize;
    for (table, key) in tables {
        let sql = format!(
            "SELECT {key}::text AS key,record FROM {table} WHERE ($1::text IS NULL OR run_id=$1) ORDER BY {key} LIMIT NULLIF($2,0)"
        );
        for row in sqlx::query(&sql)
            .bind(&args.run_id)
            .bind(args.limit)
            .fetch_all(pool)
            .await?
        {
            scanned += 1;
            let key_value: String = row.try_get("key")?;
            let mut record: Value = row.try_get("record")?;
            let cred = credential(&record);
            let apiurl = cred
                .get("apiurl")
                .or_else(|| record.get("apiurl"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let apikey = cred
                .get("apikey")
                .or_else(|| record.get("apikey"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let resolved = ProviderRegistry.resolve(&apiurl, &apikey);
            let mut provider = if resolved.spec.name == "unknown" && !apiurl.is_empty() {
                "gateway"
            } else {
                resolved.spec.name
            };
            let mut gateway = record
                .get("gateway")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if mode != "reclassify"
                && let Some((hint, gateway_hint)) = gateway_provider_hint(&record, &apiurl, &apikey)
            {
                provider = hint;
                gateway = gateway_hint.into();
            }
            if provider == "gateway" && newapi_contract(&record) {
                provider = "newapi";
                gateway = "newapi".into();
            }
            let old = record
                .pointer("/provider_info/validation_provider")
                .or_else(|| record.pointer("/provider_info/provider"))
                .or_else(|| record.get("provider"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if old == provider
                && record
                    .get("gateway")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    == gateway
            {
                continue;
            }
            changed += 1;
            if !args.apply {
                continue;
            }
            let object = record.as_object_mut().context("record must be object")?;
            let info = object
                .entry("provider_info")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .context("provider_info must be object")?;
            info.insert("provider".into(), provider.into());
            info.insert("validation_provider".into(), provider.into());
            info.insert(
                "category".into(),
                if ["gateway", "newapi", "oneapi", "litellm", "openrouter"].contains(&provider) {
                    "gateway"
                } else {
                    resolved.spec.category
                }
                .into(),
            );
            if !["gateway", "unknown", "newapi", "oneapi", "litellm"].contains(&provider) {
                info.entry("credential_issuer")
                    .or_insert_with(|| provider.into());
            }
            if !gateway.is_empty() {
                object.insert("gateway".into(), gateway.into());
            }
            if table == "results" {
                sqlx::query("UPDATE results SET validation_provider=$2,credential_issuer=CASE WHEN credential_issuer IN ('','unknown','gateway') THEN $2 ELSE credential_issuer END,record=$3 WHERE id::text=$1").bind(key_value).bind(provider).bind(record).execute(pool).await?;
            } else {
                sqlx::query("UPDATE high_value_keys SET record=$2 WHERE apikey=$1")
                    .bind(key_value)
                    .bind(record)
                    .execute(pool)
                    .await?;
            }
        }
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"mode":mode,"scanned":scanned,"changed":changed}),
    )
}

async fn backfill_unknown_provider(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    patch_provider_rows(pool, args, "unknown").await
}

async fn fix_gateway_provider_hosts(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    patch_provider_rows(pool, args, "gateway-hosts").await
}

async fn backfill_routing_fields(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let rows = sqlx::query("SELECT id,apiurl,apikey,record FROM results WHERE ($1::text IS NULL OR run_id=$1) ORDER BY id LIMIT NULLIF($2,0)")
        .bind(&args.run_id)
        .bind(args.limit)
        .fetch_all(pool)
        .await?;
    let mut changed = 0usize;
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let apiurl: String = row
            .try_get::<Option<String>, _>("apiurl")?
            .unwrap_or_default();
        let apikey: String = row
            .try_get::<Option<String>, _>("apikey")?
            .unwrap_or_default();
        let official = if ["sk-proj", "sk-admin", "sk-svcacct"]
            .iter()
            .any(|prefix| apikey.starts_with(prefix))
        {
            Some("https://api.openai.com/v1")
        } else if ["sk-ant-api", "sk-ant-oat", "sk-ant-sid"]
            .iter()
            .any(|prefix| apikey.starts_with(prefix))
        {
            Some("https://api.anthropic.com/v1")
        } else if apikey.starts_with("AIza") {
            Some("https://generativelanguage.googleapis.com/v1beta")
        } else {
            None
        };
        let known = [
            "openai.com",
            "anthropic.com",
            "googleapis.com",
            "deepseek.com",
            "moonshot.cn",
            "bigmodel.cn",
            "siliconflow.cn",
            "dashscope.aliyuncs.com",
        ]
        .iter()
        .any(|domain| apiurl.contains(domain));
        let Some(official) = official.filter(|_| !known) else {
            continue;
        };
        changed += 1;
        if args.apply {
            let mut record: Value = row.try_get("record")?;
            let cred = record
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .context("credential must be object")?;
            let origin = official.trim_end_matches("/v1").trim_end_matches("/v1beta");
            cred.insert("leak_host".into(), apiurl.clone().into());
            cred.insert("routed_to_official".into(), true.into());
            cred.insert("apiurl".into(), official.into());
            cred.insert("host".into(), origin.into());
            cred.insert("ip".into(), "".into());
            cred.insert("port".into(), "".into());
            sqlx::query("UPDATE results SET apiurl=$2,host=$3,record=$4 WHERE id=$1")
                .bind(id)
                .bind(official)
                .bind(origin)
                .bind(record)
                .execute(pool)
                .await?;
        }
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"scanned":rows.len(),"routed":changed}),
    )
}

async fn purge_google(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let patterns: [(&str, &str); 4] = [
        ("results", "apiurl ILIKE $1"),
        ("high_value_keys", "record->>'apiurl' ILIKE $1"),
        ("scan_candidates", "apiurl ILIKE $1"),
        (
            "scan_validation_results",
            "record->'credential'->>'apiurl' ILIKE $1",
        ),
    ];
    let mut counts = Map::new();
    for (table, predicate) in patterns {
        let where_run = if args.run_id.is_some() {
            " AND run_id=$2"
        } else {
            ""
        };
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE {predicate}{where_run}");
        let mut query =
            sqlx::query_scalar::<_, i64>(&sql).bind("%generativelanguage.googleapis.com%");
        if let Some(run) = &args.run_id {
            query = query.bind(run)
        }
        let count = query.fetch_one(pool).await?;
        counts.insert(table.into(), count.into());
        if args.apply && count > 0 {
            let sql = format!("DELETE FROM {table} WHERE {predicate}{where_run}");
            let mut query = sqlx::query(&sql).bind("%generativelanguage.googleapis.com%");
            if let Some(run) = &args.run_id {
                query = query.bind(run)
            }
            query.execute(pool).await?;
        }
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        Value::Object(counts),
    )
}

fn host_level_reason(error: &str) -> Option<&str> {
    [
        "honeypot:no-auth-host",
        "honeypot:steganography",
        "honeypot:prompt-injection",
        "honeypot:response-cluster",
        "honeypot:429-indiscriminate",
        "honeypot:model-mismatch",
    ]
    .into_iter()
    .find(|prefix| error.to_ascii_lowercase().starts_with(prefix))
}
async fn backfill_honeypots(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let rows=sqlx::query("SELECT run_id,record FROM results WHERE ($1::text IS NULL OR run_id=$1) UNION ALL SELECT run_id,record FROM scan_validation_results WHERE ($1::text IS NULL OR run_id=$1)").bind(&args.run_id).fetch_all(pool).await?;
    let mut candidates = BTreeMap::new();
    for row in rows {
        let run_id: String = row.try_get("run_id")?;
        let record: Value = row.try_get("record")?;
        let error = record
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Some(reason) = host_level_reason(error) {
            let raw = record
                .pointer("/credential/host")
                .or_else(|| record.pointer("/credential/apiurl"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Ok(key) = url_sanitize::host_key(raw) {
                candidates.insert(key, (reason.to_owned(), run_id));
            }
        }
    }
    if args.limit > 0 {
        candidates = candidates.into_iter().take(args.limit as usize).collect()
    }
    if args.apply {
        for (host, (reason, run)) in &candidates {
            sqlx::query("INSERT INTO honeypot_sites(host_key,host,reason,source,run_id,record) VALUES($1,$1,$2,'auto',$3,$4) ON CONFLICT(host_key) DO UPDATE SET reason=EXCLUDED.reason,source='auto',run_id=EXCLUDED.run_id,last_seen=NOW(),record=EXCLUDED.record").bind(host).bind(reason).bind(run).bind(json!({"host_key":host,"reason":reason,"source":"auto","run_id":run})).execute(pool).await?;
        }
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"eligible_hosts":candidates.len(),"written_hosts":if args.apply{candidates.len()}else{0}}),
    )
}

async fn delete_empty_runs(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let rows=sqlx::query_scalar::<_,String>("SELECT r.run_id FROM runs r WHERE ($1::text IS NULL OR r.run_id=$1) AND COALESCE(r.raw_hits,0)=0 AND COALESCE(r.unique_targets,0)=0 AND NOT EXISTS(SELECT 1 FROM results x WHERE x.run_id=r.run_id AND x.kind IN ('valid','suspicious')) AND NOT EXISTS(SELECT 1 FROM high_value_keys h WHERE h.run_id=r.run_id) ORDER BY r.run_id LIMIT NULLIF($2,0)").bind(&args.run_id).bind(args.limit).fetch_all(pool).await?;
    if args.apply && !rows.is_empty() {
        sqlx::query("DELETE FROM runs WHERE run_id=ANY($1)")
            .bind(&rows)
            .execute(pool)
            .await?;
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"candidates":rows.len(),"deleted":if args.apply{rows.len()}else{0}}),
    )
}

async fn backfill_funnel(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let rows=sqlx::query("SELECT run_id,total_hosts,total_credentials,raw_hits,unique_targets,candidates,active_requests,final_verified,suspicious,high_value_final FROM runs WHERE ($1::text IS NULL OR run_id=$1) ORDER BY run_id LIMIT NULLIF($2,0)").bind(&args.run_id).bind(args.limit).fetch_all(pool).await?;
    let mut changed = 0;
    for row in &rows {
        let run: String = row.try_get("run_id")?;
        let valid: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM results WHERE run_id=$1 AND kind='valid'")
                .bind(&run)
                .fetch_one(pool)
                .await?;
        let suspicious: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM results WHERE run_id=$1 AND kind='suspicious'",
        )
        .bind(&run)
        .fetch_one(pool)
        .await?;
        let high: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM high_value_keys WHERE run_id=$1")
            .bind(&run)
            .fetch_one(pool)
            .await?;
        let total_hosts = row.try_get::<Option<i32>, _>("total_hosts")?.unwrap_or(0);
        let total_creds = row
            .try_get::<Option<i32>, _>("total_credentials")?
            .unwrap_or(0);
        if [
            row.try_get::<i32, _>("raw_hits")?,
            row.try_get("unique_targets")?,
            row.try_get("candidates")?,
            row.try_get("final_verified")?,
            row.try_get("suspicious")?,
            row.try_get("high_value_final")?,
        ]
        .iter()
        .zip([
            total_hosts,
            total_hosts,
            total_creds,
            valid as i32,
            suspicious as i32,
            high as i32,
        ])
        .any(|(old, new)| *old == 0 && new > 0)
        {
            changed += 1;
            if args.apply {
                sqlx::query("UPDATE runs SET raw_hits=CASE WHEN raw_hits=0 THEN $2 ELSE raw_hits END,unique_targets=CASE WHEN unique_targets=0 THEN $2 ELSE unique_targets END,candidates=CASE WHEN candidates=0 THEN $3 ELSE candidates END,final_verified=CASE WHEN final_verified=0 THEN $4 ELSE final_verified END,suspicious=CASE WHEN suspicious=0 THEN $5 ELSE suspicious END,high_value_final=CASE WHEN high_value_final=0 THEN $6 ELSE high_value_final END WHERE run_id=$1").bind(run).bind(total_hosts).bind(total_creds).bind(valid).bind(suspicious).bind(high).execute(pool).await?;
            }
        }
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"scanned":rows.len(),"changed":changed}),
    )
}

fn dirty_reason(record: &Value, args: &CleanArgs) -> Option<String> {
    let error = record
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let suspicious = record
        .get("suspicious_reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if error.starts_with("honeypot:")
        || error.starts_with("blocked-key-format:")
        || suspicious.starts_with("honeypot:")
    {
        return Some(if error.is_empty() { suspicious } else { error });
    }
    let key = credential(record)
        .get("apikey")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let url = credential(record)
        .get("apiurl")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if args.drop_gemini_free
        && (key.starts_with("AIza") || url.contains("generativelanguage.googleapis.com"))
    {
        return Some("gemini_free_or_google_key".into());
    }
    if record.get("gateway").and_then(Value::as_str) == Some("nexus") {
        let balance = record
            .get("balance")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if balance
            .parse::<f64>()
            .is_ok_and(|value| (50.0..=200.0).contains(&value))
        {
            return Some(format!("nexus_fake_balance:{balance}"));
        }
    }
    if args.aggressive {
        let models = record
            .pointer("/provider_info/models_available")
            .or_else(|| record.pointer("/provider_info/models_verified"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let official = [
            "openai.com",
            "anthropic.com",
            "googleapis.com",
            "openrouter.ai",
            "dashscope",
        ]
        .iter()
        .any(|domain| url.contains(domain));
        let low_tier_only = !models.is_empty()
            && models.iter().all(|model| {
                model.as_str().is_some_and(|model| {
                    ["gpt-3.5", "gpt-4", "gpt-4o-mini", "text-davinci"]
                        .iter()
                        .any(|prefix| model.contains(prefix))
                        && ![
                            "gpt-5",
                            "o1",
                            "o3",
                            "o4",
                            "claude-opus",
                            "claude-sonnet",
                            "gemini-2",
                            "gemini-3",
                            "deepseek-v",
                            "qwen3",
                            "glm-5",
                            "kimi-k2",
                        ]
                        .iter()
                        .any(|hint| model.contains(hint))
                })
            });
        if low_tier_only && !official {
            return Some("low_tier_only_models".into());
        }
    }
    None
}

async fn clean_false_valid(pool: &PgPool, args: &CleanArgs) -> Result<()> {
    let rows=sqlx::query("SELECT id,apikey,record FROM results WHERE kind='valid' AND ($1::text IS NULL OR run_id=$1) ORDER BY id LIMIT NULLIF($2,0)").bind(&args.common.run_id).bind(args.common.limit).fetch_all(pool).await?;
    let mut dirty = Vec::new();
    for row in &rows {
        let record: Value = row.try_get("record")?;
        if let Some(reason) = dirty_reason(&record, args) {
            dirty.push((
                row.try_get::<i64, _>("id")?,
                row.try_get::<Option<String>, _>("apikey")?
                    .unwrap_or_default(),
                record,
                reason,
            ));
        }
    }
    if args.common.apply {
        for (id, key, stored_record, reason) in &dirty {
            let mut record = stored_record.clone();
            if args.delete {
                sqlx::query("DELETE FROM results WHERE id=$1")
                    .bind(id)
                    .execute(pool)
                    .await?;
            } else {
                let object = record
                    .as_object_mut()
                    .context("result record must be an object")?;
                object.insert("valid".into(), false.into());
                object.insert("validation_state".into(), "no_auth_endpoint".into());
                object.insert("cleaned_reason".into(), reason.clone().into());
                object
                    .entry("error")
                    .or_insert_with(|| format!("cleaned:{reason}").into());
                sqlx::query("UPDATE results SET kind='rejected',valid=false,record=$2 WHERE id=$1")
                    .bind(id)
                    .bind(record)
                    .execute(pool)
                    .await?;
            }
            sqlx::query("DELETE FROM high_value_keys WHERE apikey=$1")
                .bind(key)
                .execute(pool)
                .await?;
        }
        sqlx::query("UPDATE runs r SET final_verified=(SELECT COUNT(*) FROM results x WHERE x.run_id=r.run_id AND x.kind='valid'),total_valid=(SELECT COUNT(*) FROM results x WHERE x.run_id=r.run_id AND x.kind='valid'),suspicious=(SELECT COUNT(*) FROM results x WHERE x.run_id=r.run_id AND x.kind='suspicious'),high_value_final=(SELECT COUNT(*) FROM high_value_keys h WHERE h.run_id=r.run_id) WHERE ($1::text IS NULL OR r.run_id=$1)").bind(&args.common.run_id).execute(pool).await?;
    }
    print_summary(
        if args.common.apply {
            "apply"
        } else {
            "dry-run"
        },
        json!({"scanned":rows.len(),"dirty":dirty.len(),"updated":if args.common.apply{dirty.len()}else{0}}),
    )
}

async fn reprobe_balance(
    pool: &PgPool,
    settings: &Settings,
    args: &ReprobeArgs,
    high_only: bool,
) -> Result<()> {
    let sql = if high_only {
        "SELECT NULL::bigint AS id,apikey,record FROM high_value_keys ORDER BY saved_at DESC LIMIT NULLIF($1,0)"
    } else {
        "SELECT id,apikey,record FROM results WHERE kind='valid' AND ($2::text IS NULL OR run_id=$2) ORDER BY id LIMIT NULLIF($1,0)"
    };
    let mut query = sqlx::query(sql).bind(args.common.limit);
    if !high_only {
        query = query.bind(&args.common.run_id);
    }
    let rows = query.fetch_all(pool).await?;
    let service = BalanceService::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs_f64(
                settings.validate_timeout,
            ))
            .build()?,
    );
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        settings.validate_concurrency.max(1),
    ));
    let mut tasks = tokio::task::JoinSet::new();
    for row in &rows {
        let record: Value = row.try_get("record")?;
        let cred: Credential = serde_json::from_value(credential(&record).clone())?;
        if args.only_anthropic
            && !cred.apikey.starts_with("sk-ant-")
            && !cred.apiurl.contains("anthropic.com")
        {
            continue;
        }
        if !args.force
            && record
                .get("gateway")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty() && value != "unsupported")
        {
            continue;
        }
        let service = service.clone();
        let semaphore = semaphore.clone();
        let id = row.try_get::<Option<i64>, _>("id")?;
        let key = row
            .try_get::<Option<String>, _>("apikey")?
            .unwrap_or_default();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            (id, key, record, service.query(&cred).await)
        });
    }
    let mut eligible = 0usize;
    while let Some(joined) = tasks.join_next().await {
        let Ok((id, key, mut record, balance)) = joined else {
            tracing::warn!("balance task failed in isolation");
            continue;
        };
        let balance = match balance {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error,"balance reprobe failed");
                continue;
            }
        };
        if balance.gateway.is_empty() || balance.gateway == "unsupported" {
            continue;
        }
        eligible += 1;
        if args.common.apply {
            let object = record.as_object_mut().context("record must be object")?;
            object.insert("gateway".into(), balance.gateway.clone().into());
            if !balance.balance_usd.is_empty() {
                object.insert("balance".into(), balance.balance_usd.clone().into());
            }
            if !balance.tier.is_empty() {
                object.insert("tier".into(), balance.tier.clone().into());
            }
            if high_only {
                sqlx::query("UPDATE high_value_keys SET record=$2 WHERE apikey=$1")
                    .bind(key)
                    .bind(record)
                    .execute(pool)
                    .await?;
            } else if let Some(id) = id {
                sqlx::query("UPDATE results SET record=$2 WHERE id=$1")
                    .bind(id)
                    .bind(record)
                    .execute(pool)
                    .await?;
            }
        }
    }
    print_summary(
        if args.common.apply {
            "apply"
        } else {
            "dry-run"
        },
        json!({"scanned":rows.len(),"eligible":eligible,"updated":if args.common.apply{eligible}else{0}}),
    )
}

async fn verify_high_value(pool: &PgPool, settings: &Settings, args: &ReprobeArgs) -> Result<()> {
    let rows = sqlx::query("SELECT apikey,record FROM high_value_keys WHERE ($1::text IS NULL OR run_id=$1) ORDER BY saved_at DESC LIMIT NULLIF($2,0)")
        .bind(&args.common.run_id)
        .bind(args.common.limit)
        .fetch_all(pool)
        .await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs_f64(
            settings.validate_timeout,
        ))
        .redirect(reqwest::redirect::Policy::limited(
            settings.max_probe_redirects,
        ))
        .no_proxy()
        .build()?;
    let validator = aipocket_prober::Validator::new(client.clone());
    let balances = BalanceService::new(client);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        settings.validate_concurrency.max(1),
    ));
    let mut tasks = tokio::task::JoinSet::new();
    for row in &rows {
        let key: String = row.try_get("apikey")?;
        let record: Value = row.try_get("record")?;
        let mut credential: Credential = serde_json::from_value(credential(&record).clone())?;
        if credential.apikey.is_empty() {
            credential.apikey = key.clone();
        }
        if credential.apikey.starts_with("sk-ant-") {
            credential.apiurl = "https://api.anthropic.com/v1".into();
        } else if credential.apikey.starts_with("sk-proj-")
            || credential.apikey.starts_with("sk-admin-")
            || credential.apikey.starts_with("sk-svcacct-")
        {
            credential.apiurl = "https://api.openai.com/v1".into();
        }
        if args.only_anthropic && !credential.apikey.starts_with("sk-ant-") {
            continue;
        }
        if credential.apiurl.is_empty() {
            continue;
        }
        let validator = validator.clone();
        let balances = balances.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let validation = validator.validate(credential.clone()).await;
            let balance = if validation
                .as_ref()
                .is_ok_and(|result| result.valid || result.status_code == Some(429))
            {
                balances.query(&credential).await.ok()
            } else {
                None
            };
            (key, record, validation, balance)
        });
    }
    let mut reports = Vec::new();
    let mut alive = 0usize;
    while let Some(joined) = tasks.join_next().await {
        let Ok((key, mut record, validation, balance)) = joined else {
            continue;
        };
        let (is_alive, status_code, error) = match validation {
            Ok(validation) => (
                validation.valid || validation.status_code == Some(429),
                validation.status_code,
                validation.error,
            ),
            Err(error) => (false, None, error.to_string()),
        };
        alive += usize::from(is_alive);
        let gateway = balance
            .as_ref()
            .map(|value| value.gateway.as_str())
            .unwrap_or_default();
        let balance_usd = balance
            .as_ref()
            .map(|value| value.balance_usd.as_str())
            .unwrap_or_default();
        if args.common.apply {
            let object = record.as_object_mut().context("record must be object")?;
            object.insert(
                "last_verified".into(),
                chrono::Utc::now().to_rfc3339().into(),
            );
            object.insert(
                "status_code".into(),
                status_code.map_or(Value::Null, |value| value.into()),
            );
            object.insert("valid".into(), is_alive.into());
            object.insert("verification_error".into(), error.clone().into());
            if !gateway.is_empty() {
                object.insert("gateway".into(), gateway.into());
            }
            if !balance_usd.is_empty() {
                object.insert("balance".into(), balance_usd.into());
            }
            sqlx::query("UPDATE high_value_keys SET record=$2 WHERE apikey=$1")
                .bind(&key)
                .bind(&record)
                .execute(pool)
                .await?;
        }
        reports.push(json!({"apikey":mask_key(&key),"status_code":status_code,"alive":is_alive,"error":error,"gateway":gateway,"balance":balance_usd}));
    }
    print_summary(
        if args.common.apply {
            "apply"
        } else {
            "dry-run"
        },
        json!({"scanned":rows.len(),"tested":reports.len(),"alive":alive,"dead":reports.len()-alive,"results":reports}),
    )
}

fn mask_key(key: &str) -> String {
    if key.len() <= 12 {
        return "***".into();
    }
    format!("{}…{}", &key[..8], &key[key.len() - 4..])
}

async fn dedup_stats(settings: &Settings) -> Result<()> {
    let client = redis::Client::open(settings.dedup_redis_url.clone())?;
    let mut conn = redis::aio::ConnectionManager::new(client).await?;
    let mut output = Map::new();
    for (label, pattern) in [
        ("host", "aipocket:dedup:host:*"),
        ("target", "aipocket:dedup:target:*"),
        ("cred_ok", "aipocket:dedup:cred:ok:*"),
        ("cred_outcome", "aipocket:dedup:cred:outcome:*"),
        ("cred_balance", "aipocket:dedup:cred:bal:*"),
    ] {
        let mut cursor = 0u64;
        let mut count = 0usize;
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(1000)
                .query_async(&mut conn)
                .await?;
            count += keys.len();
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        output.insert(label.into(), count.into());
    }
    println!("{}", serde_json::to_string_pretty(&Value::Object(output))?);
    Ok(())
}

async fn import_jsonl(pool: &PgPool, root: PathBuf, apply: bool) -> Result<()> {
    let repository = aipocket_db::Repository::new(Some(pool.clone()));
    let mut runs = 0usize;
    let mut records = 0usize;
    let mut high_value = 0usize;
    let mut cves = 0usize;
    if root.is_dir() {
        for entry in std::fs::read_dir(&root)? {
            let path = entry?.path();
            if !path.is_dir()
                || !path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with("run_"))
            {
                continue;
            }
            let run_id = path
                .file_name()
                .context("run directory name")?
                .to_string_lossy()
                .into_owned();
            let mut metadata = json!({});
            for file in files_with_prefix(&path, "scan")? {
                if let Some(line) = std::fs::read_to_string(file)?
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    && let Ok(value) = serde_json::from_str::<Value>(line)
                {
                    metadata = value;
                    break;
                }
            }
            let mut rows = BTreeMap::<String, Vec<Value>>::new();
            for kind in ["valid", "suspicious"] {
                for file in files_with_prefix(&path, kind)? {
                    for line in std::fs::read_to_string(file)?
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                    {
                        if let Ok(record) = serde_json::from_str::<Value>(line) {
                            rows.entry(kind.into()).or_default().push(record);
                            records += 1;
                        }
                    }
                }
            }
            if apply {
                let started = metadata
                    .get("started_at")
                    .and_then(Value::as_str)
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    .map(|value| value.with_timezone(&chrono::Utc))
                    .unwrap_or_else(chrono::Utc::now);
                sqlx::query("INSERT INTO runs(run_id,started_at,finished_at,state,scan_mode,sources,hits_by_source,queries_used,total_hosts,total_credentials,total_valid,raw_hits,unique_targets,candidates,active_requests,final_verified,suspicious,high_value_final,log) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT(run_id) DO UPDATE SET started_at=EXCLUDED.started_at,finished_at=EXCLUDED.finished_at,state=EXCLUDED.state,scan_mode=EXCLUDED.scan_mode,sources=EXCLUDED.sources,hits_by_source=EXCLUDED.hits_by_source,queries_used=EXCLUDED.queries_used,total_hosts=EXCLUDED.total_hosts,total_credentials=EXCLUDED.total_credentials,total_valid=EXCLUDED.total_valid,raw_hits=EXCLUDED.raw_hits,unique_targets=EXCLUDED.unique_targets,candidates=EXCLUDED.candidates,active_requests=EXCLUDED.active_requests,final_verified=EXCLUDED.final_verified,suspicious=EXCLUDED.suspicious,high_value_final=EXCLUDED.high_value_final,log=EXCLUDED.log")
                    .bind(&run_id)
                    .bind(started)
                    .bind(metadata.get("finished_at").and_then(Value::as_str).and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok()).map(|value| value.with_timezone(&chrono::Utc)))
                    .bind(metadata.get("state").and_then(Value::as_str).unwrap_or("finished"))
                    .bind(metadata.get("scan_mode").and_then(Value::as_str).unwrap_or("incremental"))
                    .bind(metadata.get("sources").cloned().unwrap_or_else(|| json!([])))
                    .bind(metadata.get("hits_by_source").cloned().unwrap_or_else(|| json!({})))
                    .bind(metadata.get("queries_used").cloned().unwrap_or_else(|| json!([])))
                    .bind(metadata.get("total_hosts").and_then(Value::as_i64))
                    .bind(metadata.get("total_credentials").and_then(Value::as_i64))
                    .bind(rows.get("valid").map_or(0_i64, |values| values.len() as i64))
                    .bind(metadata.get("raw_hits").or_else(|| metadata.get("raw_hits_count")).and_then(Value::as_i64).unwrap_or_else(|| metadata.get("total_hosts").and_then(Value::as_i64).unwrap_or(0)))
                    .bind(metadata.get("unique_targets").and_then(Value::as_i64).unwrap_or_else(|| metadata.get("total_hosts").and_then(Value::as_i64).unwrap_or(0)))
                    .bind(metadata.get("candidates").and_then(Value::as_i64).unwrap_or(0))
                    .bind(metadata.get("active_requests").and_then(Value::as_i64).unwrap_or(0))
                    .bind(metadata.get("final_verified").and_then(Value::as_i64).unwrap_or_else(|| rows.get("valid").map_or(0, |values| values.len() as i64)))
                    .bind(metadata.get("suspicious").and_then(Value::as_i64).unwrap_or_else(|| rows.get("suspicious").map_or(0, |values| values.len() as i64)))
                    .bind(metadata.get("high_value_final").and_then(Value::as_i64).unwrap_or(0))
                    .bind(std::fs::read_to_string(path.join("run.log")).ok())
                    .execute(pool).await?;
                sqlx::query("DELETE FROM results WHERE run_id=$1")
                    .bind(&run_id)
                    .execute(pool)
                    .await?;
                for (kind, values) in &rows {
                    repository.insert_results(&run_id, kind, values).await?;
                }
            }
            runs += 1;
        }
        let high_path = root.join("high_value_keys/keys.jsonl");
        if high_path.is_file() {
            let mut by_key = BTreeMap::new();
            for line in std::fs::read_to_string(high_path)?
                .lines()
                .filter(|line| !line.trim().is_empty())
            {
                if let Ok(record) = serde_json::from_str::<Value>(line)
                    && let Some(key) = record.get("apikey").and_then(Value::as_str)
                {
                    by_key.insert(key.to_owned(), record);
                }
            }
            high_value = by_key.len();
            if apply {
                for (key, record) in by_key {
                    let run_id = record
                        .get("run_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let saved_at = record
                        .get("saved_at")
                        .and_then(Value::as_str)
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                        .map(|value| value.with_timezone(&chrono::Utc));
                    sqlx::query("INSERT INTO high_value_keys(apikey,run_id,saved_at,record) VALUES($1,NULLIF($2,''),COALESCE($3,NOW()),$4) ON CONFLICT(apikey) DO UPDATE SET run_id=EXCLUDED.run_id,saved_at=EXCLUDED.saved_at,record=EXCLUDED.record")
                        .bind(key).bind(run_id).bind(saved_at).bind(record).execute(pool).await?;
                }
            }
        }
    }
    for candidate in [
        root.parent()
            .unwrap_or(&root)
            .join("sources/cve_2026_ai.json"),
        PathBuf::from("crates/aipocket-db/data/cve_seed.json"),
    ] {
        if let Ok(values) = std::fs::read_to_string(candidate).and_then(|text| {
            serde_json::from_str::<Vec<Value>>(&text).map_err(std::io::Error::other)
        }) {
            cves = values.len();
            if apply {
                for value in values {
                    repository.upsert_cve(&value).await?;
                }
            }
            break;
        }
    }
    print_summary(
        if apply { "apply" } else { "dry-run" },
        json!({"runs":runs,"records":records,"high_value":high_value,"cves":cves}),
    )
}
fn files_with_prefix(path: &Path, kind: &str) -> Result<Vec<PathBuf>> {
    let prefix = format!("{kind}_");
    let mut files = std::fs::read_dir(path)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|v| v.to_str()) == Some("jsonl")
                && path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .is_some_and(|name| name.starts_with(&prefix))
        })
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}
async fn verify_honeypot_jsonl(
    input: &Path,
    pool: Option<&PgPool>,
    settings: &Settings,
    limit: i64,
    apply: bool,
) -> Result<()> {
    let mut records = Vec::new();
    for line in std::fs::read_to_string(input)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        if let Ok(record) = serde_json::from_str::<Value>(line)
            && record
                .get("credential")
                .and_then(Value::as_object)
                .is_some()
        {
            records.push(record);
            if limit > 0 && records.len() >= limit as usize {
                break;
            }
        }
    }
    let mut by_host = BTreeMap::<String, (Credential, Vec<Value>)>::new();
    for record in records {
        let credential: Credential = serde_json::from_value(credential(&record).clone())?;
        let host = url_sanitize::host_key(if credential.host.is_empty() {
            &credential.apiurl
        } else {
            &credential.host
        })
        .unwrap_or_else(|_| credential.apiurl.clone());
        by_host
            .entry(host)
            .or_insert_with(|| (credential, Vec::new()))
            .1
            .push(record);
    }
    let validator = aipocket_prober::Validator::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs_f64(
                settings.validate_timeout,
            ))
            .redirect(reqwest::redirect::Policy::limited(
                settings.max_probe_redirects,
            ))
            .no_proxy()
            .build()?,
    );
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        settings.validate_concurrency.max(1),
    ));
    let mut tasks = tokio::task::JoinSet::new();
    for (host, (mut credential, host_records)) in by_host {
        credential.apikey = format!("aipocket-forged-{}", uuid::Uuid::new_v4().simple());
        let validator = validator.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            (host, host_records, validator.validate(credential).await)
        });
    }
    let mut no_auth = Vec::new();
    let mut suspicious = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let Ok((host, host_records, validation)) = joined else {
            continue;
        };
        match validation {
            Ok(result) if result.valid => no_auth.push((host, host_records)),
            Ok(result) if result.status_code == Some(429) || result.status_code == Some(200) => {
                suspicious.push((host, host_records))
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "honeypot replay failed"),
        }
    }
    if apply {
        let pool = pool.context("DATABASE_URL or --database-url is required with --apply")?;
        for (host, host_records) in &no_auth {
            for record in host_records {
                let key = credential(record)
                    .get("apikey")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !key.is_empty() {
                    sqlx::query("UPDATE results SET kind='rejected',valid=false,record=jsonb_set(jsonb_set(record,'{valid}','false'::jsonb),'{error}',to_jsonb('honeypot:no-auth-host'::text)) WHERE apikey=$1 AND kind='valid'").bind(key).execute(pool).await?;
                    sqlx::query("DELETE FROM high_value_keys WHERE apikey=$1")
                        .bind(key)
                        .execute(pool)
                        .await?;
                }
            }
            sqlx::query("INSERT INTO honeypot_sites(host_key,host,reason,source,record) VALUES($1,$1,'honeypot:no-auth-host','jsonl-replay',$2) ON CONFLICT(host_key) DO UPDATE SET last_seen=NOW(),hit_count=honeypot_sites.hit_count+1,record=EXCLUDED.record")
                .bind(host).bind(json!({"host_key":host,"reason":"honeypot:no-auth-host","input":input})).execute(pool).await?;
        }
    }
    print_summary(
        if apply { "apply" } else { "dry-run" },
        json!({"input":input,"hosts":no_auth.len()+suspicious.len(),"no_auth_hosts":no_auth.iter().map(|(host,_)| host).collect::<Vec<_>>(),"suspicious_hosts":suspicious.iter().map(|(host,_)| host).collect::<Vec<_>>(),"voided_records":if apply{no_auth.iter().map(|(_,records)|records.len()).sum::<usize>()}else{0}}),
    )
}

async fn verify_honeypots(
    pool: &PgPool,
    settings: &Settings,
    limit: i64,
    apply: bool,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT id,record FROM results WHERE kind='valid' ORDER BY id LIMIT NULLIF($1,0)",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let validator = aipocket_prober::Validator::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs_f64(
                settings.validate_timeout,
            ))
            .build()?,
    );
    let mut dirty = Vec::new();
    for row in rows {
        let record: Value = row.try_get("record")?;
        let credential: Credential = serde_json::from_value(credential(&record).clone())?;
        let mut forged = credential.clone();
        forged.apikey = format!("aipocket-forged-{}", uuid::Uuid::new_v4().simple());
        if validator
            .validate(forged)
            .await
            .is_ok_and(|result| result.valid)
        {
            dirty.push((
                row.try_get::<i64, _>("id")?,
                credential.host.clone(),
                credential.apiurl.clone(),
            ));
        }
    }
    if apply {
        for (id, host, apiurl) in &dirty {
            sqlx::query("UPDATE results SET kind='rejected',valid=false,record=jsonb_set(jsonb_set(record,'{valid}','false'::jsonb),'{error}',to_jsonb('honeypot:no-auth-host'::text)) WHERE id=$1").bind(id).execute(pool).await?;
            if let Ok(key) = url_sanitize::host_key(if host.is_empty() { apiurl } else { host }) {
                sqlx::query("INSERT INTO honeypot_sites(host_key,host,reason,source,record) VALUES($1,$1,'honeypot:no-auth-host','auto',$2) ON CONFLICT(host_key) DO NOTHING").bind(&key).bind(json!({"host_key":key,"reason":"honeypot:no-auth-host"})).execute(pool).await?;
            }
        }
    }
    print_summary(
        if apply { "apply" } else { "dry-run" },
        json!({"confirmed_no_auth":dirty.len(),"updated":if apply{dirty.len()}else{0}}),
    )
}
async fn reconcile_high_value(pool: &PgPool, args: &CommonArgs) -> Result<()> {
    let stale = sqlx::query_scalar::<_, String>("SELECT h.apikey FROM high_value_keys h WHERE ($1::text IS NULL OR h.run_id=$1) AND NOT EXISTS (SELECT 1 FROM results r WHERE r.apikey=h.apikey AND r.kind='valid' AND r.valid)")
        .bind(&args.run_id).fetch_all(pool).await?;
    if args.apply && !stale.is_empty() {
        sqlx::query("DELETE FROM high_value_keys WHERE apikey=ANY($1)")
            .bind(&stale)
            .execute(pool)
            .await?;
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"stale":stale.len(),"deleted":if args.apply{stale.len()}else{0}}),
    )
}
async fn verify_gpt(pool: &PgPool, settings: &Settings, args: &VerifyGptArgs) -> Result<()> {
    let rows = sqlx::query("SELECT id,record FROM results WHERE kind='valid' AND ($1::text IS NULL OR run_id=$1) ORDER BY id LIMIT NULLIF($2,0)")
        .bind(&args.run_id)
        .bind(args.limit)
        .fetch_all(pool)
        .await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs_f64(
            settings.validate_timeout,
        ))
        .redirect(reqwest::redirect::Policy::limited(
            settings.max_probe_redirects,
        ))
        .no_proxy()
        .build()?;
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        settings.gpt_recheck_concurrency.max(1),
    ));
    let mut tasks = tokio::task::JoinSet::new();
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let record: Value = row.try_get("record")?;
        let credential: Credential = serde_json::from_value(credential(&record).clone())?;
        if credential.apikey.is_empty() || credential.apiurl.is_empty() {
            continue;
        }
        let mut urls = vec![credential.apiurl.clone()];
        if credential.apikey.starts_with("sk-proj-")
            && !credential.apiurl.contains("api.openai.com")
        {
            urls.push("https://api.openai.com/v1".into());
        }
        let client = client.clone();
        let models = args.models.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let tests = verify_gpt_credential(&client, &credential, &urls, &models).await;
            (id, record, tests)
        });
    }
    let mut reports = Vec::new();
    let mut summary = BTreeMap::<String, usize>::new();
    while let Some(joined) = tasks.join_next().await {
        let Ok((id, mut record, tests)) = joined else {
            continue;
        };
        let verdict = gpt_verdict(&tests);
        *summary.entry(verdict.into()).or_default() += 1;
        if args.apply {
            let object = record.as_object_mut().context("record must be object")?;
            object.insert(
                "gpt_verification".into(),
                json!({"checked_at":chrono::Utc::now(),"verdict":verdict,"tests":tests}),
            );
            sqlx::query("UPDATE results SET record=$2 WHERE id=$1")
                .bind(id)
                .bind(&record)
                .execute(pool)
                .await?;
        }
        reports.push(json!({"result_id":id,"verdict":verdict,"tests":tests}));
    }
    print_summary(
        if args.apply { "apply" } else { "dry-run" },
        json!({"scanned":rows.len(),"tested":reports.len(),"summary":summary,"results":reports}),
    )
}

async fn verify_gpt_credential(
    client: &reqwest::Client,
    credential: &Credential,
    urls: &[String],
    models: &[String],
) -> Vec<Value> {
    let mut tests = Vec::new();
    for base in urls {
        let endpoint = canonicalize_endpoint(base, "gateway")
            .map(|value| format!("{}/chat/completions", value.api_base.trim_end_matches('/')))
            .unwrap_or_else(|_| format!("{}/chat/completions", base.trim_end_matches('/')));
        for model in models {
            let response = client.post(&endpoint).bearer_auth(&credential.apikey).json(&json!({"model":model,"messages":[{"role":"user","content":"Say exactly: hello world"}],"max_tokens":10,"stream":false})).send().await;
            let test = match response {
                Ok(response) => {
                    let status_code = response.status().as_u16();
                    let body: Value = response
                        .json()
                        .await
                        .unwrap_or_else(|error| json!({"decode_error":error.to_string()}));
                    let content = body
                        .pointer("/choices/0/message/content")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let zero_width = content
                        .chars()
                        .filter(|character| {
                            matches!(
                                character,
                                '\u{200b}'
                                    | '\u{200c}'
                                    | '\u{200d}'
                                    | '\u{200e}'
                                    | '\u{200f}'
                                    | '\u{2060}'
                                    | '\u{feff}'
                            )
                        })
                        .count();
                    let status = if status_code == 200
                        && body.get("choices").and_then(Value::as_array).is_some()
                    {
                        "success"
                    } else if status_code == 429 {
                        "rate_limited"
                    } else if matches!(status_code, 401 | 403) {
                        "unauthorized"
                    } else if status_code == 404 {
                        "model_not_found"
                    } else {
                        "http_error"
                    };
                    json!({"url":endpoint,"model":model,"status_code":status_code,"status":status,"response":content.chars().take(200).collect::<String>(),"model_used":body.get("model"),"steganography":zero_width > 5})
                }
                Err(error) => {
                    json!({"url":endpoint,"model":model,"status":"transport_error","error":error.to_string()})
                }
            };
            let terminal = matches!(
                test.get("status").and_then(Value::as_str),
                Some("success" | "unauthorized")
            );
            tests.push(test);
            if terminal {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    tests
}

fn gpt_verdict(tests: &[Value]) -> &'static str {
    if tests
        .iter()
        .any(|test| test.get("status").and_then(Value::as_str) == Some("success"))
    {
        "LIVE_GPT"
    } else if tests
        .iter()
        .any(|test| test.get("status").and_then(Value::as_str) == Some("rate_limited"))
    {
        "RATE_LIMITED"
    } else if tests
        .iter()
        .any(|test| test.get("status").and_then(Value::as_str) == Some("unauthorized"))
    {
        "DEAD"
    } else if tests
        .iter()
        .any(|test| test.get("status").and_then(Value::as_str) == Some("model_not_found"))
    {
        "NO_MODEL_ACCESS"
    } else {
        "UNKNOWN"
    }
}

async fn retry_failed_batches(settings: &Settings, run_id: &str) -> Result<()> {
    let pool = pool(settings).await?;
    let repository = aipocket_db::Repository::new(Some(pool));
    let analyzer = aipocket_services::Analyzer::new(
        std::sync::Arc::new(settings.clone()),
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs_f64(
                settings.validate_timeout,
            ))
            .no_proxy()
            .build()?,
    );
    let report = analyzer
        .retry_failed(run_id, &settings.results_path().join(run_id), &repository)
        .await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn carve_realtest(input: &Path, output: &Path, limit: usize, apply: bool) -> Result<()> {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(input)?)?;
    let mut tagged = value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|cve| cve.get("id").and_then(Value::as_str).is_some() && cve_is_carvable(cve))
        .map(|cve| {
            (
                prober_for_product(
                    cve.get("product")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                cve,
            )
        })
        .collect::<Vec<_>>();
    tagged.sort_by(|left, right| {
        cve_priority(&left.1)
            .cmp(&cve_priority(&right.1))
            .then_with(|| cve_cvss(&right.1).total_cmp(&cve_cvss(&left.1)))
            .then_with(|| cve_id(&left.1).cmp(cve_id(&right.1)))
    });
    let mut selected = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut covered = std::collections::BTreeSet::new();
    for (prober, cve) in &tagged {
        let Some(prober) = prober else { continue };
        if covered.insert(*prober) && ids.insert(cve_id(cve).to_owned()) {
            selected.push(cve.clone());
            if selected.len() >= limit {
                break;
            }
        }
    }
    for (_, cve) in &tagged {
        if selected.len() >= limit {
            break;
        }
        if ids.insert(cve_id(cve).to_owned()) {
            selected.push(cve.clone());
        }
    }
    anyhow::ensure!(!selected.is_empty(), "no carvable CVEs found");
    let all_products = REALTEST_PRODUCT_MARKERS
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::BTreeSet<_>>();
    let missing = all_products
        .difference(&covered)
        .copied()
        .collect::<Vec<_>>();
    if apply {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            output,
            format!("{}\n", serde_json::to_string_pretty(&selected)?),
        )?;
    }
    print_summary(
        if apply { "apply" } else { "dry-run" },
        json!({"input":input,"output":output,"selected":selected.len(),"covered":covered,"missing":missing,"records":selected}),
    )
}

const REALTEST_PRODUCT_MARKERS: &[(&str, &[&str])] = &[
    (
        "anythingllm",
        &["anythingllm", "anything llm", "mintplexlabs"],
    ),
    (
        "chatgpt-next-web",
        &["nextchat", "chatgpt-next-web", "chatgpt next web"],
    ),
    ("dify", &["dify"]),
    ("fastgpt", &["fastgpt", "fast-gpt", "fast gpt"]),
    ("flowise", &["flowise", "flowiseai"]),
    ("langflow", &["langflow"]),
    ("librechat", &["librechat"]),
    ("litellm", &["litellm", "x-litellm"]),
    ("lobechat", &["lobe-chat", "lobechat", "lobehub"]),
    ("newapi", &["new-api", "new api", "newapi"]),
    ("oneapi", &["one-api", "one api", "oneapi"]),
    ("openrouter", &["openrouter", "open router", "sk-or-v1"]),
    ("openwebui", &["open webui", "open-webui", "openwebui"]),
    ("portkey", &["portkey"]),
];

fn prober_for_product(product: &str) -> Option<&'static str> {
    let normalized = product.to_ascii_lowercase();
    REALTEST_PRODUCT_MARKERS.iter().find_map(|(name, markers)| {
        markers
            .iter()
            .any(|marker| normalized.contains(marker))
            .then_some(*name)
    })
}

fn cve_priority(cve: &Value) -> u8 {
    match cve.get("type").and_then(Value::as_str).unwrap_or_default() {
        "API key泄露" | "信息泄露" | "认证绕过" => 1,
        "RCE" | "权限提升" | "SQL注入" => 2,
        "SSRF" | "沙箱逃逸" => 3,
        "DoS" => 5,
        _ => 9,
    }
}

fn cve_is_carvable(cve: &Value) -> bool {
    let product = cve
        .get("product")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    cve_priority(cve) <= 3
        && !["langgraph", "langsmith"]
            .iter()
            .any(|skip| product.contains(skip))
        && prober_for_product(&product).is_some()
}

fn cve_cvss(cve: &Value) -> f64 {
    cve.get("cvss").and_then(Value::as_f64).unwrap_or_default()
}

fn cve_id(cve: &Value) -> &str {
    cve.get("id")
        .or_else(|| cve.get("cve_id"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}
const SHODAN_FILTERS: &[(&str, &[&str])] = &[
    (
        "dify_html",
        &[
            "http.html:\"dify\"",
            "http.html:\"dify\" http.html:\"api_key\"",
        ],
    ),
    (
        "dify_title_component",
        &[
            "http.title:\"Dify\"",
            "http.title:\"dify\"",
            "http.component:\"dify\"",
            "http.component:\"Dify\"",
        ],
    ),
    (
        "dify_favicon_ssl",
        &[
            "http.favicon.hash:-890583488",
            "http.favicon.hash:2042235418",
            "ssl.cert.subject.cn:\"dify\"",
            "hostname:\"dify\"",
        ],
    ),
    (
        "other_llm_gateways",
        &[
            "http.title:\"New API\"",
            "http.title:\"One API\"",
            "http.component:\"new-api\"",
            "http.title:\"LiteLLM\"",
            "http.title:\"LobeChat\"",
            "http.title:\"Open WebUI\"",
            "http.title:\"FastGPT\"",
            "http.title:\"Flowise\"",
            "http.title:\"Langflow\"",
            "http.title:\"LibreChat\"",
        ],
    ),
];

async fn shodan_filter_probe(settings: &Settings, query: Option<&str>) -> Result<()> {
    let client = aipocket_clients::ShodanClient::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs_f64(settings.shodan_timeout))
            .build()?,
        settings,
    );
    let filters = if let Some(query) = query {
        vec![("custom", query)]
    } else {
        SHODAN_FILTERS
            .iter()
            .flat_map(|(group, queries)| queries.iter().map(move |query| (*group, *query)))
            .collect()
    };
    let mut rows = Vec::with_capacity(filters.len());
    for (index, (group, query)) in filters.into_iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        }
        match client.count(query).await {
            Ok(total) => rows.push(json!({"group":group,"query":query,"total":total})),
            Err(error) => rows.push(json!({"group":group,"query":query,"error":error.to_string()})),
        }
    }
    rows.sort_by(|left, right| {
        right
            .get("total")
            .and_then(Value::as_i64)
            .unwrap_or(-1)
            .cmp(&left.get("total").and_then(Value::as_i64).unwrap_or(-1))
    });
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}

async fn resume_raw_hits(path: PathBuf, settings: Settings) -> Result<()> {
    let hits = std::fs::read_to_string(&path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    anyhow::ensure!(!hits.is_empty(), "raw hits file is empty or invalid");
    let pg = aipocket_db::connect_pg(&settings).await?;
    if let Some(pool) = &pg {
        aipocket_db::ensure_schema(pool).await?;
    }
    let repository = aipocket_db::Repository::new(pg);
    let scanner = aipocket_services::Scanner::new(
        std::sync::Arc::new(settings.clone()),
        repository,
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs_f64(
                settings.validate_timeout,
            ))
            .redirect(reqwest::redirect::Policy::limited(
                settings.max_probe_redirects,
            ))
            .no_proxy()
            .build()?,
    );
    let source = std::sync::Arc::new(RawHitsSource { hits });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let reporter = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            tracing::info!(?event, "raw hits resume");
        }
    });
    let run_id = scanner
        .run(
            vec![source],
            aipocket_core::ScanMode::Incremental,
            tokio_util::sync::CancellationToken::new(),
            tx,
        )
        .await?;
    reporter.abort();
    println!("{run_id}");
    Ok(())
}

struct RawHitsSource {
    hits: Vec<Value>,
}

#[async_trait::async_trait]
impl aipocket_discovery::DiscoverySource for RawHitsSource {
    fn name(&self) -> &'static str {
        "raw_hits"
    }
    fn is_configured(&self) -> bool {
        !self.hits.is_empty()
    }
    async fn fetch(
        &self,
        _: &aipocket_discovery::SourceBudgets,
        _: aipocket_core::ScanMode,
    ) -> Result<aipocket_discovery::SourceFetchResult> {
        Ok(aipocket_discovery::SourceFetchResult {
            source: "raw_hits".into(),
            host_hit_count: Some(self.hits.len() as u64),
            host_hits: self.hits.clone(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};

    #[test]
    fn realtest_carving_prefers_product_coverage() {
        let input = tempfile::NamedTempFile::new().unwrap();
        let output = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            input.path(),
            serde_json::to_string(&json!([
                {"id":"CVE-DIFY-HIGH","product":"Dify","type":"RCE","cvss":9.9},
                {"id":"CVE-DIFY-LEAK","product":"Dify","type":"API key泄露","cvss":1.0},
                {"id":"CVE-FLOWISE","product":"Flowise","type":"SSRF","cvss":8.0},
                {"id":"CVE-SKIP","product":"LangGraph","type":"RCE","cvss":10.0}
            ]))
            .unwrap(),
        )
        .unwrap();
        carve_realtest(input.path(), output.path(), 2, true).unwrap();
        let selected: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(output.path()).unwrap()).unwrap();
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().any(|value| value["product"] == "Dify"));
        assert!(selected.iter().any(|value| value["product"] == "Flowise"));
    }

    #[tokio::test]
    async fn gpt_probe_classifies_success_and_steganography() {
        async fn chat() -> Json<Value> {
            Json(
                json!({"model":"gpt-fixture","choices":[{"message":{"content":"hello\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}\u{200b}"}}]}),
            )
        }
        let app = Router::new().route("/v1/chat/completions", post(chat));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let tests = verify_gpt_credential(
            &reqwest::Client::new(),
            &Credential {
                apikey: "sk-fixture".into(),
                apiurl: base.clone(),
                ..Default::default()
            },
            &[base],
            &["gpt-fixture".into()],
        )
        .await;
        assert_eq!(gpt_verdict(&tests), "LIVE_GPT");
        assert_eq!(tests[0]["steganography"], true);
        server.abort();
    }

    #[tokio::test]
    async fn honeypot_jsonl_replay_probes_each_host_once() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        async fn models(
            axum::extract::State(calls): axum::extract::State<Arc<AtomicUsize>>,
        ) -> Json<Value> {
            calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({"data":[{"id":"fixture"}]}))
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/v1/models", axum::routing::get(models))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let input = tempfile::NamedTempFile::new().unwrap();
        let record =
            json!({"valid":true,"credential":{"apikey":"sk-real","apiurl":base,"host":base}});
        std::fs::write(input.path(), format!("{}\n{}\n", record, record)).unwrap();
        let settings = Settings {
            validate_timeout: 2.0,
            ..Settings::default()
        };
        verify_honeypot_jsonl(input.path(), None, &settings, 0, false)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }
}
