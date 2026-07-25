use anyhow::{Context, Result};
use sqlx::{Executor, PgPool, postgres::PgPoolOptions};

use aipocket_core::Settings;

pub async fn connect_pg(settings: &Settings) -> Result<Option<PgPool>> {
    if !settings.pg_enabled() {
        return Ok(None);
    }
    let pool = PgPoolOptions::new()
        .min_connections(settings.pg_pool_min)
        .max_connections(settings.pg_pool_max)
        .connect(&settings.database_url)
        .await
        .context("connect PostgreSQL")?;
    Ok(Some(pool))
}

pub async fn ensure_schema(pool: &PgPool) -> Result<()> {
    pool.execute(include_str!("../../../migrations/schema.sql"))
        .await
        .context("ensure PostgreSQL schema")?;
    Ok(())
}
