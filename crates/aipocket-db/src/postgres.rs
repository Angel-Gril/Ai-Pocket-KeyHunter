use anyhow::{Context, Result};
use sqlx::{Executor, PgPool, postgres::PgPoolOptions};

const SCHEMA_LOCK_KEY: i64 = 0x4149_504f_434b_4554;

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
    // CREATE TABLE IF NOT EXISTS is not race-free when two fresh processes
    // initialize the same PostgreSQL schema concurrently. Serialize the whole
    // idempotent schema transaction across backend/worker/test processes.
    let mut transaction = pool
        .begin()
        .await
        .context("begin PostgreSQL schema transaction")?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SCHEMA_LOCK_KEY)
        .execute(&mut *transaction)
        .await
        .context("lock PostgreSQL schema initialization")?;
    transaction
        .execute(include_str!("../../../migrations/schema.sql"))
        .await
        .context("ensure PostgreSQL schema")?;
    transaction
        .commit()
        .await
        .context("commit PostgreSQL schema transaction")?;
    Ok(())
}
