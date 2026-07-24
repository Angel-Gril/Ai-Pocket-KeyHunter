use std::time::Duration;

use anyhow::{Context, Result, bail};
use redis::aio::ConnectionManager;
use tokio::{task::JoinHandle, time};
use tracing::warn;
use uuid::Uuid;

use aipocket_core::Settings;

pub const LOCK_KEY: &str = "aipocket:scan:lock";
const RENEW_SCRIPT: &str = "if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('pexpire',KEYS[1],ARGV[2]) end return 0";
const RELEASE_SCRIPT: &str =
    "if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('del',KEYS[1]) end return 0";

pub struct ScanLease {
    connection: ConnectionManager,
    token: String,
    ttl: u64,
    heartbeat: Option<JoinHandle<()>>,
}

impl ScanLease {
    pub async fn acquire(settings: &Settings) -> Result<Option<Self>> {
        if !settings.dedup_enabled {
            return Ok(None);
        }
        let client = redis::Client::open(settings.dedup_redis_url.clone()).context("open Redis")?;
        let mut connection = ConnectionManager::new(client)
            .await
            .context("connect Redis")?;
        let token = Uuid::new_v4().to_string();
        let acquired: Option<String> = redis::cmd("SET")
            .arg(LOCK_KEY)
            .arg(&token)
            .arg("NX")
            .arg("EX")
            .arg(settings.scan_lock_ttl)
            .query_async(&mut connection)
            .await?;
        if acquired.is_none() {
            bail!("scan already running")
        }
        let mut renewal = connection.clone();
        let renewal_token = token.clone();
        let ttl = settings.scan_lock_ttl;
        let heartbeat = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs((ttl / 3).max(1)));
            interval.tick().await;
            loop {
                interval.tick().await;
                let result: redis::RedisResult<i32> = redis::Script::new(RENEW_SCRIPT)
                    .key(LOCK_KEY)
                    .arg(&renewal_token)
                    .arg(ttl * 1000)
                    .invoke_async(&mut renewal)
                    .await;
                match result {
                    Ok(1) => {}
                    Ok(_) => {
                        warn!("scan lease ownership lost");
                        break;
                    }
                    Err(error) => warn!(%error,"scan lease renewal failed"),
                }
            }
        });
        Ok(Some(Self {
            connection,
            token,
            ttl,
            heartbeat: Some(heartbeat),
        }))
    }
    pub fn ttl(&self) -> u64 {
        self.ttl
    }
    pub async fn release(mut self) -> Result<bool> {
        if let Some(task) = self.heartbeat.take() {
            task.abort();
        }
        let released: i32 = redis::Script::new(RELEASE_SCRIPT)
            .key(LOCK_KEY)
            .arg(&self.token)
            .invoke_async(&mut self.connection)
            .await?;
        Ok(released == 1)
    }
}

pub async fn clear_stale_scan_lock(settings: &Settings) -> bool {
    if !settings.dedup_enabled {
        return false;
    }
    let Ok(client) = redis::Client::open(settings.dedup_redis_url.clone()) else {
        return false;
    };
    let Ok(mut connection) = ConnectionManager::new(client).await else {
        return false;
    };
    redis::cmd("DEL")
        .arg(LOCK_KEY)
        .query_async::<i32>(&mut connection)
        .await
        .unwrap_or(0)
        > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_key_is_compatible() {
        assert_eq!(LOCK_KEY, "aipocket:scan:lock");
        assert!(RELEASE_SCRIPT.contains("ARGV[1]"));
    }
}
