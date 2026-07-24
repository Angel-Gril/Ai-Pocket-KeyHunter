use redis::{AsyncCommands, aio::ConnectionManager};
use serde::{Serialize, de::DeserializeOwned};
use sha1::{Digest, Sha1};
use tracing::warn;

use aipocket_core::{Credential, Settings};

const PREFIX: &str = "aipocket:dedup";

#[derive(Clone, Default)]
pub struct DedupStore {
    connection: Option<ConnectionManager>,
    settings: Settings,
}

impl DedupStore {
    pub async fn connect(settings: &Settings) -> Self {
        if !settings.dedup_enabled {
            return Self {
                connection: None,
                settings: settings.clone(),
            };
        }
        let connection = match redis::Client::open(settings.dedup_redis_url.clone()) {
            Ok(client) => ConnectionManager::new(client).await.ok(),
            Err(error) => {
                warn!(%error, "Redis dedup disabled");
                None
            }
        };
        Self {
            connection,
            settings: settings.clone(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.connection.is_some()
    }

    pub async fn host_seen(&self, host: &str) -> bool {
        self.get_string(&format!("{PREFIX}:host:{}", hash(host)))
            .await
            .is_some()
    }
    pub async fn mark_host(&self, host: &str) {
        self.set_string(
            &format!("{PREFIX}:host:{}", hash(host)),
            "1",
            self.settings.dedup_host_ttl,
        )
        .await;
    }
    pub async fn target_seen(&self, stage: &str, identity: &str) -> bool {
        self.get_string(&format!("{PREFIX}:target:{stage}:{}", hash(identity)))
            .await
            .is_some()
    }
    pub async fn mark_target(&self, stage: &str, identity: &str) {
        self.set_string(
            &format!("{PREFIX}:target:{stage}:{}", hash(identity)),
            "1",
            self.settings.dedup_host_ttl,
        )
        .await;
    }
    pub async fn get_success<T: DeserializeOwned>(&self, credential: &Credential) -> Option<T> {
        self.get_json(&format!("{PREFIX}:cred:ok:{}", cred_hash(credential)))
            .await
    }
    pub async fn set_success<T: Serialize>(&self, credential: &Credential, value: &T) {
        self.set_json(
            &format!("{PREFIX}:cred:ok:{}", cred_hash(credential)),
            value,
            self.settings.dedup_cred_ttl,
        )
        .await;
    }
    pub async fn get_outcome(&self, credential: &Credential) -> Option<String> {
        self.get_string(&format!("{PREFIX}:cred:outcome:{}", cred_hash(credential)))
            .await
    }
    pub async fn set_outcome(&self, credential: &Credential, outcome: &str) {
        let ttl = if outcome == "rejected" {
            self.settings.dedup_rejected_ttl
        } else {
            self.settings.dedup_transient_ttl
        };
        self.set_string(
            &format!("{PREFIX}:cred:outcome:{}", cred_hash(credential)),
            outcome,
            ttl,
        )
        .await;
    }
    pub async fn get_balance<T: DeserializeOwned>(&self, credential: &Credential) -> Option<T> {
        self.get_json(&format!("{PREFIX}:cred:bal:{}", cred_hash(credential)))
            .await
    }
    pub async fn set_balance<T: Serialize>(&self, credential: &Credential, value: &T) {
        self.set_json(
            &format!("{PREFIX}:cred:bal:{}", cred_hash(credential)),
            value,
            self.settings.dedup_balance_ttl,
        )
        .await;
    }

    async fn get_string(&self, key: &str) -> Option<String> {
        let mut connection = self.connection.clone()?;
        match connection.get(key).await {
            Ok(value) => value,
            Err(error) => {
                warn!(%error,%key,"Redis cache read failed");
                None
            }
        }
    }
    async fn set_string(&self, key: &str, value: &str, ttl: u64) {
        let Some(mut connection) = self.connection.clone() else {
            return;
        };
        let result: redis::RedisResult<()> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl)
            .query_async(&mut connection)
            .await;
        if let Err(error) = result {
            warn!(%error,%key,"Redis cache write failed");
        }
    }
    async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let raw = self.get_string(key).await?;
        serde_json::from_str(&raw)
            .map_err(|error| warn!(%error,%key,"Redis cache JSON ignored"))
            .ok()
    }
    async fn set_json<T: Serialize>(&self, key: &str, value: &T, ttl: u64) {
        match serde_json::to_string(value) {
            Ok(raw) => self.set_string(key, &raw, ttl).await,
            Err(error) => warn!(%error,%key,"Redis cache JSON serialization failed"),
        }
    }
}

fn cred_hash(credential: &Credential) -> String {
    hash(&format!(
        "{}|{}",
        credential.apikey,
        if credential.apiurl.is_empty() {
            &credential.host
        } else {
            &credential.apiurl
        }
    ))
}
fn hash(value: &str) -> String {
    format!("{:x}", Sha1::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keys_match_python_sha1() {
        let credential = Credential {
            apikey: "sk-x".into(),
            apiurl: "https://a.test".into(),
            ..Default::default()
        };
        assert_eq!(
            cred_hash(&credential),
            "e67845a81809765f93ce88ab8b2e2c1f532f4e14"
        );
        assert_eq!(PREFIX, "aipocket:dedup");
    }
}
