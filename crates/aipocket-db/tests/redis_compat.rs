use aipocket_core::{Credential, Settings};
use aipocket_db::{DedupStore, ScanLease};
use serde_json::json;

fn settings() -> Settings {
    Settings {
        dedup_redis_url: std::env::var("TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:16379/0".into()),
        scan_lock_ttl: 10,
        ..Settings::default()
    }
}

#[tokio::test]
#[ignore = "requires Redis on 127.0.0.1:16379"]
async fn redis_keys_ttls_and_scan_lease_are_compatible() {
    let settings = settings();
    let store = DedupStore::connect(&settings).await;
    assert!(store.enabled());
    let credential = Credential {
        apikey: "sk-integration".into(),
        apiurl: "https://example.com".into(),
        ..Default::default()
    };
    store.mark_host("example.com").await;
    assert!(store.host_seen("example.com").await);
    store
        .mark_target("validate", "example.com|sk-integration")
        .await;
    assert!(
        store
            .target_seen("validate", "example.com|sk-integration")
            .await
    );
    store.set_success(&credential, &json!({"valid":true})).await;
    assert_eq!(
        store
            .get_success::<serde_json::Value>(&credential)
            .await
            .unwrap()["valid"],
        true
    );
    store.set_outcome(&credential, "rejected").await;
    assert_eq!(
        store.get_outcome(&credential).await.as_deref(),
        Some("rejected")
    );
    store.set_outcome(&credential, "transient").await;
    assert_eq!(
        store.get_outcome(&credential).await.as_deref(),
        Some("transient")
    );
    store.set_outcome(&credential, "rejected").await;
    assert_eq!(
        store.get_outcome(&credential).await.as_deref(),
        Some("rejected")
    );
    store
        .set_balance(&credential, &json!({"balance":"12"}))
        .await;
    assert_eq!(
        store
            .get_balance::<serde_json::Value>(&credential)
            .await
            .unwrap()["balance"],
        "12"
    );
    let lease = ScanLease::acquire(&settings).await.unwrap().unwrap();
    assert_eq!(lease.ttl(), 10);
    assert!(lease.release().await.unwrap());
}
