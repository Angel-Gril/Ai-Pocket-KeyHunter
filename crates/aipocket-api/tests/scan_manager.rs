use aipocket_api::scan_manager::ScanManager;
use aipocket_core::{ScanMode, ScanProgress, ScanState};
use aipocket_services::ScanEvent;
use std::sync::Arc;

#[tokio::test]
async fn manager_enforces_single_scan_and_replays_logs() {
    let manager = Arc::new(ScanManager::new(2));
    let (_cancel, tx, rx) = manager
        .start_channel("manual".into(), ScanMode::Incremental)
        .await
        .unwrap();
    assert!(
        manager
            .start_channel("fofa".into(), ScanMode::Incremental)
            .await
            .is_err()
    );
    let consumer = tokio::spawn(manager.clone().consume(rx));
    tx.send(ScanEvent::Phase("discovery".into())).unwrap();
    tx.send(ScanEvent::Progress(ScanProgress {
        raw_hits: 3,
        ..Default::default()
    }))
    .unwrap();
    tx.send(ScanEvent::Log("one".into())).unwrap();
    tx.send(ScanEvent::Log("two".into())).unwrap();
    tx.send(ScanEvent::Log("three".into())).unwrap();
    tx.send(ScanEvent::Finished {
        run_id: "run_2026_07_24_00-00-00".into(),
    })
    .unwrap();
    drop(tx);
    consumer.await.unwrap();
    let status = manager.status().await;
    assert_eq!(status.state, ScanState::Finished);
    assert_eq!(status.progress.raw_hits, 3);
    let logs = manager.logs_since(0).await;
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].line, "two");
    assert_eq!(logs[1].line, "three");
}
