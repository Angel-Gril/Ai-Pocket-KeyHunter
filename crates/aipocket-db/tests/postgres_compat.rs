use aipocket_core::{ScanProgress, Settings};
use aipocket_db::{Repository, connect_pg, ensure_schema};
use chrono::Utc;
use serde_json::json;

fn settings() -> Settings {
    Settings {
        database_url: std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://aipocket:aipocket@127.0.0.1:15432/aipocket".into()),
        pg_pool_min: 1,
        pg_pool_max: 3,
        ..Settings::default()
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL on 127.0.0.1:15432"]
async fn existing_schema_records_round_trip_without_migration() {
    let pool = connect_pg(&settings()).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let repo = Repository::new(Some(pool));
    let run_id = "run_2099_01_01_00-00-00";
    repo.create_run(run_id, Utc::now(), "incremental", &["manual".into()])
        .await
        .unwrap();
    let record = json!({"credential":{"apikey":"sk-plaintext-test","apiurl":"https://example.com","host":"example.com"},"valid":true,"validation_state":"final_verified","provider_info":{"provider":"openai"}});
    repo.insert_results(run_id, "valid", std::slice::from_ref(&record))
        .await
        .unwrap();
    repo.finish_run(
        run_id,
        "finished",
        &ScanProgress {
            raw_hits: 1,
            unique_targets: 1,
            candidates: 1,
            active_requests: 1,
            final_verified: 1,
            ..Default::default()
        },
        "complete",
    )
    .await
    .unwrap();
    let masked = repo.run_records(run_id, "valid", true).await.unwrap();
    assert_ne!(masked[0]["credential"]["apikey"], "sk-plaintext-test");
    let plain = repo.run_records(run_id, "valid", false).await.unwrap();
    assert_eq!(plain[0]["credential"]["apikey"], "sk-plaintext-test");
    assert!(
        repo.list_runs()
            .await
            .unwrap()
            .iter()
            .any(|day| day.runs.iter().any(|run| run.run_id == run_id))
    );
    let summary = repo
        .list_runs()
        .await
        .unwrap()
        .into_iter()
        .flat_map(|day| day.runs)
        .find(|run| run.run_id == run_id)
        .unwrap();
    assert_eq!(summary.sources, vec!["manual"]);
    assert!(repo.delete_run(run_id).await.unwrap());
}

#[tokio::test]
#[ignore = "requires PostgreSQL on TEST_DATABASE_URL"]
async fn github_checkpoint_and_work_advance_atomically_and_keep_terminal_state() {
    use aipocket_db::{
        ArtifactWorkItem, SourceCheckpoint, advance_checkpoints_with_work, claim_artifact_work,
    };
    let pool = connect_pg(&settings()).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let key = format!("coverage-{}", Utc::now().timestamp_nanos_opt().unwrap());
    let checkpoint = SourceCheckpoint {
        source: "github".into(),
        lane: "code_snapshot".into(),
        pack_id: "openai".into(),
        shard_id: key.clone(),
        watermark: "2099-01-01T00:00:00Z".into(),
        cursor_state: json!({"page":2}),
        status: "ok".into(),
        ..Default::default()
    };
    let mut work = ArtifactWorkItem {
        repo_id: key.clone(),
        repository_full_name: "fixture/repo".into(),
        commit_sha: "commit".into(),
        file_path: ".env".into(),
        object_sha: "blob".into(),
        source_kind: "code_snapshot".into(),
        work_status: "fetch_pending".into(),
        current_stage: "fetch_pending".into(),
        run_id: "run_fixture".into(),
        query_id: "query".into(),
        pack_id: "openai".into(),
        lane: "code_snapshot".into(),
        coverage_mode: "complete".into(),
        ..Default::default()
    };
    assert_eq!(
        advance_checkpoints_with_work(
            &pool,
            std::slice::from_ref(&checkpoint),
            std::slice::from_ref(&work)
        )
        .await
        .unwrap(),
        2
    );
    assert!(
        claim_artifact_work(&pool, 100)
            .await
            .unwrap()
            .iter()
            .any(|item| item.repo_id == key)
    );
    let claimed = claim_artifact_work(&pool, 100)
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.repo_id == key)
        .unwrap();
    assert_eq!(
        aipocket_db::transition_artifact_work(&pool, &claimed, "transient", "timeout", 2)
            .await
            .unwrap(),
        "transient"
    );
    let retried = aipocket_db::ArtifactWorkItem {
        attempts: 1,
        ..claimed
    };
    assert_eq!(
        aipocket_db::transition_artifact_work(&pool, &retried, "transient", "timeout", 2)
            .await
            .unwrap(),
        "source_gone"
    );
    work.work_status = "fetch_pending".into();
    work.attempts = 0;
    advance_checkpoints_with_work(&pool, &[], std::slice::from_ref(&work))
        .await
        .unwrap();
    work.work_status = "terminal".into();
    work.current_stage = "terminal".into();
    advance_checkpoints_with_work(
        &pool,
        std::slice::from_ref(&checkpoint),
        std::slice::from_ref(&work),
    )
    .await
    .unwrap();
    work.work_status = "fetch_pending".into();
    work.current_stage = "fetch_pending".into();
    advance_checkpoints_with_work(&pool, &[checkpoint], std::slice::from_ref(&work))
        .await
        .unwrap();
    assert!(
        !claim_artifact_work(&pool, 100)
            .await
            .unwrap()
            .iter()
            .any(|item| item.repo_id == key)
    );
    let stored: (String, serde_json::Value) = sqlx::query_as("SELECT watermark,cursor_state FROM source_checkpoints WHERE source='github' AND lane='code_snapshot' AND pack_id='openai' AND shard_id=$1").bind(&key).fetch_one(&pool).await.unwrap();
    assert_eq!(stored.0, "2099-01-01T00:00:00Z");
    assert_eq!(stored.1["page"], 2);
    sqlx::query("DELETE FROM github_artifacts WHERE repo_id=$1")
        .bind(&key)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM source_checkpoints WHERE shard_id=$1")
        .bind(&key)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires PostgreSQL on TEST_DATABASE_URL"]
async fn legacy_run_sources_recover_from_github_artifact_work() {
    use aipocket_db::{ArtifactWorkItem, advance_checkpoints_with_work};

    let pool = connect_pg(&settings()).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let repo = Repository::new(Some(pool.clone()));
    let suffix = Utc::now().timestamp_nanos_opt().unwrap();
    let run_id = format!("run_2099_01_01_github_{suffix}");
    repo.create_run(&run_id, Utc::now(), "incremental", &[])
        .await
        .unwrap();
    let work = ArtifactWorkItem {
        repo_id: format!("legacy-github-{suffix}"),
        repository_full_name: "fixture/repo".into(),
        commit_sha: "commit".into(),
        file_path: ".env".into(),
        object_sha: "blob".into(),
        source_kind: "code_snapshot".into(),
        work_status: "terminal".into(),
        current_stage: "terminal".into(),
        run_id: run_id.clone(),
        query_id: "query".into(),
        pack_id: "openai".into(),
        lane: "code_snapshot".into(),
        coverage_mode: "complete".into(),
        ..Default::default()
    };
    advance_checkpoints_with_work(&pool, &[], &[work])
        .await
        .unwrap();

    let summary = repo
        .list_runs()
        .await
        .unwrap()
        .into_iter()
        .flat_map(|day| day.runs)
        .find(|run| run.run_id == run_id)
        .unwrap();
    assert_eq!(summary.sources, vec!["github"]);
    assert!(repo.delete_run(&run_id).await.unwrap());
}

#[tokio::test]
#[ignore = "requires PostgreSQL on TEST_DATABASE_URL"]
async fn query_metrics_and_run_ledger_state_replace_atomically() {
    use aipocket_core::QueryFunnel;
    use aipocket_db::QueryMetricRecord;
    let pool = connect_pg(&settings()).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let repo = Repository::new(Some(pool.clone()));
    let run_id = format!(
        "run_2099_01_01_metrics_{}",
        Utc::now().timestamp_nanos_opt().unwrap()
    );
    repo.create_run(&run_id, Utc::now(), "incremental", &[])
        .await
        .unwrap();
    let mut metric = QueryMetricRecord {
        source: "github".into(),
        query: "anchor".into(),
        query_id: "qid".into(),
        pack_id: "openai".into(),
        lane: "code_snapshot".into(),
        query_credits: 2,
        attribution_version: 2,
        funnel: QueryFunnel {
            raw_hits: 4,
            unique_targets: 3,
            active_requests: 2,
            total_active_http_requests: 2,
            final_verified: 1,
            ..Default::default()
        },
    };
    repo.persist_query_metrics(&run_id, std::slice::from_ref(&metric))
        .await
        .unwrap();
    metric.funnel.raw_hits = 7;
    repo.persist_query_metrics(&run_id, std::slice::from_ref(&metric))
        .await
        .unwrap();
    repo.finish_run_metrics(&run_id, 2, false, "partial instrumentation")
        .await
        .unwrap();
    let row: (i32, i32, i32, bool, String) = sqlx::query_as("SELECT qm.raw_hits,qm.attribution_version,r.total_active_http_requests,r.ledger_complete,r.ledger_incomplete_reason FROM query_metrics qm JOIN runs r USING(run_id) WHERE run_id=$1 AND source='github' AND query='anchor'").bind(&run_id).fetch_one(&pool).await.unwrap();
    assert_eq!(row.0, 7);
    assert_eq!(row.1, 2);
    assert_eq!(row.2, 2);
    assert!(!row.3);
    assert_eq!(row.4, "partial instrumentation");
    let summary = repo
        .list_runs()
        .await
        .unwrap()
        .into_iter()
        .flat_map(|day| day.runs)
        .find(|run| run.run_id == run_id)
        .unwrap();
    assert_eq!(summary.sources, vec!["github"]);
    assert!(repo.delete_run(&run_id).await.unwrap());
}

#[tokio::test]
#[ignore = "requires PostgreSQL on TEST_DATABASE_URL"]
async fn spill_tables_round_trip_candidates_hits_and_validation_results() {
    use aipocket_core::{Credential, ValidationResult};
    use aipocket_db::{
        load_candidate_page, load_discovery_hits, load_validation_results, upsert_candidates,
        upsert_discovery_hits, upsert_validation_results,
    };

    let pool = connect_pg(&settings()).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let run_id = format!(
        "run_2099_01_01_spill_{}",
        Utc::now().timestamp_nanos_opt().unwrap()
    );
    let repo = Repository::new(Some(pool.clone()));
    repo.create_run(&run_id, Utc::now(), "incremental", &[])
        .await
        .unwrap();
    let credential = Credential {
        apikey: "sk-spill-abcdefghijkl".into(),
        apiurl: "https://spill.example/v1".into(),
        host: "spill.example".into(),
        backend: "github".into(),
        ..Default::default()
    };
    assert_eq!(
        upsert_candidates(&pool, &run_id, std::slice::from_ref(&credential))
            .await
            .unwrap(),
        1
    );
    let candidates = load_candidate_page(&pool, &run_id, 0, 10).await.unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].1.apikey, credential.apikey);

    let hits = [
        json!({"_source":"github","_query_id":"q","host":"https://spill.example","ip":"127.0.0.1","port":443,"protocol":"https"}),
        json!({"url":"https://second.example","port":"8443"}),
    ];
    assert_eq!(
        upsert_discovery_hits(&pool, &run_id, &hits).await.unwrap(),
        2
    );
    assert_eq!(load_discovery_hits(&pool, &run_id).await.unwrap().len(), 2);

    let validation = ValidationResult {
        credential,
        valid: true,
        validation_state: "final_verified".into(),
        ..Default::default()
    };
    assert_eq!(
        upsert_validation_results(&pool, &run_id, std::slice::from_ref(&validation))
            .await
            .unwrap(),
        1
    );
    let validation_rows = load_validation_results(&pool, &run_id).await.unwrap();
    assert_eq!(validation_rows.len(), 1);
    assert!(validation_rows[0].valid);

    for table in [
        "scan_candidates",
        "scan_discovery_hits",
        "scan_validation_results",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE run_id=$1"))
            .bind(&run_id)
            .execute(&pool)
            .await
            .unwrap();
    }
    assert!(repo.delete_run(&run_id).await.unwrap());
}

#[tokio::test]
#[ignore = "requires PostgreSQL on TEST_DATABASE_URL"]
async fn repository_resume_append_balance_and_high_value_paths_persist() {
    let pool = connect_pg(&settings()).await.unwrap().unwrap();
    ensure_schema(&pool).await.unwrap();
    let repo = Repository::new(Some(pool.clone()));
    let run_id = format!(
        "run_2099_01_01_repo_{}",
        Utc::now().timestamp_nanos_opt().unwrap()
    );
    repo.create_run(&run_id, Utc::now(), "full", &[])
        .await
        .unwrap();
    repo.update_phase(&run_id, "validate", json!({"page":2}))
        .await
        .unwrap();
    assert_eq!(
        repo.resumable_run(&run_id).await.unwrap(),
        Some(("running".into(), "validate".into()))
    );

    let record = json!({
        "credential":{"apikey":"sk-repo-abcdefghijkl","apiurl":"https://repo.example/v1","host":"repo.example"},
        "valid":true,
        "validation_state":"final_verified",
        "gateway":"",
        "balance":"",
        "tier":"",
        "provider_evidence":{}
    });
    repo.append_results(&run_id, "valid", std::slice::from_ref(&record))
        .await
        .unwrap();
    let rows = repo.run_records(&run_id, "valid", false).await.unwrap();
    let result_id = rows[0]["result_id"].as_i64().unwrap();
    let high = json!({
        "apikey":"sk-repo-abcdefghijkl",
        "credential":{"apikey":"sk-repo-abcdefghijkl","apiurl":"https://repo.example/v1"},
        "gateway":"",
        "balance":"",
        "tier":"",
        "provider_evidence":{}
    });
    assert!(repo.upsert_high_value(&run_id, &high).await.unwrap());
    let persisted = repo
        .persist_balance(aipocket_db::BalancePersistence {
            result_id: Some(result_id),
            apikey: "sk-repo-abcdefghijkl",
            gateway: "openai",
            balance: "42.00",
            tier: "paid",
            detail: &json!({"source":"fixture"}),
            high_value: true,
        })
        .await
        .unwrap();
    assert_eq!(persisted, (true, true));
    let updated = repo.run_records(&run_id, "valid", false).await.unwrap();
    assert_eq!(updated[0]["balance"], "42.00");
    let high_rows = repo.high_value(false).await.unwrap();
    assert!(
        high_rows
            .iter()
            .any(|row| { row["apikey"] == "sk-repo-abcdefghijkl" && row["balance"] == "42.00" })
    );

    let (transitioned, skipped) = repo
        .transition_results(&[result_id], "unavailable", "manual rejection")
        .await
        .unwrap();
    assert_eq!(transitioned, [result_id]);
    assert!(skipped.is_empty());
    assert!(
        repo.run_records(&run_id, "valid", false)
            .await
            .unwrap()
            .is_empty()
    );
    let unavailable = repo
        .run_records(&run_id, "unavailable", false)
        .await
        .unwrap();
    assert_eq!(unavailable[0]["manual_status"], "unavailable");
    let (restored, skipped) = repo
        .transition_results(&[result_id], "valid", "manual restore")
        .await
        .unwrap();
    assert_eq!(restored, [result_id]);
    assert!(skipped.is_empty());
    let restored_rows = repo.run_records(&run_id, "valid", false).await.unwrap();
    assert_eq!(restored_rows[0]["manual_status"], "valid");

    let first_host = "a.ip.linodeusercontent.com:443";
    let second_host = "b.ip.linodeusercontent.com:8443";
    for host in [first_host, second_host] {
        sqlx::query("INSERT INTO honeypot_sites(host_key,host,reason,source) VALUES($1,$1,'honeypot:fixture','auto') ON CONFLICT(host_key) DO UPDATE SET reason=EXCLUDED.reason")
            .bind(host)
            .execute(&pool)
            .await
            .unwrap();
    }
    let grouped = repo
        .list_honeypots("linodeusercontent", None, 10, 0)
        .await
        .unwrap();
    let group = grouped
        .0
        .iter()
        .find(|row| row.host == "linodeusercontent.com")
        .unwrap();
    assert_eq!(group.member_count, 2);
    repo.update_honeypot(&group.host_key, None, Some("group note"))
        .await
        .unwrap();
    let noted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM honeypot_sites WHERE host_key = ANY($1) AND notes='group note'",
    )
    .bind(vec![first_host, second_host])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(noted, 2);
    assert_eq!(
        repo.delete_honeypots(std::slice::from_ref(&group.host_key))
            .await
            .unwrap(),
        2
    );

    assert!(repo.delete_run(&run_id).await.unwrap());
    sqlx::query("DELETE FROM high_value_keys WHERE apikey=$1")
        .bind("sk-repo-abcdefghijkl")
        .execute(&pool)
        .await
        .unwrap();
}
