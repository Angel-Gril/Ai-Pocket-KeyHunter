use aipocket_core::{ScanLogLine, ScanMode, ScanProgress, ScanState, ScanStatus};
use aipocket_db::Repository;
use aipocket_services::ScanEvent;
use chrono::Utc;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
#[derive(Debug)]
pub struct ScanManager {
    status: RwLock<ScanStatus>,
    logs: Mutex<VecDeque<ScanLogLine>>,
    transcript: Mutex<String>,
    capacity: usize,
    persist_interval: u64,
    tx: broadcast::Sender<ScanLogLine>,
    cancel: Mutex<Option<CancellationToken>>,
    stopped: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl ScanManager {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(16));
        Self {
            status: RwLock::new(ScanStatus::default()),
            logs: Mutex::new(VecDeque::with_capacity(capacity)),
            transcript: Mutex::new(String::new()),
            capacity,
            persist_interval: (capacity / 4).clamp(1, 50) as u64,
            tx,
            cancel: Mutex::new(None),
            stopped: Mutex::new(None),
        }
    }
    pub async fn status(&self) -> ScanStatus {
        self.status.read().await.clone()
    }
    pub async fn set_options(&self, github_pack_ids: Vec<String>, manual_enrich: Vec<String>) {
        let mut status = self.status.write().await;
        status.github_pack_ids = github_pack_ids;
        status.manual_enrich = manual_enrich;
    }
    pub async fn start_channel(
        &self,
        source: String,
        mode: ScanMode,
    ) -> Result<
        (
            CancellationToken,
            mpsc::UnboundedSender<ScanEvent>,
            mpsc::UnboundedReceiver<ScanEvent>,
            tokio::sync::oneshot::Sender<()>,
        ),
        (),
    > {
        let mut status = self.status.write().await;
        if matches!(status.state, ScanState::Running | ScanState::Stopping) {
            return Err(());
        }
        let cancel = CancellationToken::new();
        *self.cancel.lock().await = Some(cancel.clone());
        let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
        *self.stopped.lock().await = Some(stopped_rx);
        self.logs.lock().await.clear();
        self.transcript.lock().await.clear();
        let mode_label = mode_label(&mode);
        *status = ScanStatus {
            state: ScanState::Running,
            source: Some(source.clone()),
            mode,
            started_at: Some(Utc::now()),
            ..Default::default()
        };
        drop(status);
        self.push_log(format!(
            "扫描请求已接受 · 数据源 {source} · 模式 {mode_label}"
        ))
        .await;
        let (tx, rx) = mpsc::unbounded_channel();
        Ok((cancel, tx, rx, stopped_tx))
    }
    pub async fn consume(
        self: Arc<Self>,
        mut rx: mpsc::UnboundedReceiver<ScanEvent>,
        repository: Repository,
        stopped: tokio::sync::oneshot::Sender<()>,
    ) {
        while let Some(event) = rx.recv().await {
            let terminal_run = match event {
                ScanEvent::Started { run_id } => {
                    self.status.write().await.run_id = Some(run_id.clone());
                    self.push_log(format!("扫描运行已创建 · {run_id}")).await;
                    None
                }
                ScanEvent::Phase(phase) => {
                    self.status.write().await.phase = phase.clone();
                    self.push_log(format!("阶段 · {}", phase_label(&phase)))
                        .await;
                    None
                }
                ScanEvent::Progress(progress) => {
                    self.status.write().await.progress = progress.clone();
                    self.push_log(progress_line(&progress)).await;
                    None
                }
                ScanEvent::Log(line) => {
                    self.push_log(line).await;
                    None
                }
                ScanEvent::Finished { run_id } => {
                    {
                        let mut status = self.status.write().await;
                        status.state = ScanState::Finished;
                        status.phase = "finished".into();
                        status.run_id = Some(run_id.clone());
                        status.finished_at = Some(Utc::now());
                    }
                    self.push_log(format!("扫描完成 · {run_id}")).await;
                    Some(run_id)
                }
                ScanEvent::Interrupted { run_id, error } => {
                    {
                        let mut status = self.status.write().await;
                        status.state = ScanState::Interrupted;
                        status.run_id = Some(run_id.clone());
                        status.error = Some(error.clone());
                        status.finished_at = Some(Utc::now());
                    }
                    self.push_log(format!("扫描中断 · {error}")).await;
                    Some(run_id)
                }
            };
            if let Some(run_id) = terminal_run {
                self.persist_log(&repository, &run_id).await;
            } else if (self.status.read().await.log_seq == 2
                || self.status.read().await.log_seq % self.persist_interval == 0)
                && let Some(run_id) = self.status.read().await.run_id.clone()
            {
                self.persist_log(&repository, &run_id).await;
            }
        }
        let _ = stopped.send(());
    }
    async fn persist_log(&self, repository: &Repository, run_id: &str) {
        let log = self.log_text().await;
        if let Err(error) = repository.set_run_log(run_id, &log).await {
            tracing::warn!(%run_id, %error, "failed to persist scan log");
        }
    }

    pub async fn stop(&self) -> bool {
        {
            let mut status = self.status.write().await;
            if !matches!(status.state, ScanState::Running) {
                return false;
            }
            status.state = ScanState::Stopping;
        }
        if let Some(cancel) = self.cancel.lock().await.as_ref() {
            cancel.cancel();
        }
        let stopped = self.stopped.lock().await.take();
        if let Some(stopped) = stopped {
            let _ = stopped.await;
        }
        true
    }
    pub async fn push_log(&self, line: String) {
        let mut status = self.status.write().await;
        status.log_seq += 1;
        let item = ScanLogLine {
            seq: status.log_seq,
            line,
        };
        drop(status);
        let mut logs = self.logs.lock().await;
        if logs.len() == self.capacity {
            logs.pop_front();
        }
        logs.push_back(item.clone());
        let mut transcript = self.transcript.lock().await;
        if !transcript.is_empty() {
            transcript.push('\n');
        }
        transcript.push_str(&item.line);
        let _ = self.tx.send(item);
    }
    pub async fn log_text(&self) -> String {
        self.transcript.lock().await.clone()
    }
    pub async fn logs_since(&self, since: u64) -> Vec<ScanLogLine> {
        self.logs
            .lock()
            .await
            .iter()
            .filter(|line| line.seq > since)
            .cloned()
            .collect()
    }
    pub fn subscribe(&self) -> broadcast::Receiver<ScanLogLine> {
        self.tx.subscribe()
    }
}

fn mode_label(mode: &ScanMode) -> &'static str {
    match mode {
        ScanMode::Full => "全量",
        ScanMode::Incremental => "增量",
    }
}

fn phase_label(phase: &str) -> &str {
    match phase {
        "discovery" => "发现",
        "extract_validate" => "提取与验证",
        "balance_finalize" => "余额探测与结果落库",
        "finished" => "完成",
        other => other,
    }
}

fn progress_line(progress: &ScanProgress) -> String {
    format!(
        "进度 · 原始命中 {} · 唯一目标 {} · 候选密钥 {} · 已验证 {} · 最终可用 {} · 可疑 {} · 高价值 {}",
        progress.raw_hits,
        progress.unique_targets,
        progress.candidates,
        progress.active_requests,
        progress.final_verified,
        progress.suspicious,
        progress.high_value_final
    )
}
