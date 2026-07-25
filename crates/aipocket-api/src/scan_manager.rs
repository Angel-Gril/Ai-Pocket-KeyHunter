use aipocket_core::{ScanLogLine, ScanMode, ScanState, ScanStatus};
use aipocket_services::ScanEvent;
use chrono::Utc;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
#[derive(Debug)]
pub struct ScanManager {
    status: RwLock<ScanStatus>,
    logs: Mutex<VecDeque<ScanLogLine>>,
    capacity: usize,
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
            capacity,
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
        *status = ScanStatus {
            state: ScanState::Running,
            source: Some(source),
            mode,
            started_at: Some(Utc::now()),
            ..Default::default()
        };
        let (tx, rx) = mpsc::unbounded_channel();
        Ok((cancel, tx, rx, stopped_tx))
    }
    pub async fn consume(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<ScanEvent>) {
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::Started { run_id } => {
                    self.status.write().await.run_id = Some(run_id);
                }
                ScanEvent::Phase(phase) => self.status.write().await.phase = phase,
                ScanEvent::Progress(progress) => self.status.write().await.progress = progress,
                ScanEvent::Log(line) => self.push_log(line).await,
                ScanEvent::Finished { run_id } => {
                    let mut s = self.status.write().await;
                    s.state = ScanState::Finished;
                    s.run_id = Some(run_id);
                    s.finished_at = Some(Utc::now());
                }
                ScanEvent::Interrupted { run_id, error } => {
                    let mut s = self.status.write().await;
                    s.state = ScanState::Interrupted;
                    s.run_id = Some(run_id);
                    s.error = Some(error);
                    s.finished_at = Some(Utc::now());
                }
            }
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
        let _ = self.tx.send(item);
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
