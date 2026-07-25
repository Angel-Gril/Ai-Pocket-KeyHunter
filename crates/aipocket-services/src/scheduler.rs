use aipocket_core::Settings;
use anyhow::Result;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::time;
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct Scheduler {
    settings: Arc<Settings>,
}
impl Scheduler {
    pub fn new(settings: Arc<Settings>) -> Self {
        Self { settings }
    }
    pub async fn run_forever<F, Fut>(&self, cancel: CancellationToken, mut job: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let mut interval =
            time::interval(Duration::from_secs(self.settings.scheduler_interval.max(1)));
        loop {
            tokio::select! {_ = cancel.cancelled()=>break,_=interval.tick()=>{job().await?;}}
        }
        Ok(())
    }
}
