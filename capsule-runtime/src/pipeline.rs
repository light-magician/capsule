//! Common pipeline traits and patterns for async components

use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Options for running pipeline components
#[derive(Default)]
pub struct RunOptions {
    pub ready_tx: Option<mpsc::Sender<()>>,
    pub cancellation_token: Option<CancellationToken>,
}

impl RunOptions {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn with_ready(mut self, ready_tx: mpsc::Sender<()>) -> Self {
        self.ready_tx = Some(ready_tx);
        self
    }
    
    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation_token = Some(token);
        self
    }
}

/// Common trait for async pipeline components
pub trait AsyncPipeline {
    type Input;
    type Output;
    
    /// Run the component with basic configuration
    async fn run(
        self,
        input: Self::Input,
        output: Self::Output,
    ) -> Result<()>;
    
    /// Run the component with full options (ready signal + cancellation)
    async fn run_with_options(
        self,
        input: Self::Input,
        output: Self::Output,
        options: RunOptions,
    ) -> Result<()>;
}

/// Helper function to signal readiness if a sender is provided
pub async fn signal_ready(ready_tx: &Option<mpsc::Sender<()>>) {
    if let Some(tx) = ready_tx {
        let _ = tx.send(()).await;
    }
}