//! Process tracking and tree management
//!
//! Maintains real-time ProcessTrees from ProcessEvent streams

use anyhow::Result;
use chrono::Utc;
use core::events::ProcessEvent;
use core::tree::ProcessTree;

use serde_json;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

pub struct ProcessTracker {
    /// in mem process tree
    tree: ProcessTree,
    /// File writer for ProcessEvent JSONL stream
    events_writer: BufWriter<File>,
    /// Session start time for relative timestamps
    session_start: chrono::DateTime<Utc>,
}

impl ProcessTracker {
    /// Create new tracker with session directory
    pub async fn new(session_dir: String) -> Result<Self> {
        let events_file_path = format!("{}/events.jsonl", session_dir);
        let events_file = File::create(&events_file_path).await?;
        let events_writer = BufWriter::new(events_file);

        Ok(Self {
            tree: ProcessTree::new(),
            events_writer,
            session_start: Utc::now(),
        })
    }

    /// Main tracking loop - subscribe to ProcessEvent stream
    pub async fn run(
        mut self,
        mut rx_events: broadcast::Receiver<ProcessEvent>,
        ready_tx: mpsc::Sender<()>,
        cancellation_token: CancellationToken,
    ) -> Result<()> {
        // Signal ready
        ready_tx.send(()).await?;

        loop {
            tokio::select! {
                event_result = rx_events.recv() => {
                    match event_result {
                        Ok(process_event) => {
                            if let Err(e) = self.process_event(process_event).await {
                                eprintln!("Error processing event: {}", e);
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("Tracker lagged by {} events", n);
                        },
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                },
                _ = cancellation_token.cancelled() => {
                    self.final_flush().await?;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a ProcessEvent - update tree and write to file
    async fn process_event(&mut self, process_event: ProcessEvent) -> Result<()> {
        // Update tree
        self.tree.update(process_event.clone())?;

        // Write to file
        self.write_event_to_file(&process_event).await?;

        Ok(())
    }


    /// Write ProcessEvent to JSONL file
    async fn write_event_to_file(&mut self, event: &ProcessEvent) -> Result<()> {
        let json_line = serde_json::to_string(event)?;
        self.events_writer.write_all(json_line.as_bytes()).await?;
        self.events_writer.write_all(b"\n").await?;
        self.events_writer.flush().await?;
        Ok(())
    }

    /// Final flush and cleanup
    async fn final_flush(&mut self) -> Result<()> {
        self.events_writer.flush().await?;
        Ok(())
    }

    /// Get reference to current tree (for external access)
    pub fn tree(&self) -> &ProcessTree {
        &self.tree
    }
}
