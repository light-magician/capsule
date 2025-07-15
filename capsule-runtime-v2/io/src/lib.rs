//! Basic streaming infrastructure for broadcast → write pipeline

use anyhow::Result;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// High-performance async writer
pub struct StreamWriter {
    writer: BufWriter<File>,
    line_count: u64,
    file_path: PathBuf,
}

impl StreamWriter {
    pub async fn new(file_path: PathBuf) -> Result<Self> {
        let file = File::create(&file_path).await?;
        let writer = BufWriter::with_capacity(64 * 1024, file); // 64KB buffer
        
        info!("Created stream writer for {:?}", file_path);
        
        Ok(Self {
            writer,
            line_count: 0,
            file_path,
        })
    }
    
    pub async fn write_line(&mut self, line: &str) -> Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        
        self.line_count += 1;
        
        // Flush every 100 lines
        if self.line_count % 100 == 0 {
            self.writer.flush().await?;
            debug!("Flushed {} lines to {:?}", self.line_count, self.file_path);
        }
        
        Ok(())
    }
    
    pub async fn close(mut self) -> Result<()> {
        self.writer.flush().await?;
        info!("Closed stream writer for {:?} after {} lines", self.file_path, self.line_count);
        Ok(())
    }
}

/// A simple receiver that just writes broadcast data to a file
pub struct StreamReceiver {
    file_path: PathBuf,
}

impl StreamReceiver {
    pub fn new(file_path: PathBuf) -> Self {
        Self { file_path }
    }
    
    pub async fn start(
        self,
        mut rx: broadcast::Receiver<String>,
        cancellation_token: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<Result<()>>> {
        let mut writer = StreamWriter::new(self.file_path.clone()).await?;
        let file_name = self.file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        let handle = tokio::spawn(async move {
            info!("Started stream receiver for {}", file_name);
            
            loop {
                tokio::select! {
                    data_result = rx.recv() => {
                        match data_result {
                            Ok(data) => {
                                if let Err(e) = writer.write_line(&data).await {
                                    error!("Failed to write to {}: {}", file_name, e);
                                    break;
                                }
                            },
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("Stream receiver {} lagged by {} events", file_name, n);
                            },
            Err(broadcast::error::RecvError::Closed) => {
                                info!("Stream channel closed for {}", file_name);
                                break;
                            }
                        }
                    },
                    _ = cancellation_token.cancelled() => {
                        info!("Stream receiver {} received cancellation", file_name);
                        break;
                    }
                }
            }
            
            if let Err(e) = writer.close().await {
                error!("Error closing writer for {}: {}", file_name, e);
            }
            
            info!("Stream receiver {} finished", file_name);
            Ok(())
        });
        
        Ok(handle)
    }
}

/// Coordinator for managing stream receivers
pub struct StreamCoordinator {
    session_dir: PathBuf,
    receivers: Vec<StreamReceiver>,
}

impl StreamCoordinator {
    pub fn new(session_dir: PathBuf) -> Self {
        Self {
            session_dir,
            receivers: Vec::new(),
        }
    }
    
    /// Add a receiver for the specified filename
    pub fn add_receiver(&mut self, filename: &str) {
        let file_path = self.session_dir.join(filename);
        let receiver = StreamReceiver::new(file_path);
        self.receivers.push(receiver);
    }
    
    /// Start all receivers
    pub async fn start_all(
        self,
        broadcast_rx: broadcast::Receiver<String>,
        cancellation_token: CancellationToken,
    ) -> Result<Vec<tokio::task::JoinHandle<Result<()>>>> {
        let mut handles = Vec::new();
        
        for receiver in self.receivers {
            let rx = broadcast_rx.resubscribe();
            let handle = receiver.start(rx, cancellation_token.clone()).await?;
            handles.push(handle);
        }
        
        info!("Started {} stream receivers", handles.len());
        Ok(handles)
    }
}