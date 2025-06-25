//! Hash-chained log writer + live broadcast server (tail TBD).

use crate::{constants::*, model::*};
use anyhow::{Context, Result};
use blake3::Hasher;
use chrono::Utc;
use serde_json;
use std::path::PathBuf;
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::{broadcast::{Receiver, Sender}, mpsc},
    task::JoinHandle,
};
use uuid::Uuid;

/// Individual log writer for a specific data stream
struct LogWriter {
    file: File,
    hasher: Hasher,
    broadcast_tx: Option<Sender<String>>, // For live tail functionality
}

impl LogWriter {
    async fn new(log_path: PathBuf, broadcast_tx: Option<Sender<String>>) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await
            .with_context(|| format!("open log {:?}", log_path))?;
            
        Ok(Self {
            file,
            hasher: Hasher::new(),
            broadcast_tx,
        })
    }
    
    async fn write_entry(&mut self, payload: &str) -> Result<()> {
        // Compute hash chain
        let _prev = self.hasher.finalize();
        self.hasher.update(payload.as_bytes());
        let next = self.hasher.finalize();
        
        // Write hash-chained entry
        let line = format!("{} {}\n", hex::encode(next.as_bytes()), payload);
        self.file.write_all(line.as_bytes()).await?;
        
        // Broadcast for live tail if enabled
        if let Some(tx) = &self.broadcast_tx {
            let _ = tx.send(line);
        }
        
        // Update hash chain
        self.hasher = Hasher::new_keyed(next.as_bytes());
        Ok(())
    }
}

/// Raw syscall log writer task
async fn raw_writer_task(
    mut rx_raw: Receiver<String>,
    log_path: PathBuf,
    broadcast_tx: Option<Sender<String>>,
) -> Result<()> {
    let mut writer = LogWriter::new(log_path, broadcast_tx).await?;
    
    // Write session header
    let header = serde_json::json!({
        "start": Utc::now().to_rfc3339(),
        "session": Uuid::new_v4(),
        "stream": "raw_syscalls"
    }).to_string();
    writer.write_entry(&header).await?;

    loop {
        match rx_raw.recv().await {
            Ok(line) => writer.write_entry(&line).await?,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
    Ok(())
}

/// Event log writer task
async fn event_writer_task(
    mut rx_evt: Receiver<SyscallEvent>,
    log_path: PathBuf,
    broadcast_tx: Option<Sender<String>>,
) -> Result<()> {
    let mut writer = LogWriter::new(log_path, broadcast_tx).await?;
    
    // Write session header
    let header = serde_json::json!({
        "start": Utc::now().to_rfc3339(),
        "session": Uuid::new_v4(),
        "stream": "syscall_events"
    }).to_string();
    writer.write_entry(&header).await?;
    eprintln!("DEBUG: Event writer started, wrote header");

    let mut event_count = 0;
    loop {
        match rx_evt.recv().await {
            Ok(event) => {
                event_count += 1;
                if event_count <= 5 {
                    eprintln!("DEBUG: Event writer received event #{}: {} (pid={})", event_count, event.call, event.pid);
                }
                let line = serde_json::to_string(&event)?;
                writer.write_entry(&line).await?;
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                eprintln!("DEBUG: Event writer closed. Total events written: {}", event_count);
                break;
            },
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                eprintln!("DEBUG: Event writer lagged {} messages", n);
                continue;
            },
        }
    }
    Ok(())
}

/// Enriched event log writer task
async fn enriched_writer_task(
    mut rx_enriched: Receiver<SyscallEvent>,
    log_path: PathBuf,
    broadcast_tx: Option<Sender<String>>,
) -> Result<()> {
    let mut writer = LogWriter::new(log_path, broadcast_tx).await?;
    
    // Write session header
    let header = serde_json::json!({
        "start": Utc::now().to_rfc3339(),
        "session": Uuid::new_v4(),
        "stream": "enriched_events"
    }).to_string();
    writer.write_entry(&header).await?;

    loop {
        match rx_enriched.recv().await {
            Ok(event) => {
                let line = serde_json::to_string(&event)?;
                writer.write_entry(&line).await?;
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
    Ok(())
}

/// Action log writer task
async fn action_writer_task(
    mut rx_act: Receiver<Action>,
    log_path: PathBuf,
    broadcast_tx: Option<Sender<String>>,
) -> Result<()> {
    let mut writer = LogWriter::new(log_path, broadcast_tx).await?;
    
    // Write session header
    let header = serde_json::json!({
        "start": Utc::now().to_rfc3339(),
        "session": Uuid::new_v4(),
        "stream": "actions"
    }).to_string();
    writer.write_entry(&header).await?;

    loop {
        match rx_act.recv().await {
            Ok(action) => {
                let line = serde_json::to_string(&action)?;
                writer.write_entry(&line).await?;
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
    Ok(())
}

/// Risk log writer task - filters events with non-empty risk_tags
async fn risk_writer_task(
    mut rx_enriched: Receiver<SyscallEvent>,
    log_path: PathBuf,
    broadcast_tx: Option<Sender<String>>,
) -> Result<()> {
    let mut writer = LogWriter::new(log_path, broadcast_tx).await?;
    
    // Write session header
    let header = serde_json::json!({
        "start": Utc::now().to_rfc3339(),
        "session": Uuid::new_v4(),
        "stream": "risks"
    }).to_string();
    writer.write_entry(&header).await?;

    loop {
        match rx_enriched.recv().await {
            Ok(event) => {
                // Only log events that have risk tags
                if !event.risk_tags.is_empty() {
                    let line = serde_json::to_string(&event)?;
                    writer.write_entry(&line).await?;
                }
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
    Ok(())
}

/// Spawn separate log writer tasks for each stream
pub async fn logger(
    rx_raw: Receiver<String>,
    rx_evt: Receiver<SyscallEvent>,
    rx_enriched: Receiver<SyscallEvent>,
    rx_act: Receiver<Action>,
    run_dir: std::path::PathBuf,
) -> Result<()> {
    let log_dir = create_log_directory().await?;
    write_log_dir_metadata(&log_dir, &run_dir).await?;
    
    // Create broadcast channels for live tail functionality
    let (raw_tail_tx, _) = tokio::sync::broadcast::channel::<String>(1024);
    let (evt_tail_tx, _) = tokio::sync::broadcast::channel::<String>(1024);
    let (enriched_tail_tx, _) = tokio::sync::broadcast::channel::<String>(1024);
    let (act_tail_tx, _) = tokio::sync::broadcast::channel::<String>(1024);
    let (risk_tail_tx, _) = tokio::sync::broadcast::channel::<String>(1024);
    
    // Clone enriched receiver for risk writer
    let rx_enriched_for_risk = rx_enriched.resubscribe();
    
    // Spawn independent writer tasks
    let raw_task = tokio::spawn(raw_writer_task(
        rx_raw,
        log_dir.join(SYSCALL_FILE),
        Some(raw_tail_tx),
    ));
    
    let evt_task = tokio::spawn(event_writer_task(
        rx_evt,
        log_dir.join(EVENT_FILE),
        Some(evt_tail_tx),
    ));
    
    let enriched_task = tokio::spawn(enriched_writer_task(
        rx_enriched,
        log_dir.join(ENRICHED_FILE),
        Some(enriched_tail_tx),
    ));
    
    let risk_task = tokio::spawn(risk_writer_task(
        rx_enriched_for_risk,
        log_dir.join(RISK_FILE),
        Some(risk_tail_tx),
    ));
    
    let act_task = tokio::spawn(action_writer_task(
        rx_act,
        log_dir.join(ACTION_FILE),
        Some(act_tail_tx),
    ));
    
    // Wait for all writer tasks to complete
    let _ = tokio::try_join!(raw_task, evt_task, enriched_task, risk_task, act_task)?;
    Ok(())
}

pub async fn logger_with_ready(
    mut rx_raw: Receiver<String>,
    mut rx_evt: Receiver<SyscallEvent>,
    mut rx_enriched: Receiver<SyscallEvent>,
    mut rx_act: Receiver<Action>,
    ready_tx: mpsc::Sender<()>,
    run_dir: std::path::PathBuf,
) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run the normal logger
    logger(rx_raw, rx_evt, rx_enriched, rx_act, run_dir).await
}

// ───────────────────────────────────────────────────────────────────

/// Create a timestamped log directory
async fn create_log_directory() -> Result<PathBuf> {
    let dir = {
        let mut d = crate::constants::LOG_ROOT.clone();
        d.push(format!(
            "{}-{}",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            Uuid::new_v4()
        ));
        tokio::fs::create_dir_all(&d).await?;
        d
    };
    Ok(dir)
}


/// Write log directory path to the specified run directory
async fn write_log_dir_metadata(log_dir: &std::path::Path, run_dir: &std::path::Path) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    
    let metadata_path = run_dir.join(LOG_DIR_FILE);
    let mut file = tokio::fs::File::create(&metadata_path).await
        .with_context(|| format!("create metadata file {:?}", metadata_path))?;
    
    file.write_all(log_dir.to_string_lossy().as_bytes()).await
        .with_context(|| "write log directory path")?;
    
    Ok(())
}

/// Stub – later: serve Unix socket frames to `capsule tail`.
pub async fn tail_socket(
    _tx_raw: tokio::sync::broadcast::Sender<String>,
    _tx_evt: tokio::sync::broadcast::Sender<SyscallEvent>,
    _tx_act: tokio::sync::broadcast::Sender<Action>,
) -> Result<()> {
    Ok(())
}
