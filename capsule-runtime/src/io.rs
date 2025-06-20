//! Hash-chained log writer + live broadcast server (tail TBD).

use crate::{constants::*, model::*};
use anyhow::{Context, Result};
use blake3::Hasher;
use chrono::Utc;
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::{broadcast::Receiver, mpsc},
};
use uuid::Uuid;

struct Files {
    raw: File,
    evt: File,
    act: File,
}

/// Top-level logger task.
pub async fn logger(
    mut rx_raw: Receiver<String>,
    mut rx_evt: Receiver<SyscallEvent>,
    mut rx_act: Receiver<Action>,
) -> Result<()> {
    let (mut files, log_dir) = open_files().await?;
    
    // Write log directory path to run directory for tail command
    write_log_dir_metadata(&log_dir).await?;
    let mut hasher = Hasher::new(); // current chain head = zero-hash

    // header line
    let header = serde_json::json!({
        "start": Utc::now().to_rfc3339(),
        "session": Uuid::new_v4(),
    })
    .to_string();
    write_frame(&mut files.raw, &mut hasher, &header).await?;

    loop {
        tokio::select! {
            res = rx_raw.recv() => match res {
                Ok(l) => write_frame(&mut files.raw, &mut hasher, &l).await?,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                _ => {}
            },
            res = rx_evt.recv() => if let Ok(e) = res {
                let line = serde_json::to_string(&e)?;
                write_frame(&mut files.evt, &mut hasher, &line).await?;
            },
            res = rx_act.recv() => if let Ok(a) = res {
                let line = serde_json::to_string(&a)?;
                write_frame(&mut files.act, &mut hasher, &line).await?;
            },
        }
    }
    Ok(())
}

pub async fn logger_with_ready(
    mut rx_raw: Receiver<String>,
    mut rx_evt: Receiver<SyscallEvent>,
    mut rx_act: Receiver<Action>,
    ready_tx: mpsc::Sender<()>,
) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run the normal logger
    logger(rx_raw, rx_evt, rx_act).await
}

// ───────────────────────────────────────────────────────────────────

async fn open_files() -> Result<(Files, std::path::PathBuf)> {
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

    async fn create(dir: &std::path::Path, name: &str) -> Result<File> {
        let p = dir.join(name);
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .await
            .with_context(|| format!("open log {:?}", name))
    }

    Ok((Files {
        raw: create(&dir, SYSCALL_FILE).await?,
        evt: create(&dir, EVENT_FILE).await?,
        act: create(&dir, ACTION_FILE).await?,
    }, dir))
}

/// Append `payload` plus Blake3 hash chain.
async fn write_frame(file: &mut File, chain: &mut blake3::Hasher, payload: &str) -> Result<()> {
    // compute next hash = blake3(prev || payload)
    let _prev = chain.finalize();
    chain.update(payload.as_bytes());
    let next = chain.finalize();
    // write "<hexhash> <payload>\n"
    file.write_all(format!("{} {}\n", hex::encode(next.as_bytes()), payload).as_bytes())
        .await?;
    // update chain by resetting hasher to next
    *chain = Hasher::new_keyed(next.as_bytes());
    Ok(())
}

/// Write log directory path to the current working directory (run directory)
async fn write_log_dir_metadata(log_dir: &std::path::Path) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    
    let metadata_path = std::env::current_dir()?.join(LOG_DIR_FILE);
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
