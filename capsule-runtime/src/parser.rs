use crate::model::SyscallEvent;
use anyhow::Result;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;

/// Public entry: consumes raw strace lines, emits typed events.
///
/// * `rx`  – cloned receiver from the raw-syscall broadcast bus
/// * `tx_evt` – sender on the event bus
pub async fn run(mut rx: Receiver<String>, tx_evt: Sender<SyscallEvent>) -> Result<()> {
    loop {
        match rx.recv().await {
            Ok(line) => {
                if let Some(evt) = parse_line(&line) {
                    // Ignore lagged receivers; only producers enforce back-pressure.
                    let _ = tx_evt.send(evt);
                }
            }
            // Channel closed → upstream tracer exited; time to shut down.
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            // We fell behind the ring buffer; skip and continue.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
    Ok(())
}

pub async fn run_with_ready(mut rx: Receiver<String>, tx_evt: Sender<SyscallEvent>, ready_tx: mpsc::Sender<()>) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run the normal processing loop
    run(rx, tx_evt).await
}

// ── stub parser – replace with a nom state-machine later ─────────────
fn parse_line(line: &str) -> Option<SyscallEvent> {
    // Example strace line: "12345  1708118061.123456 openat(..."
    let mut parts = line.split_whitespace();
    let pid: u32 = parts.next()?.parse().ok()?;
    let ts_f64: f64 = parts.next()?.parse().ok()?;
    Some(SyscallEvent {
        ts: (ts_f64 * 1_000_000.0) as u64, // µs
        pid,
        call: "unknown".into(),
        args: [0; 6],
        retval: 0,
        enrichment: None, // Will be filled by enricher stage
    })
}
