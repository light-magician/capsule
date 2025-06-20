use crate::model::{Action, ActionKind, SyscallEvent};
use anyhow::Result;
use smallvec::smallvec;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;

/// Groups bursts of low-level events into semantic `Action`s.
///
/// For now: one-to-one passthrough.  Replace the body with a
/// sliding-window coalescer when ready.
pub async fn run(mut rx_evt: Receiver<SyscallEvent>, tx_act: Sender<Action>) -> Result<()> {
    while let Ok(ev) = rx_evt.recv().await {
        let act = Action {
            first_ts: ev.ts,
            last_ts: ev.ts,
            pids: smallvec![ev.pid],
            kind: ActionKind::Other { describe: ev.call },
        };
        let _ = tx_act.send(act); // drop if nobody is listening
    }
    Ok(())
}

pub async fn run_with_ready(mut rx_evt: Receiver<SyscallEvent>, tx_act: Sender<Action>, ready_tx: mpsc::Sender<()>) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run the normal processing loop
    run(rx_evt, tx_act).await
}
