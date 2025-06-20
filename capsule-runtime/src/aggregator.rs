use crate::model::{Action, ActionKind, SyscallEvent};
use anyhow::Result;
use smallvec::smallvec;
use tokio::sync::broadcast::{Receiver, Sender};

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
