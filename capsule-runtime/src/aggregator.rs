use crate::model::{Action, ActionKind, SyscallEvent};
use anyhow::Result;
use smallvec::smallvec;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Aggregation key for grouping related syscalls
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AggregationKey {
    pid: u32,
    fd: Option<i32>,
    path: Option<PathBuf>,
    operation_type: String,
}

/// Pending action being accumulated
#[derive(Debug, Clone)]
struct PendingAction {
    first_ts: u64,
    last_ts: u64,
    pids: Vec<u32>,
    bytes: usize,
    count: usize,
    last_activity: Instant,
    kind_template: ActionKind,
}

/// Groups bursts of low-level events into semantic `Action`s using sliding windows
pub async fn run(mut rx_evt: Receiver<SyscallEvent>, tx_act: Sender<Action>) -> Result<()> {
    run_with_cancellation(rx_evt, tx_act, CancellationToken::new()).await
}

/// Groups bursts of low-level events with cancellation support
pub async fn run_with_cancellation(
    mut rx_evt: Receiver<SyscallEvent>,
    tx_act: Sender<Action>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    let mut pending: HashMap<AggregationKey, PendingAction> = HashMap::new();
    let mut flush_interval = time::interval(Duration::from_millis(100));
    
    loop {
        tokio::select! {
            // Process incoming events
            event_result = rx_evt.recv() => {
                match event_result {
                    Ok(ev) => {
                        if let Some(action) = process_event(ev, &mut pending) {
                            let _ = tx_act.send(action);
                        }
                    },
                    Err(_) => break, // Channel closed
                }
            },
            
            // Periodic flush of stale pending actions
            _ = flush_interval.tick() => {
                let stale_actions = flush_stale_actions(&mut pending, Duration::from_millis(500));
                for action in stale_actions {
                    let _ = tx_act.send(action);
                }
            },
            
            // Graceful shutdown signal
            _ = cancellation_token.cancelled() => {
                // Aggregator received cancellation, flushing pending actions
                break;
            }
        }
    }
    
    // Flush remaining actions on shutdown
    for (_, pending_action) in pending {
        let action = finalize_action(pending_action);
        let _ = tx_act.send(action);
    }
    
    Ok(())
}

/// Process a single syscall event, either aggregating it or emitting an immediate action
fn process_event(
    ev: SyscallEvent,
    pending: &mut HashMap<AggregationKey, PendingAction>,
) -> Option<Action> {
    // Determine if this event should be aggregated or emitted immediately
    let (key, should_aggregate) = match classify_event(&ev) {
        Some((k, agg)) => (k, agg),
        None => {
            // Unrecognized syscall, emit immediately as Other
            return Some(Action {
                first_ts: ev.ts,
                last_ts: ev.ts,
                pids: smallvec![ev.pid],
                kind: ActionKind::Other {
                    syscall: ev.call.clone(),
                    describe: format!("Unknown syscall: {}", ev.call),
                },
            });
        }
    };

    if !should_aggregate {
        // Emit immediately for non-aggregatable events (like process spawn/exit)
        let kind = create_action_kind(&ev);
        return Some(Action {
            first_ts: ev.ts,
            last_ts: ev.ts,
            pids: smallvec![ev.pid],
            kind,
        });
    }

    // Handle aggregatable events
    let now = Instant::now();
    match pending.get_mut(&key) {
        Some(pending_action) => {
            // Update existing aggregation
            pending_action.last_ts = ev.ts;
            pending_action.last_activity = now;
            pending_action.count += 1;
            if ev.retval > 0 {
                pending_action.bytes += ev.retval as usize;
            }
            if !pending_action.pids.contains(&ev.pid) {
                pending_action.pids.push(ev.pid);
            }
            None
        }
        None => {
            // Start new aggregation
            let kind_template = create_action_kind(&ev);
            let bytes = if ev.retval > 0 { ev.retval as usize } else { 0 };
            
            pending.insert(
                key,
                PendingAction {
                    first_ts: ev.ts,
                    last_ts: ev.ts,
                    pids: vec![ev.pid],
                    bytes,
                    count: 1,
                    last_activity: now,
                    kind_template,
                },
            );
            None
        }
    }
}

/// Classify an event and determine its aggregation key and whether it should be aggregated
fn classify_event(ev: &SyscallEvent) -> Option<(AggregationKey, bool)> {
    let syscall = ev.call.as_str();
    
    match syscall {
        // File I/O operations - aggregate by PID + FD/path
        "read" | "write" | "pread64" | "pwrite64" => {
            let fd = ev.args[0] as i32;
            Some((
                AggregationKey {
                    pid: ev.pid,
                    fd: Some(fd),
                    path: None,
                    operation_type: if syscall.contains("read") { "read".to_string() } else { "write".to_string() },
                },
                true,
            ))
        }
        
        // Process lifecycle - don't aggregate, emit immediately
        "fork" | "vfork" | "clone" | "execve" | "exit" | "exit_group" => {
            Some((
                AggregationKey {
                    pid: ev.pid,
                    fd: None,
                    path: None,
                    operation_type: syscall.to_string(),
                },
                false,
            ))
        }
        
        // File operations - aggregate by path
        "open" | "openat" | "stat" | "lstat" | "fstat" | "chmod" | "chown" => {
            Some((
                AggregationKey {
                    pid: ev.pid,
                    fd: None,
                    path: None, // TODO: Extract path from args when enricher is available
                    operation_type: syscall.to_string(),
                },
                true,
            ))
        }
        
        // Network operations - don't aggregate initially
        "socket" | "connect" | "bind" | "accept" | "listen" => {
            Some((
                AggregationKey {
                    pid: ev.pid,
                    fd: Some(ev.args[0] as i32),
                    path: None,
                    operation_type: syscall.to_string(),
                },
                false,
            ))
        }
        
        _ => None, // Unrecognized syscall
    }
}

/// Create an ActionKind from a syscall event, using enrichment data when available
fn create_action_kind(ev: &SyscallEvent) -> ActionKind {
    match ev.call.as_str() {
        "read" | "pread64" => {
            let fd = ev.args[0] as i32;
            let path = ev.enrichment.as_ref()
                .and_then(|ctx| ctx.fd_map.get(&fd))
                .map(|p| PathBuf::from(p))
                .unwrap_or_else(|| PathBuf::from(format!("fd:{}", fd)));
            
            ActionKind::FileRead {
                path,
                bytes: if ev.retval > 0 { ev.retval as usize } else { 0 },
            }
        },
        "write" | "pwrite64" => {
            let fd = ev.args[0] as i32;
            let path = ev.enrichment.as_ref()
                .and_then(|ctx| ctx.fd_map.get(&fd))
                .map(|p| PathBuf::from(p))
                .unwrap_or_else(|| PathBuf::from(format!("fd:{}", fd)));
            
            ActionKind::FileWrite {
                path,
                bytes: if ev.retval > 0 { ev.retval as usize } else { 0 },
            }
        },
        "fork" | "vfork" | "clone" => ActionKind::ProcessSpawn {
            pid: if ev.retval > 0 { ev.retval as u32 } else { ev.pid },
            argv: ev.enrichment.as_ref()
                .and_then(|ctx| ctx.argv.clone())
                .unwrap_or_default(),
            parent_pid: ev.pid,
        },
        "execve" => ActionKind::ProcessExec {
            argv: ev.enrichment.as_ref()
                .and_then(|ctx| ctx.argv.clone())
                .unwrap_or_default(),
        },
        "exit" | "exit_group" => ActionKind::ProcessExit {
            pid: ev.pid,
            exit_code: ev.args[0] as i32,
        },
        "open" | "openat" => {
            // Try to extract path from enrichment or construct from args
            let path = ev.enrichment.as_ref()
                .and_then(|ctx| ctx.cwd.as_ref())
                .map(|cwd| cwd.join("unknown")) // TODO: parse path from strace args
                .unwrap_or_else(|| PathBuf::from("unknown"));
            
            ActionKind::FileOpen {
                path,
                flags: format!("{:#x}", ev.args[1]),
            }
        },
        "socket" => ActionKind::Other {
            syscall: ev.call.clone(),
            describe: format!("Socket creation: domain={}, type={}, protocol={}", 
                ev.args[0], ev.args[1], ev.args[2]),
        },
        "connect" => {
            let fd = ev.args[0] as i32;
            let socket_desc = ev.enrichment.as_ref()
                .and_then(|ctx| ctx.fd_map.get(&fd))
                .cloned()
                .unwrap_or_else(|| format!("socket:{}", fd));
            
            ActionKind::Other {
                syscall: ev.call.clone(),
                describe: format!("Connect to {}", socket_desc),
            }
        },
        _ => ActionKind::Other {
            syscall: ev.call.clone(),
            describe: format!("Syscall: {}", ev.call),
        },
    }
}

/// Flush actions that haven't seen activity within the timeout
fn flush_stale_actions(
    pending: &mut HashMap<AggregationKey, PendingAction>,
    timeout: Duration,
) -> Vec<Action> {
    let now = Instant::now();
    let mut stale_keys = Vec::new();
    let mut actions = Vec::new();

    for (key, pending_action) in pending.iter() {
        if now.duration_since(pending_action.last_activity) > timeout {
            stale_keys.push(key.clone());
            actions.push(finalize_action(pending_action.clone()));
        }
    }

    for key in stale_keys {
        pending.remove(&key);
    }

    actions
}

/// Convert a PendingAction to a final Action
fn finalize_action(pending_action: PendingAction) -> Action {
    let mut kind = pending_action.kind_template;
    
    // Update byte counts for aggregated operations
    match &mut kind {
        ActionKind::FileRead { bytes, .. } => *bytes = pending_action.bytes,
        ActionKind::FileWrite { bytes, .. } => *bytes = pending_action.bytes,
        _ => {}
    }
    
    Action {
        first_ts: pending_action.first_ts,
        last_ts: pending_action.last_ts,
        pids: pending_action.pids.into(),
        kind,
    }
}

pub async fn run_with_ready(mut rx_evt: Receiver<SyscallEvent>, tx_act: Sender<Action>, ready_tx: mpsc::Sender<()>) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run the normal processing loop
    run(rx_evt, tx_act).await
}

pub async fn run_with_ready_and_cancellation(
    rx_evt: Receiver<SyscallEvent>,
    tx_act: Sender<Action>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run with cancellation support
    run_with_cancellation(rx_evt, tx_act, cancellation_token).await
}
