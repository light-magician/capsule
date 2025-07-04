use crate::model::{Action, ActionKind, SyscallEvent, SyscallCategory, SyscallOperation};
use anyhow::Result;
use smallvec::smallvec;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Enhanced aggregation key for grouping related syscalls
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AggregationKey {
    pid: u32,
    category: SyscallCategory,
    operation: SyscallOperation,
    target: AggregationTarget,
}

/// Target of the aggregation for more precise grouping
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum AggregationTarget {
    File { path: String },
    FileDescriptor { fd: i32 },
    Network { address: String },
    Process { target_pid: u32 },
    Memory { address: String },
    System,
    Unknown,
}

/// Pending action being accumulated with enhanced context
#[derive(Debug, Clone)]
struct PendingAction {
    first_ts: u64,
    last_ts: u64,
    pids: Vec<u32>,
    bytes: usize,
    count: usize,
    last_activity: Instant,
    kind_template: ActionKind,
    syscall_sequence: Vec<String>,  // Track syscall sequence for pattern recognition
    security_events: u32,           // Count of security-relevant events
    human_descriptions: Vec<String>, // Collect human descriptions
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

/// Enhanced event classification using new syscall categorization
fn classify_event(ev: &SyscallEvent) -> Option<(AggregationKey, bool)> {
    let category = ev.syscall_category.as_ref()?;
    let operation = ev.syscall_operation.as_ref()?;
    
    // Determine aggregation target based on syscall context
    let target = determine_aggregation_target(ev, category, operation);
    
    // Determine if this event should be aggregated based on category and operation
    let should_aggregate = should_aggregate_event(category, operation);
    
    Some((
        AggregationKey {
            pid: ev.pid,
            category: category.clone(),
            operation: operation.clone(),
            target,
        },
        should_aggregate,
    ))
}

/// Determine the target for aggregation based on syscall context
fn determine_aggregation_target(ev: &SyscallEvent, category: &SyscallCategory, operation: &SyscallOperation) -> AggregationTarget {
    match category {
        SyscallCategory::FileSystem => {
            // Prefer absolute path, fall back to file descriptor
            if let Some(path) = &ev.abs_path {
                AggregationTarget::File { path: path.clone() }
            } else if let Some(fd) = ev.fd {
                AggregationTarget::FileDescriptor { fd }
            } else {
                AggregationTarget::Unknown
            }
        },
        SyscallCategory::NetworkCommunication => {
            // Use network address if available, fall back to fd
            if let Some(net) = &ev.net {
                let address = match (&net.remote_addr, &net.remote_port) {
                    (Some(addr), Some(port)) => format!("{}:{}", addr, port),
                    (Some(addr), None) => addr.clone(),
                    _ => format!("fd:{}", ev.fd.unwrap_or(-1)),
                };
                AggregationTarget::Network { address }
            } else if let Some(fd) = ev.fd {
                AggregationTarget::FileDescriptor { fd }
            } else {
                AggregationTarget::Unknown
            }
        },
        SyscallCategory::ProcessControl => {
            // For process signals, use target PID; otherwise use system
            match operation {
                SyscallOperation::ProcessSignal => {
                    // Target PID is usually in first argument for kill, tkill
                    let target_pid = ev.args[0] as u32;
                    AggregationTarget::Process { target_pid }
                },
                _ => AggregationTarget::System,
            }
        },
        SyscallCategory::MemoryManagement => {
            // Group by memory address for mapping operations
            let address = match operation {
                SyscallOperation::MemoryMap | SyscallOperation::MemoryUnmap => {
                    format!("0x{:x}", ev.args.get(0).unwrap_or(&0))
                },
                _ => "heap".to_string(),
            };
            AggregationTarget::Memory { address }
        },
        _ => AggregationTarget::System,
    }
}

/// Determine if events of this type should be aggregated
fn should_aggregate_event(category: &SyscallCategory, operation: &SyscallOperation) -> bool {
    match category {
        // File I/O operations benefit from aggregation
        SyscallCategory::FileSystem => {
            matches!(operation, 
                SyscallOperation::FileRead | 
                SyscallOperation::FileWrite |
                SyscallOperation::FileStat |
                SyscallOperation::DirectoryRead
            )
        },
        
        // Process lifecycle events should be immediate
        SyscallCategory::ProcessControl => {
            !matches!(operation,
                SyscallOperation::ProcessCreate |
                SyscallOperation::ProcessExecute |
                SyscallOperation::ProcessTerminate
            )
        },
        
        // Network operations - aggregate data transfer, not connections
        SyscallCategory::NetworkCommunication => {
            matches!(operation,
                SyscallOperation::NetworkSend |
                SyscallOperation::NetworkReceive
            )
        },
        
        // Memory operations can be aggregated
        SyscallCategory::MemoryManagement => true,
        
        // Background system operations should be aggregated
        SyscallCategory::InterProcessCommunication => true,
        SyscallCategory::TimeManagement => true,
        SyscallCategory::SystemInformation => true,
        
        // Security and device operations are usually important - don't aggregate
        SyscallCategory::SecurityManagement => false,
        SyscallCategory::DeviceManagement => false,
        
        // Unknown category - don't aggregate to be safe
        SyscallCategory::Unknown => false,
    }
}

/// Create an ActionKind from a syscall event using enhanced classification
fn create_action_kind(ev: &SyscallEvent) -> ActionKind {
    let category = ev.syscall_category.as_ref();
    let operation = ev.syscall_operation.as_ref();
    
    match (category, operation) {
        // File System Operations
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::FileRead)) => {
            let path = get_file_path(ev);
            ActionKind::FileRead {
                path,
                bytes: if ev.retval > 0 { ev.retval as usize } else { 0 },
            }
        },
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::FileWrite)) => {
            let path = get_file_path(ev);
            ActionKind::FileWrite {
                path,
                bytes: if ev.retval > 0 { ev.retval as usize } else { 0 },
            }
        },
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::FileOpen)) => {
            let path = ev.abs_path.as_ref()
                .map(|p| PathBuf::from(p))
                .unwrap_or_else(|| PathBuf::from("unknown"));
            ActionKind::FileOpen {
                path,
                flags: format!("{:#x}", ev.args.get(1).unwrap_or(&0)),
            }
        },
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::FileClose)) => {
            let path = get_file_path(ev);
            ActionKind::FileClose { path }
        },
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::FileStat)) => {
            let path = ev.abs_path.as_ref()
                .map(|p| PathBuf::from(p))
                .unwrap_or_else(|| PathBuf::from("unknown"));
            ActionKind::FileStat { path }
        },
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::FileChmod)) => {
            let path = get_file_path(ev);
            ActionKind::FileChmod {
                path,
                mode: ev.args.get(1).unwrap_or(&0) as &u32,
            }
        },
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::FileChown)) => {
            let path = get_file_path(ev);
            ActionKind::FileChown {
                path,
                uid: ev.args.get(1).unwrap_or(&0) as &u32,
                gid: ev.args.get(2).unwrap_or(&0) as &u32,
            }
        },
        (Some(SyscallCategory::FileSystem), Some(SyscallOperation::DirectoryRead)) => {
            let path = get_file_path(ev);
            // Rough estimate of entries based on bytes returned
            let entries = if ev.retval > 0 { (ev.retval / 20).max(1) as usize } else { 0 };
            ActionKind::DirectoryList { path, entries }
        },
        
        // Process Control Operations
        (Some(SyscallCategory::ProcessControl), Some(SyscallOperation::ProcessCreate)) => {
            ActionKind::ProcessSpawn {
                pid: if ev.retval > 0 { ev.retval as u32 } else { ev.pid },
                argv: ev.argv.clone().unwrap_or_default(),
                parent_pid: ev.pid,
            }
        },
        (Some(SyscallCategory::ProcessControl), Some(SyscallOperation::ProcessExecute)) => {
            ActionKind::ProcessExec {
                argv: ev.argv.clone().unwrap_or_default(),
            }
        },
        (Some(SyscallCategory::ProcessControl), Some(SyscallOperation::ProcessTerminate)) => {
            ActionKind::ProcessExit {
                pid: ev.pid,
                exit_code: ev.args.get(0).unwrap_or(&0) as &i32,
            }
        },
        (Some(SyscallCategory::ProcessControl), Some(SyscallOperation::ProcessSignal)) => {
            ActionKind::SignalSend {
                target_pid: ev.args.get(0).unwrap_or(&0) as &u32,
                signal: ev.args.get(1).unwrap_or(&0) as &i32,
            }
        },
        
        // Network Operations
        (Some(SyscallCategory::NetworkCommunication), Some(SyscallOperation::NetworkConnect)) => {
            if let Some(net) = &ev.net {
                if let (Some(addr), Some(port)) = (&net.remote_addr, &net.remote_port) {
                    if let Ok(socket_addr) = format!("{}:{}", addr, port).parse() {
                        return ActionKind::SocketConnect {
                            addr: socket_addr,
                            protocol: net.protocol.clone().unwrap_or_else(|| "TCP".to_string()),
                        };
                    }
                }
            }
            ActionKind::Other {
                syscall: ev.call.clone(),
                describe: ev.human_description.clone().unwrap_or_else(|| "Network connect".to_string()),
            }
        },
        (Some(SyscallCategory::NetworkCommunication), Some(SyscallOperation::NetworkBind)) => {
            if let Some(net) = &ev.net {
                if let (Some(addr), Some(port)) = (&net.local_addr, &net.local_port) {
                    if let Ok(socket_addr) = format!("{}:{}", addr, port).parse() {
                        return ActionKind::SocketBind {
                            addr: socket_addr,
                            protocol: net.protocol.clone().unwrap_or_else(|| "TCP".to_string()),
                        };
                    }
                }
            }
            ActionKind::Other {
                syscall: ev.call.clone(),
                describe: ev.human_description.clone().unwrap_or_else(|| "Network bind".to_string()),
            }
        },
        (Some(SyscallCategory::NetworkCommunication), Some(SyscallOperation::NetworkAccept)) => {
            if let Some(net) = &ev.net {
                if let (Some(local_addr), Some(local_port), Some(remote_addr), Some(remote_port)) = 
                    (&net.local_addr, &net.local_port, &net.remote_addr, &net.remote_port) {
                    if let (Ok(local_socket), Ok(remote_socket)) = 
                        (format!("{}:{}", local_addr, local_port).parse(), 
                         format!("{}:{}", remote_addr, remote_port).parse()) {
                        return ActionKind::SocketAccept {
                            local_addr: local_socket,
                            remote_addr: remote_socket,
                        };
                    }
                }
            }
            ActionKind::Other {
                syscall: ev.call.clone(),
                describe: ev.human_description.clone().unwrap_or_else(|| "Network accept".to_string()),
            }
        },
        
        // Memory Management Operations
        (Some(SyscallCategory::MemoryManagement), Some(SyscallOperation::MemoryMap)) => {
            ActionKind::MemoryMap {
                addr: ev.args.get(0).unwrap_or(&0) as &u64,
                size: ev.args.get(1).unwrap_or(&0) as &usize,
                prot: format!("{:#x}", ev.args.get(2).unwrap_or(&0)),
            }
        },
        (Some(SyscallCategory::MemoryManagement), Some(SyscallOperation::MemoryUnmap)) => {
            ActionKind::MemoryUnmap {
                addr: ev.args.get(0).unwrap_or(&0) as &u64,
                size: ev.args.get(1).unwrap_or(&0) as &usize,
            }
        },
        
        // Default fallback using human description
        _ => {
            ActionKind::Other {
                syscall: ev.call.clone(),
                describe: ev.human_description.clone()
                    .unwrap_or_else(|| format!("{}({})", ev.call, 
                        ev.args.iter().take(3).map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                    )),
            }
        },
    }
}

/// Helper function to get file path from syscall event
fn get_file_path(ev: &SyscallEvent) -> PathBuf {
    if let Some(path) = &ev.abs_path {
        PathBuf::from(path)
    } else if let Some(fd) = ev.fd {
        ev.fd_map.get(&fd)
            .map(|p| PathBuf::from(p))
            .unwrap_or_else(|| PathBuf::from(format!("fd:{}", fd)))
    } else {
        PathBuf::from("unknown")
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
