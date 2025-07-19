//! Shared agent state management
//!
//! Maintains real-time agent state from ProcessEvent streams
//! Shared between tracking and TUI components via Arc<RwLock>

use anyhow::Result;
use chrono::Utc;
use core::events::{ProcessEvent, ProcessEventType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// Live process information for TUI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: Vec<String>,
    pub start_time: u64,
    pub end_time: Option<u64>,
}

/// Shared agent state - single source of truth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// All processes by PID
    pub processes: HashMap<u32, LiveProcess>,
    /// Currently active (not exited) PIDs
    pub active_pids: HashSet<u32>,
    /// Recent exits for deduplication (PID -> exit timestamp)
    pub recent_exits: HashMap<u32, u64>,
    /// Capsule target name (e.g., "claude" from "capsule run claude")
    pub capsule_target: Option<String>,
    /// Last state update timestamp
    pub last_updated: u64,
    /// Session start time
    pub session_start: u64,
}

/// Process tracker with shared state
pub struct ProcessTracker {
    /// Shared state accessible by TUI
    state: Arc<RwLock<AgentState>>,
    /// Exit deduplication window (5 seconds)
    exit_window: Duration,
}

impl LiveProcess {
    /// Generate human-readable process name
    pub fn generate_name(command_line: &[String], capsule_target: Option<&str>) -> String {
        // If this matches the capsule target
        if let Some(target) = capsule_target {
            if command_line.iter().any(|arg| arg.contains(target)) {
                return target.to_string();
            }
        }
        
        // Extract executable name
        if let Some(executable) = command_line.first() {
            let binary_name = executable.split('/').last().unwrap_or(executable);
            
            // For interpreters, try to get script name
            match binary_name {
                "python" | "python3" | "node" | "ruby" => {
                    if command_line.len() > 1 {
                        let script = &command_line[1];
                        if let Some(script_name) = script.split('/').last() {
                            return script_name.trim_end_matches(".py")
                                           .trim_end_matches(".js")
                                           .trim_end_matches(".rb")
                                           .to_string();
                        }
                    }
                    binary_name.to_string()
                }
                _ => binary_name.to_string()
            }
        } else {
            "unknown".to_string()
        }
    }
}

impl AgentState {
    /// Create new empty agent state
    pub fn new(capsule_target: Option<String>) -> Self {
        let now = Utc::now().timestamp_micros() as u64;
        Self {
            processes: HashMap::new(),
            active_pids: HashSet::new(),
            recent_exits: HashMap::new(),
            capsule_target,
            last_updated: now,
            session_start: now,
        }
    }
    
    /// Get all currently live processes (for TUI)
    pub fn live_processes(&self) -> Vec<&LiveProcess> {
        self.active_pids
            .iter()
            .filter_map(|pid| self.processes.get(pid))
            .collect()
    }
    
    /// Get process by PID
    pub fn get_process(&self, pid: u32) -> Option<&LiveProcess> {
        self.processes.get(&pid)
    }
    
    /// Get root process (first one added)
    pub fn root_process(&self) -> Option<&LiveProcess> {
        self.processes.values().min_by_key(|p| p.start_time)
    }
    
    /// Count of active processes
    pub fn active_count(&self) -> usize {
        self.active_pids.len()
    }
}

impl ProcessTracker {
    /// Create new tracker with shared state
    pub fn new(capsule_target: Option<String>) -> (Self, Arc<RwLock<AgentState>>) {
        let state = Arc::new(RwLock::new(AgentState::new(capsule_target)));
        let tracker = Self {
            state: state.clone(),
            exit_window: Duration::from_secs(5),
        };
        (tracker, state)
    }

    /// Main tracking loop - subscribe to ProcessEvent stream
    pub async fn run(
        self,
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
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a ProcessEvent - update shared state
    async fn process_event(&self, event: ProcessEvent) -> Result<()> {
        let mut state = self.state.write().await;
        
        match event.event_type {
            ProcessEventType::Spawn => {
                let name = LiveProcess::generate_name(&event.command_line, state.capsule_target.as_deref());
                let process = LiveProcess {
                    pid: event.pid,
                    ppid: event.ppid,
                    name,
                    command_line: event.command_line,
                    start_time: event.timestamp,
                    end_time: None,
                };
                
                state.processes.insert(event.pid, process);
                state.active_pids.insert(event.pid);
            }
            ProcessEventType::Exit => {
                // Check for duplicate exit within window
                if let Some(last_exit) = state.recent_exits.get(&event.pid) {
                    let time_diff = event.timestamp.saturating_sub(*last_exit);
                    if time_diff < self.exit_window.as_micros() as u64 {
                        return Ok(()); // Duplicate exit, ignore
                    }
                }
                
                // Record exit
                state.recent_exits.insert(event.pid, event.timestamp);
                state.active_pids.remove(&event.pid);
                
                // Update process end time
                if let Some(process) = state.processes.get_mut(&event.pid) {
                    process.end_time = Some(event.timestamp);
                }
            }
        }
        
        state.last_updated = event.timestamp;
        Ok(())
    }
    
    /// Get shared state reference for external access (TUI)
    pub fn state(&self) -> Arc<RwLock<AgentState>> {
        self.state.clone()
    }
}
