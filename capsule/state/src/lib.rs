//! Shared agent state management
//!
//! Maintains real-time agent state from ProcessEvent streams
//! Shared between tracking and TUI components via Arc<RwLock>

use anyhow::Result;
use chrono::Utc;
use core::{SyscallEvent, SyscallCategory, ProcessSyscall, ProcessEvent, ProcessEventType, DomainEvent};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// Debug logging that goes to a file to avoid interfering with TUI
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if std::env::var("CAPSULE_DEBUG").is_ok() {
            use std::fs::OpenOptions;
            use std::io::Write;
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/capsule_debug.log") {
                let _ = writeln!(file, "[{}] {}",
                    chrono::Utc::now().format("%H:%M:%S%.3f"),
                    format_args!($($arg)*));
            }
        }
    };
}

/// Initialize debug logging if enabled
pub fn init_debug_logging() {
    if std::env::var("CAPSULE_DEBUG").is_ok() {
        // Clear previous log file
        let _ = std::fs::remove_file("/tmp/capsule_debug.log");
        debug_log!("=== CAPSULE DEBUG SESSION STARTED ===");
        eprintln!("Debug logging enabled. Logs are written to: /tmp/capsule_debug.log");
        eprintln!("To view logs: tail -f /tmp/capsule_debug.log");
    }
}

/// Process state for lifecycle tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProcessState {
    /// Process created but waiting for execve
    Spawning,
    /// Process actively running with command
    Active,
    /// Process is waiting to execute
    Waiting,
    /// Process has triggered exit but is not yet executed
    Exiting,
    /// Process has exited
    Exited,
}

/// Live process information for TUI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: Vec<String>,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub state: ProcessState,
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
    /// Ring buffer of raw syscall lines for TUI display
    pub raw_syscalls: VecDeque<String>,
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
                            return script_name
                                .trim_end_matches(".py")
                                .trim_end_matches(".js")
                                .trim_end_matches(".rb")
                                .to_string();
                        }
                    }
                    binary_name.to_string()
                }
                _ => binary_name.to_string(),
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
            raw_syscalls: VecDeque::new(),
        }
    }

    /// Add raw syscall line to buffer (bounded to 1000 entries)
    pub fn add_syscall(&mut self, syscall_line: String) {
        const MAX_SYSCALLS: usize = 1000;

        if self.raw_syscalls.len() >= MAX_SYSCALLS {
            self.raw_syscalls.pop_front();
        }
        self.raw_syscalls.push_back(syscall_line);
        self.last_updated = Utc::now().timestamp_micros() as u64;
    }

    /// Get recent syscalls for TUI display (newest first)
    pub fn recent_syscalls(&self) -> Vec<&String> {
        self.raw_syscalls.iter().collect()
    }

    /// Get all currently live processes (for TUI) sorted by PID ascending
    pub fn live_processes(&self) -> Vec<&LiveProcess> {
        let mut processes: Vec<&LiveProcess> = self
            .active_pids
            .iter()
            .filter_map(|pid| self.processes.get(pid))
            .collect();

        // Sort by PID ascending for consistent display order
        processes.sort_by_key(|process| process.pid);
        processes
    }

    /// Get all processes sorted by state (Active first), then PID
    /// Shows ALL processes including exited ones for debugging
    pub fn processes_by_state(&self) -> Vec<&LiveProcess> {
        // Get ALL processes, not just active ones
        let mut processes: Vec<&LiveProcess> = self.processes.values().collect();

        // CONSISTENCY CHECK: Fix any processes where active_pids and ProcessState are inconsistent
        let mut active_count = 0;
        let mut spawning_count = 0;
        let mut exited_count = 0;

        for process in &processes {
            let is_in_active_pids = self.active_pids.contains(&process.pid);
            match process.state {
                ProcessState::Active => {
                    active_count += 1;
                    if !is_in_active_pids {
                        debug_log!(
                            "DEBUG: INCONSISTENCY - Process {} is Active but NOT in active_pids",
                            process.pid
                        );
                    }
                }
                ProcessState::Waiting => {
                    // Waiting processes are considered active (they're just waiting for something)
                    if !is_in_active_pids {
                        debug_log!(
                            "DEBUG: INCONSISTENCY - Process {} is Waiting but NOT in active_pids",
                            process.pid
                        );
                    }
                }
                ProcessState::Spawning => {
                    spawning_count += 1;
                    if !is_in_active_pids {
                        debug_log!(
                            "DEBUG: INCONSISTENCY - Process {} is Spawning but NOT in active_pids",
                            process.pid
                        );
                    }
                }
                ProcessState::Exiting => {
                    // Exiting processes are still technically active until fully exited
                    if !is_in_active_pids {
                        debug_log!(
                            "DEBUG: INCONSISTENCY - Process {} is Exiting but NOT in active_pids",
                            process.pid
                        );
                    }
                }
                ProcessState::Exited => {
                    exited_count += 1;
                    if is_in_active_pids {
                        debug_log!(
                            "DEBUG: INCONSISTENCY - Process {} is Exited but STILL in active_pids",
                            process.pid
                        );
                    }
                }
            }
        }

        // Only log state summary if there are inconsistencies or every 10th call
        if active_count + spawning_count != self.active_pids.len() || processes.len() % 10 == 0 {
            debug_log!(
                "DEBUG: State summary - Active: {}, Spawning: {}, Exited: {}, active_pids size: {}",
                active_count,
                spawning_count,
                exited_count,
                self.active_pids.len()
            );
        }

        // Sort by state priority (Active > Spawning > Exited), then by PID
        processes.sort_by(|a, b| {
            let state_order_a = match a.state {
                ProcessState::Spawning => 0,
                ProcessState::Active => 1,
                ProcessState::Waiting => 2,
                ProcessState::Exiting => 3,
                ProcessState::Exited => 4,
            };
            let state_order_b = match b.state {
                ProcessState::Spawning => 0,
                ProcessState::Active => 1,
                ProcessState::Waiting => 2,
                ProcessState::Exiting => 3,
                ProcessState::Exited => 4,
            };

            state_order_a.cmp(&state_order_b).then(a.pid.cmp(&b.pid))
        });

        processes
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

    /// Get processes in tree order with indentation for TUI display
    pub fn tree_processes(&self) -> Vec<(u32, String, &LiveProcess)> {
        let mut tree_items = Vec::new();
        let mut visited = std::collections::HashSet::new();

        // First, find root processes (PPID = 0 or parent not in our process list)
        let mut roots: Vec<&LiveProcess> = self
            .processes
            .values()
            .filter(|p| p.ppid == 0 || !self.processes.contains_key(&p.ppid))
            .collect();
        roots.sort_by_key(|p| p.pid);

        // Build tree recursively for each root
        for root in roots {
            self.build_tree_recursive(root, 0, &mut tree_items, &mut visited);
        }

        tree_items
    }

    fn build_tree_recursive<'a>(
        &'a self,
        process: &'a LiveProcess,
        depth: u32,
        tree_items: &mut Vec<(u32, String, &'a LiveProcess)>,
        visited: &mut std::collections::HashSet<u32>,
    ) {
        if visited.contains(&process.pid) {
            return; // Avoid cycles
        }
        visited.insert(process.pid);

        // Generate indent string
        let indent = if depth == 0 {
            String::new()
        } else {
            let mut indent = String::new();
            for i in 0..depth {
                if i == depth - 1 {
                    indent.push_str("├");
                } else {
                    indent.push_str("│ ");
                }
            }
            indent
        };

        tree_items.push((depth, indent, process));

        // Find and add children
        let mut children: Vec<&LiveProcess> = self
            .processes
            .values()
            .filter(|p| p.ppid == process.pid && p.pid != process.pid) // Avoid self-reference
            .collect();
        children.sort_by_key(|p| p.pid);

        for child in children.iter() {
            self.build_tree_recursive(child, depth + 1, tree_items, visited);
        }
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

    /// Main tracking loop - subscribe to ProcessEvent stream and raw syscalls
    pub async fn run(
        self,
        mut rx_events: broadcast::Receiver<ProcessEvent>,
        mut rx_raw: broadcast::Receiver<String>,
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
                raw_result = rx_raw.recv() => {
                    match raw_result {
                        Ok(syscall_line) => {
                            if let Err(e) = self.process_syscall(syscall_line).await {
                                eprintln!("Error processing syscall: {}", e);
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("Syscall tracker lagged by {} lines", n);
                        },
                        Err(broadcast::error::RecvError::Closed) => {
                            eprintln!("Raw syscall stream closed");
                        }
                    }
                },
                _ = cancellation_token.cancelled() => {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Main tracking loop for SyscallEvent stream - NEW INTERFACE
    pub async fn run_syscall(
        self,
        mut rx_syscalls: broadcast::Receiver<SyscallEvent>,
        ready_tx: mpsc::Sender<()>,
        cancellation_token: CancellationToken,
    ) -> Result<()> {
        // Signal ready
        ready_tx.send(()).await?;

        loop {
            tokio::select! {
                syscall_result = rx_syscalls.recv() => {
                    match syscall_result {
                        Ok(syscall_event) => {
                            if let Err(e) = self.process_syscall_event(syscall_event).await {
                                eprintln!("Error processing syscall event: {}", e);
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("Syscall tracker lagged by {} events", n);
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

    /// Process a SyscallEvent - categorize and convert to domain events as needed
    async fn process_syscall_event(&self, syscall_event: SyscallEvent) -> Result<()> {
        // Always add raw syscall to buffer for TUI display
        {
            let mut state = self.state.write().await;
            state.add_syscall(syscall_event.raw_line.clone());
        }

        // Categorize the syscall
        let category = syscall_event.categorize();
        
        // Handle process events - convert to ProcessEvent and process
        if let SyscallCategory::Process(process_syscall) = category {
            if let Some(process_event) = self.convert_to_process_event(&syscall_event, &process_syscall) {
                self.process_event(process_event).await?;
            }
        }
        
        // Future: Handle other domain events (FileIo, Network, etc.)
        // For now, we just log them or ignore them
        
        Ok(())
    }

    /// Convert SyscallEvent to ProcessEvent for process-related syscalls
    fn convert_to_process_event(&self, syscall_event: &SyscallEvent, process_syscall: &ProcessSyscall) -> Option<ProcessEvent> {
        match process_syscall {
            ProcessSyscall::Execve => {
                // Parse command line from execve arguments
                let command_line = self.parse_execve_syscall(&syscall_event.args, syscall_event.result.as_deref())
                    .unwrap_or_else(|| vec!["execve".to_string()]);

                Some(ProcessEvent::exec(
                    syscall_event.timestamp,
                    syscall_event.pid,
                    0, // PPID will be resolved by state tracker
                    command_line,
                    None, // Working directory not available from strace
                ))
            },
            ProcessSyscall::Clone => {
                // Parse child PID from return value
                if let Some(child_pid) = self.parse_clone_result(syscall_event.result.as_deref()) {
                    Some(ProcessEvent::clone(syscall_event.timestamp, syscall_event.pid, child_pid))
                } else {
                    None // Invalid clone - no child PID
                }
            },
            ProcessSyscall::Fork => {
                // Parse child PID from return value
                if let Some(child_pid) = self.parse_fork_result(syscall_event.result.as_deref()) {
                    Some(ProcessEvent::fork(syscall_event.timestamp, syscall_event.pid, child_pid))
                } else {
                    None // Invalid fork - no child PID
                }
            },
            ProcessSyscall::VFork => {
                // Parse child PID from return value
                if let Some(child_pid) = self.parse_vfork_result(syscall_event.result.as_deref()) {
                    Some(ProcessEvent::vfork(syscall_event.timestamp, syscall_event.pid, child_pid))
                } else {
                    None // Invalid vfork - no child PID
                }
            },
            ProcessSyscall::Exit => {
                // Parse exit code from first argument (exit(0))
                let exit_code = syscall_event.args
                    .first()
                    .and_then(|arg| arg.parse::<i32>().ok());

                Some(ProcessEvent::exit(syscall_event.timestamp, syscall_event.pid, exit_code))
            },
            ProcessSyscall::ExitGroup => {
                // Parse exit code from result
                let exit_code = syscall_event.result
                    .as_ref()
                    .and_then(|r| r.parse::<i32>().ok());

                Some(ProcessEvent::exit(syscall_event.timestamp, syscall_event.pid, exit_code))
            },
            ProcessSyscall::ProcessExited => {
                // Synthetic event from strace "+++ exited +++" - process fully terminated
                let exit_code = syscall_event.args
                    .first()
                    .and_then(|arg| arg.parse::<i32>().ok());

                // Create a special "fully exited" ProcessEvent
                Some(ProcessEvent::fully_exited(syscall_event.timestamp, syscall_event.pid, exit_code))
            },
            ProcessSyscall::Wait4 => {
                // Parse child PID and exit code from arguments and result
                if let Some((child_pid, child_exit_code)) = self.parse_wait4_syscall(&syscall_event.args, syscall_event.result.as_deref()) {
                    Some(ProcessEvent::wait(syscall_event.timestamp, syscall_event.pid, child_pid, child_exit_code))
                } else {
                    None // Invalid wait4 - couldn't parse
                }
            },
            ProcessSyscall::WaitPid => {
                // Parse child PID and exit code from arguments and result
                if let Some((child_pid, child_exit_code)) = self.parse_waitpid_syscall(&syscall_event.args, syscall_event.result.as_deref()) {
                    Some(ProcessEvent::wait(syscall_event.timestamp, syscall_event.pid, child_pid, child_exit_code))
                } else {
                    None // Invalid waitpid - couldn't parse
                }
            },
        }
    }

    /// Process a ProcessEvent - update shared state
    async fn process_event(&self, event: ProcessEvent) -> Result<()> {
        let mut state = self.state.write().await;

        // Debug: Track all events we're processing (to stderr to avoid TUI interference)
        match event.event_type {
            ProcessEventType::Clone { child_pid } => {
                debug_log!(
                    "DEBUG: EVENT - Clone: parent {} created child {}",
                    event.pid,
                    child_pid
                );
                self.handle_process_creation(&mut state, event.pid, child_pid, &event, "clone")
                    .await?;
            }
            ProcessEventType::Fork { child_pid } => {
                debug_log!(
                    "DEBUG: EVENT - Fork: parent {} created child {}",
                    event.pid,
                    child_pid
                );
                self.handle_process_creation(&mut state, event.pid, child_pid, &event, "fork")
                    .await?;
            }
            ProcessEventType::VFork { child_pid } => {
                debug_log!(
                    "DEBUG: EVENT - VFork: parent {} created child {}",
                    event.pid,
                    child_pid
                );
                self.handle_process_creation(&mut state, event.pid, child_pid, &event, "vfork")
                    .await?;
            }
            ProcessEventType::Exec => {
                debug_log!(
                    "DEBUG: EVENT - Exec: PID {} -> {:?}",
                    event.pid,
                    event
                        .command_line
                        .get(0)
                        .unwrap_or(&"<no command>".to_string())
                );
                self.handle_exec(&mut state, &event).await?;
            }
            ProcessEventType::Exit => {
                debug_log!(
                    "DEBUG: EVENT - Exit: PID {} (exit code: {:?}) - entering exit sequence",
                    event.pid,
                    event.exit_code
                );
                self.handle_exit_start(&mut state, &event).await?;
            }
            ProcessEventType::FullyExited => {
                debug_log!(
                    "DEBUG: EVENT - FullyExited: PID {} (exit code: {:?}) - process completely terminated",
                    event.pid,
                    event.exit_code
                );
                self.handle_fully_exited(&mut state, &event).await?;
            }
            ProcessEventType::Wait {
                child_pid,
                child_exit_code,
            } => {
                debug_log!(
                    "DEBUG: EVENT - Wait: parent {} waited for child {} (exit code: {:?})",
                    event.pid,
                    child_pid,
                    child_exit_code
                );
                self.handle_wait(&mut state, event.pid, child_pid, child_exit_code, &event)
                    .await?;
            }
        }

        state.last_updated = event.timestamp;
        Ok(())
    }

    /// Handle process creation (clone/fork/vfork)
    async fn handle_process_creation(
        &self,
        state: &mut AgentState,
        parent_pid: u32,
        child_pid: u32,
        event: &ProcessEvent,
        creation_type: &str,
    ) -> Result<()> {
        // Get parent name for better child naming
        let parent_name = state
            .processes
            .get(&parent_pid)
            .map(|p| p.name.as_str())
            .unwrap_or("unknown");

        // Create a placeholder process for the child with parent context
        let child_name = format!("{}:{}", creation_type, parent_name);
        let child_process = LiveProcess {
            pid: child_pid,
            ppid: parent_pid,
            name: child_name,
            command_line: vec![format!("{}:{}", creation_type, parent_name)], // Temporary until execve
            start_time: event.timestamp,
            end_time: None,
            state: ProcessState::Spawning, // Waiting for execve
        };

        // Add child to processes and active PIDs
        state.processes.insert(child_pid, child_process);
        state.active_pids.insert(child_pid);

        // Update parent's PPID if we know it now
        if let Some(_parent_process) = state.processes.get_mut(&parent_pid) {
            // Parent might have had PPID=0, but now we can establish the relationship
        }

        Ok(())
    }

    /// Handle exec - process executed new program
    async fn handle_exec(&self, state: &mut AgentState, event: &ProcessEvent) -> Result<()> {
        let name = LiveProcess::generate_name(&event.command_line, state.capsule_target.as_deref());

        if let Some(existing_process) = state.processes.get_mut(&event.pid) {
            // Update existing process (from clone/fork) with real command line
            // Keep the existing PPID from clone/fork event
            existing_process.name = name;
            existing_process.command_line = event.command_line.clone();
            existing_process.state = ProcessState::Active; // Now actively running

            debug_log!(
                "DEBUG: Exec updated existing process {} with PPID {} -> {:?}",
                event.pid,
                existing_process.ppid,
                event
                    .command_line
                    .get(0)
                    .unwrap_or(&"<no command>".to_string())
            );
        } else {
            // New process we haven't seen before (direct execve)
            // Try to resolve PPID from /proc filesystem if available
            let resolved_ppid = self
                .resolve_ppid_from_proc(event.pid)
                .await
                .unwrap_or(event.ppid);

            let process = LiveProcess {
                pid: event.pid,
                ppid: resolved_ppid,
                name,
                command_line: event.command_line.clone(),
                start_time: event.timestamp,
                end_time: None,
                state: ProcessState::Active, // Directly active
            };

            debug_log!(
                "DEBUG: Exec created new process {} with resolved PPID {} -> {:?}",
                event.pid,
                resolved_ppid,
                event
                    .command_line
                    .get(0)
                    .unwrap_or(&"<no command>".to_string())
            );

            state.processes.insert(event.pid, process);
            state.active_pids.insert(event.pid);
        }

        Ok(())
    }

    /// Handle exit start - process called exit() syscall and is entering exit sequence
    async fn handle_exit_start(&self, state: &mut AgentState, event: &ProcessEvent) -> Result<()> {
        // Check for duplicate exit within window
        if let Some(last_exit) = state.recent_exits.get(&event.pid) {
            let time_diff = event.timestamp.saturating_sub(*last_exit);
            if time_diff < self.exit_window.as_micros() as u64 {
                debug_log!(
                    "DEBUG: Ignoring duplicate exit start for PID {} (within {}μs window)",
                    event.pid,
                    self.exit_window.as_micros()
                );
                return Ok(()); // Duplicate exit, ignore
            }
        }

        // Check if this is a root/main process
        let is_root_process = if let Some(process) = state.processes.get(&event.pid) {
            process.ppid == 0 || !state.processes.contains_key(&process.ppid)
        } else {
            false
        };

        if is_root_process {
            debug_log!("DEBUG: WARNING - Root/main process {} is starting exit sequence! This might indicate session end.", event.pid);
        }

        // Update process state to Exiting (not yet fully terminated)
        if let Some(process) = state.processes.get_mut(&event.pid) {
            process.state = ProcessState::Exiting;
            debug_log!(
                "DEBUG: Process {} ({}) marked as exiting",
                event.pid,
                process.name
            );
        } else {
            debug_log!("DEBUG: Exit start event for unknown process {}", event.pid);
        }

        Ok(())
    }

    /// Handle fully exited - process has been completely terminated (strace "+++ exited +++" or equivalent)
    async fn handle_fully_exited(&self, state: &mut AgentState, event: &ProcessEvent) -> Result<()> {
        // Record exit
        state.recent_exits.insert(event.pid, event.timestamp);
        state.active_pids.remove(&event.pid);

        // Update process end time and state
        if let Some(process) = state.processes.get_mut(&event.pid) {
            process.end_time = Some(event.timestamp);
            process.state = ProcessState::Exited;
            debug_log!(
                "DEBUG: Process {} ({}) marked as fully exited",
                event.pid,
                process.name
            );
        } else {
            debug_log!("DEBUG: Fully exited event for unknown process {}", event.pid);
        }

        Ok(())
    }

    /// Handle wait - parent waited for child
    async fn handle_wait(
        &self,
        _state: &mut AgentState,
        parent_pid: u32,
        child_pid: u32,
        child_exit_code: Option<i32>,
        _event: &ProcessEvent,
    ) -> Result<()> {
        // For now, just track the wait event
        // In the future, this could be used for more sophisticated parent-child relationship tracking
        Ok(())
    }

    /// Process a raw syscall line - add to buffer
    async fn process_syscall(&self, syscall_line: String) -> Result<()> {
        let mut state = self.state.write().await;
        state.add_syscall(syscall_line);
        Ok(())
    }

    /// Get shared state reference for external access (TUI)
    pub fn state(&self) -> Arc<RwLock<AgentState>> {
        self.state.clone()
    }

    /// Resolve PPID from /proc filesystem
    async fn resolve_ppid_from_proc(&self, pid: u32) -> Result<u32> {
        let proc_stat_path = format!("/proc/{}/stat", pid);

        match tokio::fs::read_to_string(&proc_stat_path).await {
            Ok(stat_content) => {
                // /proc/pid/stat format: pid (comm) state ppid ...
                // We need to parse carefully because comm can contain spaces and parentheses

                // Find the last ')' which ends the comm field
                if let Some(comm_end) = stat_content.rfind(')') {
                    let after_comm = &stat_content[comm_end + 1..];
                    let fields: Vec<&str> = after_comm.trim().split_whitespace().collect();

                    // After comm, we have: state ppid ...
                    if fields.len() >= 2 {
                        if let Ok(ppid) = fields[1].parse::<u32>() {
                            debug_log!("DEBUG: Resolved PPID {} for PID {} from /proc", ppid, pid);
                            return Ok(ppid);
                        }
                    }
                }

                debug_log!(
                    "DEBUG: Failed to parse PPID from /proc/{}/stat: {}",
                    pid,
                    stat_content
                );
                Err(anyhow::anyhow!("Failed to parse /proc/{}/stat", pid))
            }
            Err(e) => {
                debug_log!("DEBUG: Could not read /proc/{}/stat: {}", pid, e);
                Err(anyhow::anyhow!("Could not read /proc/{}/stat: {}", pid, e))
            }
        }
    }

    // SYSCALL PARSING METHODS - moved from pipeline layer

    /// Parse execve syscall arguments to extract command line
    /// Format: execve("/bin/ls", ["ls", "-la", "/home"], ["PATH=/usr/bin", ...])
    fn parse_execve_syscall(&self, args: &[String], _result: Option<&str>) -> Option<Vec<String>> {
        // The args from SyscallEvent are already split by comma, but for execve we need
        // to extract the argv array which is the second parameter
        // For now, we'll do a simple heuristic: look for the second arg that looks like an array
        
        if args.len() >= 2 {
            let argv_str = &args[1];
            
            // Look for bracketed content like ["ls", "-la", "/home"]
            if let (Some(start), Some(end)) = (argv_str.find('['), argv_str.find(']')) {
                let content = &argv_str[start + 1..end];
                
                // Parse quoted arguments
                let mut command_line = Vec::new();
                let mut current_arg = String::new();
                let mut in_quotes = false;
                let mut escape_next = false;
                
                for ch in content.chars() {
                    if escape_next {
                        current_arg.push(ch);
                        escape_next = false;
                    } else if ch == '\\' {
                        escape_next = true;
                    } else if ch == '"' && !escape_next {
                        in_quotes = !in_quotes;
                    } else if ch == ',' && !in_quotes {
                        if !current_arg.trim().is_empty() {
                            command_line.push(current_arg.trim().to_string());
                            current_arg.clear();
                        }
                    } else if !ch.is_whitespace() || in_quotes {
                        current_arg.push(ch);
                    }
                }
                
                // Don't forget the last argument
                if !current_arg.trim().is_empty() {
                    command_line.push(current_arg.trim().to_string());
                }
                
                if !command_line.is_empty() {
                    return Some(command_line);
                }
            }
        }
        
        // Fallback: return the first argument as the command
        if !args.is_empty() {
            Some(vec![args[0].clone()])
        } else {
            None
        }
    }

    /// Parse clone syscall result to extract child PID
    fn parse_clone_result(&self, result: Option<&str>) -> Option<u32> {
        result?.trim().parse::<u32>().ok()
    }

    /// Parse fork syscall result to extract child PID
    fn parse_fork_result(&self, result: Option<&str>) -> Option<u32> {
        result?.trim().parse::<u32>().ok()
    }

    /// Parse vfork syscall result to extract child PID
    fn parse_vfork_result(&self, result: Option<&str>) -> Option<u32> {
        result?.trim().parse::<u32>().ok()
    }

    /// Parse wait4 syscall to extract child PID and exit status
    fn parse_wait4_syscall(&self, args: &[String], result: Option<&str>) -> Option<(u32, Option<i32>)> {
        // Extract child PID from first argument
        let child_pid = args.first()?
            .trim()
            .parse::<u32>()
            .ok()?;
        
        // Extract exit code from wstatus - look for WEXITSTATUS(s) == N in args
        let exit_code = if args.len() > 1 {
            let wstatus_arg = &args[1];
            if wstatus_arg.contains("WEXITSTATUS") {
                // Find WEXITSTATUS(s) == N pattern
                if let Some(start) = wstatus_arg.find("WEXITSTATUS(s) == ") {
                    let start = start + "WEXITSTATUS(s) == ".len();
                    if let Some(end) = wstatus_arg[start..].find(['}', ',', ')'].as_ref()) {
                        wstatus_arg[start..start + end].trim().parse::<i32>().ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else if wstatus_arg.contains("WIFSIGNALED") {
                // Process was terminated by signal - use negative signal number
                if let Some(start) = wstatus_arg.find("WTERMSIG(s) == ") {
                    let start = start + "WTERMSIG(s) == ".len();
                    if let Some(end) = wstatus_arg[start..].find(['}', ',', ')'].as_ref()) {
                        // Return negative signal number to indicate termination by signal
                        wstatus_arg[start..start + end].trim().parse::<i32>().map(|sig| -sig).ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        
        // Verify return value matches child PID if available
        if let Some(returned_pid) = result {
            if returned_pid.trim().parse::<u32>().ok()? == child_pid {
                Some((child_pid, exit_code))
            } else {
                None
            }
        } else {
            Some((child_pid, exit_code))
        }
    }

    /// Parse waitpid syscall to extract child PID and exit status
    fn parse_waitpid_syscall(&self, args: &[String], result: Option<&str>) -> Option<(u32, Option<i32>)> {
        // Same parsing logic as wait4, just different syscall name
        self.parse_wait4_syscall(args, result)
    }
}
