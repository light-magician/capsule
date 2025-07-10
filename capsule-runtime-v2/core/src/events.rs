//! Core process event types for cross-platform process tracking
//!
//! These types represent Processes in the UNIX environment.
//! Platform specific parsers (eBPF, strace, dtrace) should convert
//! their raw output into ProcessEvent structs, allowing downstream
//! components to work regardless of platform.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Timestamp in microseconds since epoch
    pub timestamp: u64,
    /// Process ID of the event
    pub pid: u32,
    /// parent process ID (0 if unknown / root)
    pub ppid: u32,
    /// Type of process event
    pub event_type: ProcessEventType,
    /// full comand line including arguments
    /// Example: ["python3", "/usr/bin/script.py", "--verbose"]
    pub command_line: Vec<String>,
    /// working directory at tie of event (if available)
    pub working_dir: Option<String>,
    /// exit code (only for Exit events)
    pub exit_code: Option<i32>,
}

/// Process event types we track
///
/// Just Spawn and Exit events at this point
/// Tracks entire Process lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEventType {
    /// Process spawned (execve, clone, fork)
    Spawn,
    /// Process exited (exit_group, termination)
    Exit,
}

impl ProcessEvent {
    /// Create a new spawn event
    pub fn spawn(
        timestamp: u64,
        pid: u32,
        ppid: u32,
        command_line: Vec<String>,
        working_dir: Option<String>,
    ) -> Self {
        Self {
            timestamp,
            pid,
            ppid,
            event_type: ProcessEventType::Spawn,
            command_line,
            working_dir,
            exit_code: None,
        }
    }

    /// Create a new exit event
    pub fn exit(timestamp: u64, pid: u32, exit_code: Option<i32>) -> Self {
        Self {
            timestamp,
            pid,
            ppid: 0, // not relevant for exit events
            event_type: ProcessEventType::Exit,
            command_line: Vec::new(), // not relevant for exit events
            working_dir: None,
            exit_code,
        }
    }

    /// get the executable nae from command line
    pub fn executable(&self) -> Option<&str> {
        self.command_line.first().map(|s| s.as_str())
    }
}
