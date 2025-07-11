//! Process Tree data structures for tracking huerarchical relationships
//!
//! ProcessTree maintains an in-mem representation of all processes
//! and their parent-child relationships. It's designed for real-time updates
//! as ProcessEvents stream through the pipeline.

use crate::events::{ProcessEvent, ProcessEventType};
use crate::workflow::{AgentWorkflow, ProcessLabel};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use anyhow::Result;
/// A single process node in the process tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Full command line with arguments
    pub command_line: Vec<String>,
    /// Classification of this process (Agent, Tool, etc.)
    pub label: ProcessLabel,
    /// Detected workflow pattern (if any)
    pub workflow: Option<AgentWorkflow>,
    /// List of child process PIDs
    pub children: Vec<u32>,
    /// When this process started (timestamp in microseconds)
    pub start_time: u64,
    /// When this process ended (None if still running)
    pub end_time: Option<u64>,
}

/// Process tree maintaining hierarchical relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTree {
    /// All processes indexed by PID
    nodes: HashMap<u32, ProcessNode>,
    /// The root process PID (the one we're tracing)
    root_pid: Option<u32>,
    /// Set of currently active (not exited) PIDs
    active_pids: HashSet<u32>,
}

impl ProcessTree {
    /// create new empty process tree
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_pid: None,
            active_pids: HashSet::new(),
        }
    }

    /// update tree with a process event
    pub fn update(&mut self, event: ProcessEvent) -> Result<()> {
        match event.event_type {
            ProcessEventType::Spawn => self.add_process(event),
            ProcessEventType::Exit => self.remove_process(event.pid, event.exit_code),
        }
    }

    /// add a new process to the tree
    fn add_process(&mut self, event: ProcessEvent) -> Result<()> {
        // set root if this is the first process
        if self.root_pid.is_none() {
            self.root_pid = Some(event.pid);
        }
        // classify the process
        let label = ProcessLabel::classify_from_command(&event.command_line);
        let workflow = AgentWorkflow::classify_from_command(&event.command_line);
        let node = ProcessNode {
            pid: event.pid,
            ppid: event.ppid,
            command_line: event.command_line,
            label,
            workflow,
            children: Vec::new(),
            start_time: event.timestamp,
            end_time: None,
        };
        // Add to parent's children list
        if let Some(parent) = self.nodes.get_mut(&event.ppid) {
            parent.children.push(event.pid);
        }
        self.nodes.insert(event.pid, node);
        self.active_pids.insert(event.pid);

        Ok(())
    }

    /// remove process from active set and mark end time
    fn remove_process(&mut self, pid: u32, exit_code: Option<i32>) -> Result<()> {
        if let Some(node) = self.nodes.get_mut(&pid) {
            node.end_time = Some(chrono::Utc::now().timestamp_micros() as u64);
        }
        self.active_pids.remove(&pid);
        Ok(())
    }

    // get process by PID
    pub fn get_process(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// get all active processes
    pub fn get_active_processes(&self) -> Vec<&ProcessNode> {
        self.active_pids
            .iter()
            .filter_map(|pid| self.nodes.get(pid))
            .collect()
    }

    /// get root process
    pub fn root_process(&self) -> Option<&ProcessNode> {
        self.root_pid.and_then(|pid| self.nodes.get(&pid))
    }
}
