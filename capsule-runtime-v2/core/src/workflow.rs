//! Agent workflow classification and process labeling
//!
//! This module defines the behavioral classification system for
//! tracking agent behavior.
//! TODO: add Network, File IO, SecurityAlteration, etc.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Process based agent classifications
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessLabel {
    /// The root AI agent process itself
    Agent,
    /// Tools explicitely spawned by the agent
    Tool,
    /// System processes (sh, bash, etc.)
    SystemTool,
    /// Process classification not yet determined
    Unknown,
}

/// Agent workflow patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentWorkflow {
    /// Spawning development tools and utilities
    /// Patterns: git, find, grep, python3 subprocess calls
    ToolExecution,
    /// Creating or running code/scripts
    /// Patterns: python3 script.py, node script.js
    CodeExecution,
    /// Version control operations
    /// Patterns: git clone, git status, git commit, git push
    RepositoryOperations,
    /// System exploration via process spawning
    /// Patterns: which, env, ps, ls (when used to explore system)
    SystemExploration,
    /// Multi-process coordination and orchestration
    /// Patterns: parallel execution, process pipelines
    ProcessCoordination,
    /// Container operations
    /// Patterns: docker, podman subprocess calls
    ContainerOperation,
    /// Package management operations
    /// Patterns: pip, npm, cargo subprocess calls
    PackageManagement,
}

// TODO: Future workflow categories (non-process based)
// These will be added when we expand beyond process-only tracking:
//
// FileWorkflow:
// - FileAnalysis (reading/analyzing files via syscalls)
// - FileModification (writing/creating files)
// - DirectoryTraversal (exploring filesystem)
//
// NetworkWorkflow:
// - APICommuncation (HTTP requests, API calls)
// - DataTransfer (large uploads/downloads)
// - ServiceDiscovery (DNS lookups, port scanning)
//
// SecurityWorkflow:
// - CredentialAccess (accessing ssh keys, tokens)
// - PrivilegeEscalation (sudo, setuid operations)
// - CryptoOperations (key generation, encryption)
impl ProcessLabel {
    /// Classify a process based on its command line
    /// TODO: the agent process can be received from the command that capsule runs
    pub fn classify_from_command(command_line: &[String]) -> Self {
        let executable = match command_line.first() {
            Some(exe) => exe,
            None => return ProcessLabel::Unknown,
        };

        let binary_name = executable.split('/').last().unwrap_or(executable);

        match binary_name {
            // Known AI agent binaries
            "claude" | "chatgpt" | "copilot" => ProcessLabel::Agent,

            // Python/Node that might be agents (basic heuristic)
            "python" | "python3" | "node" => {
                if command_line.iter().any(|arg| {
                    arg.contains("agent") || arg.contains("claude") || arg.contains("gpt")
                }) {
                    ProcessLabel::Agent
                } else {
                    ProcessLabel::Tool
                }
            }

            // Development tools
            "git" | "find" | "grep" | "rg" => ProcessLabel::Tool,

            // System utilities
            "sh" | "bash" | "which" | "env" | "ls" | "echo" => ProcessLabel::SystemTool,

            _ => ProcessLabel::Unknown,
        }
    }

    pub fn is_agent(&self) -> bool {
        matches!(self, ProcessLabel::Agent)
    }

    pub fn is_tool(&self) -> bool {
        matches!(self, ProcessLabel::Tool | ProcessLabel::SystemTool)
    }
}

impl AgentWorkflow {
    /// Classify workflow based on command line patterns
    pub fn classify_from_command(command_line: &[String]) -> Option<Self> {
        let executable = command_line.first()?;
        let binary_name = executable.split('/').last().unwrap_or(executable);

        match binary_name {
            // Version control operations
            "git" => Some(AgentWorkflow::RepositoryOperations),

            // Development tools
            "find" | "grep" | "rg" | "awk" | "sed" | "sort" | "uniq" => {
                Some(AgentWorkflow::ToolExecution)
            }

            // Code execution
            "python" | "python3" | "node" | "ruby" | "php" | "java" => {
                // If executing a script, it's code execution
                if command_line.len() > 1 && command_line[1].ends_with(".py")
                    || command_line[1].ends_with(".js")
                    || command_line[1].ends_with(".rb")
                {
                    Some(AgentWorkflow::CodeExecution)
                } else {
                    Some(AgentWorkflow::ToolExecution)
                }
            }

            // System exploration
            "which" | "env" | "ps" | "ls" | "cat" | "head" | "tail" | "file" => {
                Some(AgentWorkflow::SystemExploration)
            }

            // Container operations
            "docker" | "podman" | "kubectl" => Some(AgentWorkflow::ContainerOperation),

            // Package management
            "pip" | "npm" | "cargo" | "yarn" | "composer" | "gem" => {
                Some(AgentWorkflow::PackageManagement)
            }

            // Shell coordination
            "sh" | "bash" | "zsh" => {
                // Analyze the command being executed
                if command_line.len() > 2 && command_line[1] == "-c" {
                    // Check if it's a complex pipeline or coordination
                    let cmd = &command_line[2];
                    if cmd.contains("|") || cmd.contains("&&") || cmd.contains("||") {
                        Some(AgentWorkflow::ProcessCoordination)
                    } else {
                        Some(AgentWorkflow::ToolExecution)
                    }
                } else {
                    Some(AgentWorkflow::ToolExecution)
                }
            }

            _ => None,
        }
    }
}

impl fmt::Display for ProcessLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessLabel::Agent => write!(f, "AGENT"),
            ProcessLabel::Tool => write!(f, "TOOL"),
            ProcessLabel::SystemTool => write!(f, "SYSTEM"),
            ProcessLabel::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl fmt::Display for AgentWorkflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentWorkflow::ToolExecution => write!(f, "ToolExecution"),
            AgentWorkflow::CodeExecution => write!(f, "CodeExecution"),
            AgentWorkflow::RepositoryOperations => write!(f, "RepositoryOps"),
            AgentWorkflow::SystemExploration => write!(f, "SystemExplore"),
            AgentWorkflow::ProcessCoordination => write!(f, "ProcessCoord"),
            AgentWorkflow::ContainerOperation => write!(f, "ContainerOps"),
            AgentWorkflow::PackageManagement => write!(f, "PackageMgmt"),
        }
    }
}
