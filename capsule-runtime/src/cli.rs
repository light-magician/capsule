use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
//TODO: subcommands of capsule daemon not showing in capsule --help output

/// Command-line interface for Capsule
#[derive(Parser)]
#[command(name = "capsule")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

/// Actions for controlling the daemon
#[derive(Subcommand)]
pub enum DaemonAction {
    /// Start the background daemon
    Start,
    /// Stop the running daemon
    Stop,
    /// Show daemon status
    Status,
}

/// Top-level commands supported by the CLI
#[derive(Subcommand)]
pub enum Command {
    /// Run as background daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Execute a program and trace its syscalls
    Run {
        /// Program and arguments to execute
        #[arg(
            value_name = "CMD...",
            num_args = 1..,
            trailing_var_arg = true
        )]
        cmd: Vec<String>,
    },
}
