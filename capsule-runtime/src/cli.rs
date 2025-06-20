//! Command-line parsing (shared by foreground CLI and tests).

use clap::{Parser as ClapParser, Subcommand};

#[derive(ClapParser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Launch an agent and detach.
    Run {
        program: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Gracefully stop the most-recent (or specific) run.
    Stop {
        #[arg(long, help = "UUID of run to stop (default: latest)")]
        run: Option<String>,
    },
    /// Tail a live or historical log stream.
    Tail {
        #[arg(value_parser = ["syscalls", "events", "actions"])]
        stream: String,
        #[arg(long, help = "UUID of run to tail (default: latest)")]
        run: Option<String>,
    },
}
