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
    /// Run a program with syscall tracing and logging (foreground mode).
    ///
    /// Examples:
    ///   capsule run python3 server.py
    ///   capsule run node app.js
    ///   capsule run ./my-binary
    Run {
        program: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Tail a log stream from a run (live following).
    ///
    /// Examples:
    ///   capsule tail syscalls
    ///   capsule tail events --run abc123
    ///   capsule tail enriched
    ///   capsule tail actions
    Tail {
        #[arg(value_parser = ["syscalls", "events", "enriched", "actions", "risks"])]
        stream: String,
        #[arg(long, help = "UUID of run to tail (default: latest)")]
        run: Option<String>,
    },
    /// Show the UUID of the most recent run.
    ///
    /// Examples:
    ///   capsule last
    Last,
    /// List all run UUIDs in chronological order (most recent first).
    ///
    /// Examples:
    ///   capsule list
    ///   capsule list --limit 10
    List {
        #[arg(long, help = "Maximum number of runs to show", default_value = "20")]
        limit: usize,
    },
    /// Send run data to database for analysis.
    ///
    /// Examples:
    ///   capsule send                    # Send latest run
    ///   capsule send abc123-def456...   # Send specific run
    Send {
        #[arg(help = "Run UUID to send (default: latest run)")]
        run_id: Option<String>,
    },
}
