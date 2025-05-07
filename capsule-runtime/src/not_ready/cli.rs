// src/cli.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::runtime;

/// CLI entry point for capsule-runtime
#[derive(Parser)]
#[command(
    name = "capsule-runtime",
    about = "Policy-enforced, hash-logged runtime"
)]
struct Cli {
    /// Dispatch to one of:
    /// - `run <policy> <cmd>…`  
    /// - `verify [logfile]`  
    /// - *any other* command (captured by `Other`)  
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command under a given policy
    Run {
        /// Path to your capsule.yaml policy file
        #[arg(value_parser)]
        policy: PathBuf,

        /// The command + args to execute (only whitelisted commands allowed)
        #[arg(required = true, num_args = 1..)]
        cmd: Vec<String>,
    },

    /// Verify the hash chain of a log file
    Verify {
        /// Path to the log file to verify
        #[arg(value_parser, default_value = "capsule.log")]
        logfile: PathBuf,
    },

    /// Any other program + args → run under default `"capsule.yaml"` policy
    #[command(external_subcommand)]
    Other(Vec<String>),
}

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // explicit `capsule-runtime run <policy> <cmd>…`
        Commands::Run { policy, cmd } => runtime::run_command(&policy, cmd),

        // explicit `capsule-runtime verify [logfile]`
        Commands::Verify { logfile } => runtime::verify_log(&logfile),

        // catch‐all: e.g. `capsule-runtime echo hello`
        Commands::Other(cmd) => {
            let policy_path = PathBuf::from("capsule.yaml");
            runtime::run_command(&policy_path, cmd)
        }
    }
}
