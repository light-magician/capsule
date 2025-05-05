use crate::log;
use crate::sandbox;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "capsule", about = "capsule runtime and verifier")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

pub enum Commands {
    // run the MCP server/executable under ther capsule sandbox
    Run {
        // path to yaml policy file
        policy: PathBuf,
        // command and arguments to execute
        cmd: Vec<String>,
    },
    Verify {
        // path to the log file to check
        logfile: PathBuf,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run { policy, cmd } => {
            sandbox::run_under_sandbox(&policy, &cmd)?;
        }
        Commands::Verify { logfile } => {
            log::verify(&logfile)?;
        }
    }
    Ok(())
}
