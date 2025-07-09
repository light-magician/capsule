//! Main CLI entry point

mod cli;
mod commands;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Cmd};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // init tracing
    tracing_subscriber::fmt::init();

    //TODO: ensure the ~/.capsule directories exist
    // constants::ensure_dirs()?;
    match Cli::parse().cmd {
        Cmd::Run { program, args } => commands::run_transient(program, args).await,
    }
}
