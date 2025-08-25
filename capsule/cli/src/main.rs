//! Main CLI entry point

mod cli;
mod commands;
mod ipc;
mod monitor;
mod pipeline;
mod session;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Cmd};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Ensure base directories exist
    session::SessionManager::ensure_base_directories().await?;

    // Parse and execute commands
    match Cli::parse().cmd {
        Cmd::Run { program, args } => commands::run_with_pipeline(program, args).await,
        Cmd::Monitor { session } => commands::run_monitor(session).await,
        Cmd::Demo => commands::run_demo_tui().await,
    }
}
