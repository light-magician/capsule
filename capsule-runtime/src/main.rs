mod cli;
mod daemon;
mod log;

use clap::Parser;
use cli::Cli;
use daemon::{start_daemon, status, stop_daemon};

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        cli::Command::Daemon { .. } => daemon::start_daemon(),
        cli::Command::Shutdown => daemon::stop_daemon(),
        cli::Command::Status => daemon::status(),
    }
}
