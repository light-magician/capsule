mod cli;
mod daemon;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        cli::Command::Daemon { .. } => daemon::start_daemon(),
        cli::Command::Shutdown => daemon::stop_daemon(),
        cli::Command::Status => daemon::status(),
    }
}
