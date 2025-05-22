mod cli;
mod client;
mod constants;
mod daemon;
mod log;
mod protocol;
use clap::Parser;
use cli::Cli;
use cli::DaemonAction;
use client::send_run_request;
use daemon::{start_daemon, status, stop_daemon};

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        cli::Command::Daemon { action } => match action {
            DaemonAction::Start => start_daemon(),
            DaemonAction::Stop => stop_daemon(),
            DaemonAction::Status => status(),
        },
        cli::Command::Run { cmd } => {
            if let Err(err) = send_run_request(cmd) {
                //TODO: should not break here
                eprintln!("failed to send run request: {}", err);
                std::process::exit(1);
            }
        }
    }
}
