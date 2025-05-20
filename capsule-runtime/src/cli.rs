use clap::{Parser, Subcommand};

const PID_FILE: &str = "/tmp/capsule.pid";
const SOCKET_PATH: &str = "/tmp/capsule.sock";

#[derive(Parser)]
#[command(name = "capsule-daemon")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run as background daemon
    Daemon {
        #[arg(long)]
        daemon: bool,
    },
    /// Stop the running daemon (gracefully via socket, fallback to SIGTERM)
    Shutdown,
    /// Verify daemon is running
    Status,

    Run {
        /// args for that program
        #[arg(
            value_name = "CMD…",
            num_args = 1..,
            trailing_var_arg = true
        )]
        cmd: Vec<String>,
    },
}
