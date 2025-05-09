use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "capsule",
    version = env!("CARGO_PKG_VERSION"),       // ← provide version or clap will panic
    about = "OS-level sandbox & audit for AI agents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Enforce policy + sandbox + exec
    Run {
        command: String,
        args: Vec<String>,
        /// log file path, defaults to ./capsule.log or $CAPSULE_LOG
        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,
    },

    /// Verify integrity of an existing log
    Verify {
        /// log file path, defaults to ./capsule.log or $CAPSULE_LOG
        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,
    },

    /// Profile syscalls for a list of commands
    Profile {
        input: String,
        #[arg(long)]
        out_dir: String,
    },

    /// (stub) run as a long-lived daemon
    Daemon {
        #[arg(long)]
        socket: String,
    },

    /// Catch-all for bare invocations (so `capsule echo …` still works)
    #[command(external_subcommand)]
    External(Vec<String>),
}
