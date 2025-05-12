use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "capsule", version, about)]
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

        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,

        /// Path to a policy file, or the word `none` (default = none)
        #[arg(long)]
        policy: Option<String>,
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
    /// Start a long-lived tracing daemon
    Daemon {
        /// Unix-socket path (default /tmp/capsule.sock)
        #[arg(long, default_value = "/tmp/capsule.sock")]
        socket: String,

        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,

        /// Policy file or `none` (default none = unrestricted)
        #[arg(long)]
        policy: Option<String>,
    },

    /// Catch-all for bare invocations (so `capsule echo …` still works)
    #[command(external_subcommand)]
    External(Vec<String>),
}
