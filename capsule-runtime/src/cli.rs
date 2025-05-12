use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "capsule", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run one command under Capsule (policy + seccomp + Merkle log)
    Run {
        command: String,
        args: Vec<String>,

        /// log file (default $CAPSULE_LOG or ./capsule.log)
        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,

        /// policy file or literal `none`  (default none = unrestricted)
        #[arg(long)]
        policy: Option<String>,
    },

    /// Verify an existing log
    Verify {
        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,
    },

    /// Profile a newline-separated list of commands
    Profile {
        input: String,
        #[arg(long, default_value = "profiles")]
        out_dir: String,
    },

    /// Start the always-on daemon (defaults shown)
    Daemon {
        #[arg(long, default_value = "/tmp/capsule.sock")]
        socket: String,

        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,

        #[arg(long)]
        policy: Option<String>,
    },

    /// So that `capsule echo …` still works
    #[command(external_subcommand)]
    External(Vec<String>),
}
