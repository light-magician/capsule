use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "capsule", version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the daemon (binds /tmp/capsule.sock)
    Daemon {
        #[arg(long, default_value = "/tmp/capsule.sock")]
        socket: String,
        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,
        #[arg(long)]
        policy: Option<String>,
    },
    /// Verify capsule.log
    Verify {
        #[arg(long, env = "CAPSULE_LOG", default_value = "capsule.log")]
        log: String,
    },
    /// Shortcut: `capsule echo hello`
    #[command(external_subcommand)]
    External(Vec<String>),
}
