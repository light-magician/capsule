use clap::{Parser, Subcommand};

/// Command-line interface for Capsule
#[derive(Parser)]
#[command(name = "capsule", author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

/// Top-level commands supported by the CLI
#[derive(Subcommand)]
pub enum Command {
    /// Execute a program and trace its syscalls
    Trace {
        // path or binary name of the program to execute
        target: String,
        /// arguments forwarded verbatim to the target
        #[arg()]
        args: Vec<String>,
        // write to a specific file instead of default
        #[arg(short, long)]
        log: Option<String>,
    },
}

/// convnience helper so main.rs can just match parse()
pub fn parse() -> Command {
    Cli::parse().cmd
}
