use clap::{Parser as ClapParser, Subcommand};

#[derive(ClapParser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// run a program with tracing
    ///
    /// Examples:
    ///             capsule run pthon3 server.py
    ///             capsule run node app.js
    ///             capsule run ./binary
    ///             capsule run claude
    Run {
        program: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// monitor live processes in a TUI
    ///
    /// Shows real-time process list with keyboard navigation.
    /// Use arrow keys to navigate, 'r' to refresh, 'q' to quit.
    Monitor {
        /// Session ID to monitor (optional, defaults to latest)
        #[arg(short, long)]
        session: Option<String>,
    },
    /// demo TUI with sample data
    ///
    /// Shows the monitoring TUI with demo processes and syscalls
    /// for testing the display without running a real session.
    Demo,
}
