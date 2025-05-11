// src/main.rs
mod cli;
mod log;
mod policy;
mod profile;
mod sandbox;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use log::Logger;
use policy::Policy;
use sandbox::apply_seccomp;
use std::{
    env,
    error::Error,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{exit, Command},
};

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Run { command, args, log } => handle_run(&command, &args, &log)?,

        Commands::Verify { log } => {
            // explicitly convert String→PathBuf
            let verify_path = PathBuf::from(&log);
            // restore the old “failed hash” message that tests expect:
            if let Err(e) = Logger::verify_chain(&verify_path) {
                eprintln!("failed hash: {}", e);
                exit(1);
            }
            println!("✔ All entries verified");
        }

        Commands::Profile { input, out_dir } => profile::profile_commands(&input, &out_dir)?,

        Commands::Daemon { socket } => serve_daemon(&socket)?,

        Commands::External(mut ext) => {
            // map `capsule echo foo` → Run { command="echo", args=["foo"], log=... }
            let cmd = ext.remove(0);
            let args = ext;
            let log = std::env::var("CAPSULE_LOG").unwrap_or_else(|_| "capsule.log".into());
            handle_run(&cmd, &args, &log)?
        }
    }

    Ok(())
}

/// Parses CLI args, enforces policy, logs activity, and runs the requested command
/// NOTE: This is a temporary, ad-hoc dispatch.  
/// TODO: Replace with a proper CLI parser (e.g. `clap`) so we can support subcommands cleanly.
/// Enforce policy, sandbox and exec a single invocation,
/// logging both start and end to `log_path`.
fn handle_run(command: &str, args: &[String], log: &str) -> Result<(), Box<dyn Error>> {
    // 1) Initialize logger
    let log_path = PathBuf::from(log);
    let mut logger = Logger::new(&log_path)?;

    // 2) Log invocation start
    let mut full_cmd = Vec::with_capacity(1 + args.len());
    full_cmd.push(command.to_string());
    full_cmd.extend_from_slice(args);
    logger.log_invocation_start(full_cmd)?;

    // 3) Policy check
    let rest_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    if !Policy::validate_call(command, &rest_ref) {
        logger.log_invocation_end(1)?;
        eprintln!("error: command '{}' not allowed by policy", command);
        exit(1);
    }

    // 4) Fork + exec under seccomp
    let mut child = Command::new(command);
    child.args(args);
    unsafe {
        child.pre_exec(|| {
            apply_seccomp()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        });
    }
    let status = child.status()?; // wait for the child

    // 5) Log end & propagate exit code
    let code = status.code().unwrap_or(1);
    logger.log_invocation_end(code)?;
    exit(code);
}

/// Placeholder for the `daemon` subcommand.
/// Right now it simply logs that daemon‐mode isn’t implemented.
fn serve_daemon(_socket: &str) -> Result<()> {
    // would run with capsule daemon --socket /path/to.sock
    eprintln!(
        "⚙️  Daemon mode requested on '{}', but it’s not implemented yet.",
        _socket
    );

    // TODO: full daemon implementation
    //  1) Bind a UnixListener on the given socket path
    //  2) Loop over incoming connections:
    //       • Read JSON requests, e.g. { cmd: "...", args: [...], log: "..." }
    //       • Call `handle_run(&cmd, &args, &log)?` for each one
    //       • Write back a JSON response with the exit code
    //  3) Add error handling, timeouts, and graceful shutdown
    //  4) (Optional) Support multiple concurrent clients

    Ok(())
}
