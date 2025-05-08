// src/main.rs
mod log;
mod policy;
mod sandbox;
use anyhow::Result;
use log::Logger;
use policy::Policy;
use sandbox::apply_seccomp;
use std::{
    env,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{exit, Command},
};
/// implementes the capsule-runtime binary
/// parses CLI args (<command> [args...])
/// appends an "OK" or "error:" entry to capsule.log
/// forks + execs the requested command, installing a seccomp-BPF in the child
///     so that only a narrow set of syscalls (read, write, fastat, close, exit)
///     are permitted
/// exits with status of child process
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        exit(1);
    }
}

/// Parses CLI args, enforces policy, logs activity, and runs the requested command
/// NOTE: This is a temporary, ad-hoc dispatch.  
/// TODO: Replace with a proper CLI parser (e.g. `clap`) so we can support subcommands cleanly.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Pick our log file
    let log_path: PathBuf = env::var("CAPSULE_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::current_dir().unwrap().join("capsule.log"));
    let mut logger = Logger::new(&log_path)?;

    // 2) Shallow arg parsing
    let mut args = env::args();
    let _prog = args.next();
    let cmd = args.next().unwrap_or_else(|| {
        eprintln!("Usage: capsule <command> [args...]");
        exit(1);
    });
    let rest: Vec<String> = args.collect();
    let rest_ref: Vec<&str> = rest.iter().map(String::as_str).collect();

    // 3) Handle our built-in `verify` BEFORE policy or sandbox
    // TODO: this must be changed later
    if cmd == "verify" {
        if let Err(e) = Logger::verify_chain(&log_path) {
            eprintln!("failed hash: {}", e);
            exit(1);
        }
        println!("✔ All entries verified");
        exit(0);
    }

    // 4) Normal invocation: log start
    let mut full_cmd = Vec::with_capacity(1 + rest.len());
    full_cmd.push(cmd.clone());
    full_cmd.extend(rest.clone());
    logger.log_invocation_start(full_cmd)?;

    // 5) Policy check
    if !Policy::validate_call(&cmd, &rest_ref) {
        logger.log_invocation_end(1)?;
        eprintln!("error: command '{}' not allowed by policy", cmd);
        exit(1);
    }

    // 6) Fork+exec under seccomp
    let mut child = Command::new(&cmd);
    child.args(&rest);
    unsafe {
        child.pre_exec(|| {
            apply_seccomp()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        });
    }
    let status = child.status()?; // wait for the child

    // 7) Log end, propagate exit code
    let code = status.code().unwrap_or(1);
    logger.log_invocation_end(code)?;
    exit(code);
}
