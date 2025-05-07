// src/main.rs
mod policy;
mod sandbox;
use anyhow::Result;
use policy::Policy;
use sandbox::apply_seccomp_echo_only;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        exit(1);
    }
}

/// Parses CLI args, enforces policy, logs activity, and runs the requested command
fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Parse program name and command + args
    let mut args = std::env::args();
    let _prog = args.next();
    let cmd = match args.next() {
        Some(c) => c,
        None => {
            eprintln!("Usage: capsule-runtime <command> [args...]");
            exit(1);
        }
    };
    let rest: Vec<String> = args.collect();
    let rest_ref: Vec<&str> = rest.iter().map(String::as_str).collect();

    // 2) Validate against policy
    if !Policy::validate_call(&cmd, &rest_ref) {
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open("capsule.log")?;
        writeln!(
            log,
            "ERROR: command '{}' rejected by policy (no access to {})",
            cmd,
            rest_ref.join(" ")
        )?;
        eprintln!("error: command '{}' not allowed by policy", cmd);
        exit(1);
    }

    // 3) Audit-log the allowed invocation
    {
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open("capsule.log")?;
        writeln!(log, "OK: {} {}", cmd, rest_ref.join(" "))?;
    }

    // 4) Spawn child with seccomp filter applied *only* in the child
    let status = Command::new(&cmd)
        .args(&rest)
        .before_exec(|| {
            // this closure runs in the child _after_ fork() but _before_ execve()
            apply_seccomp_echo_only()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
        .status()?; // failure to fork/exec here will be returned as Err(_)

    // 5) Exit with the same code as the child process
    exit(status.code().unwrap_or(1));
}
