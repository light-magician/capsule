//! capsule-runtime core modules
pub mod policy;
pub mod sandbox;

use anyhow::Result;
use policy::Policy;
use sandbox::apply_seccomp_echo_only;
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args();
    let _prog = args.next();

    let cmd = match args.next() {
        Some(c) => c,
        None => {
            eprintln!("Usage: capsule-runtime <command> [args...]");
            process::exit(1);
        }
    };

    let rest: Vec<String> = args.collect();
    let rest_ref: Vec<&str> = rest.iter().map(String::as_str).collect();

    if !Policy::validate_call(&cmd, &rest_ref) {
        // write an ERROR entry before exiting
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open("capsule.log")?;

        writeln!(
            log,
            "ERROR: command '{} rejected by policy (no access to {})",
            cmd,
            rest_ref.join(" "),
        )?;

        eprintln!("Command '{}' not allowed by policy", cmd);
        process::exit(1);
    }
    apply_seccomp_echo_only()?;
    let status = process::Command::new(&cmd).args(&rest).status()?;
    process::exit(status.code().unwrap_or(1));
}
