// src/daemon.rs
//! Very small “capsule daemon” that:
//
// • binds a Unix-domain socket (supplied on the CLI)
// • accepts one connection ⇒ one command line
// • traces the command with `strace`, feeds every syscall into Logger
// • sends the child’s exit-status back to the client
//!
//! Text protocol (no JSON to stay tiny):
//!     <cmd and args joined by spaces>\n          → run it
//!     shutdown\n                                → terminate daemon
//!
//! Example client:
//!     echo "ls -l /etc" | socat - UNIX-CONNECT:/tmp/capsule.sock
//!
//! The daemon keeps running until it receives the literal word `shutdown`.
//
// ──────────────────────────────────────────────────────────────────────────────
use anyhow::Result;
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
};

use chrono::Local;

use crate::{log::Logger, policy::Policy, profile};

const DEFAULT_SOCK: &str = "/tmp/capsule.sock";
const TRACE_DIR: &str = "/tmp/capsule_traces";

pub fn run(socket: Option<String>, log: &Path, policy: Policy) -> Result<()> {
    let sock_path = socket.unwrap_or_else(|| DEFAULT_SOCK.into());

    // fresh socket each launch
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)?;
    println!("🛡  capsule daemon listening on {sock_path}");

    for stream in listener.incoming() {
        let mut conn = stream?;
        let mut req = String::new();
        conn.read_to_string(&mut req)?;
        let line = req.trim();

        if line == "shutdown" {
            writeln!(conn, "ok")?;
            break;
        }
        if line.is_empty() {
            writeln!(conn, "err empty request")?;
            continue;
        }

        // split first token = cmd, rest = args
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap().to_string();
        let args: Vec<String> = parts.map(|s| s.to_string()).collect();

        let exit = spawn_and_log(&cmd, &args, log, &policy)?;
        writeln!(conn, "{exit}")?;
    }
    Ok(())
}

//──────────────────────────────────────────────────────────────────────────────

fn spawn_and_log(cmd: &str, args: &[String], log_file: &Path, policy: &Policy) -> Result<i32> {
    // policy gate
    let rest: Vec<&str> = args.iter().map(String::as_str).collect();
    if !policy.validate_call(cmd, &rest) {
        return Ok(1); // deny – non-zero exit
    }

    // open / append Merkle log
    let mut logger = Logger::new(log_file)?;
    logger.log_invocation_start(
        std::iter::once(cmd.to_string())
            .chain(args.iter().cloned())
            .collect(),
    )?;

    // trace the command (profile helper)
    let syscalls = profile::trace_single(cmd, args, Path::new(TRACE_DIR))?;

    for name in syscalls {
        // -1 pid, empty args, 0 return value -> good enough for demo
        logger.log_syscall(-1, name, Vec::new(), 0)?;
    }

    logger.log_invocation_end(0)?;
    Ok(0) // success
}
