//! --------- Why trace this way --------------------------
//!
//! strace is a near-complete forensic ledger of everything that
//! crossed the user kernel boundary. If an attacker opens a file,
//! starts a shell, dials a C2 domain, spawns a crypto-miner, or
//! flips capabilities, you will see the syscall entry in black and white.
//!
//! What it will NOT tell you is why the program made the call,
//! what it computed before it, or what encrypted bytes were on the wire.
//!
//! --------- What you get with strace --------------------
//!
//! strace sits on the ptrace syscall and records
//! every kernel-userspace transition your program makes.
//! That means strace observes all:
//!     - file system accesses
//!     - networking
//!     - process control
//!     - memory-management
//!     - IPC
//!     - and signal syscalls
//! provided you've told strace to follow every
//! thread and child process. Nothing a program does
//! can reach the kernel without making on of those syscalls.
//!
//! ---------- What you don't get with strace ---------------
//!
//! strace only fires when a syscall crosses into the kernel.
//! pure computation of in memory tampering is invisible.
//! SOLUTION: combine with eBPF uprobes, perf, or sandbox-level
//! integrity checks.
//!
//! actual payload data
//! SOLUTION: Parallel packet capture
//!
//!

use crate::constants;
use crate::log;
use anyhow::{Context, Result};
use chrono::Utc;
use std::path::PathBuf;
use std::process::{Command, Stdio};
/// Trace a command using strace and write to the provided log file path.
/// This will observe all syscalls (including subprocesses) and log them for profiling.
pub fn trace(argv: Vec<String>, log_override: Option<PathBuf>) -> Result<()> {
    if argv.is_empty() {
        anyhow::bail!("trace: no command provided");
    }

    let log_path = log_override.unwrap_or_else(|| constants::SYSLOG_PATH.into());

    // Write a timestamped session marker
    log::append_to(
        &log_path,
        format!(
            "### START {} cmd={}",
            Utc::now().to_rfc3339(),
            argv.join(" ")
        ),
    )?;

    // Spawn strace on the command
    let mut cmd = Command::new("strace");
    cmd.arg("-f") // follow forks/threads
        .arg("-tt") // timestamps
        .arg("-s")
        .arg("1000") // capture long strings
        .arg("-e")
        .arg("trace=all") // trace all syscalls
        .arg("-o")
        .arg(&log_path) // output file
        .arg("--") // separator
        .args(&argv) // command to run
        // NOTE: here is where the output destinations are controlled.
        //       to make this appear transient, we should inhereit
        //       stdin stdout and stderr
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn().context("failed to start strace")?;
    let status = child.wait()?; // propagate exit status
    if !status.success() {
        anyhow::bail!("strace exited with error code: {}", status);
    }

    Ok(())
}
