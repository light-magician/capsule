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
