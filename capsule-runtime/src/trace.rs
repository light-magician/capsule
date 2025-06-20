//! Launch `strace`, capture syscall traces via stderr, program output goes to original terminal.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::broadcast::Sender,
};

pub async fn run(cmdline: Vec<String>, tx_raw: Sender<String>) -> Result<()> {
    if cmdline.is_empty() {
        anyhow::bail!("trace: empty command line");
    }

    // ── Build child ─────────────────────────────────────────────────────────
    let mut child = Command::new("strace");
    child
        .arg("-f")         // follow forks
        .arg("-tt")        // timestamps
        .arg("-yy")        // decode file descriptors  
        .arg("-s")
        .arg("1000")       // string length
        .arg("-e")
        .arg("trace=all")  // trace all syscalls
        .arg("--")
        .args(&cmdline)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())  // Program output goes to user's terminal
        .stderr(Stdio::piped());   // Syscall traces captured here

    let mut child = child.spawn().with_context(|| "failed to spawn strace")?;

    // ── Async-read strace output from stderr ────────────────────────────────
    let stderr = child.stderr.take().unwrap();
    let mut rdr = BufReader::new(stderr).lines();

    while let Some(line) = rdr.next_line().await? {
        if tx_raw.send(line).is_err() {
            break;
        }
    }

    child.wait().await?;
    Ok(())
}