//! Launch `strace`, capture syscall traces via stderr, program output goes to original terminal.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::broadcast::Sender,
};
use tokio_util::sync::CancellationToken;

pub async fn run(cmdline: Vec<String>, tx_raw: Sender<String>) -> Result<()> {
    run_with_cancellation(cmdline, tx_raw, CancellationToken::new()).await
}

pub async fn run_with_cancellation(
    cmdline: Vec<String>,
    tx_raw: Sender<String>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    if cmdline.is_empty() {
        anyhow::bail!("trace: empty command line");
    }

    // ── Build child ─────────────────────────────────────────────────────────
    let mut child = Command::new("strace");
    child
        .arg("-f") // follow forks
        .arg("-tt") // timestamps with microseconds
        .arg("-yy") // decode file descriptors  
        .arg("-v") // verbose - don't abbreviate structures
        .arg("-x") // print strings in hex (no escape sequences)
        .arg("-s")
        .arg("1000") // string length
        .arg("-e")
        .arg("trace=all") // trace all syscalls
        .arg("--")
        .args(&cmdline)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit()) // Program output goes to user's terminal
        .stderr(Stdio::piped()) // Syscall traces captured here
        .kill_on_drop(true); // Ensure child is killed when dropped

    let mut child = child.spawn().with_context(|| "failed to spawn strace")?;
    let child_id = child.id();

    // ── Async-read strace output from stderr ────────────────────────────────
    let stderr = child.stderr.take().unwrap();
    let mut rdr = BufReader::new(stderr).lines();

    println!(
        "Started tracing process {} with strace",
        child_id.unwrap_or(0)
    );

    tokio::select! {
        // Read strace lines
        result = async {
            while let Some(line) = rdr.next_line().await? {
                if tx_raw.send(line).is_err() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        } => {
            if let Err(e) = result {
                eprintln!("Error reading strace output: {}", e);
            }
        },

        // Handle cancellation
        _ = cancellation_token.cancelled() => {
            println!("Received cancellation signal, terminating traced process...");
            if let Some(pid) = child.id() {
                // Kill the entire process group
                let _ = kill_process_group(pid).await;
            }
            
            // Force kill the strace process itself
            let _ = child.kill().await;
        }
    }

    // Ensure child is terminated
    let exit_status = child.wait().await?;
    println!("Traced process exited with status: {:?}", exit_status);

    Ok(())
}

async fn kill_process_group(pid: u32) -> Result<()> {
    use tokio::process::Command;

    println!("Terminating process group for PID {}", pid);
    
    // First, try to kill child processes nicely
    let _ = Command::new("pkill")
        .arg("-TERM")
        .arg("-P")
        .arg(pid.to_string())
        .output()
        .await;
    
    // Give processes a moment to terminate gracefully
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Then force kill any remaining processes
    let _ = Command::new("pkill")
        .arg("-KILL")
        .arg("-P")
        .arg(pid.to_string())
        .output()
        .await;
    
    // Also kill the main process
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .output()
        .await;
    
    println!("Sent termination signals to process group {}", pid);

    Ok(())
}
