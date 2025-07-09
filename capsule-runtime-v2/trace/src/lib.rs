//! process traceing

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

pub struct LinuxTracer;

impl LinuxTracer {
    /// run strace with cancellation support and broadcast channel
    pub async fn run_with_cancellation(
        cmdline: Vec<String>,
        tx_raw: broadcast::Sender<String>,
        cancellation_token: CancellationToken,
    ) -> Result<()> {
        if cmdline.is_empty() {
            anyhow::bail!("trace: command line empty");
        }
        // Build strace command - process-focused for now
        let mut child = Command::new("strace");
        child
            .arg("-f") // follow forks
            .arg("-tt") // timestamps with microseconds
            .arg("-e")
            .arg("trace=process") // Only process syscalls for now
            .arg("--")
            .args(&cmdline)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit()) // Program output goes to user's terminal
            .stderr(Stdio::piped()) // Syscall traces captured here
            .kill_on_drop(true); // Ensure child is killed when dropped
        let mut child = child.spawn().with_context(|| "failed to spawn strace")?;

        // async-read strace output from stderr ??? (a good idea?)
        let stderr = child.stderr.take().unwrap();
        let mut rdr = BufReader::new(stderr).lines();

        tokio::select! {
            // Read strace lines
            result = async {
                while let Some(line) = rdr.next_line().await? {
                    // Filter for process events only
                    if Self::is_process_event(&line) {
                        if tx_raw.send(line.clone()).is_err() {
                            break;
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            } => {
                if let Err(_) = result {
                    // Error reading strace output
                }
            },

            // Handle cancellation
            _ = cancellation_token.cancelled() => {
                let pid = child.id().unwrap_or(0);
                if pid > 0 {
                    // Kill the entire process group
                    let _ = kill_process_group(pid).await;
                }

                // Force kill the strace process itself
                let _ = child.kill();
            }
        }

        // Ensure child is terminated
        let _exit_status = child.wait().await?;

        Ok(())
    }

    fn is_process_event(line: &str) -> bool {
        //TODO: refactor needed
        line.contains("execve(")
            || line.contains("clone(")
            || line.contains("fork(")
            || line.contains("vfork(")
            || line.contains("exit_group(")
            || line.contains("wait4(")
            || line.contains("waitpid(")
    }

    async fn kill_process_group(pid: u32) -> Result<()> {
        use tokio::process::Command;

        // Terminating process group

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

        // Sent termination signals to process group

        Ok(())
    }
}

// Missing function that was being called
async fn kill_process_group(pid: u32) -> Result<()> {
    LinuxTracer::kill_process_group(pid).await
}
