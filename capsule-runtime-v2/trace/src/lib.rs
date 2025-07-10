//! Process tracing via Linux strace
//!
//! This crate handles subprocess execution and raw strace output streaming.
//! It sends raw strace lines that the parse/ crate converts to ProcessEvent structs.
//!
//! ## Sample Raw Strace Output (what this crate produces):
//! ```text
//! [pid  1234] 14:30:25.123456 execve("/usr/bin/python3", ["python3", "script.py"], 0x7fff12345678 /* 16 vars */) = 0
//! [pid  1234] 14:30:25.125789 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f1234567890) = 1235
//! [pid  1235] 14:30:25.126012 execve("/usr/bin/git", ["git", "status"], 0x7fff87654321 /* 16 vars */) = 0
//! [pid  1235] 14:30:25.789123 exit_group(0) = ?
//! [pid  1234] 14:30:25.789456 wait4(1235, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 1235
//! ```
//!
//! ## What this crate produces (StraceEvent):
//! ```rust
//! # use trace::StraceEvent;
//! let event = StraceEvent {
//!     pid: 1234,
//!     timestamp: "14:30:25.123456".to_string(),
//!     syscall: "execve".to_string(),
//!     args: "\"/usr/bin/python3\", [\"python3\", \"script.py\"], env".to_string(),
//!     result: Some("0".to_string()),
//!     is_complete: true,
//!     raw_line: "[pid  1234] 14:30:25.123456 execve(...)".to_string(),
//! };
//! ```

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::OnceLock;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StraceEvent {
    pub pid: u32,
    pub timestamp: String,
    pub syscall: String,
    pub args: String,
    pub result: Option<String>,
    pub is_complete: bool,
    pub raw_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StraceParseResult {
    Event(StraceEvent),
    Attachment(String), // "strace: Process 2438 attached"
    Unparseable(String),
}

pub struct StraceOutputRaw;
pub struct StraceOutputJson;

pub struct LinuxTracer;

/// Traces Program Execution in Linux Environments
impl LinuxTracer {
    /// run strace with cancellation support and broadcast channel
    /// strace manual https://man7.org/linux/man-pages/man1/strace.1.html
    ///
    /// Ex: capsule run claude
    ///
    /// Executes claude binary with strance enabled.
    ///
    /// * Arguments
    ///
    /// `cmdline` - command line input
    ///             Ex: capsule run claude
    /// `tx_raw` - a tokio Sender, used to broadcast
    ///            to all connected Receivers, which in
    ///            this case will be file writers
    /// `cancellation_token` - Ctrl + C
    ///                        A way to take keyboard
    ///                        input to terminate the program
    ///
    /// * Returns
    ///
    /// anyhow Result
    ///
    ///
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
            .arg("--follow-forks") // follow forks
            .arg("-tt") // timestamps with microseconds
            .arg("-e")
            // TODO:trace more with -> trace=process,file,network,signal, creds" (security mods?)
            .arg("trace=process") // Only process syscalls for now
            .arg("--")
            .args(&cmdline)
            .stdin(Stdio::inherit())
            // stdout will still be the terminal that ran the command
            // this gives the experience of transience
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
                    // Parse the line
                    let parsed = Self::parse_strace_line(&line);

                    // Filter for process events and send structured data
                    match parsed {
                        StraceParseResult::Event(event) if Self::is_process_event(&event.syscall) => {
                            // Send JSON-serialized event
                            let json_line = serde_json::to_string(&event).unwrap_or_else(|_| line.clone());
                            if tx_raw.send(json_line).is_err() {
                                break;
                            }
                        }
                        StraceParseResult::Attachment(msg) => {
                            // Optionally send attachment notifications
                            if tx_raw.send(msg).is_err() {
                                break;
                            }
                        }
                        _ => {
                            // Skip unparseable lines or non-process events
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

    /// Parse strace output line into structured format using comprehensive regex
    fn parse_strace_line(line: &str) -> StraceParseResult {
        // Remove "TRACE: " prefix if present
        let clean_line = line.strip_prefix("TRACE: ").unwrap_or(line);

        // Handle attachment messages
        if clean_line.starts_with("strace: Process") {
            return StraceParseResult::Attachment(clean_line.to_string());
        }

        // Comprehensive regex for any syscall
        static STRACE_REGEX: OnceLock<Regex> = OnceLock::new();
        let regex = STRACE_REGEX.get_or_init(|| {
            Regex::new(r"^\[pid\s+(?P<pid>\d+)\]\s+(?P<timestamp>\d+:\d+:\d+\.\d+)\s+(?P<syscall>\w+)\((?P<args>.*?)(?:\)|<unfinished)(?:\s*=\s*(?P<result>[^<\n]+))?.*")
                .unwrap()
        });

        if let Some(captures) = regex.captures(clean_line) {
            let pid = captures
                .name("pid")
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);

            let timestamp = captures
                .name("timestamp")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            let syscall = captures
                .name("syscall")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            let args = captures
                .name("args")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            let result = captures
                .name("result")
                .map(|m| m.as_str().trim().to_string())
                .filter(|s| !s.is_empty());

            // Syscall is complete if we have a result and it's not unfinished
            let is_complete = result.is_some() && !clean_line.contains("<unfinished");

            StraceParseResult::Event(StraceEvent {
                pid,
                timestamp,
                syscall,
                args,
                result,
                is_complete,
                raw_line: line.to_string(),
            })
        } else {
            StraceParseResult::Unparseable(line.to_string())
        }
    }

    /// determines if syscall is a process event (process control related)
    /// a process control related event is one that signifies program execution,
    /// new processes starting, processes exiting, and processes waiting
    /// supported:
    ///     execve: execute a program
    ///     fork: clone parent process and start new child process
    ///     vfork: fork that shares parent mem and suspends parent
    ///            execution. Faster but less safe than fork because
    ///            of uninitended consequences of shared mem w parent
    ///     exit_group: terminates all threads in a process group
    ///     wait4: waits for child process state changes with resource
    ///            usage. (does more than wait basically)
    ///     wiatpid: waits for specific child process state changes
    fn is_process_event(syscall: &str) -> bool {
        matches!(
            syscall,
            "execve" | "clone" | "fork" | "vfork" | "exit_group" | "wait4" | "waitpid"
        )
    }

    // kills processes groups by process id
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

// terminates a process given a process
//
// `id` - unsigned integer for running process
async fn kill_process_group(pid: u32) -> Result<()> {
    LinuxTracer::kill_process_group(pid).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_complete_syscall() {
        let line = "TRACE: [pid  2427] 23:59:08.547188 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID) = 2438";
        let result = LinuxTracer::parse_strace_line(line);

        if let StraceParseResult::Event(event) = result {
            assert_eq!(event.pid, 2427);
            assert_eq!(event.syscall, "clone");
            assert_eq!(event.result, Some("2438".to_string()));
            assert!(event.is_complete);
        } else {
            panic!("Expected Event result");
        }
    }

    #[test]
    fn test_parse_incomplete_syscall() {
        let line = "TRACE: [pid  2441] 23:59:08.663678 execve(\"/usr/bin/which\", [\"which\", \"zsh\"], 0xaaaadbfe1858 /* 15 vars */ <unfinished ...>";
        let result = LinuxTracer::parse_strace_line(line);

        if let StraceParseResult::Event(event) = result {
            assert_eq!(event.pid, 2441);
            assert_eq!(event.syscall, "execve");
            assert!(!event.is_complete);
        } else {
            panic!("Expected Event result");
        }
    }

    #[test]
    fn test_parse_attachment() {
        let line = "TRACE: strace: Process 2438 attached";
        let result = LinuxTracer::parse_strace_line(line);

        if let StraceParseResult::Attachment(msg) = result {
            assert_eq!(msg, "strace: Process 2438 attached");
        } else {
            panic!("Expected Attachment result");
        }
    }
}
