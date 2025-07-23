//! Tokio pipeline orchestration for trace → parse → track
//!
//! Coordinates the async pipeline using JoinSet, broadcast channels,
//! and cancellation tokens for graceful shutdown.

use anyhow::Result;
use core::events::ProcessEvent;
use io::StreamCoordinator;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn, error};
use crate::ipc::{SessionLockManager, StateServer};

pub struct Pipeline {
    cancellation_token: CancellationToken,
    task_set: JoinSet<Result<()>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            cancellation_token: CancellationToken::new(),
            task_set: JoinSet::new(),
        }
    }

    /// Run the complete pipeline: trace → parse → track
    pub async fn run(&mut self, cmdline: Vec<String>, session_dir: String) -> Result<()> {
        info!("Starting pipeline for command: {:?}", cmdline);
        
        // Initialize debug logging if enabled
        state::init_debug_logging();

        // Extract session ID from session_dir path
        let session_id = PathBuf::from(&session_dir)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid session directory"))?
            .to_string();

        // Create session lock for monitoring
        let session_lock = SessionLockManager::create_lock(session_id, cmdline.clone()).await?;
        info!("Created session lock: {}", session_lock.session_id);

        // Create shared state for tracking and monitoring
        let (tracker, shared_state) = state::ProcessTracker::new(
            cmdline.first().map(|s| s.clone()) // Use first command as target
        );

        // Start state server for monitoring
        let state_server = StateServer::new(&session_lock.socket_path, shared_state.clone()).await?;
        let state_cancellation = self.cancellation_token.clone();
        self.task_set.spawn(async move {
            state_server.run(state_cancellation).await
        });

        // Create broadcast channels for pipeline communication
        let (tx_raw, _) = broadcast::channel::<String>(8192);
        let (tx_events, _) = broadcast::channel::<ProcessEvent>(4096);

        // Ready synchronization - wait for all tasks to be ready
        let (ready_tx, mut ready_rx) = mpsc::channel::<()>(4); // Increased for state server

        // Setup stream coordinator
        let mut coordinator = StreamCoordinator::new(PathBuf::from(&session_dir));
        
        // Add receivers - for now just the strace output
        coordinator.add_receiver("syscalls.jsonl");
        
        // Start all receivers
        let receiver_handles = coordinator.start_all(
            tx_raw.subscribe(),
            self.cancellation_token.clone(),
        ).await?;

        // Add receiver handles to task set
        for handle in receiver_handles {
            self.task_set.spawn(async move {
                match handle.await {
                    Ok(result) => result,
                    Err(e) => Err(anyhow::anyhow!("Receiver task failed: {}", e)),
                }
            });
        }

        // Spawn trace task
        self.task_set.spawn(spawn_trace_task(
            cmdline,
            tx_raw.clone(),
            ready_tx.clone(),
            self.cancellation_token.clone(),
        ));

        // Spawn parse task  
        self.task_set.spawn(spawn_parse_task(
            tx_raw.subscribe(),
            tx_events.clone(),
            ready_tx.clone(),
            self.cancellation_token.clone(),
        ));

        // Spawn track task with shared state
        self.task_set.spawn(spawn_track_task(
            tx_events.subscribe(),
            tx_raw.subscribe(),
            tracker,
            ready_tx,
            self.cancellation_token.clone(),
        ));

        // Wait for all tasks to signal ready
        info!("Waiting for pipeline tasks to be ready...");
        for i in 0..3 {
            match ready_rx.recv().await {
                Some(()) => info!("Task {} ready", i + 1),
                None => return Err(anyhow::anyhow!("Ready channel closed unexpectedly")),
            }
        }
        info!("All pipeline tasks ready, starting execution");

        // Handle graceful shutdown
        tokio::select! {
            // Wait for tasks to complete naturally
            result = self.wait_for_tasks() => {
                match result {
                    Ok(()) => info!("Pipeline completed successfully"),
                    Err(e) => error!("Pipeline error: {}", e),
                }
            },
            // Handle Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                warn!("Received Ctrl+C, initiating graceful shutdown...");
                self.cancellation_token.cancel();
                
                // Give tasks 5 seconds to clean up
                let shutdown_result = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.wait_for_tasks()
                ).await;
                
                match shutdown_result {
                    Ok(Ok(())) => info!("Graceful shutdown completed"),
                    Ok(Err(e)) => warn!("Shutdown with errors: {}", e),
                    Err(_) => warn!("Shutdown timeout, some tasks may not have cleaned up"),
                }
            }
        }

        // Clean up session lock
        info!("Cleaning up session lock");
        if let Err(e) = SessionLockManager::remove_lock().await {
            warn!("Failed to remove session lock: {}", e);
        }

        Ok(())
    }

}

async fn spawn_trace_task(
    cmdline: Vec<String>,
    tx_raw: broadcast::Sender<String>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
        // Signal ready immediately (trace doesn't need setup)
        ready_tx.send(()).await.map_err(|_| anyhow::anyhow!("Ready channel closed"))?;
        
        // Start tracing
        trace::LinuxTracer::run_with_cancellation(cmdline, tx_raw, cancellation_token).await
    }

async fn spawn_parse_task(
    mut rx_raw: broadcast::Receiver<String>,
    tx_events: broadcast::Sender<ProcessEvent>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
        // Signal ready immediately (parser doesn't need setup)
        ready_tx.send(()).await.map_err(|_| anyhow::anyhow!("Ready channel closed"))?;

        // Parse strace lines and filter for process events
        loop {
            tokio::select! {
                line_result = rx_raw.recv() => {
                    match line_result {
                        Ok(line) => {
                            // Parse the strace line
                            let parse_result = parse::StraceParser::parse_line(&line);
                            
                            if let parse::StraceParseResult::Event(strace_event) = parse_result {
                                // Filter for process events only
                                if parse::StraceParser::is_process_event(&strace_event.syscall) {
                                    // Convert StraceEvent to ProcessEvent
                                    if let Some(process_event) = convert_to_process_event(strace_event) {
                                        if tx_events.send(process_event).is_err() {
                                            // No more receivers
                                            break;
                                        }
                                    }
                                }
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Parser lagged by {} events", n);
                        },
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                },
                _ = cancellation_token.cancelled() => {
                    info!("Parse task received cancellation signal");
                    break;
                }
            }
        }

        Ok(())
    }

async fn spawn_track_task(
    rx_events: broadcast::Receiver<ProcessEvent>,
    rx_raw: broadcast::Receiver<String>,
    tracker: state::ProcessTracker,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
        // Run the tracker with shared state
        tracker.run(rx_events, rx_raw, ready_tx, cancellation_token).await
    }

/// Convert StraceEvent to ProcessEvent based on syscall type
fn convert_to_process_event(strace_event: parse::StraceEvent) -> Option<ProcessEvent> {
        use core::events::ProcessEvent;
        
        // Parse timestamp - convert from HH:MM:SS.microseconds to microseconds since epoch
        let timestamp = parse_timestamp(&strace_event.timestamp);
        
        match strace_event.syscall.as_str() {
            "execve" => {
                // Parse command line from execve arguments
                let command_line = parse_execve_syscall(&strace_event.args, strace_event.result.as_deref())
                    .unwrap_or_else(|| vec!["execve".to_string()]);

                Some(ProcessEvent::exec(
                    timestamp,
                    strace_event.pid,
                    0, // PPID will be resolved by state tracker
                    command_line,
                    None, // Working directory not available from strace
                ))
            },
            "clone" => {
                // Parse child PID from return value
                if let Some(child_pid) = parse_clone_syscall(&strace_event.args, strace_event.result.as_deref()) {
                    Some(ProcessEvent::clone(timestamp, strace_event.pid, child_pid))
                } else {
                    None // Invalid clone - no child PID
                }
            },
            "fork" => {
                // Parse child PID from return value
                if let Some(child_pid) = parse_fork_syscall(&strace_event.args, strace_event.result.as_deref()) {
                    Some(ProcessEvent::fork(timestamp, strace_event.pid, child_pid))
                } else {
                    None // Invalid fork - no child PID
                }
            },
            "vfork" => {
                // Parse child PID from return value
                if let Some(child_pid) = parse_vfork_syscall(&strace_event.args, strace_event.result.as_deref()) {
                    Some(ProcessEvent::vfork(timestamp, strace_event.pid, child_pid))
                } else {
                    None // Invalid vfork - no child PID
                }
            },
            "exit_group" => {
                // Parse exit code from result
                let exit_code = strace_event.result
                    .and_then(|r| r.parse::<i32>().ok());

                Some(ProcessEvent::exit(timestamp, strace_event.pid, exit_code))
            },
            "wait4" => {
                // Parse child PID and exit code from arguments and result
                if let Some((child_pid, child_exit_code)) = parse_wait4_syscall(&strace_event.args, strace_event.result.as_deref()) {
                    Some(ProcessEvent::wait(timestamp, strace_event.pid, child_pid, child_exit_code))
                } else {
                    None // Invalid wait4 - couldn't parse
                }
            },
            "waitpid" => {
                // Parse child PID and exit code from arguments and result
                if let Some((child_pid, child_exit_code)) = parse_waitpid_syscall(&strace_event.args, strace_event.result.as_deref()) {
                    Some(ProcessEvent::wait(timestamp, strace_event.pid, child_pid, child_exit_code))
                } else {
                    None // Invalid waitpid - couldn't parse
                }
            },
            _ => None, // Not a process event we care about
        }
    }

fn parse_timestamp(_timestamp_str: &str) -> u64 {
    // Convert HH:MM:SS.microseconds to microseconds since start
    // For now, just use current time in microseconds
    chrono::Utc::now().timestamp_micros() as u64
}

/// Parse execve syscall arguments to extract command line
/// Format: execve("/bin/ls", ["ls", "-la", "/home"], ["PATH=/usr/bin", ...])
fn parse_execve_syscall(args: &str, _result: Option<&str>) -> Option<Vec<String>> {
    // Find the argv array - it's the second parameter in brackets
    // execve("/bin/ls", ["ls", "-la", "/home"], ...)
    //                   ^^^^^^^^^^^^^^^^^^^^^^^^^
    
    let start_bracket = args.find('[').map(|i| i + 1)?;
    let end_bracket = args[start_bracket..].find(']').map(|i| i + start_bracket)?;
    
    let argv_str = &args[start_bracket..end_bracket];
    
    // Parse individual arguments - they're quoted strings separated by commas
    let mut command_line = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;
    let mut escape_next = false;
    
    for ch in argv_str.chars() {
        if escape_next {
            current_arg.push(ch);
            escape_next = false;
        } else if ch == '\\' {
            escape_next = true;
        } else if ch == '"' && !escape_next {
            in_quotes = !in_quotes;
        } else if ch == ',' && !in_quotes {
            if !current_arg.trim().is_empty() {
                command_line.push(current_arg.trim().to_string());
                current_arg.clear();
            }
        } else if !ch.is_whitespace() || in_quotes {
            current_arg.push(ch);
        }
    }
    
    // Don't forget the last argument
    if !current_arg.trim().is_empty() {
        command_line.push(current_arg.trim().to_string());
    }
    
    if command_line.is_empty() {
        None
    } else {
        Some(command_line)
    }
}

/// Parse clone syscall to extract child PID from return value
/// Format: clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID) = 1234
fn parse_clone_syscall(_args: &str, result: Option<&str>) -> Option<u32> {
    result?.trim().parse::<u32>().ok()
}

/// Parse fork syscall to extract child PID from return value  
/// Format: fork() = 1235
fn parse_fork_syscall(_args: &str, result: Option<&str>) -> Option<u32> {
    result?.trim().parse::<u32>().ok()
}

/// Parse vfork syscall to extract child PID from return value
/// Format: vfork() = 1236  
fn parse_vfork_syscall(_args: &str, result: Option<&str>) -> Option<u32> {
    result?.trim().parse::<u32>().ok()
}

/// Parse wait4 syscall to extract child PID and exit status
/// Format: wait4(1234, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 1234
fn parse_wait4_syscall(args: &str, result: Option<&str>) -> Option<(u32, Option<i32>)> {
    // Extract child PID from first argument
    let child_pid = args
        .split(',')
        .next()?
        .trim()
        .parse::<u32>()
        .ok()?;
    
    // Extract exit code from wstatus - look for WEXITSTATUS(s) == N
    let exit_code = if args.contains("WEXITSTATUS") {
        // Find WEXITSTATUS(s) == N pattern
        if let Some(start) = args.find("WEXITSTATUS(s) == ") {
            let start = start + "WEXITSTATUS(s) == ".len();
            if let Some(end) = args[start..].find(['}', ',', ')'].as_ref()) {
                args[start..start + end].trim().parse::<i32>().ok()
            } else {
                None
            }
        } else {
            None
        }
    } else if args.contains("WIFSIGNALED") {
        // Process was terminated by signal - use negative signal number
        if let Some(start) = args.find("WTERMSIG(s) == ") {
            let start = start + "WTERMSIG(s) == ".len();
            if let Some(end) = args[start..].find(['}', ',', ')'].as_ref()) {
                // Return negative signal number to indicate termination by signal
                args[start..start + end].trim().parse::<i32>().map(|sig| -sig).ok()
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    
    // Verify return value matches child PID
    if let Some(returned_pid) = result {
        if returned_pid.trim().parse::<u32>().ok()? == child_pid {
            Some((child_pid, exit_code))
        } else {
            None
        }
    } else {
        Some((child_pid, exit_code))
    }
}

/// Parse waitpid syscall to extract child PID and exit status
/// Format: waitpid(1234, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0) = 1234
fn parse_waitpid_syscall(args: &str, result: Option<&str>) -> Option<(u32, Option<i32>)> {
    // Same parsing logic as wait4, just different syscall name
    parse_wait4_syscall(args, result)
}

impl Pipeline {
    async fn wait_for_tasks(&mut self) -> Result<()> {
        while let Some(result) = self.task_set.join_next().await {
            match result {
                Ok(task_result) => {
                    if let Err(e) = task_result {
                        error!("Task error: {}", e);
                    }
                },
                Err(e) => {
                    error!("Task join error: {}", e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::events::{ProcessEvent, ProcessEventType};

    #[test]
    fn test_parse_execve_syscall_basic() {
        let args = r#""/bin/ls", ["ls", "-la", "/home"], 0x7fff5fbff000 /* 16 vars */"#;
        let result = parse_execve_syscall(args, None);
        
        assert_eq!(
            result,
            Some(vec!["ls".to_string(), "-la".to_string(), "/home".to_string()])
        );
    }

    #[test]
    fn test_parse_execve_syscall_with_quotes() {
        let args = r#""/usr/bin/python3", ["python3", "/path/to/script.py", "--arg", "value with spaces"], 0x7fff5fbff000"#;
        let result = parse_execve_syscall(args, None);
        
        assert_eq!(
            result,
            Some(vec![
                "python3".to_string(),
                "/path/to/script.py".to_string(), 
                "--arg".to_string(),
                "value with spaces".to_string()
            ])
        );
    }

    #[test]
    fn test_parse_execve_syscall_empty_args() {
        let args = r#""/bin/echo", [], 0x7fff5fbff000"#;
        let result = parse_execve_syscall(args, None);
        
        assert_eq!(result, None); // Empty argv should return None
    }

    #[test]
    fn test_parse_execve_syscall_no_brackets() {
        let args = r#""/bin/ls", NULL, 0x7fff5fbff000"#;
        let result = parse_execve_syscall(args, None);
        
        assert_eq!(result, None); // No brackets should return None
    }

    #[test]
    fn test_parse_clone_syscall_success() {
        let args = "child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID, child_tidptr=0x7f8b2c5a1a10";
        let result = parse_clone_syscall(args, Some("1234"));
        
        assert_eq!(result, Some(1234));
    }

    #[test]
    fn test_parse_clone_syscall_failure() {
        let args = "child_stack=NULL, flags=CLONE_CHILD_CLEARTID";
        let result = parse_clone_syscall(args, Some("-1"));
        
        assert_eq!(result, None); // -1 is not a valid PID
    }

    #[test]
    fn test_parse_fork_syscall_success() {
        let args = "";
        let result = parse_fork_syscall(args, Some("1235"));
        
        assert_eq!(result, Some(1235));
    }

    #[test]
    fn test_parse_vfork_syscall_success() {
        let args = "";
        let result = parse_vfork_syscall(args, Some("1236"));
        
        assert_eq!(result, Some(1236));
    }

    #[test]
    fn test_parse_wait4_syscall_normal_exit() {
        let args = "1234, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL";
        let result = parse_wait4_syscall(args, Some("1234"));
        
        assert_eq!(result, Some((1234, Some(0))));
    }

    #[test]
    fn test_parse_wait4_syscall_error_exit() {
        let args = "1234, [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL";
        let result = parse_wait4_syscall(args, Some("1234"));
        
        assert_eq!(result, Some((1234, Some(1))));
    }

    #[test]
    fn test_parse_wait4_syscall_signal_termination() {
        let args = "1234, [{WIFSIGNALED(s) && WTERMSIG(s) == 9}], 0, NULL";
        let result = parse_wait4_syscall(args, Some("1234"));
        
        assert_eq!(result, Some((1234, Some(-9)))); // Negative signal number
    }

    #[test]
    fn test_parse_wait4_syscall_no_exit_status() {
        let args = "1234, NULL, 0, NULL";
        let result = parse_wait4_syscall(args, Some("1234"));
        
        assert_eq!(result, Some((1234, None)));
    }

    #[test]
    fn test_parse_waitpid_syscall_success() {
        let args = "1234, [{WIFEXITED(s) && WEXITSTATUS(s) == 42}], 0";
        let result = parse_waitpid_syscall(args, Some("1234"));
        
        assert_eq!(result, Some((1234, Some(42))));
    }

    #[test]
    fn test_convert_to_process_event_execve() {
        let strace_event = parse::StraceEvent {
            pid: 1000,
            timestamp: "12:34:56.789123".to_string(),
            syscall: "execve".to_string(),
            args: r#""/bin/ls", ["ls", "-la"], 0x7fff5fbff000"#.to_string(),
            result: Some("0".to_string()),
            is_complete: true,
            raw_line: "test".to_string(),
        };
        
        let result = convert_to_process_event(strace_event);
        assert!(result.is_some());
        
        let event = result.unwrap();
        assert_eq!(event.pid, 1000);
        assert!(matches!(event.event_type, ProcessEventType::Exec));
        assert_eq!(event.command_line, vec!["ls".to_string(), "-la".to_string()]);
    }

    #[test]
    fn test_convert_to_process_event_clone() {
        let strace_event = parse::StraceEvent {
            pid: 1000,
            timestamp: "12:34:56.789123".to_string(),
            syscall: "clone".to_string(),
            args: "child_stack=NULL, flags=CLONE_CHILD_CLEARTID".to_string(),
            result: Some("1001".to_string()),
            is_complete: true,
            raw_line: "test".to_string(),
        };
        
        let result = convert_to_process_event(strace_event);
        assert!(result.is_some());
        
        let event = result.unwrap();
        assert_eq!(event.pid, 1000); // Parent PID
        assert!(matches!(event.event_type, ProcessEventType::Clone { child_pid: 1001 }));
    }

    #[test]
    fn test_convert_to_process_event_fork() {
        let strace_event = parse::StraceEvent {
            pid: 1000,
            timestamp: "12:34:56.789123".to_string(),
            syscall: "fork".to_string(),
            args: "".to_string(),
            result: Some("1002".to_string()),
            is_complete: true,
            raw_line: "test".to_string(),
        };
        
        let result = convert_to_process_event(strace_event);
        assert!(result.is_some());
        
        let event = result.unwrap();
        assert_eq!(event.pid, 1000); // Parent PID
        assert!(matches!(event.event_type, ProcessEventType::Fork { child_pid: 1002 }));
    }

    #[test]
    fn test_convert_to_process_event_exit_group() {
        let strace_event = parse::StraceEvent {
            pid: 1000,
            timestamp: "12:34:56.789123".to_string(),
            syscall: "exit_group".to_string(),
            args: "0".to_string(),
            result: Some("?".to_string()),
            is_complete: true,
            raw_line: "test".to_string(),
        };
        
        let result = convert_to_process_event(strace_event);
        assert!(result.is_some());
        
        let event = result.unwrap();
        assert_eq!(event.pid, 1000);
        assert!(matches!(event.event_type, ProcessEventType::Exit));
        assert_eq!(event.exit_code, None); // Can't parse "?" as exit code
    }

    #[test]
    fn test_convert_to_process_event_wait4() {
        let strace_event = parse::StraceEvent {
            pid: 1000,
            timestamp: "12:34:56.789123".to_string(),
            syscall: "wait4".to_string(),
            args: "1001, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL".to_string(),
            result: Some("1001".to_string()),
            is_complete: true,
            raw_line: "test".to_string(),
        };
        
        let result = convert_to_process_event(strace_event);
        assert!(result.is_some());
        
        let event = result.unwrap();
        assert_eq!(event.pid, 1000); // Parent PID
        assert!(matches!(event.event_type, ProcessEventType::Wait { child_pid: 1001, child_exit_code: Some(0) }));
    }

    #[test]
    fn test_convert_to_process_event_unsupported_syscall() {
        let strace_event = parse::StraceEvent {
            pid: 1000,
            timestamp: "12:34:56.789123".to_string(),
            syscall: "read".to_string(),
            args: "0, buf, 1024".to_string(),
            result: Some("1024".to_string()),
            is_complete: true,
            raw_line: "test".to_string(),
        };
        
        let result = convert_to_process_event(strace_event);
        assert!(result.is_none()); // Non-process syscalls should return None
    }

    #[test]
    fn test_convert_to_process_event_failed_clone() {
        let strace_event = parse::StraceEvent {
            pid: 1000,
            timestamp: "12:34:56.789123".to_string(),
            syscall: "clone".to_string(),
            args: "child_stack=NULL, flags=CLONE_CHILD_CLEARTID".to_string(),
            result: Some("-1".to_string()), // Failed clone
            is_complete: true,
            raw_line: "test".to_string(),
        };
        
        let result = convert_to_process_event(strace_event);
        assert!(result.is_none()); // Failed syscalls should return None
    }
}