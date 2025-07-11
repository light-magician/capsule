//! Process tracking and tree management
//!
//! Converts StraceEvent streams to ProcessEvents and maintains
//! real-time ProcessTrees

use anyhow::Result;
use chrono::Utc;
use core::events::{ProcessEvent, ProcessEventType};
use core::tree::ProcessTree;

use parse::{StraceEvent, StraceParseResult, StraceParser};
use serde_json;
use std::collections::HashMap;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

pub struct ProcessTracker {
    /// in mem process tree
    tree: ProcessTree,
    /// File writer for ProcessEvent JSONL stream
    events_writer: BufWriter<File>,
    /// track PID -> PPID relationships from clone/fork results
    pid_parent_map: HashMap<u32, u32>,
    /// Session start time for relative timestamps
    session_start: chrono::DateTime<Utc>,
}

impl ProcessTracker {
    /// Create new tracker with output file
    pub async fn new(events_file_path: &str) -> Result<Self> {
        let events_file = File::create(events_file_path).await?;
        let events_writer = BufWriter::new(events_file);

        Ok(Self {
            tree: ProcessTree::new(),
            events_writer,
            pid_parent_map: HashMap::new(),
            session_start: Utc::now(),
        })
    }

    /// Main tracking loop - subscribe to StraceEvent stream
    pub async fn run(
        mut self,
        mut rx_strace: broadcast::Receiver<String>,
        ready_tx: mpsc::Sender<()>,
        cancellation_token: CancellationToken,
    ) -> Result<()> {
        // Signal ready
        ready_tx.send(()).await?;

        loop {
            tokio::select! {
                line_result = rx_strace.recv() => {
                    match line_result {
                        Ok(raw_line) => {
                            if let Err(e) = self.process_strace_line(raw_line).await {
                                eprintln!("Error processing line: {}", e);
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("Tracker lagged by {} events", n);
                        },
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                },
                _ = cancellation_token.cancelled() => {
                    self.final_flush().await?;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a single strace line
    async fn process_strace_line(&mut self, raw_line: String) -> Result<()> {
        // Parse raw line to StraceEvent
        let parse_result = StraceParser::parse_line(&raw_line);

        match parse_result {
            StraceParseResult::Event(strace_event) => {
                // Only process process-related syscalls
                if StraceParser::is_process_event(&strace_event.syscall) {
                    if let Some(process_event) = self.convert_to_process_event(strace_event).await?
                    {
                        // Update tree
                        self.tree.update(process_event.clone())?;

                        // Write to file
                        self.write_event_to_file(&process_event).await?;
                    }
                }
            }
            StraceParseResult::Attachment(_) => {
                // Log attachment messages but don't process
            }
            StraceParseResult::Unparseable(_) => {
                // Skip unparseable lines
            }
        }

        Ok(())
    }

    /// Convert StraceEvent → ProcessEvent
    async fn convert_to_process_event(
        &mut self,
        strace_event: StraceEvent,
    ) -> Result<Option<ProcessEvent>> {
        let timestamp = self.convert_timestamp(&strace_event.timestamp)?;

        match strace_event.syscall.as_str() {
            "execve" => {
                let command_line = self.parse_execve_args(&strace_event.args);
                let ppid = self.get_ppid(strace_event.pid);

                Ok(Some(ProcessEvent::spawn(
                    timestamp,
                    strace_event.pid,
                    ppid,
                    command_line,
                    None, // working_dir - could extract from args later
                )))
            }
            "clone" | "fork" | "vfork" => {
                if let Some(result) = &strace_event.result {
                    if let Ok(child_pid) = result.parse::<u32>() {
                        // Record parent-child relationship for future use
                        self.pid_parent_map.insert(child_pid, strace_event.pid);

                        // The clone syscall itself doesn't create a ProcessEvent
                        // We'll get the execve for the actual command later
                    }
                }
                Ok(None)
            }
            "exit_group" => {
                let exit_code = strace_event.args.parse::<i32>().ok();

                Ok(Some(ProcessEvent::exit(
                    timestamp,
                    strace_event.pid,
                    exit_code,
                )))
            }
            "wait4" | "waitpid" => {
                // Parent waiting for child - no ProcessEvent needed
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Convert strace timestamp to microseconds since epoch
    fn convert_timestamp(&self, time_str: &str) -> Result<u64> {
        // Parse "14:30:25.123456" format
        let today = self.session_start.date_naive();
        let time = chrono::NaiveTime::parse_from_str(time_str, "%H:%M:%S%.f")?;
        let datetime = today.and_time(time);
        let datetime_utc = datetime.and_utc();

        Ok(datetime_utc.timestamp_micros() as u64)
    }

    /// Get PPID for a given PID (from our tracking)
    fn get_ppid(&self, pid: u32) -> u32 {
        self.pid_parent_map.get(&pid).copied().unwrap_or(0)
    }

    /// Parse execve arguments to extract command line
    fn parse_execve_args(&self, args: &str) -> Vec<String> {
        // Basic parsing for: "/usr/bin/python3", ["python3", "script.py"], env
        // For now, just extract the executable path
        if let Some(start) = args.find('"') {
            if let Some(end) = args[start + 1..].find('"') {
                let executable = &args[start + 1..start + 1 + end];
                return vec![executable.to_string()];
            }
        }

        // Fallback
        vec!["unknown".to_string()]
    }

    /// Write ProcessEvent to JSONL file
    async fn write_event_to_file(&mut self, event: &ProcessEvent) -> Result<()> {
        let json_line = serde_json::to_string(event)?;
        self.events_writer.write_all(json_line.as_bytes()).await?;
        self.events_writer.write_all(b"\n").await?;
        self.events_writer.flush().await?;
        Ok(())
    }

    /// Final flush and cleanup
    async fn final_flush(&mut self) -> Result<()> {
        self.events_writer.flush().await?;
        Ok(())
    }

    /// Get reference to current tree (for external access)
    pub fn tree(&self) -> &ProcessTree {
        &self.tree
    }
}
