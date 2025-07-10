//! Strace output parsing to structured events
//!
//! Converts raw strace lines into StraceEvent structs for downstream processing.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

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

pub struct StraceParser;

impl StraceParser {
    /// Parse strace output line into structured format using comprehensive regex
    pub fn parse_line(line: &str) -> StraceParseResult {
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
    pub fn is_process_event(syscall: &str) -> bool {
        matches!(
            syscall,
            "execve" | "clone" | "fork" | "vfork" | "exit_group" | "wait4" | "waitpid"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_complete_syscall() {
        let line = "TRACE: [pid  2427] 23:59:08.547188 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID) = 2438";
        let result = StraceParser::parse_line(line);

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
        let result = StraceParser::parse_line(line);

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
        let result = StraceParser::parse_line(line);

        if let StraceParseResult::Attachment(msg) = result {
            assert_eq!(msg, "strace: Process 2438 attached");
        } else {
            panic!("Expected Attachment result");
        }
    }
}
