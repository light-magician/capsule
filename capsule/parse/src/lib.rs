//! Strace output parsing to universal syscall events
//!
//! Converts raw strace lines into SyscallEvent structs for downstream processing.
//! All syscalls are parsed and emitted - no filtering at this layer.

use core::SyscallEvent;
use chrono;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// STRACE-SPECIFIC PATTERNS
// These patterns support an optional "[pid N]" prefix because strace may omit it
// for the thread-group leader when starting a fresh trace (not attaching).
// For lines without a PID, we emit events with pid=0; downstream resolves leader PID on exec.
static STRACE_EXIT_STATUS_PATTERN: &str = r"^(?:\[pid\s+(?P<pid>\d+)\]\s+)?(?P<timestamp>\d+:\d+:\d+\.\d+)\s+\+\+\+\s+exited\s+with\s+(?P<exit_code>\d+)\s+\+\+\+";
static STRACE_SYSCALL_PATTERN: &str = r"^(?:\[pid\s+(?P<pid>\d+)\]\s+)?(?P<timestamp>\d+:\d+:\d+\.\d+)\s+(?P<syscall>\w+)\((?P<args>.*?)(?:\)|<unfinished)(?:\s*=\s*(?P<result>[^<\n]+))?.*";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StraceParseResult {
    Event(SyscallEvent),
    Attachment(String), // "strace: Process 2438 attached"
    Unparseable(String),
}

pub struct StraceParser;

impl StraceParser {
    /// Parse strace output line into SyscallEvent using comprehensive regex
    /// Parses ALL syscalls, no filtering at this layer
    pub fn parse_line(line: &str) -> StraceParseResult {
        // Remove "TRACE: " prefix if present
        // TODO: remove, might be unnecessary now but need to check
        let clean_line = line.strip_prefix("TRACE: ").unwrap_or(line);

        // Handle attachment messages
        if clean_line.starts_with("strace: Process") {
            return StraceParseResult::Attachment(clean_line.to_string());
        }

        // Handle strace exit status annotations: "[pid  2008] 13:13:48.055387 +++ exited with 0 +++"
        // NOTE: This is strace-specific editorial content, not a raw syscall
        static EXIT_STATUS_REGEX: OnceLock<Regex> = OnceLock::new();
        let exit_regex = EXIT_STATUS_REGEX.get_or_init(|| {
            Regex::new(STRACE_EXIT_STATUS_PATTERN).unwrap()
        });

        if let Some(captures) = exit_regex.captures(clean_line) {
            // PID may be missing for leader lines; use 0 as sentinel
            let pid = captures
                .name("pid")
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);

            let timestamp = chrono::Utc::now().timestamp_micros() as u64;

            let exit_code = captures
                .name("exit_code")
                .and_then(|m| m.as_str().parse::<i32>().ok());

            // Create a synthetic "process_exited" event for the "+++ exited +++" pattern
            // This allows us to distinguish between exit() syscall (Exiting) and full termination (Exited)
            let syscall_event = SyscallEvent::new(
                pid,
                timestamp,
                "process_exited".to_string(), // Synthetic event name
                vec![exit_code.map(|c| c.to_string()).unwrap_or_else(|| "0".to_string())],
                exit_code.map(|c| c.to_string()),
                line.to_string(),
            );

            return StraceParseResult::Event(syscall_event);
        }

        // Comprehensive regex for any syscall
        static STRACE_REGEX: OnceLock<Regex> = OnceLock::new();
        let regex = STRACE_REGEX.get_or_init(|| {
            Regex::new(STRACE_SYSCALL_PATTERN).unwrap()
        });

        if let Some(captures) = regex.captures(clean_line) {
            // PID may be absent for leader lines; we set 0 and handle later on exec
            let pid = captures
                .name("pid")
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);

            let timestamp_str = captures
                .name("timestamp")
                .map(|m| m.as_str())
                .unwrap_or("");
            
            // Convert timestamp to microseconds since epoch
            // For now, use current time - proper timestamp parsing can be added later
            let timestamp = chrono::Utc::now().timestamp_micros() as u64;

            let syscall_name = captures
                .name("syscall")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            let args_str = captures
                .name("args")
                .map(|m| m.as_str())
                .unwrap_or("");
            
            // Parse args into vector - simple comma split for now
            // More sophisticated parsing can be added later per syscall type
            let args = if args_str.is_empty() {
                Vec::new()
            } else {
                args_str.split(',').map(|s| s.trim().to_string()).collect()
            };

            let result = captures
                .name("result")
                .map(|m| m.as_str().trim().to_string())
                .filter(|s| !s.is_empty());

            let syscall_event = SyscallEvent::new(
                pid,
                timestamp,
                syscall_name,
                args,
                result,
                line.to_string(),
            );

            StraceParseResult::Event(syscall_event)
        } else {
            StraceParseResult::Unparseable(line.to_string())
        }
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
            assert_eq!(event.syscall_name, "clone");
            assert_eq!(event.result, Some("2438".to_string()));
            assert_eq!(event.args.len(), 2); // child_stack=NULL, flags=CLONE_CHILD_CLEARTID
            assert_eq!(event.raw_line, line);
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
            assert_eq!(event.syscall_name, "execve");
            assert_eq!(event.result, None); // unfinished, so no result
            assert!(event.args.len() > 0); // Should have parsed some args
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
