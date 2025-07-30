//! Strace output parsing to universal syscall events
//!
//! Converts raw strace lines into SyscallEvent structs for downstream processing.
//! All syscalls are parsed and emitted - no filtering at this layer.

use core::SyscallEvent;
use chrono;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

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
