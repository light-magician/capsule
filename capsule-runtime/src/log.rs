use crate::constants::{AUDIT_LOG, COMMAND_LOG_PATH, OUT_LOG, SYSLOG_PATH};
use chrono::{Local, Utc};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::{self, Write},
};
use uuid::Uuid;

/// Structure of each “command” log entry.
/// Recorded once per client request.
#[derive(Serialize)]
struct CommandLog {
    client_id: Uuid,
    session_id: Uuid,
    timestamp: String,    // ISO8601 UTC
    command: Vec<String>, // argv list
}

/// Structure of each “syscall” log entry.
/// Recorded on every intercepted syscall stop.
#[derive(Serialize)]
struct SyscallLog {
    session_id: Uuid,
    timestamp: String,         // ISO8601 UTC
    pid: i32,                  // process ID that issued the syscall
    syscall: String,           // name, e.g. "openat"
    args: Vec<String>,         // textualized arguments
    return_value: Option<i64>, // leave None for entry‐only tracing
}

/// Append an operational event (startup, error, shutdown) to the daemon’s event log.
/// Format: "YYYY-MM-DD HH:MM:SS EVENT: <msg>"
pub fn log_event(msg: &str) -> io::Result<()> {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
    let mut file = OpenOptions::new().create(true).append(true).open(OUT_LOG)?;
    writeln!(file, "{} EVENT: {}", ts, msg)?;
    Ok(())
}

/// Append an audit entry (raw JSON command) to the audit log.
/// Format: "YYYY-MM-DD HH:MM:SS AUDIT: <raw>"
pub fn log_audit(raw: &str) -> io::Result<()> {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG)?;
    writeln!(file, "{} AUDIT: {}", ts, raw.trim_end())?;
    Ok(())
}

/// Append a single command invocation to COMMAND_LOG_PATH.
///
/// # Why
/// - Durable audit of “what the client asked us to run.”
/// - Ties together client_id + session_id for later correlation.
pub fn log_command(client_id: &Uuid, session_id: &Uuid, command: &[String]) -> io::Result<()> {
    let entry = CommandLog {
        client_id: *client_id,
        session_id: *session_id,
        timestamp: Utc::now().to_rfc3339(),
        command: command.to_owned(),
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(COMMAND_LOG_PATH)?;
    let line = serde_json::to_string(&entry)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Append a single syscall event to SYSLOG_PATH.
///
/// # Why
/// - Durable audit at syscall granularity.
/// - session_id ties it back to the originating command.
/// - We record args; return_value is optional (can be filled later).
pub fn log_syscall_event(
    session_id: &Uuid,
    pid: i32,
    syscall: &str,
    args: &[String],
    return_value: Option<i64>,
) -> io::Result<()> {
    let entry = SyscallLog {
        session_id: *session_id,
        timestamp: Utc::now().to_rfc3339(),
        pid,
        syscall: syscall.to_string(),
        args: args.to_owned(),
        return_value,
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(SYSLOG_PATH)?;
    let line = serde_json::to_string(&entry)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
