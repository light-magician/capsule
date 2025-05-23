use crate::constants::{AUDIT_LOG, OUT_LOG};
use chrono::Local;
use std::{
    fs::OpenOptions,
    io::{self, Write},
};

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
