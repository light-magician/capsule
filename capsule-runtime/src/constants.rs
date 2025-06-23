//! Global paths and filenames.

use once_cell::sync::Lazy;
use std::path::PathBuf;

/// ~/.capsule
pub static CAPS_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    let mut p = dirs::home_dir().expect("$HOME not set");
    p.push(".capsule");
    p
});

/// ~/.capsule/run
pub static RUN_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    let mut p = CAPS_ROOT.clone();
    p.push("run");
    p
});

/// ~/.capsule/logs
pub static LOG_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    let mut p = CAPS_ROOT.clone();
    p.push("logs");
    p
});
// PID and Socket files
pub const PID_FILE: &str = "caps.pid";
pub const SOCK_FILE: &str = "caps.sock";
// Metadata files
pub const LOG_DIR_FILE: &str = "log_dir.txt";
// log files
pub const SYSCALL_FILE: &str = "syscalls.log";
pub const EVENT_FILE: &str = "events.jsonl";
pub const ACTION_FILE: &str = "actions.jsonl";
pub const PARSE_ERROR_FILE: &str = "parse_errors.log";

/// Ensure ~/.capsule, run/, and logs/ exist.  Call once during CLI startup.
pub fn ensure_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all(&*RUN_ROOT)?;
    std::fs::create_dir_all(&*LOG_ROOT)?;
    Ok(())
}
