//! Single-writer, multi-producer logger for Capsule.
//!
//! * Always appends to SYSLOG_PATH.
//! * Spawns one background thread the first time you call append()
//! * Non-blocking on the hot path - if the queue is full or the
//! thread has crashed, the line is silently dropped
//! (tracing must never stop the sandbox)
//! TODO: a better solution to make the logging more robust
//!       should be put in place in later versions.
//!       The logging is the whole point of the app, so
//!       if we miss logs we miss profiling and allow
//!       malicious code to slip through.

// log file can be initialized only once
use crate::constants::SYSLOG_PATH;
use once_cell::sync::Lazy;
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    sync::mpsc::{self, Sender},
    thread,
};

/// channel handle returned by LOGGER.
type Tx = Sender<String>;
/// global, lazily initialized logger handle
static LOGGER: Lazy<Tx> = Lazy::new(|| {
    // unbounded channel is find, ptrace rate << disk write rate
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(|| {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(SYSLOG_PATH)
            .expect("open syslog file");
        let mut writer = BufWriter::new(file);
        for line in rx {
            // TODO: here is the write that can fail
            //       we need to add persistent non-blocking writes here
            if writeln!(writer, "{}", line).is_err() {
                // TODO: a temporary error message
                eprintln!("capsule-logger: write failed");
            }
        }
    });
    tx
});

/// Append one log to the Capsule system log.
///
/// Non-blocking. Drops the line if the logger thread is gone.
#[inline]
pub fn append(line: impl Into<String>) {
    let _ = LOGGER.send(line.into());
}
