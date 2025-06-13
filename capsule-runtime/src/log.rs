use crate::constants;
use anyhow::Result;
use once_cell::sync::Lazy;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::thread;

/// channel handle returned by LOGGER.
type Tx = Sender<String>;

/// global, lazily initialized logger handle
static LOGGER: Lazy<Tx> = Lazy::new(|| {
    // unbounded channel is fine; ptrace rate << disk write rate
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(|| {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(constants::SYSLOG_PATH)
            .expect("open syslog file");
        let mut writer = BufWriter::new(file);
        for line in rx {
            if writeln!(writer, "{}", line).is_err() {
                eprintln!("capsule-logger: write failed");
            }
        }
    });
    tx
});

/// Append a line to the default capsule log file.
pub fn append(line: impl Into<String>) -> Result<()> {
    LOGGER
        .send(line.into())
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

/// Append a line to a specified log file path.
pub fn append_to(path: &Path, line: impl AsRef<str>) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "{}", line.as_ref())?;
    Ok(())
}
