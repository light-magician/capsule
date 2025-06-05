//! A minimal “polling” tail for the Capsule audit log (`capsule tail`).
//! No notify/notify-debouncer; just sleep + read.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::PathBuf,
    sync::mpsc::{self, Sender},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use ctrlc;

use crate::constants::SYSLOG_PATH as DEFAULT_LOG_PATH;

/// Entry point for `capsule tail`.
pub fn tail(file_override: Option<PathBuf>) -> Result<()> {
    // 1) Decide which file to tail (or use default).
    let path: PathBuf = file_override.unwrap_or_else(|| DEFAULT_LOG_PATH.into());

    // 2) “Touch”/create the file so that opening it for reading won't fail.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to create/open log file at {:?}", path))?;

    // 3) Channel for forwarding any new lines from the background thread.
    let (line_tx, line_rx) = mpsc::channel::<String>();

    // 4) Spawn a background thread that polls the file every 200 ms.
    spawn_poller(path.clone(), line_tx)?;

    // 5) Install a Ctrl-C handler so we can exit cleanly.
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, std::sync::atomic::Ordering::SeqCst);
        })
        .expect("failed to install Ctrl-C handler");
    }

    // 6) In the main thread, loop and print any lines received.
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        // Use a 250 ms timeout so we wake up reasonably often to check `running`.
        if let Ok(line) = line_rx.recv_timeout(Duration::from_millis(250)) {
            print!("{line}");
        }
    }

    Ok(())
}

/// Spawn a thread that periodically (every 200 ms) reads any new lines
/// appended to `path` and sends them down `tx`.
fn spawn_poller(path: PathBuf, tx: Sender<String>) -> Result<()> {
    thread::spawn(move || -> Result<()> {
        // 1) Open the file for reading and seek to EOF so we only see "future" lines.
        let file = File::open(&path).context("failed to open log file for reading")?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::End(0))?;

        // 2) Loop forever, sleeping between polls.
        loop {
            // Read any newly‐appended lines
            let mut buf = String::new();
            while reader.read_line(&mut buf)? != 0 {
                let _ = tx.send(buf.clone()); // ignore send errors on shutdown
                buf.clear();
            }

            // Sleep before checking again
            thread::sleep(Duration::from_millis(200));
        }
    });

    Ok(())
}
