//! Simple file-follower for syscalls / events / actions.

use crate::constants::*;
use anyhow::{Result, Context};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    thread,
    time::Duration,
};

/// Follow a chosen stream in the given (or newest) run directory.
pub fn tail(stream: &str, run_uuid: Option<String>) -> Result<()> {
    let run_path = match run_uuid {
        Some(uuid) => RUN_ROOT.join(uuid),
        None => newest_run_dir()?,
    };

    // Read the actual log directory from metadata file
    let log_dir = read_log_dir_from_run(&run_path)?;

    let filename = match stream {
        "syscalls" => SYSCALL_FILE,
        "events" => EVENT_FILE,
        "enriched" => ENRICHED_FILE,
        "actions" => ACTION_FILE,
        _ => anyhow::bail!("unknown stream {stream}"),
    };
    let file_path = log_dir.join(filename);
    println!("Tailing {file_path:?}");

    let f = File::open(&file_path)?;
    let mut r = BufReader::new(f);

    loop {
        let mut buf = String::new();
        let n = r.read_line(&mut buf)?;
        if n == 0 {
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        print!("{buf}");
    }
}

/// Read the log directory path from the run directory's metadata file.
fn read_log_dir_from_run(run_path: &std::path::Path) -> Result<std::path::PathBuf> {
    let metadata_path = run_path.join(LOG_DIR_FILE);
    let log_dir_str = std::fs::read_to_string(&metadata_path)
        .with_context(|| format!("read log directory metadata from {:?}", metadata_path))?;
    
    Ok(std::path::PathBuf::from(log_dir_str.trim()))
}

/// Live trace of the most recent run logs.
pub fn trace_live(stream: &str) -> Result<()> {
    println!("Starting live trace for {} stream...", stream);
    
    // Just tail the newest run - since runs are transient, this is the best we can do
    match newest_run_dir() {
        Ok(run_dir) => {
            let run_uuid = run_dir.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            println!("📡 Tracing {} from most recent run: {}", stream, run_uuid);
            tail(stream, Some(run_uuid.to_string()))
        }
        Err(e) => {
            println!("⏳ No capsule runs found: {}", e);
            println!("Run 'capsule run <program>' in another terminal to generate logs.");
            Ok(())
        }
    }
}


/// Locate the most-recent run directory under ~/.capsule/run.
pub fn newest_run_dir() -> Result<std::path::PathBuf> {
    let mut latest = None;
    for entry in std::fs::read_dir(&*RUN_ROOT)? {
        let e = entry?;
        let md = e.metadata()?;
        let ts = md.created().or(md.modified())?;
        if latest.as_ref().map(|(_, t)| ts > *t).unwrap_or(true) {
            latest = Some((e.path(), ts));
        }
    }
    latest
        .map(|(p, _)| p)
        .ok_or_else(|| anyhow::anyhow!("no runs found"))
}
