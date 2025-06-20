//! Simple file-follower for syscalls / events / actions.

use crate::constants::*;
use anyhow::{Result, Context};
use std::{
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
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

/// Live trace of active capsule runs with auto-discovery and reconnection.
pub fn trace_live(stream: &str) -> Result<()> {
    println!("Starting live trace for {} stream...", stream);
    
    loop {
        match find_active_run()? {
            Some(run_dir) => {
                let run_uuid = run_dir.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                println!("📡 Tracing {} from active run: {}", stream, run_uuid);
                
                if let Err(e) = tail_with_monitoring(stream, &run_dir) {
                    eprintln!("⚠️  Lost connection: {}. Searching for new runs...", e);
                    thread::sleep(Duration::from_millis(500));
                }
            }
            None => {
                println!("⏳ No active capsule runs found. Waiting for new runs...");
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// Find the most active run (with running process) or fallback to newest.
pub fn find_active_run() -> Result<Option<PathBuf>> {
    let mut active_runs = Vec::new();
    let mut all_runs = Vec::new();
    
    for entry in std::fs::read_dir(&*RUN_ROOT)? {
        let entry = entry?;
        let run_dir = entry.path();
        
        if is_process_active(&run_dir)? {
            active_runs.push(run_dir.clone());
        }
        
        // Collect all runs for fallback
        if let Ok(md) = entry.metadata() {
            if let Ok(ts) = md.created().or_else(|_| md.modified()) {
                all_runs.push((run_dir, ts));
            }
        }
    }
    
    // Return most recent active run
    if !active_runs.is_empty() {
        active_runs.sort_by_key(|path| {
            std::fs::metadata(path)
                .and_then(|md| md.created().or_else(|_| md.modified()))
                .unwrap_or(std::time::UNIX_EPOCH)
        });
        return Ok(active_runs.into_iter().last());
    }
    
    // Fallback to newest run if no active processes
    all_runs.sort_by_key(|(_, ts)| *ts);
    Ok(all_runs.into_iter().last().map(|(path, _)| path))
}

/// Check if the process associated with a run directory is still active.
fn is_process_active(run_dir: &Path) -> Result<bool> {
    let pid_file = run_dir.join(PID_FILE);
    if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            return Ok(process_exists(pid));
        }
    }
    Ok(false)
}

/// Check if a process with the given PID exists.
fn process_exists(pid: i32) -> bool {
    use std::process::Command;
    
    // Use `kill -0` to check if process exists without actually sending a signal
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Tail a file while monitoring the associated process.
fn tail_with_monitoring(stream: &str, run_dir: &Path) -> Result<()> {
    let log_dir = read_log_dir_from_run(run_dir)?;
    let filename = match stream {
        "syscalls" => SYSCALL_FILE,
        "events" => EVENT_FILE,
        "actions" => ACTION_FILE,
        _ => anyhow::bail!("unknown stream {}", stream),
    };
    let file_path = log_dir.join(filename);
    
    let mut file = File::open(&file_path)?;
    let mut reader = BufReader::new(&mut file);
    let mut last_pos = 0u64;
    
    loop {
        // Check if process is still active
        if !is_process_active(run_dir)? {
            println!("🔴 Process ended for this run.");
            return Err(anyhow::anyhow!("Process no longer active"));
        }
        
        // Read new lines
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data, wait and continue
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Ok(n) => {
                print!("{}", line);
                last_pos += n as u64;
                line.clear();
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Read error: {}", e));
            }
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
