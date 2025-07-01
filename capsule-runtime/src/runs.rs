//! Run management utilities for listing and finding runs.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use chrono::{DateTime, Utc};

/// Metadata about a Capsule run
#[derive(Debug)]
pub struct RunInfo {
    pub uuid: String,
    pub log_directory: Option<PathBuf>,
    pub created_at: Option<DateTime<Utc>>,
}

impl RunInfo {
    /// Create RunInfo from a run directory
    fn from_run_dir(uuid: String, run_dir: &PathBuf) -> Result<Self> {
        let log_dir_file = run_dir.join(crate::constants::LOG_DIR_FILE);
        let log_directory = if log_dir_file.exists() {
            let log_path = fs::read_to_string(&log_dir_file)
                .with_context(|| format!("read log directory file {:?}", log_dir_file))?;
            Some(PathBuf::from(log_path.trim()))
        } else {
            None
        };

        // Try to get creation time from the log directory name if available
        let created_at = if let Some(ref log_dir) = log_directory {
            parse_timestamp_from_log_dir(log_dir)
        } else {
            // Fallback to filesystem metadata
            run_dir.metadata()
                .ok()
                .and_then(|meta| meta.created().ok())
                .and_then(|sys_time| DateTime::from_timestamp(
                    sys_time.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64, 0
                ))
        };

        Ok(RunInfo {
            uuid,
            log_directory,
            created_at,
        })
    }
}

/// Parse timestamp from log directory name format: YYYYMMDDTHHMMSSZ-uuid
fn parse_timestamp_from_log_dir(log_dir: &PathBuf) -> Option<DateTime<Utc>> {
    let dir_name = log_dir.file_name()?.to_str()?;
    let timestamp_part = dir_name.split('-').next()?;
    
    // Parse format: YYYYMMDDTHHMMSSZ
    if timestamp_part.len() == 16 && timestamp_part.ends_with('Z') {
        let timestamp_str = &timestamp_part[..15]; // Remove 'Z'
        DateTime::parse_from_str(&format!("{}Z", timestamp_str), "%Y%m%dT%H%M%S%Z")
            .ok()?
            .with_timezone(&Utc)
            .into()
    } else {
        None
    }
}

/// Get all runs sorted by creation time (most recent first)
pub fn list_runs(limit: Option<usize>) -> Result<Vec<RunInfo>> {
    let run_root = &crate::constants::RUN_ROOT;
    
    if !run_root.exists() {
        return Ok(Vec::new());
    }

    let mut runs = Vec::new();
    
    // Read all run directories
    for entry in fs::read_dir(run_root)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_dir() {
            if let Some(uuid) = path.file_name().and_then(|n| n.to_str()) {
                match RunInfo::from_run_dir(uuid.to_string(), &path) {
                    Ok(run_info) => runs.push(run_info),
                    Err(_) => continue, // Skip invalid runs
                }
            }
        }
    }
    
    // Sort by creation time (most recent first)
    runs.sort_by(|a, b| {
        match (a.created_at, b.created_at) {
            (Some(a_time), Some(b_time)) => b_time.cmp(&a_time),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.uuid.cmp(&b.uuid), // Fallback to UUID comparison
        }
    });
    
    // Apply limit if specified
    if let Some(limit) = limit {
        runs.truncate(limit);
    }
    
    Ok(runs)
}

/// Get the most recent run UUID
pub fn get_last_run() -> Result<Option<String>> {
    let runs = list_runs(Some(1))?;
    Ok(runs.into_iter().next().map(|run| run.uuid))
}

/// Print run list in a formatted way
pub fn print_run_list(runs: &[RunInfo]) {
    if runs.is_empty() {
        println!("No runs found.");
        return;
    }

    println!("{:<38} {:<20} {:<50}", "UUID", "CREATED", "LOG DIRECTORY");
    println!("{}", "-".repeat(110));
    
    for run in runs {
        let created_str = run.created_at
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "unknown".to_string());
            
        let log_dir_str = run.log_directory
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
            
        println!("{:<38} {:<20} {:<50}", run.uuid, created_str, log_dir_str);
    }
}

/// Handle the "last" command
pub fn handle_last_command() -> Result<()> {
    match get_last_run()? {
        Some(uuid) => {
            println!("{}", uuid);
            Ok(())
        }
        None => {
            eprintln!("No runs found.");
            std::process::exit(1);
        }
    }
}

/// Handle the "list" command
pub fn handle_list_command(limit: usize) -> Result<()> {
    let runs = list_runs(Some(limit))?;
    print_run_list(&runs);
    Ok(())
}