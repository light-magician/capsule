use crate::model::SyscallEvent;
use anyhow::Result;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

/// Public entry: consumes raw strace lines, emits typed events.
///
/// * `rx`  – cloned receiver from the raw-syscall broadcast bus
/// * `tx_evt` – sender on the event bus
pub async fn run(mut rx: Receiver<String>, tx_evt: Sender<SyscallEvent>) -> Result<()> {
    run_with_cancellation(rx, tx_evt, CancellationToken::new()).await
}

/// Parser with cancellation support
pub async fn run_with_cancellation(
    mut rx: Receiver<String>,
    tx_evt: Sender<SyscallEvent>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    let mut line_count = 0;
    let mut event_count = 0;
    let mut parse_error_count = 0;
    
    // Create parse error log file
    let error_log = create_parse_error_log().await?;
    
    loop {
        tokio::select! {
            recv_result = rx.recv() => {
                match recv_result {
                    Ok(line) => {
                        line_count += 1;
                        if line_count % 100 == 0 {
                            eprintln!("DEBUG: Parser received {} lines, produced {} events", line_count, event_count);
                        }
                        
                        match parse_line(&line) {
                            Some(evt) => {
                                event_count += 1;
                                if event_count <= 5 {
                                    eprintln!("DEBUG: Parser produced event #{}: {} (pid={})", event_count, evt.call, evt.pid);
                                }
                                // Ignore lagged receivers; only producers enforce back-pressure.
                                if let Err(e) = tx_evt.send(evt) {
                                    eprintln!("DEBUG: Failed to send event: {}", e);
                                }
                            },
                            None => {
                                // Log parse failures for analysis
                                if !line.trim().is_empty() && 
                                   !line.contains("strace:") && 
                                   !line.trim_start().starts_with('{') {
                                    parse_error_count += 1;
                                    log_parse_error(&error_log, line_count, &line).await;
                                    
                                    if parse_error_count <= 3 {
                                        eprintln!("DEBUG: Failed to parse line #{}: '{}'", line_count, 
                                                 if line.len() > 100 { &line[..100] } else { &line });
                                    }
                                }
                            }
                        }
                    }
                    // Channel closed → upstream tracer exited; time to shut down.
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        eprintln!("DEBUG: Parser channel closed. Total: {} lines → {} events, {} parse errors", 
                                 line_count, event_count, parse_error_count);
                        break;
                    },
                    // We fell behind the ring buffer; skip and continue.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("DEBUG: Parser lagged {} messages", n);
                        continue;
                    },
                }
            },
            _ = cancellation_token.cancelled() => {
                println!("Parser received cancellation, shutting down...");
                eprintln!("DEBUG: Parser final stats: {} lines → {} events, {} parse errors", 
                         line_count, event_count, parse_error_count);
                break;
            }
        }
    }
    Ok(())
}

pub async fn run_with_ready(mut rx: Receiver<String>, tx_evt: Sender<SyscallEvent>, ready_tx: mpsc::Sender<()>) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run the normal processing loop
    run(rx, tx_evt).await
}

pub async fn run_with_ready_and_cancellation(
    rx: Receiver<String>,
    tx_evt: Sender<SyscallEvent>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Now run with cancellation support
    run_with_cancellation(rx, tx_evt, cancellation_token).await
}

/// Simple, robust parser - extract only timestamp and syscall name
fn parse_line(line: &str) -> Option<SyscallEvent> {
    static mut DEBUG_COUNT: u32 = 0;
    
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    
    // Skip pure strace info messages
    if line.starts_with("strace:") {
        return None;
    }
    
    // Clean concatenated strace messages
    let clean_line = if let Some(strace_pos) = line.find("strace:") {
        line[..strace_pos].trim_end()
    } else {
        line
    };
    
    // Skip lines without syscall completion marker
    if !clean_line.contains(" = ") {
        return None;
    }
    
    unsafe {
        DEBUG_COUNT += 1;
        if DEBUG_COUNT <= 10 {
            eprintln!("DEBUG: Parsing line #{}: '{}'", DEBUG_COUNT, clean_line);
        }
    }
    
    // Extract timestamp and syscall name - super simple approach
    let (timestamp, syscall_name) = extract_timestamp_and_syscall(clean_line)?;
    
    unsafe {
        if DEBUG_COUNT <= 10 {
            eprintln!("DEBUG: Extracted: ts={}, call={}", timestamp, syscall_name);
        }
    }
    
    Some(SyscallEvent {
        ts: (timestamp * 1_000_000.0) as u64,
        pid: 0, // Simplified - no PID parsing for now
        call: syscall_name,
        args: [0; 6], // Simplified - no arg parsing
        retval: 0, // Simplified - no retval parsing
        raw_line: line.to_string(),
        
        // Initialize all new fields as None/empty
        tid: None,
        ppid: None,
        exe_path: None,
        cwd: None,
        uid: None,
        gid: None,
        euid: None,
        egid: None,
        caps: None,
        fd: None,
        abs_path: None,
        resource_type: None,
        operation: None,
        perm_bits: None,
        byte_count: None,
        latency_us: None,
        net: None,
        risk_tags: Vec::new(),
        high_level_kind: None,
        
        // Legacy compatibility
        enrichment: None,
    })
}

/// Extract just timestamp and syscall name from strace line
fn extract_timestamp_and_syscall(line: &str) -> Option<(f64, String)> {
    // Skip optional [pid NNN] prefix
    let line = if line.starts_with('[') {
        if let Some(bracket_end) = line.find(']') {
            line[bracket_end + 1..].trim_start()
        } else {
            line
        }
    } else {
        line
    };
    
    // Find first space (end of timestamp)
    let space_pos = line.find(' ')?;
    let timestamp_str = &line[..space_pos];
    let remainder = &line[space_pos + 1..];
    
    // Parse timestamp
    let timestamp = parse_strace_timestamp(timestamp_str)?;
    
    // Extract syscall name (everything before first '(')
    let paren_pos = remainder.find('(')?;
    let syscall_name = remainder[..paren_pos].trim().to_string();
    
    if syscall_name.is_empty() {
        return None;
    }
    
    Some((timestamp, syscall_name))
}



/// Parse strace timestamp format: HH:MM:SS.microseconds -> seconds as f64
fn parse_strace_timestamp(ts_str: &str) -> Option<f64> {
    // Format: "20:10:33.123456"
    let parts: Vec<&str> = ts_str.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    
    let hours: f64 = parts[0].parse().ok()?;
    let minutes: f64 = parts[1].parse().ok()?;
    
    // Handle seconds.microseconds
    let sec_parts: Vec<&str> = parts[2].split('.').collect();
    if sec_parts.len() != 2 {
        return None;
    }
    
    let seconds: f64 = sec_parts[0].parse().ok()?;
    let microseconds: f64 = sec_parts[1].parse().ok()?;
    
    // Convert to total seconds since start of day
    let total_seconds = hours * 3600.0 + minutes * 60.0 + seconds + (microseconds / 1_000_000.0);
    
    Some(total_seconds)
}

/// Create parse error log file
async fn create_parse_error_log() -> Result<Arc<Mutex<tokio::fs::File>>> {
    use crate::constants::LOG_ROOT;
    
    // Create log directory if it doesn't exist
    tokio::fs::create_dir_all(&*LOG_ROOT).await?;
    
    // Create timestamped error log file
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let error_file_path = LOG_ROOT.join(format!("parse_errors_{}.log", timestamp));
    
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&error_file_path)
        .await?;
    
    Ok(Arc::new(Mutex::new(file)))
}

/// Log a parse error to the error log file
async fn log_parse_error(error_log: &Arc<Mutex<tokio::fs::File>>, line_num: u32, line: &str) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let truncated_line = if line.len() > 500 { 
        format!("{}... (truncated from {} chars)", &line[..500], line.len())
    } else { 
        line.to_string() 
    };
    
    let error_entry = format!("{} [Line {}] {}\n", timestamp, line_num, truncated_line);
    
    let mut file = error_log.lock().await;
    let _ = file.write_all(error_entry.as_bytes()).await;
    let _ = file.flush().await;
}
