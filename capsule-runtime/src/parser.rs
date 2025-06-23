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
    
    // Extract all strace data - enhanced parsing
    let (timestamp, pid, tid, syscall_name, args, retval) = extract_strace_data(clean_line)?;
    
    unsafe {
        if DEBUG_COUNT <= 10 {
            eprintln!("DEBUG: Extracted: ts={}, pid={}, tid={:?}, call={}, retval={}", 
                     timestamp, pid, tid, syscall_name, retval);
        }
    }
    
    Some(SyscallEvent {
        ts: (timestamp * 1_000_000.0) as u64,
        pid,
        call: syscall_name,
        args,
        retval,
        raw_line: line.to_string(),
        
        // Initialize all new fields as None/empty
        tid,
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

/// Extract timestamp, PID, syscall name, args, and retval from strace line
fn extract_strace_data(line: &str) -> Option<(f64, u32, Option<u32>, String, [u64; 6], i64)> {
    let original_line = line;
    
    // Extract PID and TID from [pid NNNN] or [pid NNNN TTTT] prefix
    let (pid, tid, line_after_pid) = if line.starts_with('[') {
        let bracket_end = line.find(']')?;
        let pid_section = &line[1..bracket_end]; // Remove [ and ]
        let line_remainder = line[bracket_end + 1..].trim_start();
        
        if pid_section.starts_with("pid") {
            let pid_parts: Vec<&str> = pid_section.split_whitespace().collect();
            if pid_parts.len() >= 2 {
                let pid = pid_parts[1].parse::<u32>().ok()?;
                let tid = if pid_parts.len() >= 3 {
                    pid_parts[2].parse::<u32>().ok()
                } else {
                    None
                };
                (pid, tid, line_remainder)
            } else {
                return None;
            }
        } else {
            return None;
        }
    } else {
        // No PID prefix, assume PID 0
        (0, None, line)
    };
    
    // Extract timestamp (first token after PID)
    let space_pos = line_after_pid.find(' ')?;
    let timestamp_str = &line_after_pid[..space_pos];
    let remainder = &line_after_pid[space_pos + 1..];
    let timestamp = parse_strace_timestamp(timestamp_str)?;
    
    // Handle resumed syscalls like "<... fstat resumed>"
    let (syscall_name, args_section) = if remainder.starts_with("<...") {
        // Extract syscall name from "<... syscall_name resumed>"
        let parts: Vec<&str> = remainder.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "resumed>" {
            let syscall = parts[1].to_string();
            // For resumed calls, we can't easily parse args, so return zeros
            return Some((timestamp, pid, tid, syscall, [0; 6], 0));
        } else {
            return None;
        }
    } else {
        // Normal syscall: extract name and arguments
        let paren_pos = remainder.find('(')?;
        let syscall_name = remainder[..paren_pos].trim().to_string();
        
        // Find the closing parenthesis for args
        let equals_pos = remainder.rfind(" = ")?;
        let args_section = &remainder[paren_pos + 1..equals_pos];
        
        (syscall_name, args_section)
    };
    
    if syscall_name.is_empty() {
        return None;
    }
    
    // Parse return value (everything after " = ")
    let equals_pos = remainder.rfind(" = ")?;
    let retval_section = &remainder[equals_pos + 3..];
    let retval = parse_return_value(retval_section);
    
    // Parse arguments (simplified - extract up to 6 numeric values)
    let args = parse_syscall_args(args_section);
    
    Some((timestamp, pid, tid, syscall_name, args, retval))
}

/// Parse return value from strace output (handles -1 ERRNO cases)
fn parse_return_value(retval_str: &str) -> i64 {
    // Handle cases like "0", "-1 EINVAL (Invalid argument)", "1024"
    let first_token = retval_str.split_whitespace().next().unwrap_or("0");
    first_token.parse::<i64>().unwrap_or(0)
}

/// Parse syscall arguments (simplified extraction of numeric values)
fn parse_syscall_args(args_str: &str) -> [u64; 6] {
    let mut args = [0u64; 6];
    let mut arg_count = 0;
    
    // Split by commas and try to extract numeric values
    for arg in args_str.split(',') {
        if arg_count >= 6 {
            break;
        }
        
        let arg = arg.trim();
        
        // Try to parse different numeric formats
        if let Some(val) = parse_numeric_arg(arg) {
            args[arg_count] = val;
        }
        
        arg_count += 1;
    }
    
    args
}

/// Parse individual numeric argument (handles hex, decimal, constants)
fn parse_numeric_arg(arg: &str) -> Option<u64> {
    let arg = arg.trim();
    
    // Handle hex values like 0xffffffff
    if arg.starts_with("0x") {
        return u64::from_str_radix(&arg[2..], 16).ok();
    }
    
    // Handle negative numbers
    if arg.starts_with('-') {
        if let Ok(val) = arg.parse::<i64>() {
            return Some(val as u64);
        }
    }
    
    // Handle positive decimal
    if let Ok(val) = arg.parse::<u64>() {
        return Some(val);
    }
    
    // Handle special constants (simplified)
    match arg {
        "AT_FDCWD" => Some((-100i64) as u64),
        "NULL" => Some(0),
        _ => None,
    }
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
