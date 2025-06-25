use crate::model::{SyscallEvent, Operation, ResourceType, NetworkInfo};
use crate::risk;
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
    
    // Parse semantic arguments for this syscall
    let (fd, abs_path, perm_bits, byte_count) = parse_semantic_args(&syscall_name, clean_line, &args);
    
    // Classify operation and resource type
    let (operation, resource_type) = classify_syscall(&syscall_name, fd.as_ref(), abs_path.as_ref());
    
    // Parse network information for socket syscalls
    let net_info = parse_network_info(&syscall_name, clean_line, &resource_type);
    
    // Analyze security risks and categorize behavior
    let risk_tags = risk::analyze_risk_tags(&syscall_name, abs_path.as_ref(), &operation, &resource_type, &args, retval);
    let high_level_kind = risk::categorize_high_level_kind(&syscall_name, &operation, &resource_type);
    
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
        fd,
        abs_path,
        resource_type,
        operation,
        perm_bits,
        byte_count,
        latency_us: None,
        net: net_info,
        risk_tags,
        high_level_kind,
        
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

/// Parse semantic arguments from syscall to extract fd, paths, permissions, byte counts
fn parse_semantic_args(syscall_name: &str, line: &str, args: &[u64; 6]) -> (Option<i32>, Option<String>, Option<u32>, Option<u64>) {
    // Extract the arguments section from the line
    let args_section = match extract_args_section(line) {
        Some(section) => section,
        None => return (None, None, None, None),
    };
    
    match syscall_name {
        // File descriptor syscalls with path arguments
        "openat" | "newfstatat" | "readlinkat" | "linkat" | "symlinkat" | "unlinkat" | "mkdirat" => {
            let fd = extract_fd_from_strace_text(line);
            let path = extract_first_string_arg(&args_section);
            let perm_bits = if syscall_name == "openat" { extract_mode_arg(&args_section) } else { None };
            (fd, path, perm_bits, None)
        },
        
        // File operations with FD and byte counts
        "read" | "write" | "pread64" | "pwrite64" => {
            let fd = extract_fd_from_strace_text(line);
            let byte_count = extract_third_numeric_arg(&args_section);
            (fd, None, None, byte_count)
        },
        
        // File operations with byte counts but no FD
        "readv" | "writev" => {
            let fd = if args[0] <= i32::MAX as u64 { Some(args[0] as i32) } else { None };
            // For readv/writev, count is in args[2] usually
            let byte_count = if args.len() > 2 { Some(args[2]) } else { None };
            (fd, None, None, byte_count)
        },
        
        // Permission change syscalls
        "chmod" | "fchmod" | "fchmodat" => {
            let fd = if syscall_name.starts_with("fchmod") { extract_fd_from_args(args) } else { None };
            let path = if syscall_name == "chmod" { extract_first_string_arg(&args_section) } else { None };
            let perm_bits = extract_mode_arg(&args_section);
            (fd, path, perm_bits, None)
        },
        
        // Directory operations
        "getdents64" | "getdents" => {
            let fd = extract_fd_from_strace_text(line);
            let byte_count = extract_last_numeric_arg(&args_section);
            (fd, None, None, byte_count)
        },
        
        // Socket operations (basic fd extraction)
        "socket" | "bind" | "connect" | "accept" | "listen" | "recv" | "send" | "recvfrom" | "sendto" => {
            let fd = extract_fd_from_strace_text(line);
            let byte_count = match syscall_name {
                "recv" | "send" | "recvfrom" | "sendto" => extract_third_numeric_arg(&args_section),
                _ => None,
            };
            (fd, None, None, byte_count)
        },
        
        // Memory mapping with byte counts
        "mmap" | "munmap" => {
            let byte_count = if args.len() > 1 { Some(args[1]) } else { None };
            (None, None, None, byte_count)
        },
        
        // Default: try to extract FD from first arg if it looks like one
        _ => {
            let fd = extract_fd_from_strace_text(line);
            (fd, None, None, None)
        }
    }
}

/// Extract file descriptor from arguments (first arg if it's a reasonable FD value)
fn extract_fd_from_args(args: &[u64; 6]) -> Option<i32> {
    let first_arg = args[0];
    
    // Handle special FD constants
    if first_arg == (-100i64) as u64 {
        return Some(-100); // AT_FDCWD
    }
    
    // Regular FDs are small positive integers or 0, 1, 2 for stdin/stdout/stderr
    if first_arg <= 65535 { // Reasonable FD range
        Some(first_arg as i32)
    } else {
        None
    }
}

/// Extract the first string argument from strace arguments section
fn extract_first_string_arg(args_section: &str) -> Option<String> {
    // Look for quoted strings like "/path/to/file"
    let mut in_quotes = false;
    let mut start = None;
    let mut chars = args_section.char_indices();
    
    while let Some((i, ch)) = chars.next() {
        match ch {
            '"' if !in_quotes => {
                in_quotes = true;
                start = Some(i + 1);
            },
            '"' if in_quotes => {
                if let Some(start_pos) = start {
                    return Some(args_section[start_pos..i].to_string());
                }
            },
            '\\' if in_quotes => {
                // Skip escaped character
                chars.next();
            },
            _ => {}
        }
    }
    
    None
}

/// Extract mode/permission bits from arguments (looks for octal numbers)
fn extract_mode_arg(args_section: &str) -> Option<u32> {
    // Look for octal permission patterns like 0644, 0755, etc.
    for token in args_section.split(&[',', ' ', '\t']) {
        let token = token.trim();
        
        // Check for octal format (0xxx)
        if token.starts_with("0") && token.len() >= 3 && token.len() <= 5 {
            if let Ok(mode) = u32::from_str_radix(&token[1..], 8) {
                // Reasonable permission bits range
                if mode <= 0o7777 {
                    return Some(mode);
                }
            }
        }
    }
    
    None
}

/// Extract file descriptor from strace text (handles fd numbers and paths like "6</path>")
fn extract_fd_from_strace_text(line: &str) -> Option<i32> {
    // Look for patterns like "syscall(6</path>" or "syscall(AT_FDCWD"
    if let Some(paren_pos) = line.find('(') {
        if let Some(args_end) = line.rfind(" = ") {
            let args_section = &line[paren_pos + 1..args_end];
            
            // Handle AT_FDCWD constant
            if args_section.starts_with("AT_FDCWD") {
                return Some(-100);
            }
            
            // Look for "number<" pattern (like "6</path>")
            if let Some(angle_pos) = args_section.find('<') {
                let before_angle = &args_section[..angle_pos];
                if let Ok(fd) = before_angle.trim().parse::<i32>() {
                    return Some(fd);
                }
            }
            
            // Look for simple number at start
            let first_token = args_section.split(&[',', ' ', '\t']).next().unwrap_or("").trim();
            if let Ok(fd) = first_token.parse::<i32>() {
                if fd >= -100 && fd <= 65535 { // Reasonable FD range
                    return Some(fd);
                }
            }
        }
    }
    
    None
}

/// Extract the last numeric argument from args section (for buffer sizes, counts)
fn extract_last_numeric_arg(args_section: &str) -> Option<u64> {
    // Split by commas and find the last numeric value
    let tokens: Vec<&str> = args_section.split(',').collect();
    
    for token in tokens.iter().rev() {
        let clean_token = token.trim().split_whitespace().next().unwrap_or("");
        if let Ok(val) = clean_token.parse::<u64>() {
            return Some(val);
        }
    }
    
    None
}

/// Extract the third numeric argument from args section (for byte counts in read/write)
fn extract_third_numeric_arg(args_section: &str) -> Option<u64> {
    let tokens: Vec<&str> = args_section.split(',').collect();
    
    if tokens.len() >= 3 {
        let third_token = tokens[2].trim().split_whitespace().next().unwrap_or("");
        if let Ok(val) = third_token.parse::<u64>() {
            return Some(val);
        }
    }
    
    None
}

/// Classify syscall into operation type and resource type
fn classify_syscall(syscall_name: &str, fd: Option<&i32>, abs_path: Option<&String>) -> (Option<Operation>, Option<ResourceType>) {
    let operation = match syscall_name {
        // File I/O operations
        "read" | "pread64" | "readv" | "preadv" => Some(Operation::Read),
        "write" | "pwrite64" | "writev" | "pwritev" => Some(Operation::Write),
        
        // File operations
        "open" | "openat" | "creat" => Some(Operation::Open),
        "close" => Some(Operation::Close),
        "stat" | "lstat" | "fstat" | "newfstatat" | "statx" => Some(Operation::Stat),
        "chmod" | "fchmod" | "fchmodat" => Some(Operation::Chmod),
        "chown" | "fchown" | "lchown" | "fchownat" => Some(Operation::Chown),
        
        // Directory operations
        "getdents64" | "getdents" | "readdir" => Some(Operation::Read), // Reading directory entries
        "mkdir" | "mkdirat" => Some(Operation::Open), // Creating directory
        "rmdir" | "unlink" | "unlinkat" => Some(Operation::Close), // Removing directory/file
        
        // Network operations
        "socket" => Some(Operation::Open), // Creating socket
        "bind" => Some(Operation::Bind),
        "connect" => Some(Operation::Connect),
        "accept" | "accept4" => Some(Operation::Accept),
        "listen" => Some(Operation::Bind), // Setting up listener
        "send" | "sendto" | "sendmsg" => Some(Operation::Write),
        "recv" | "recvfrom" | "recvmsg" => Some(Operation::Read),
        
        // Memory operations
        "mmap" | "mmap2" => Some(Operation::Mmap),
        "munmap" => Some(Operation::Munmap),
        
        // Process operations
        "fork" | "vfork" | "clone" => Some(Operation::Fork),
        "execve" | "execveat" => Some(Operation::Execute),
        "exit" | "exit_group" => Some(Operation::Close), // Terminating process
        
        // Signal operations  
        "kill" | "tkill" | "tgkill" => Some(Operation::Signal),
        
        // Default for unclassified syscalls
        _ => Some(Operation::Other),
    };
    
    let resource_type = classify_resource_type(syscall_name, fd, abs_path);
    
    (operation, resource_type)
}

/// Classify the resource type based on syscall context
fn classify_resource_type(syscall_name: &str, fd: Option<&i32>, abs_path: Option<&String>) -> Option<ResourceType> {
    // Network syscalls
    if matches!(syscall_name, "socket" | "bind" | "connect" | "accept" | "accept4" | "listen" | 
                              "send" | "sendto" | "sendmsg" | "recv" | "recvfrom" | "recvmsg") {
        return Some(ResourceType::Socket);
    }
    
    // Memory operations
    if matches!(syscall_name, "mmap" | "mmap2" | "munmap" | "mprotect" | "madvise") {
        return Some(ResourceType::SharedMemory);
    }
    
    // Analyze path if available
    if let Some(path) = abs_path {
        return classify_path_resource_type(path);
    }
    
    // Analyze file descriptor context if available
    if let Some(fd_num) = fd {
        return classify_fd_resource_type(*fd_num, syscall_name);
    }
    
    // Directory-specific operations
    if matches!(syscall_name, "getdents64" | "getdents" | "mkdir" | "mkdirat" | "rmdir") {
        return Some(ResourceType::Directory);
    }
    
    // Default for file operations
    if matches!(syscall_name, "read" | "write" | "open" | "openat" | "close" | "stat" | "fstat" | 
                              "chmod" | "chown" | "lseek" | "dup" | "dup2") {
        return Some(ResourceType::File);
    }
    
    None
}

/// Classify resource type based on file path patterns
fn classify_path_resource_type(path: &str) -> Option<ResourceType> {
    if path.starts_with("/proc/") {
        Some(ResourceType::ProcFs)
    } else if path.starts_with("/dev/") {
        Some(ResourceType::DevFs)
    } else if path.starts_with("/sys/") {
        Some(ResourceType::SysFs)
    } else if path.contains("/pipe:") || path.contains("/socket:") {
        if path.contains("/socket:") {
            Some(ResourceType::Socket)
        } else {
            Some(ResourceType::Pipe)
        }
    } else {
        // Check file extension for directory vs file
        if path.ends_with('/') || !path.contains('.') {
            Some(ResourceType::Directory)
        } else {
            Some(ResourceType::File)
        }
    }
}

/// Classify resource type based on file descriptor number and context
fn classify_fd_resource_type(fd_num: i32, syscall_name: &str) -> Option<ResourceType> {
    match fd_num {
        -100 => None, // AT_FDCWD - not a real resource
        0..=2 => Some(ResourceType::File), // stdin/stdout/stderr
        _ => {
            // For higher FDs, use syscall context as hint
            if matches!(syscall_name, "getdents64" | "getdents") {
                Some(ResourceType::Directory)
            } else {
                Some(ResourceType::File) // Default assumption
            }
        }
    }
}

/// Parse network information from socket syscalls
fn parse_network_info(syscall_name: &str, line: &str, resource_type: &Option<ResourceType>) -> Option<NetworkInfo> {
    // Only parse network info for socket resources
    if !matches!(resource_type, Some(ResourceType::Socket)) {
        return None;
    }
    
    match syscall_name {
        "socket" => parse_socket_syscall(line),
        "bind" | "connect" => parse_bind_connect_syscall(line),
        "accept" | "accept4" => parse_accept_syscall(line),
        "send" | "sendto" | "recv" | "recvfrom" => parse_send_recv_syscall(line),
        _ => None,
    }
}

/// Parse socket() syscall to extract protocol family and type
fn parse_socket_syscall(line: &str) -> Option<NetworkInfo> {
    // Example: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
    if let Some(args_start) = line.find("socket(") {
        if let Some(args_end) = line.find(") = ") {
            let args_section = &line[args_start + 7..args_end];
            let parts: Vec<&str> = args_section.split(',').map(|s| s.trim()).collect();
            
            if parts.len() >= 2 {
                let family = parse_address_family(parts[0]);
                let protocol = parse_socket_type_and_protocol(&parts[1..]);
                
                return Some(NetworkInfo {
                    family,
                    protocol,
                    local_addr: None,
                    local_port: None,
                    remote_addr: None,
                    remote_port: None,
                });
            }
        }
    }
    None
}

/// Parse bind() or connect() syscall to extract address information
fn parse_bind_connect_syscall(line: &str) -> Option<NetworkInfo> {
    // Example: connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
    // Example: bind(3, {sa_family=AF_UNIX, sun_path="/tmp/socket"}, 110) = 0
    
    if let Some(sock_start) = line.find('{') {
        if let Some(sock_end) = line.find('}') {
            let socket_info = &line[sock_start + 1..sock_end];
            
            let family = extract_sa_family(socket_info);
            let (addr, port) = extract_address_port(socket_info, &family);
            
            return Some(NetworkInfo {
                family: family.clone(),
                protocol: None, // Protocol info not available in bind/connect
                local_addr: if line.contains("bind(") { addr.clone() } else { None },
                local_port: if line.contains("bind(") { port } else { None },
                remote_addr: if line.contains("connect(") { addr } else { None },
                remote_port: if line.contains("connect(") { port } else { None },
            });
        }
    }
    None
}

/// Parse accept() syscall to extract peer address information
fn parse_accept_syscall(line: &str) -> Option<NetworkInfo> {
    // Example: accept(3, {sa_family=AF_INET, sin_port=htons(12345), sin_addr=inet_addr("127.0.0.1")}, [16]) = 4
    
    if let Some(sock_start) = line.find('{') {
        if let Some(sock_end) = line.find('}') {
            let socket_info = &line[sock_start + 1..sock_end];
            
            let family = extract_sa_family(socket_info);
            let (addr, port) = extract_address_port(socket_info, &family);
            
            return Some(NetworkInfo {
                family,
                protocol: None,
                local_addr: None,
                local_port: None,
                remote_addr: addr,
                remote_port: port,
            });
        }
    }
    None
}

/// Parse send/recv syscalls (limited info available)
fn parse_send_recv_syscall(line: &str) -> Option<NetworkInfo> {
    // For send/recv, we don't get address info in the syscall itself
    // We can only infer it's a socket operation
    Some(NetworkInfo {
        family: "UNKNOWN".to_string(),
        protocol: None,
        local_addr: None,
        local_port: None,
        remote_addr: None,
        remote_port: None,
    })
}

/// Extract address family from strace output
fn parse_address_family(family_str: &str) -> String {
    match family_str.trim() {
        "AF_INET" | "PF_INET" => "AF_INET".to_string(),
        "AF_INET6" | "PF_INET6" => "AF_INET6".to_string(),
        "AF_UNIX" | "AF_LOCAL" | "PF_UNIX" | "PF_LOCAL" => "AF_UNIX".to_string(),
        "AF_NETLINK" | "PF_NETLINK" => "AF_NETLINK".to_string(),
        _ => family_str.trim().to_string(),
    }
}

/// Parse socket type and protocol into a protocol string
fn parse_socket_type_and_protocol(parts: &[&str]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    
    let socket_type = parts[0].trim();
    let protocol = if parts.len() > 1 { parts[1].trim() } else { "" };
    
    match (socket_type, protocol) {
        ("SOCK_STREAM", "IPPROTO_TCP") | ("SOCK_STREAM", _) => Some("TCP".to_string()),
        ("SOCK_DGRAM", "IPPROTO_UDP") | ("SOCK_DGRAM", _) => Some("UDP".to_string()),
        ("SOCK_RAW", _) => Some("RAW".to_string()),
        _ => Some(socket_type.to_string()),
    }
}

/// Extract sa_family from socket address structure
fn extract_sa_family(socket_info: &str) -> String {
    for part in socket_info.split(',') {
        let part = part.trim();
        if part.starts_with("sa_family=") {
            return parse_address_family(&part[10..]);
        }
    }
    "UNKNOWN".to_string()
}

/// Extract IP address and port from socket address structure
fn extract_address_port(socket_info: &str, family: &str) -> (Option<String>, Option<u16>) {
    let mut addr = None;
    let mut port = None;
    
    for part in socket_info.split(',') {
        let part = part.trim();
        
        // Extract port
        if part.starts_with("sin_port=htons(") {
            if let Some(port_end) = part.find(')') {
                let port_str = &part[15..port_end];
                port = port_str.parse::<u16>().ok();
            }
        }
        
        // Extract IPv4 address
        if part.starts_with("sin_addr=inet_addr(\"") {
            if let Some(addr_end) = part.find("\")") {
                addr = Some(part[20..addr_end].to_string());
            }
        }
        
        // Extract IPv6 address (simplified)
        if part.starts_with("sin6_addr=") {
            // IPv6 parsing is more complex, simplified here
            addr = Some("::1".to_string()); // Placeholder
        }
        
        // Extract Unix domain socket path
        if part.starts_with("sun_path=\"") {
            // Find the closing quote after the opening quote
            if let Some(path_end) = part[10..].find('"') {
                addr = Some(part[10..10 + path_end].to_string());
            }
        }
    }
    
    (addr, port)
}

/// Extract the arguments section from a strace line
fn extract_args_section(line: &str) -> Option<String> {
    // Find opening and closing parentheses for the syscall arguments
    let paren_start = line.find('(')?;
    let equals_pos = line.rfind(" = ")?;
    
    // Find the matching closing parenthesis before " = "
    let mut paren_count = 0;
    let mut paren_end = None;
    
    for (i, ch) in line[paren_start..equals_pos].char_indices() {
        match ch {
            '(' => paren_count += 1,
            ')' => {
                paren_count -= 1;
                if paren_count == 0 {
                    paren_end = Some(paren_start + i);
                    break;
                }
            },
            _ => {}
        }
    }
    
    if let Some(end) = paren_end {
        Some(line[paren_start + 1..end].to_string())
    } else {
        None
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
