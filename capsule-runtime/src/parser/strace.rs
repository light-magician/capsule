//! Core strace line parsing - extracting timestamp, PID, syscall name, args, retval

/// Raw strace data extracted from a single line
#[derive(Debug, Clone)]
pub struct StraceData {
    pub timestamp: f64,
    pub pid: u32,
    pub tid: Option<u32>,
    pub syscall_name: String,
    pub args: [u64; 6],
    pub retval: i64,
}

/// Parse a complete strace line into structured data
pub fn parse_strace_line(line: &str) -> Option<StraceData> {
    let (timestamp, pid, tid, syscall_name, args, retval) = extract_strace_data(line)?;
    
    Some(StraceData {
        timestamp,
        pid,
        tid,
        syscall_name,
        args,
        retval,
    })
}

/// Extract timestamp, PID, syscall name, args, and retval from strace line
fn extract_strace_data(line: &str) -> Option<(f64, u32, Option<u32>, String, [u64; 6], i64)> {
    // Extract PID and TID from [pid NNNN] or [pid NNNN TTTT] prefix
    let (pid, tid, line_after_pid) = if line.starts_with('[') {
        let bracket_end = line.find(']')?;
        let pid_section = &line[1..bracket_end];
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
        (0, None, line)
    };
    
    // Extract timestamp (first token after PID)
    let space_pos = line_after_pid.find(' ')?;
    let timestamp_str = &line_after_pid[..space_pos];
    let remainder = &line_after_pid[space_pos + 1..];
    let timestamp = parse_strace_timestamp(timestamp_str)?;
    
    // Handle resumed syscalls like "<... fstat resumed>"
    let (syscall_name, args_section) = if remainder.starts_with("<...") {
        let parts: Vec<&str> = remainder.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "resumed>" {
            let syscall = parts[1].to_string();
            return Some((timestamp, pid, tid, syscall, [0; 6], 0));
        } else {
            return None;
        }
    } else {
        // Normal syscall: extract name and arguments
        let paren_pos = remainder.find('(')?;
        let syscall_name = remainder[..paren_pos].trim().to_string();
        
        let equals_pos = remainder.rfind(" = ")?;
        let args_section = &remainder[paren_pos + 1..equals_pos];
        
        (syscall_name, args_section)
    };
    
    if syscall_name.is_empty() {
        return None;
    }
    
    // Parse return value
    let equals_pos = remainder.rfind(" = ")?;
    let retval_section = &remainder[equals_pos + 3..];
    let retval = parse_return_value(retval_section);
    
    // Parse arguments
    let args = parse_syscall_args(args_section);
    
    Some((timestamp, pid, tid, syscall_name, args, retval))
}

/// Parse strace timestamp format: HH:MM:SS.microseconds -> seconds as f64
fn parse_strace_timestamp(ts_str: &str) -> Option<f64> {
    let parts: Vec<&str> = ts_str.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    
    let hours: f64 = parts[0].parse().ok()?;
    let minutes: f64 = parts[1].parse().ok()?;
    
    let sec_parts: Vec<&str> = parts[2].split('.').collect();
    if sec_parts.len() != 2 {
        return None;
    }
    
    let seconds: f64 = sec_parts[0].parse().ok()?;
    let microseconds: f64 = sec_parts[1].parse().ok()?;
    
    let total_seconds = hours * 3600.0 + minutes * 60.0 + seconds + (microseconds / 1_000_000.0);
    Some(total_seconds)
}

/// Parse return value from strace output (handles -1 ERRNO cases)
fn parse_return_value(retval_str: &str) -> i64 {
    let first_token = retval_str.split_whitespace().next().unwrap_or("0");
    first_token.parse::<i64>().unwrap_or(0)
}

/// Parse syscall arguments (simplified extraction of numeric values)
fn parse_syscall_args(args_str: &str) -> [u64; 6] {
    let mut args = [0u64; 6];
    let mut arg_count = 0;
    
    for arg in args_str.split(',') {
        if arg_count >= 6 {
            break;
        }
        
        if let Some(val) = parse_numeric_arg(arg.trim()) {
            args[arg_count] = val;
        }
        
        arg_count += 1;
    }
    
    args
}

/// Parse individual numeric argument (handles hex, decimal, constants)
fn parse_numeric_arg(arg: &str) -> Option<u64> {
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
    
    // Handle special constants
    match arg {
        "AT_FDCWD" => Some((-100i64) as u64),
        "NULL" => Some(0),
        _ => None,
    }
}