//! Semantic argument parsing - extracting file descriptors, paths, permissions, etc.

/// Semantic data extracted from syscall arguments
#[derive(Debug, Clone)]
pub struct SemanticData {
    pub fd: Option<i32>,
    pub abs_path: Option<String>,
    pub perm_bits: Option<u32>,
    pub byte_count: Option<u64>,
}

/// Parse semantic arguments from syscall
pub fn parse_syscall_semantics(syscall_name: &str, line: &str, args: &[u64; 6]) -> SemanticData {
    let args_section = match extract_args_section(line) {
        Some(section) => section,
        None => return SemanticData { fd: None, abs_path: None, perm_bits: None, byte_count: None },
    };
    
    match syscall_name {
        // File descriptor syscalls with path arguments
        "openat" | "newfstatat" | "readlinkat" | "linkat" | "symlinkat" | "unlinkat" | "mkdirat" => {
            SemanticData {
                fd: extract_fd_from_strace_text(line),
                abs_path: extract_first_string_arg(&args_section),
                perm_bits: if syscall_name == "openat" { extract_mode_arg(&args_section) } else { None },
                byte_count: None,
            }
        },
        
        // File operations with FD and byte counts
        "read" | "write" | "pread64" | "pwrite64" => {
            SemanticData {
                fd: extract_fd_from_strace_text(line),
                abs_path: None,
                perm_bits: None,
                byte_count: extract_third_numeric_arg(&args_section),
            }
        },
        
        // File operations with byte counts but no FD
        "readv" | "writev" => {
            SemanticData {
                fd: if args[0] <= i32::MAX as u64 { Some(args[0] as i32) } else { None },
                abs_path: None,
                perm_bits: None,
                byte_count: if args.len() > 2 { Some(args[2]) } else { None },
            }
        },
        
        // Permission change syscalls
        "chmod" | "fchmod" | "fchmodat" => {
            SemanticData {
                fd: if syscall_name.starts_with("fchmod") { extract_fd_from_args(args) } else { None },
                abs_path: if syscall_name == "chmod" { extract_first_string_arg(&args_section) } else { None },
                perm_bits: extract_mode_arg(&args_section),
                byte_count: None,
            }
        },
        
        // Directory operations
        "getdents64" | "getdents" => {
            SemanticData {
                fd: extract_fd_from_strace_text(line),
                abs_path: None,
                perm_bits: None,
                byte_count: extract_last_numeric_arg(&args_section),
            }
        },
        
        // Socket operations
        "socket" | "bind" | "connect" | "accept" | "listen" | "recv" | "send" | "recvfrom" | "sendto" => {
            SemanticData {
                fd: extract_fd_from_strace_text(line),
                abs_path: None,
                perm_bits: None,
                byte_count: match syscall_name {
                    "recv" | "send" | "recvfrom" | "sendto" => extract_third_numeric_arg(&args_section),
                    _ => None,
                },
            }
        },
        
        // Memory mapping
        "mmap" | "munmap" => {
            SemanticData {
                fd: None,
                abs_path: None,
                perm_bits: None,
                byte_count: if args.len() > 1 { Some(args[1]) } else { None },
            }
        },
        
        // Default: try to extract FD from first arg
        _ => {
            SemanticData {
                fd: extract_fd_from_strace_text(line),
                abs_path: None,
                perm_bits: None,
                byte_count: None,
            }
        }
    }
}

/// Extract file descriptor from arguments
fn extract_fd_from_args(args: &[u64; 6]) -> Option<i32> {
    let first_arg = args[0];
    
    if first_arg == (-100i64) as u64 {
        return Some(-100); // AT_FDCWD
    }
    
    if first_arg <= 65535 {
        Some(first_arg as i32)
    } else {
        None
    }
}

/// Extract the first string argument from strace arguments section
fn extract_first_string_arg(args_section: &str) -> Option<String> {
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
                chars.next();
            },
            _ => {}
        }
    }
    
    None
}

/// Extract mode/permission bits from arguments
fn extract_mode_arg(args_section: &str) -> Option<u32> {
    for token in args_section.split(&[',', ' ', '\t']) {
        let token = token.trim();
        
        if token.starts_with("0") && token.len() >= 3 && token.len() <= 5 {
            if let Ok(mode) = u32::from_str_radix(&token[1..], 8) {
                if mode <= 0o7777 {
                    return Some(mode);
                }
            }
        }
    }
    
    None
}

/// Extract file descriptor from strace text
fn extract_fd_from_strace_text(line: &str) -> Option<i32> {
    if let Some(paren_pos) = line.find('(') {
        if let Some(args_end) = line.rfind(" = ") {
            let args_section = &line[paren_pos + 1..args_end];
            
            if args_section.starts_with("AT_FDCWD") {
                return Some(-100);
            }
            
            if let Some(angle_pos) = args_section.find('<') {
                let before_angle = &args_section[..angle_pos];
                if let Ok(fd) = before_angle.trim().parse::<i32>() {
                    return Some(fd);
                }
            }
            
            let first_token = args_section.split(&[',', ' ', '\t']).next().unwrap_or("").trim();
            if let Ok(fd) = first_token.parse::<i32>() {
                if fd >= -100 && fd <= 65535 {
                    return Some(fd);
                }
            }
        }
    }
    
    None
}

/// Extract the last numeric argument from args section
fn extract_last_numeric_arg(args_section: &str) -> Option<u64> {
    let tokens: Vec<&str> = args_section.split(',').collect();
    
    for token in tokens.iter().rev() {
        let clean_token = token.trim().split_whitespace().next().unwrap_or("");
        if let Ok(val) = clean_token.parse::<u64>() {
            return Some(val);
        }
    }
    
    None
}

/// Extract the third numeric argument from args section
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

/// Extract the arguments section from a strace line
fn extract_args_section(line: &str) -> Option<String> {
    let paren_start = line.find('(')?;
    let equals_pos = line.rfind(" = ")?;
    
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