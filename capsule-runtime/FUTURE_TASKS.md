# Future EnhancedEvent Implementation Tasks

## Task 7: Implement risk_tags and high_level_kind categorization

### Overview
Add heuristic security analysis to flag potentially risky behavior and categorize events for aggregator grouping.

### Implementation Steps

#### 7.1 Add risk_tags logic to parser.rs
Add this function after the network parsing functions:

```rust
/// Analyze syscall for security risk indicators
fn analyze_risk_tags(syscall_name: &str, abs_path: Option<&String>, operation: &Option<Operation>, 
                     resource_type: &Option<ResourceType>, args: &[u64; 6], retval: i64) -> Vec<String> {
    let mut tags = Vec::new();
    
    // Execution risks
    if matches!(operation, Some(Operation::Execute)) {
        tags.push("EXEC".to_string());
        
        if let Some(path) = abs_path {
            if path.starts_with("/tmp/") || path.contains("/tmp/") {
                tags.push("TMP_EXEC".to_string());
            }
            if path.starts_with("/dev/shm/") {
                tags.push("SHM_EXEC".to_string());
            }
            if !path.starts_with("/usr/") && !path.starts_with("/bin/") {
                tags.push("NON_SYSTEM_EXEC".to_string());
            }
        }
    }
    
    // File access risks
    if let Some(path) = abs_path {
        if path.contains("/etc/passwd") || path.contains("/etc/shadow") {
            tags.push("PASSWD_ACCESS".to_string());
        }
        if path.contains("/proc/") && (path.contains("/mem") || path.contains("/maps")) {
            tags.push("PROC_MEM_ACCESS".to_string());
        }
        if path.starts_with("/sys/") && matches!(operation, Some(Operation::Write)) {
            tags.push("SYSFS_WRITE".to_string());
        }
        if path.contains("..") {
            tags.push("PATH_TRAVERSAL".to_string());
        }
    }
    
    // Network risks
    if matches!(resource_type, Some(ResourceType::Socket)) {
        match syscall_name {
            "bind" => {
                // Check for privileged ports (< 1024)
                if args.len() > 1 && args[1] < 1024 {
                    tags.push("PRIV_PORT_BIND".to_string());
                }
            },
            "connect" => tags.push("OUTBOUND_CONNECT".to_string()),
            _ => {}
        }
    }
    
    // Permission escalation risks
    if matches!(syscall_name, "setuid" | "setgid" | "setresuid" | "setresgid") {
        tags.push("PRIV_ESC".to_string());
    }
    
    // Large data operations
    if let Some(Operation::Read | Operation::Write) = operation {
        if args.len() > 2 && args[2] > 1024*1024 { // > 1MB
            tags.push("LARGE_IO".to_string());
        }
    }
    
    // Failed operations (potential probing)
    if retval < 0 {
        match syscall_name {
            "open" | "openat" => tags.push("FAILED_OPEN".to_string()),
            "connect" => tags.push("FAILED_CONNECT".to_string()),
            "stat" | "fstat" | "newfstatat" => tags.push("FAILED_STAT".to_string()),
            _ => {}
        }
    }
    
    tags
}
```

#### 7.2 Add high_level_kind logic
Add this function after risk_tags:

```rust
/// Categorize syscall into high-level behavioral buckets for aggregator
fn categorize_high_level_kind(syscall_name: &str, operation: &Option<Operation>, 
                               resource_type: &Option<ResourceType>) -> Option<String> {
    match (operation, resource_type) {
        // File operations
        (Some(Operation::Read), Some(ResourceType::File)) => Some("FileRead".to_string()),
        (Some(Operation::Write), Some(ResourceType::File)) => Some("FileWrite".to_string()),
        (Some(Operation::Open), Some(ResourceType::File)) => Some("FileOpen".to_string()),
        (Some(Operation::Stat), Some(ResourceType::File)) => Some("FileMetadata".to_string()),
        (Some(Operation::Chmod | Operation::Chown), Some(ResourceType::File)) => Some("FilePermissions".to_string()),
        
        // Directory operations
        (Some(Operation::Read), Some(ResourceType::Directory)) => Some("DirList".to_string()),
        (Some(Operation::Open), Some(ResourceType::Directory)) => Some("DirCreate".to_string()),
        (Some(Operation::Stat), Some(ResourceType::Directory)) => Some("DirMetadata".to_string()),
        
        // Network operations
        (Some(Operation::Connect), Some(ResourceType::Socket)) => Some("NetConnect".to_string()),
        (Some(Operation::Bind), Some(ResourceType::Socket)) => Some("NetBind".to_string()),
        (Some(Operation::Accept), Some(ResourceType::Socket)) => Some("NetAccept".to_string()),
        (Some(Operation::Read), Some(ResourceType::Socket)) => Some("NetReceive".to_string()),
        (Some(Operation::Write), Some(ResourceType::Socket)) => Some("NetSend".to_string()),
        
        // Process operations
        (Some(Operation::Fork), _) => Some("ProcessSpawn".to_string()),
        (Some(Operation::Execute), _) => Some("ProcessExec".to_string()),
        (Some(Operation::Signal), _) => Some("ProcessSignal".to_string()),
        
        // Memory operations
        (Some(Operation::Mmap), Some(ResourceType::SharedMemory)) => Some("MemoryMap".to_string()),
        (Some(Operation::Munmap), Some(ResourceType::SharedMemory)) => Some("MemoryUnmap".to_string()),
        
        // System file access
        (_, Some(ResourceType::ProcFs)) => Some("ProcFsAccess".to_string()),
        (_, Some(ResourceType::DevFs)) => Some("DeviceAccess".to_string()),
        (_, Some(ResourceType::SysFs)) => Some("SysfsAccess".to_string()),
        
        // Default
        _ => Some("Other".to_string()),
    }
}
```

#### 7.3 Update parse_line function
In the `parse_line` function, after classification logic, add:

```rust
// Analyze security risks and categorize behavior
let risk_tags = analyze_risk_tags(&syscall_name, abs_path.as_ref(), &operation, &resource_type, &args, retval);
let high_level_kind = categorize_high_level_kind(&syscall_name, &operation, &resource_type);
```

Then update the SyscallEvent creation:
```rust
risk_tags,
high_level_kind,
```

### Verification
- Look for events with `"risk_tags":["TMP_EXEC","NON_SYSTEM_EXEC"]` when executing from /tmp
- Check `"high_level_kind":"FileRead"` for read operations on files
- Verify `"risk_tags":["OUTBOUND_CONNECT"]` for network connections

---

## Task 8: Add latency tracking between syscall entry/exit when available

### Overview
Some strace output includes both syscall entry and completion with timing. Parse these to calculate latency.

### Implementation Context
strace can show unfinished syscalls like:
```
[pid 1234] 10:30:15.123456 read(3, <unfinished ...>
[pid 1234] 10:30:15.125789 <... read resumed> "data", 1024) = 4
```

The latency would be 125789 - 123456 = 2333 microseconds.

### Implementation Steps

#### 8.1 Add state tracking for unfinished syscalls
In parser.rs, add a module-level state tracker:

```rust
use std::collections::HashMap;

// Add to top of file
thread_local! {
    static UNFINISHED_SYSCALLS: std::cell::RefCell<HashMap<u32, (String, u64)>> = 
        std::cell::RefCell::new(HashMap::new());
}
```

#### 8.2 Add latency parsing logic
Add this function:

```rust
/// Track unfinished syscalls and calculate latency when resumed
fn calculate_latency(pid: u32, syscall_name: &str, timestamp: u64, line: &str) -> Option<u64> {
    UNFINISHED_SYSCALLS.with(|map| {
        let mut map = map.borrow_mut();
        
        // Check if this is an unfinished syscall
        if line.contains("<unfinished ...>") {
            // Store the start time
            map.insert(pid, (syscall_name.to_string(), timestamp));
            return None;
        }
        
        // Check if this is a resumed syscall
        if line.contains("<... ") && line.contains(" resumed>") {
            if let Some((stored_call, start_time)) = map.remove(&pid) {
                if stored_call == syscall_name {
                    // Calculate latency in microseconds
                    if timestamp > start_time {
                        return Some(timestamp - start_time);
                    }
                }
            }
        }
        
        None
    })
}
```

#### 8.3 Update extract_strace_data function
In the `extract_strace_data` function, after parsing timestamp:

```rust
// Calculate latency for resumed syscalls
let latency = calculate_latency(pid, &syscall_name, (timestamp * 1_000_000.0) as u64, original_line);
```

Update the return tuple:
```rust
Some((timestamp, pid, tid, syscall_name, args, retval, latency))
```

#### 8.4 Update parse_line function
Update the destructuring:
```rust
let (timestamp, pid, tid, syscall_name, args, retval, latency_us) = extract_strace_data(clean_line)?;
```

Update SyscallEvent creation:
```rust
latency_us,
```

### Alternative Simple Approach (Recommended)
If the above state tracking is complex, implement a simpler version:

```rust
/// Simple latency extraction from single-line syscalls with timing info
fn extract_simple_latency(line: &str) -> Option<u64> {
    // Look for patterns like "= 0 <0.000123>" indicating 123 microseconds
    if let Some(timing_start) = line.rfind(" <") {
        if let Some(timing_end) = line[timing_start..].find('>') {
            let timing_section = &line[timing_start + 2..timing_start + timing_end];
            if let Ok(seconds) = timing_section.parse::<f64>() {
                return Some((seconds * 1_000_000.0) as u64);
            }
        }
    }
    None
}
```

### Verification
- Run: `strace -tt -T command` (the -T flag shows timing)
- Look for events with `"latency_us":1234` showing microsecond timing
- Verify latency makes sense (file I/O: 1-1000μs, network: 1000-100000μs)

### Testing Commands
```bash
# Generate syscalls with timing
strace -tt -T -o trace.log ls /usr/bin

# Look for patterns like:
# 10:30:15.123456 openat(AT_FDCWD, "/usr/bin", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3 <0.000045>
```

---

## Notes for Implementation

### Priority Order
1. Implement Task 7 (risk_tags) first - it's more immediately useful for security analysis
2. Implement Task 8 (latency) second - it requires timing-enabled strace which may not always be available

### Integration Points
- Both tasks integrate into the `parse_line` function in parser.rs
- Update the SyscallEvent struct creation with new field values
- Test incrementally - build and verify each piece works before moving to the next

### Future Enhancements
- **Risk tags**: Add ML-based anomaly detection, behavioral baselines
- **Latency**: Add percentile tracking, latency distribution analysis
- **Performance**: Consider moving state tracking to enricher stage if parser becomes too complex