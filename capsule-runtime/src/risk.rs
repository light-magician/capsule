use crate::model::{Operation, ResourceType};

/// Analyze syscall for security risk indicators
pub fn analyze_risk_tags(
    syscall_name: &str,
    abs_path: Option<&String>,
    operation: &Option<Operation>,
    resource_type: &Option<ResourceType>,
    args: &[u64; 6],
    retval: i64,
) -> Vec<String> {
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
            }
            "connect" => tags.push("OUTBOUND_CONNECT".to_string()),
            _ => {}
        }
    }

    // Permission escalation risks
    if matches!(
        syscall_name,
        "setuid" | "setgid" | "setresuid" | "setresgid"
    ) {
        tags.push("PRIV_ESC".to_string());
    }

    // Large data operations
    if let Some(Operation::Read | Operation::Write) = operation {
        if args.len() > 2 && args[2] > 1024 * 1024 {
            // > 1MB
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

/// Categorize syscall into high-level behavioral buckets for aggregator
pub fn categorize_high_level_kind(
    syscall_name: &str,
    operation: &Option<Operation>,
    resource_type: &Option<ResourceType>,
) -> Option<String> {
    match (operation, resource_type) {
        // File operations
        (Some(Operation::Read), Some(ResourceType::File)) => Some("FileRead".to_string()),
        (Some(Operation::Write), Some(ResourceType::File)) => Some("FileWrite".to_string()),
        (Some(Operation::Open), Some(ResourceType::File)) => Some("FileOpen".to_string()),
        (Some(Operation::Stat), Some(ResourceType::File)) => Some("FileMetadata".to_string()),
        (Some(Operation::Chmod | Operation::Chown), Some(ResourceType::File)) => {
            Some("FilePermissions".to_string())
        }

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
        (Some(Operation::Mmap), Some(ResourceType::SharedMemory)) => {
            Some("MemoryMap".to_string())
        }
        (Some(Operation::Munmap), Some(ResourceType::SharedMemory)) => {
            Some("MemoryUnmap".to_string())
        }

        // System file access
        (_, Some(ResourceType::ProcFs)) => Some("ProcFsAccess".to_string()),
        (_, Some(ResourceType::DevFs)) => Some("DeviceAccess".to_string()),
        (_, Some(ResourceType::SysFs)) => Some("SysfsAccess".to_string()),

        // Default
        _ => Some("Other".to_string()),
    }
}