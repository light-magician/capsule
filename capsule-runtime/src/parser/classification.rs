//! Syscall classification into operations and resource types

use crate::model::{Operation, ResourceType};
use std::path::PathBuf;

/// Classify syscall into operation type and resource type
pub fn classify_syscall(syscall_name: &str, fd: Option<&i32>, abs_path: Option<&String>) -> (Option<Operation>, Option<ResourceType>) {
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
        "getdents64" | "getdents" | "readdir" => Some(Operation::Read),
        "mkdir" | "mkdirat" => Some(Operation::Open),
        "rmdir" | "unlink" | "unlinkat" => Some(Operation::Close),
        
        // Network operations
        "socket" => Some(Operation::Open),
        "bind" => Some(Operation::Bind),
        "connect" => Some(Operation::Connect),
        "accept" | "accept4" => Some(Operation::Accept),
        "listen" => Some(Operation::Bind),
        "send" | "sendto" | "sendmsg" => Some(Operation::Write),
        "recv" | "recvfrom" | "recvmsg" => Some(Operation::Read),
        
        // Memory operations
        "mmap" | "mmap2" => Some(Operation::Mmap),
        "munmap" => Some(Operation::Munmap),
        
        // Process operations
        "fork" | "vfork" | "clone" => Some(Operation::Fork),
        "execve" | "execveat" => Some(Operation::Execute),
        "exit" | "exit_group" => Some(Operation::Close),
        
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