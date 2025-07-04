//! Syscall classification into operations and resource types

use crate::model::{Operation, ResourceType, SyscallCategory, SyscallOperation};
use std::path::PathBuf;

/// Enhanced syscall classification result with human-readable descriptions
#[derive(Debug, Clone)]
pub struct SyscallClassification {
    pub category: SyscallCategory,
    pub operation: SyscallOperation,
    pub legacy_operation: Operation,
    pub resource_type: Option<ResourceType>,
    pub human_description: String,
    pub security_relevant: bool,
}

/// Enhanced syscall classification with comprehensive coverage
pub fn classify_syscall_enhanced(syscall_name: &str, fd: Option<&i32>, abs_path: Option<&String>, retval: i64) -> SyscallClassification {
    match syscall_name {
        // File System Operations - Read Operations
        "read" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileRead,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::File),
            human_description: format!("Read {} bytes from file", retval.max(0)),
            security_relevant: false,
        },
        "pread64" | "preadv" | "preadv2" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileRead,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::File),
            human_description: format!("Positioned read {} bytes from file", retval.max(0)),
            security_relevant: false,
        },
        "readv" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileRead,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::File),
            human_description: format!("Vectored read {} bytes from file", retval.max(0)),
            security_relevant: false,
        },
        "readlink" | "readlinkat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileRead,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::File),
            human_description: "Read symbolic link target".to_string(),
            security_relevant: false,
        },
        
        // File System Operations - Write Operations
        "write" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileWrite,
            legacy_operation: Operation::Write,
            resource_type: Some(ResourceType::File),
            human_description: format!("Write {} bytes to file", retval.max(0)),
            security_relevant: false,
        },
        "pwrite64" | "pwritev" | "pwritev2" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileWrite,
            legacy_operation: Operation::Write,
            resource_type: Some(ResourceType::File),
            human_description: format!("Positioned write {} bytes to file", retval.max(0)),
            security_relevant: false,
        },
        "writev" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileWrite,
            legacy_operation: Operation::Write,
            resource_type: Some(ResourceType::File),
            human_description: format!("Vectored write {} bytes to file", retval.max(0)),
            security_relevant: false,
        },
        
        // File System Operations - File Management
        "open" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileOpen,
            legacy_operation: Operation::Open,
            resource_type: Some(ResourceType::File),
            human_description: "Open file".to_string(),
            security_relevant: false,
        },
        "openat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileOpen,
            legacy_operation: Operation::Open,
            resource_type: classify_resource_type(syscall_name, fd, abs_path),
            human_description: format!("Open file{}", 
                abs_path.map(|p| format!(" {}", p)).unwrap_or_default()),
            security_relevant: abs_path.map(|p| is_sensitive_path(p)).unwrap_or(false),
        },
        "creat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileCreate,
            legacy_operation: Operation::Open,
            resource_type: Some(ResourceType::File),
            human_description: "Create new file".to_string(),
            security_relevant: false,
        },
        "close" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileClose,
            legacy_operation: Operation::Close,
            resource_type: Some(ResourceType::File),
            human_description: "Close file descriptor".to_string(),
            security_relevant: false,
        },
        "unlink" | "unlinkat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileDelete,
            legacy_operation: Operation::Close,
            resource_type: Some(ResourceType::File),
            human_description: "Delete file".to_string(),
            security_relevant: true,
        },
        "rename" | "renameat" | "renameat2" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileRename,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Rename/move file".to_string(),
            security_relevant: false,
        },
        "link" | "linkat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileLink,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Create hard link".to_string(),
            security_relevant: false,
        },
        "symlink" | "symlinkat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileLink,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Create symbolic link".to_string(),
            security_relevant: false,
        },
        
        // File System Operations - File Information
        "stat" | "lstat" | "fstat" | "newfstatat" | "statx" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileStat,
            legacy_operation: Operation::Stat,
            resource_type: classify_resource_type(syscall_name, fd, abs_path),
            human_description: "Get file information".to_string(),
            security_relevant: abs_path.map(|p| is_sensitive_path(p)).unwrap_or(false),
        },
        "access" | "faccessat" | "faccessat2" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileStat,
            legacy_operation: Operation::Stat,
            resource_type: classify_resource_type(syscall_name, fd, abs_path),
            human_description: "Check file access permissions".to_string(),
            security_relevant: abs_path.map(|p| is_sensitive_path(p)).unwrap_or(false),
        },
        "chmod" | "fchmod" | "fchmodat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileChmod,
            legacy_operation: Operation::Chmod,
            resource_type: Some(ResourceType::File),
            human_description: "Change file permissions".to_string(),
            security_relevant: true,
        },
        "chown" | "fchown" | "lchown" | "fchownat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileChown,
            legacy_operation: Operation::Chown,
            resource_type: Some(ResourceType::File),
            human_description: "Change file ownership".to_string(),
            security_relevant: true,
        },
        "lseek" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileSeek,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Seek file position".to_string(),
            security_relevant: false,
        },
        "fsync" | "fdatasync" | "sync" | "syncfs" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileSync,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Synchronize file data to storage".to_string(),
            security_relevant: false,
        },
        "dup" | "dup2" | "dup3" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileDuplicate,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Duplicate file descriptor".to_string(),
            security_relevant: false,
        },
        "flock" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileLock,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Apply file lock".to_string(),
            security_relevant: false,
        },
        "truncate" | "ftruncate" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileTruncate,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "Truncate file to specified length".to_string(),
            security_relevant: false,
        },
        "getxattr" | "lgetxattr" | "fgetxattr" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileAttributeRead,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::File),
            human_description: "Read extended file attributes".to_string(),
            security_relevant: false,
        },
        "setxattr" | "lsetxattr" | "fsetxattr" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileAttributeWrite,
            legacy_operation: Operation::Write,
            resource_type: Some(ResourceType::File),
            human_description: "Write extended file attributes".to_string(),
            security_relevant: false,
        },
        "listxattr" | "llistxattr" | "flistxattr" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileAttributeRead,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::File),
            human_description: "List extended file attributes".to_string(),
            security_relevant: false,
        },
        "removexattr" | "lremovexattr" | "fremovexattr" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileAttributeWrite,
            legacy_operation: Operation::Write,
            resource_type: Some(ResourceType::File),
            human_description: "Remove extended file attributes".to_string(),
            security_relevant: false,
        },
        
        // Directory Operations
        "getdents64" | "getdents" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::DirectoryRead,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::Directory),
            human_description: format!("Read {} directory entries", retval.max(0) / 20), // Rough estimate
            security_relevant: false,
        },
        "mkdir" | "mkdirat" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::DirectoryCreate,
            legacy_operation: Operation::Open,
            resource_type: Some(ResourceType::Directory),
            human_description: "Create directory".to_string(),
            security_relevant: false,
        },
        "rmdir" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::DirectoryDelete,
            legacy_operation: Operation::Close,
            resource_type: Some(ResourceType::Directory),
            human_description: "Remove directory".to_string(),
            security_relevant: true,
        },
        "chdir" | "fchdir" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::DirectoryChange,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::Directory),
            human_description: "Change current directory".to_string(),
            security_relevant: false,
        },
        "getcwd" => SyscallClassification {
            category: SyscallCategory::SystemInformation,
            operation: SyscallOperation::SystemInfo,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::Directory),
            human_description: "Get current working directory".to_string(),
            security_relevant: false,
        },
        
        // Process Control Operations
        "fork" | "vfork" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessCreate,
            legacy_operation: Operation::Fork,
            resource_type: None,
            human_description: format!("Create new process (child PID: {})", 
                if retval > 0 { retval.to_string() } else { "failed".to_string() }),
            security_relevant: true,
        },
        "clone" | "clone3" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessCreate,
            legacy_operation: Operation::Fork,
            resource_type: None,
            human_description: "Create new process/thread".to_string(),
            security_relevant: true,
        },
        "execve" | "execveat" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessExecute,
            legacy_operation: Operation::Execute,
            resource_type: None,
            human_description: format!("Execute program{}", 
                abs_path.map(|p| format!(" {}", p)).unwrap_or_default()),
            security_relevant: true,
        },
        "exit" | "exit_group" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessTerminate,
            legacy_operation: Operation::Close,
            resource_type: None,
            human_description: format!("Exit process (code: {})", retval),
            security_relevant: false,
        },
        "wait4" | "waitpid" | "waitid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessWait,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Wait for child process".to_string(),
            security_relevant: false,
        },
        "getpid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessGetId,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: format!("Get process ID ({})", retval),
            security_relevant: false,
        },
        "getppid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessGetId,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: format!("Get parent process ID ({})", retval),
            security_relevant: false,
        },
        "gettid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessGetId,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: format!("Get thread ID ({})", retval),
            security_relevant: false,
        },
        "getuid" | "geteuid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessGetId,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: format!("Get user ID ({})", retval),
            security_relevant: false,
        },
        "getgid" | "getegid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessGetId,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: format!("Get group ID ({})", retval),
            security_relevant: false,
        },
        "setuid" | "seteuid" => SyscallClassification {
            category: SyscallCategory::SecurityManagement,
            operation: SyscallOperation::SecuritySetUid,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Change user ID".to_string(),
            security_relevant: true,
        },
        "setgid" | "setegid" => SyscallClassification {
            category: SyscallCategory::SecurityManagement,
            operation: SyscallOperation::SecuritySetGid,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Change group ID".to_string(),
            security_relevant: true,
        },
        "kill" | "tkill" | "tgkill" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessSignal,
            legacy_operation: Operation::Signal,
            resource_type: None,
            human_description: "Send signal to process".to_string(),
            security_relevant: true,
        },
        "getpriority" | "setpriority" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessPriority,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get/set process priority".to_string(),
            security_relevant: false,
        },
        "sched_setaffinity" | "sched_getaffinity" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessAffinity,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get/set CPU affinity".to_string(),
            security_relevant: false,
        },
        "setpgid" | "getpgid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessGroup,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get/set process group ID".to_string(),
            security_relevant: false,
        },
        "setsid" | "getsid" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessSession,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get/set session ID".to_string(),
            security_relevant: false,
        },
        
        // Memory Management Operations
        "mmap" | "mmap2" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemoryMap,
            legacy_operation: Operation::Mmap,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Map memory region".to_string(),
            security_relevant: false,
        },
        "munmap" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemoryUnmap,
            legacy_operation: Operation::Munmap,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Unmap memory region".to_string(),
            security_relevant: false,
        },
        "mprotect" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemoryProtect,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Change memory protection".to_string(),
            security_relevant: true,
        },
        "madvise" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemoryAdvise,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Give advice about memory usage".to_string(),
            security_relevant: false,
        },
        "mlock" | "mlock2" | "mlockall" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemoryLock,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Lock memory pages".to_string(),
            security_relevant: false,
        },
        "munlock" | "munlockall" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemoryUnlock,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Unlock memory pages".to_string(),
            security_relevant: false,
        },
        "msync" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemorySync,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Synchronize memory with storage".to_string(),
            security_relevant: false,
        },
        "brk" => SyscallClassification {
            category: SyscallCategory::MemoryManagement,
            operation: SyscallOperation::MemoryAllocate,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Change data segment size".to_string(),
            security_relevant: false,
        },
        
        // Network Operations
        "socket" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkSocketCreate,
            legacy_operation: Operation::Open,
            resource_type: Some(ResourceType::Socket),
            human_description: "Create network socket".to_string(),
            security_relevant: false,
        },
        "connect" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkConnect,
            legacy_operation: Operation::Connect,
            resource_type: Some(ResourceType::Socket),
            human_description: "Connect to remote address".to_string(),
            security_relevant: true,
        },
        "bind" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkBind,
            legacy_operation: Operation::Bind,
            resource_type: Some(ResourceType::Socket),
            human_description: "Bind socket to address".to_string(),
            security_relevant: true,
        },
        "listen" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkListen,
            legacy_operation: Operation::Bind,
            resource_type: Some(ResourceType::Socket),
            human_description: "Listen for connections".to_string(),
            security_relevant: true,
        },
        "accept" | "accept4" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkAccept,
            legacy_operation: Operation::Accept,
            resource_type: Some(ResourceType::Socket),
            human_description: "Accept incoming connection".to_string(),
            security_relevant: true,
        },
        "send" | "sendto" | "sendmsg" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkSend,
            legacy_operation: Operation::Write,
            resource_type: Some(ResourceType::Socket),
            human_description: format!("Send {} bytes over network", retval.max(0)),
            security_relevant: true,
        },
        "recv" | "recvfrom" | "recvmsg" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkReceive,
            legacy_operation: Operation::Read,
            resource_type: Some(ResourceType::Socket),
            human_description: format!("Receive {} bytes from network", retval.max(0)),
            security_relevant: true,
        },
        "shutdown" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkShutdown,
            legacy_operation: Operation::Close,
            resource_type: Some(ResourceType::Socket),
            human_description: "Shutdown socket connection".to_string(),
            security_relevant: false,
        },
        "getsockopt" | "setsockopt" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkSocketOption,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::Socket),
            human_description: "Get/set socket options".to_string(),
            security_relevant: false,
        },
        "getsockname" | "getpeername" => SyscallClassification {
            category: SyscallCategory::NetworkCommunication,
            operation: SyscallOperation::NetworkSocketOption,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::Socket),
            human_description: "Get socket address information".to_string(),
            security_relevant: false,
        },
        
        // IPC Operations
        "pipe" | "pipe2" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCPipeCreate,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::Pipe),
            human_description: "Create pipe for IPC".to_string(),
            security_relevant: false,
        },
        "mkfifo" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCFifoCreate,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::Pipe),
            human_description: "Create named pipe (FIFO)".to_string(),
            security_relevant: false,
        },
        "shmget" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCShmCreate,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Create/get shared memory segment".to_string(),
            security_relevant: false,
        },
        "shmat" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCShmAttach,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Attach shared memory segment".to_string(),
            security_relevant: false,
        },
        "shmdt" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCShmDetach,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Detach shared memory segment".to_string(),
            security_relevant: false,
        },
        "shmctl" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCShmControl,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::SharedMemory),
            human_description: "Control shared memory segment".to_string(),
            security_relevant: false,
        },
        "msgget" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCMsgCreate,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Create/get message queue".to_string(),
            security_relevant: false,
        },
        "msgsnd" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCMsgSend,
            legacy_operation: Operation::Write,
            resource_type: None,
            human_description: "Send message to queue".to_string(),
            security_relevant: false,
        },
        "msgrcv" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCMsgReceive,
            legacy_operation: Operation::Read,
            resource_type: None,
            human_description: "Receive message from queue".to_string(),
            security_relevant: false,
        },
        "msgctl" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCMsgControl,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Control message queue".to_string(),
            security_relevant: false,
        },
        "semget" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCSemCreate,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Create/get semaphore set".to_string(),
            security_relevant: false,
        },
        "semop" | "semtimedop" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCSemOperate,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Operate on semaphore set".to_string(),
            security_relevant: false,
        },
        "semctl" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCSemControl,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Control semaphore set".to_string(),
            security_relevant: false,
        },
        "eventfd" | "eventfd2" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCEventFd,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Create event file descriptor".to_string(),
            security_relevant: false,
        },
        "signalfd" | "signalfd4" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCSignalFd,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Create signal file descriptor".to_string(),
            security_relevant: false,
        },
        
        // System Information
        "uname" => SyscallClassification {
            category: SyscallCategory::SystemInformation,
            operation: SyscallOperation::SystemUname,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get system information".to_string(),
            security_relevant: false,
        },
        "sysinfo" => SyscallClassification {
            category: SyscallCategory::SystemInformation,
            operation: SyscallOperation::SystemSysinfo,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get system statistics".to_string(),
            security_relevant: false,
        },
        "gethostname" | "sethostname" => SyscallClassification {
            category: SyscallCategory::SystemInformation,
            operation: SyscallOperation::SystemHostname,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get/set hostname".to_string(),
            security_relevant: false,
        },
        "getrlimit" | "prlimit64" => SyscallClassification {
            category: SyscallCategory::SystemInformation,
            operation: SyscallOperation::SystemGetResourceLimit,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get resource limits".to_string(),
            security_relevant: false,
        },
        "setrlimit" => SyscallClassification {
            category: SyscallCategory::SystemInformation,
            operation: SyscallOperation::SystemSetResourceLimit,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Set resource limits".to_string(),
            security_relevant: true,
        },
        "getrusage" => SyscallClassification {
            category: SyscallCategory::SystemInformation,
            operation: SyscallOperation::SystemGetResourceUsage,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get resource usage statistics".to_string(),
            security_relevant: false,
        },
        
        // Time Management
        "time" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeGet,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get current time".to_string(),
            security_relevant: false,
        },
        "gettimeofday" | "clock_gettime" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeGet,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get current time with high precision".to_string(),
            security_relevant: false,
        },
        "settimeofday" | "clock_settime" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeSet,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Set system time".to_string(),
            security_relevant: true,
        },
        "nanosleep" | "clock_nanosleep" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeSleep,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Sleep for specified time".to_string(),
            security_relevant: false,
        },
        "alarm" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeAlarm,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Set alarm signal".to_string(),
            security_relevant: false,
        },
        "timer_create" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeTimerCreate,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Create POSIX timer".to_string(),
            security_relevant: false,
        },
        "timer_delete" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeTimerDelete,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Delete POSIX timer".to_string(),
            security_relevant: false,
        },
        "timer_settime" | "timer_gettime" => SyscallClassification {
            category: SyscallCategory::TimeManagement,
            operation: SyscallOperation::TimeTimerSet,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Set/get POSIX timer".to_string(),
            security_relevant: false,
        },
        
        // Device Management
        "ioctl" => SyscallClassification {
            category: SyscallCategory::DeviceManagement,
            operation: SyscallOperation::DeviceIoctl,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::DevFs),
            human_description: "Device I/O control operation".to_string(),
            security_relevant: true,
        },
        "poll" | "ppoll" => SyscallClassification {
            category: SyscallCategory::DeviceManagement,
            operation: SyscallOperation::DevicePoll,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Wait for events on file descriptors".to_string(),
            security_relevant: false,
        },
        "select" | "pselect6" => SyscallClassification {
            category: SyscallCategory::DeviceManagement,
            operation: SyscallOperation::DeviceSelect,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Synchronous I/O multiplexing".to_string(),
            security_relevant: false,
        },
        "epoll_create" | "epoll_create1" => SyscallClassification {
            category: SyscallCategory::DeviceManagement,
            operation: SyscallOperation::DeviceEpoll,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Create epoll instance".to_string(),
            security_relevant: false,
        },
        "epoll_ctl" => SyscallClassification {
            category: SyscallCategory::DeviceManagement,
            operation: SyscallOperation::DeviceEpoll,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Control epoll instance".to_string(),
            security_relevant: false,
        },
        "epoll_wait" | "epoll_pwait" => SyscallClassification {
            category: SyscallCategory::DeviceManagement,
            operation: SyscallOperation::DeviceEpoll,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Wait for epoll events".to_string(),
            security_relevant: false,
        },
        
        // Security Management
        "capget" | "capset" => SyscallClassification {
            category: SyscallCategory::SecurityManagement,
            operation: SyscallOperation::SecurityCapability,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Get/set process capabilities".to_string(),
            security_relevant: true,
        },
        "chroot" => SyscallClassification {
            category: SyscallCategory::SecurityManagement,
            operation: SyscallOperation::SecurityChroot,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Change root directory".to_string(),
            security_relevant: true,
        },
        "ptrace" => SyscallClassification {
            category: SyscallCategory::SecurityManagement,
            operation: SyscallOperation::SecurityPtrace,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Process trace and debug".to_string(),
            security_relevant: true,
        },
        "prctl" => SyscallClassification {
            category: SyscallCategory::SecurityManagement,
            operation: SyscallOperation::SecuritySeccomp,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Process control operations".to_string(),
            security_relevant: true,
        },
        "seccomp" => SyscallClassification {
            category: SyscallCategory::SecurityManagement,
            operation: SyscallOperation::SecuritySeccomp,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Configure seccomp filter".to_string(),
            security_relevant: true,
        },
        
        // Thread synchronization (common background noise)
        "futex" => SyscallClassification {
            category: SyscallCategory::InterProcessCommunication,
            operation: SyscallOperation::IPCSemOperate,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: "Fast userspace mutex operation".to_string(),
            security_relevant: false,
        },
        
        // Signal handling
        "rt_sigaction" | "sigaction" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessSignal,
            legacy_operation: Operation::Signal,
            resource_type: None,
            human_description: "Set signal handler".to_string(),
            security_relevant: false,
        },
        "rt_sigprocmask" | "sigprocmask" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessSignal,
            legacy_operation: Operation::Signal,
            resource_type: None,
            human_description: "Change signal mask".to_string(),
            security_relevant: false,
        },
        "rt_sigpending" | "sigpending" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessSignal,
            legacy_operation: Operation::Signal,
            resource_type: None,
            human_description: "Get pending signals".to_string(),
            security_relevant: false,
        },
        "rt_sigsuspend" | "sigsuspend" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessSignal,
            legacy_operation: Operation::Signal,
            resource_type: None,
            human_description: "Wait for signal".to_string(),
            security_relevant: false,
        },
        "rt_sigreturn" | "sigreturn" => SyscallClassification {
            category: SyscallCategory::ProcessControl,
            operation: SyscallOperation::ProcessSignal,
            legacy_operation: Operation::Signal,
            resource_type: None,
            human_description: "Return from signal handler".to_string(),
            security_relevant: false,
        },
        
        // File control operations
        "fcntl" => SyscallClassification {
            category: SyscallCategory::FileSystem,
            operation: SyscallOperation::FileLock,
            legacy_operation: Operation::Other,
            resource_type: Some(ResourceType::File),
            human_description: "File control operation".to_string(),
            security_relevant: false,
        },
        
        // Default fallback for unclassified syscalls
        _ => SyscallClassification {
            category: SyscallCategory::Unknown,
            operation: SyscallOperation::Other,
            legacy_operation: Operation::Other,
            resource_type: None,
            human_description: format!("Unclassified syscall: {}", syscall_name),
            security_relevant: false,
        },
    }
}

/// Legacy function for backward compatibility
pub fn classify_syscall(syscall_name: &str, fd: Option<&i32>, abs_path: Option<&String>) -> (Option<Operation>, Option<ResourceType>) {
    let classification = classify_syscall_enhanced(syscall_name, fd, abs_path, 0);
    (Some(classification.legacy_operation), classification.resource_type)
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

/// Check if a file path is security-sensitive
fn is_sensitive_path(path: &str) -> bool {
    // System configuration and security files
    if path.starts_with("/etc/") {
        return matches!(path, 
            "/etc/passwd" | "/etc/shadow" | "/etc/group" | "/etc/gshadow" |
            "/etc/sudoers" | "/etc/hosts" | "/etc/ssh/" | "/etc/ssl/" |
            "/etc/pam.d/" | "/etc/security/" | "/etc/cron.d/" |
            "/etc/systemd/" | "/etc/init.d/"
        ) || path.contains("passwd") || path.contains("shadow") || path.contains("ssh");
    }
    
    // User home directory sensitive files
    if path.contains("/.ssh/") || path.contains("/.gnupg/") || 
       path.contains(".aws/credentials") || path.contains(".config/gcloud/") ||
       path.ends_with(".pem") || path.ends_with(".key") || path.ends_with(".p12") {
        return true;
    }
    
    // Process and system information
    if path.starts_with("/proc/") {
        return path.contains("/proc/self/mem") || path.contains("/proc/") && path.contains("/mem") ||
               path.contains("/proc/") && path.contains("/maps") ||
               path.contains("/proc/") && path.contains("/environ");
    }
    
    // System directories
    path.starts_with("/sys/") || path.starts_with("/dev/mem") || path.starts_with("/dev/kmem")
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