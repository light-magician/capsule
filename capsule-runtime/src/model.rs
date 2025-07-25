use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Enhanced syscall event - canonical record after enrichment stage
/// Follows EnhancedEvent specification from next-task.md
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    // Core syscall data (Must)
    pub ts: u64,          // microseconds since tracer start
    pub pid: u32,         // Linux PID of calling thread
    pub call: String,     // syscall name
    pub args: [u64; 6],   // raw six argument words
    pub retval: i64,      // return value from strace
    pub raw_line: String, // original strace line for provenance

    // Thread/process context (Should)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>, // thread ID when different from PID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>, // parent PID snapshot

    // Process metadata (Should)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>, // absolute path of /proc/pid/exe
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>, // current working directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>, // command line arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>, // real UID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>, // real GID

    // Security context (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub euid: Option<u32>, // effective UID if different
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egid: Option<u32>, // effective GID if different
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<u64>, // CapEff bitmap (≤ 64 caps)

    // Resource context (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>, // FD number referenced (-1 if none)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abs_path: Option<String>, // resolved absolute path
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub fd_map: HashMap<i32, String>, // fd -> path/socket description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<ResourceType>, // high-level resource kind
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>, // semantic intent

    // Operation details (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perm_bits: Option<u32>, // octal mode from openat, chmod, etc
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<u64>, // size requested/transferred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<u64>, // Δ between entry/exit when captured

    // Network context (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<NetworkInfo>, // populated for socket syscalls

    // Risk analysis (May)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub risk_tags: Vec<String>, // heuristic flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_level_kind: Option<String>, // bucket used by Aggregator

    // Enhanced classification (New)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_category: Option<SyscallCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_operation: Option<SyscallOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_description: Option<String>, // "Read 1.2KB from Python source file"

    // Forensic tracking fields (Wave 1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_forensics: Option<ProcessForensics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_forensics: Option<FileForensics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_forensics: Option<NetworkForensics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_forensics: Option<MemoryForensics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_forensics: Option<SecurityForensics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_forensics: Option<SignalForensics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_forensics: Option<EnvironmentForensics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_analysis: Option<PermissionAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forensic_summary: Option<String>, // Comprehensive human-readable forensic description
}

/// Resource type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    #[serde(rename = "FILE")]
    File,
    #[serde(rename = "DIR")]
    Directory,
    #[serde(rename = "SOCKET")]
    Socket,
    #[serde(rename = "PIPE")]
    Pipe,
    #[serde(rename = "SHM")]
    SharedMemory,
    #[serde(rename = "PROCFS")]
    ProcFs,
    #[serde(rename = "DEVFS")]
    DevFs,
    #[serde(rename = "SYSFS")]
    SysFs,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

/// High-level syscall categories for better classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SyscallCategory {
    #[serde(rename = "FILE_SYSTEM")]
    FileSystem,
    #[serde(rename = "PROCESS_CONTROL")]
    ProcessControl,
    #[serde(rename = "MEMORY_MANAGEMENT")]
    MemoryManagement,
    #[serde(rename = "NETWORK_COMMUNICATION")]
    NetworkCommunication,
    #[serde(rename = "INTER_PROCESS_COMMUNICATION")]
    InterProcessCommunication,
    #[serde(rename = "SYSTEM_INFORMATION")]
    SystemInformation,
    #[serde(rename = "DEVICE_MANAGEMENT")]
    DeviceManagement,
    #[serde(rename = "SECURITY_MANAGEMENT")]
    SecurityManagement,
    #[serde(rename = "TIME_MANAGEMENT")]
    TimeManagement,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

/// Detailed operation classification with human descriptions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SyscallOperation {
    // File System Operations
    #[serde(rename = "FILE_READ")]
    FileRead,
    #[serde(rename = "FILE_WRITE")]
    FileWrite,
    #[serde(rename = "FILE_OPEN")]
    FileOpen,
    #[serde(rename = "FILE_CLOSE")]
    FileClose,
    #[serde(rename = "FILE_CREATE")]
    FileCreate,
    #[serde(rename = "FILE_DELETE")]
    FileDelete,
    #[serde(rename = "FILE_STAT")]
    FileStat,
    #[serde(rename = "FILE_CHMOD")]
    FileChmod,
    #[serde(rename = "FILE_CHOWN")]
    FileChown,
    #[serde(rename = "FILE_SEEK")]
    FileSeek,
    #[serde(rename = "FILE_SYNC")]
    FileSync,
    #[serde(rename = "FILE_DUPLICATE")]
    FileDuplicate,
    #[serde(rename = "FILE_LOCK")]
    FileLock,
    #[serde(rename = "FILE_TRUNCATE")]
    FileTruncate,
    #[serde(rename = "FILE_RENAME")]
    FileRename,
    #[serde(rename = "FILE_LINK")]
    FileLink,
    #[serde(rename = "DIR_READ")]
    DirectoryRead,
    #[serde(rename = "DIR_CREATE")]
    DirectoryCreate,
    #[serde(rename = "DIR_DELETE")]
    DirectoryDelete,
    #[serde(rename = "DIR_CHANGE")]
    DirectoryChange,
    #[serde(rename = "FILE_ATTR_READ")]
    FileAttributeRead,
    #[serde(rename = "FILE_ATTR_WRITE")]
    FileAttributeWrite,

    // Process Control Operations
    #[serde(rename = "PROCESS_CREATE")]
    ProcessCreate,
    #[serde(rename = "PROCESS_EXECUTE")]
    ProcessExecute,
    #[serde(rename = "PROCESS_TERMINATE")]
    ProcessTerminate,
    #[serde(rename = "PROCESS_WAIT")]
    ProcessWait,
    #[serde(rename = "PROCESS_SIGNAL")]
    ProcessSignal,
    #[serde(rename = "PROCESS_QUERY")]
    ProcessQuery,
    #[serde(rename = "PROCESS_PRIORITY")]
    ProcessPriority,
    #[serde(rename = "PROCESS_AFFINITY")]
    ProcessAffinity,
    #[serde(rename = "PROCESS_SETID")]
    ProcessSetId,
    #[serde(rename = "PROCESS_GETID")]
    ProcessGetId,
    #[serde(rename = "PROCESS_GROUP")]
    ProcessGroup,
    #[serde(rename = "PROCESS_SESSION")]
    ProcessSession,

    // Memory Management Operations
    #[serde(rename = "MEMORY_ALLOCATE")]
    MemoryAllocate,
    #[serde(rename = "MEMORY_FREE")]
    MemoryFree,
    #[serde(rename = "MEMORY_MAP")]
    MemoryMap,
    #[serde(rename = "MEMORY_UNMAP")]
    MemoryUnmap,
    #[serde(rename = "MEMORY_PROTECT")]
    MemoryProtect,
    #[serde(rename = "MEMORY_ADVISE")]
    MemoryAdvise,
    #[serde(rename = "MEMORY_LOCK")]
    MemoryLock,
    #[serde(rename = "MEMORY_UNLOCK")]
    MemoryUnlock,
    #[serde(rename = "MEMORY_SYNC")]
    MemorySync,

    // Network Operations
    #[serde(rename = "NETWORK_SOCKET_CREATE")]
    NetworkSocketCreate,
    #[serde(rename = "NETWORK_CONNECT")]
    NetworkConnect,
    #[serde(rename = "NETWORK_BIND")]
    NetworkBind,
    #[serde(rename = "NETWORK_LISTEN")]
    NetworkListen,
    #[serde(rename = "NETWORK_ACCEPT")]
    NetworkAccept,
    #[serde(rename = "NETWORK_SEND")]
    NetworkSend,
    #[serde(rename = "NETWORK_RECEIVE")]
    NetworkReceive,
    #[serde(rename = "NETWORK_SHUTDOWN")]
    NetworkShutdown,
    #[serde(rename = "NETWORK_SOCKOPT")]
    NetworkSocketOption,

    // IPC Operations
    #[serde(rename = "IPC_PIPE_CREATE")]
    IPCPipeCreate,
    #[serde(rename = "IPC_FIFO_CREATE")]
    IPCFifoCreate,
    #[serde(rename = "IPC_SHM_CREATE")]
    IPCShmCreate,
    #[serde(rename = "IPC_SHM_ATTACH")]
    IPCShmAttach,
    #[serde(rename = "IPC_SHM_DETACH")]
    IPCShmDetach,
    #[serde(rename = "IPC_SHM_CONTROL")]
    IPCShmControl,
    #[serde(rename = "IPC_MSG_CREATE")]
    IPCMsgCreate,
    #[serde(rename = "IPC_MSG_SEND")]
    IPCMsgSend,
    #[serde(rename = "IPC_MSG_RECEIVE")]
    IPCMsgReceive,
    #[serde(rename = "IPC_MSG_CONTROL")]
    IPCMsgControl,
    #[serde(rename = "IPC_SEM_CREATE")]
    IPCSemCreate,
    #[serde(rename = "IPC_SEM_OPERATE")]
    IPCSemOperate,
    #[serde(rename = "IPC_SEM_CONTROL")]
    IPCSemControl,
    #[serde(rename = "IPC_EVENTFD")]
    IPCEventFd,
    #[serde(rename = "IPC_SIGNALFD")]
    IPCSignalFd,

    // System Information
    #[serde(rename = "SYSTEM_INFO")]
    SystemInfo,
    #[serde(rename = "SYSTEM_HOSTNAME")]
    SystemHostname,
    #[serde(rename = "SYSTEM_UNAME")]
    SystemUname,
    #[serde(rename = "SYSTEM_SYSINFO")]
    SystemSysinfo,
    #[serde(rename = "SYSTEM_GETRLIMIT")]
    SystemGetResourceLimit,
    #[serde(rename = "SYSTEM_SETRLIMIT")]
    SystemSetResourceLimit,
    #[serde(rename = "SYSTEM_GETRUSAGE")]
    SystemGetResourceUsage,

    // Time Management
    #[serde(rename = "TIME_GET")]
    TimeGet,
    #[serde(rename = "TIME_SET")]
    TimeSet,
    #[serde(rename = "TIME_SLEEP")]
    TimeSleep,
    #[serde(rename = "TIME_ALARM")]
    TimeAlarm,
    #[serde(rename = "TIME_TIMER_CREATE")]
    TimeTimerCreate,
    #[serde(rename = "TIME_TIMER_DELETE")]
    TimeTimerDelete,
    #[serde(rename = "TIME_TIMER_SET")]
    TimeTimerSet,

    // Device Management
    #[serde(rename = "DEVICE_IOCTL")]
    DeviceIoctl,
    #[serde(rename = "DEVICE_POLL")]
    DevicePoll,
    #[serde(rename = "DEVICE_SELECT")]
    DeviceSelect,
    #[serde(rename = "DEVICE_EPOLL")]
    DeviceEpoll,

    // Security Management
    #[serde(rename = "SECURITY_SETUID")]
    SecuritySetUid,
    #[serde(rename = "SECURITY_SETGID")]
    SecuritySetGid,
    #[serde(rename = "SECURITY_CAPABILITY")]
    SecurityCapability,
    #[serde(rename = "SECURITY_CHROOT")]
    SecurityChroot,
    #[serde(rename = "SECURITY_PTRACE")]
    SecurityPtrace,
    #[serde(rename = "SECURITY_SECCOMP")]
    SecuritySeccomp,

    // Catch-all
    #[serde(rename = "OTHER")]
    Other,
}

/// Legacy Operation enum for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    #[serde(rename = "READ")]
    Read,
    #[serde(rename = "WRITE")]
    Write,
    #[serde(rename = "EXEC")]
    Execute,
    #[serde(rename = "CONNECT")]
    Connect,
    #[serde(rename = "BIND")]
    Bind,
    #[serde(rename = "ACCEPT")]
    Accept,
    #[serde(rename = "STAT")]
    Stat,
    #[serde(rename = "OPEN")]
    Open,
    #[serde(rename = "CLOSE")]
    Close,
    #[serde(rename = "CHMOD")]
    Chmod,
    #[serde(rename = "CHOWN")]
    Chown,
    #[serde(rename = "MMAP")]
    Mmap,
    #[serde(rename = "MUNMAP")]
    Munmap,
    #[serde(rename = "FORK")]
    Fork,
    #[serde(rename = "SIGNAL")]
    Signal,
    #[serde(rename = "OTHER")]
    Other,
}

/// Network information for socket syscalls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub family: String, // "AF_INET"|"AF_INET6"|"AF_UNIX"|"AF_NETLINK"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>, // "TCP"|"UDP"|...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<String>, // "127.0.0.1"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>, // 8000
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>, // "1.2.3.4"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>, // 443
}

/// Legacy ProcessContext for backward compatibility during transition
/// TODO: Remove once enricher is updated to populate SyscallEvent directly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub exe_path: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub argv: Option<Vec<String>>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    pub ppid: Option<u32>,
    pub fd_map: HashMap<i32, String>, // fd -> path/socket description
    pub capabilities: Option<String>,
    pub namespaces: HashMap<String, String>, // namespace type -> id
}

/// High-level semantic action emitted by the aggregator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub first_ts: u64,
    pub last_ts: u64,
    pub pids: SmallVec<[u32; 4]>,
    pub kind: ActionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionKind {
    FileRead {
        path: PathBuf,
        bytes: usize,
    },
    FileWrite {
        path: PathBuf,
        bytes: usize,
    },
    DirectoryList {
        path: PathBuf,
        entries: usize,
    },
    SocketConnect {
        addr: SocketAddr,
        protocol: String,
    },
    SocketBind {
        addr: SocketAddr,
        protocol: String,
    },
    SocketAccept {
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    ProcessSpawn {
        pid: u32,
        argv: Vec<String>,
        parent_pid: u32,
    },
    ProcessExec {
        argv: Vec<String>,
    },
    ProcessExit {
        pid: u32,
        exit_code: i32,
    },
    SignalSend {
        target_pid: u32,
        signal: i32,
    },
    SignalReceive {
        signal: i32,
    },
    MemoryMap {
        addr: u64,
        size: usize,
        prot: String,
    },
    MemoryUnmap {
        addr: u64,
        size: usize,
    },
    FileOpen {
        path: PathBuf,
        flags: String,
    },
    FileClose {
        path: PathBuf,
    },
    FileStat {
        path: PathBuf,
    },
    FileChmod {
        path: PathBuf,
        mode: u32,
    },
    FileChown {
        path: PathBuf,
        uid: u32,
        gid: u32,
    },
    Other {
        syscall: String,
        describe: String,
    },
}

// ============================================================================
// FORENSIC TRACKING DATA STRUCTURES
// ============================================================================

/// Process genealogy and session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessForensics {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,                      // Process group ID from getpgid()
    pub sid: u32,                       // Session ID from getsid()
    pub ancestry: Vec<ProcessAncestor>, // Full process tree
    pub spawn_time: u64,
    pub is_daemon: bool, // Detached from terminal
    pub thread_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub command: String,
    pub start_time: u64,
}

/// File system forensics with detailed tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileForensics {
    pub fd: i32,
    pub absolute_path: String,
    pub open_flags: OpenFlags,
    pub permission_mode: Option<u32>,
    pub file_type: FileType,
    pub inode: Option<u64>,
    pub device: Option<u64>,
    pub size_at_open: Option<u64>,
    pub size_at_close: Option<u64>,
    pub modification_time: Option<u64>,
    pub access_time: Option<u64>,
    pub creation_time: Option<u64>,
    pub was_created: bool, // File didn't exist before open
    pub was_deleted: bool, // File was unlinked during session
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub exclusive: bool,
    pub truncate: bool,
    pub append: bool,
    pub nonblock: bool,
    pub sync: bool,
    pub raw_flags: u32,
    pub human_description: String, // "Read-write, create if missing, fail if exists"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileType {
    Regular,
    Directory,
    SymbolicLink,
    Socket,
    Pipe,
    CharacterDevice,
    BlockDevice,
    Unknown,
}

/// Network forensics with comprehensive tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkForensics {
    pub socket_fd: i32,
    pub family: SocketFamily,
    pub socket_type: SocketType,
    pub protocol: Protocol,
    pub local_address: SocketAddress,
    pub remote_address: Option<SocketAddress>,
    pub socket_state: SocketState,
    pub dns_resolution: Option<DnsInfo>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_time: Option<u64>,
    pub close_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SocketFamily {
    Inet,    // AF_INET
    Inet6,   // AF_INET6
    Unix,    // AF_UNIX
    Netlink, // AF_NETLINK
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SocketType {
    Stream,    // SOCK_STREAM (TCP)
    Dgram,     // SOCK_DGRAM (UDP)
    Raw,       // SOCK_RAW
    SeqPacket, // SOCK_SEQPACKET
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unix,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketAddress {
    pub address: String,   // IP address or socket path
    pub port: Option<u16>, // Port for IP sockets
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SocketState {
    Created,
    Bound,
    Listening,
    Connecting,
    Connected,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub hostname: Option<String>,
    pub resolved_ips: Vec<String>,
    pub resolution_time: u64,
}

/// Memory and IPC forensics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryForensics {
    pub operation_type: MemoryOperation,
    pub address: Option<u64>,
    pub size: Option<usize>,
    pub protection: Option<MemoryProtection>,
    pub mapping_type: Option<MappingType>, // File-backed, anonymous, shared
    pub shared_memory_key: Option<u32>,    // For SysV shared memory
    pub pipe_info: Option<PipeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MemoryOperation {
    Map,
    Unmap,
    Protect,
    Lock,
    Unlock,
    Sync,
    ShmCreate,
    ShmAttach,
    ShmDetach,
    PipeCreate,
    FifoCreate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub raw_prot: u32,
    pub human_description: String, // "Read-write, no execute"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MappingType {
    Anonymous,  // No backing file
    FileBacked, // Backed by a file
    Shared,     // Shared between processes
    Private,    // Copy-on-write
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeInfo {
    pub pipe_type: PipeType, // Anonymous, Named (FIFO)
    pub read_fd: Option<i32>,
    pub write_fd: Option<i32>,
    pub path: Option<String>, // For named pipes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PipeType {
    Anonymous, // Created with pipe()
    Named,     // FIFO created with mkfifo
}

/// Security context forensics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityForensics {
    pub operation_type: SecurityOperation,
    pub old_uid: Option<u32>,
    pub new_uid: Option<u32>,
    pub old_gid: Option<u32>,
    pub new_gid: Option<u32>,
    pub capability_changes: Vec<CapabilityChange>,
    pub namespace_operations: Vec<NamespaceOperation>,
    pub security_context: Option<String>, // SELinux/AppArmor context
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityOperation {
    SetUid,
    SetGid,
    SetGroups,
    CapabilitySet,
    NamespaceCreate,
    NamespaceJoin,
    Chroot,
    PivotRoot,
    Ptrace,
    Seccomp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityChange {
    pub capability: String, // CAP_NET_RAW, CAP_SYS_ADMIN, etc.
    pub action: CapabilityAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityAction {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceOperation {
    pub namespace_type: String, // "pid", "net", "user", etc.
    pub action: NamespaceAction,
    pub target_ns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NamespaceAction {
    Create,
    Join,
    Leave,
}

/// Signal and process control forensics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalForensics {
    pub operation_type: SignalOperation,
    pub signal_number: Option<i32>,
    pub signal_name: Option<String>, // SIGTERM, SIGKILL, etc.
    pub target_pid: Option<u32>,
    pub source_pid: Option<u32>,
    pub handler_action: Option<String>, // Default, Ignore, Custom
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalOperation {
    Send,
    Receive,
    SetHandler,
    Mask,
    Wait,
}

/// Environment manipulation forensics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentForensics {
    pub operation_type: EnvironmentOperation,
    pub variable_name: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub working_directory: Option<String>,
    pub affects_children: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvironmentOperation {
    SetEnv,
    UnsetEnv,
    ChangeDir,
    ModifyPath,
}

/// Permission analysis with security implications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAnalysis {
    pub requested_permissions: Vec<Permission>,
    pub effective_permissions: Vec<Permission>,
    pub human_description: String,
    pub security_implications: Vec<String>,
    pub violates_policy: bool,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub permission_type: PermissionType,
    pub granted: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionType {
    FileRead,
    FileWrite,
    FileExecute,
    FileCreate,
    FileDelete,
    NetworkBind,
    NetworkConnect,
    ProcessCreate,
    ProcessKill,
    MemoryExecute,
    SystemAdmin,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}
