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
    pub ts: u64,                    // microseconds since tracer start
    pub pid: u32,                   // Linux PID of calling thread
    pub call: String,               // syscall name
    pub args: [u64; 6],            // raw six argument words
    pub retval: i64,               // return value from strace
    pub raw_line: String,          // original strace line for provenance
    
    // Thread/process context (Should)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>,           // thread ID when different from PID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,          // parent PID snapshot
    
    // Process metadata (Should)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,   // absolute path of /proc/pid/exe
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,        // current working directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,           // real UID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,           // real GID
    
    // Security context (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub euid: Option<u32>,          // effective UID if different
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egid: Option<u32>,          // effective GID if different
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<u64>,          // CapEff bitmap (≤ 64 caps)
    
    // Resource context (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,            // FD number referenced (-1 if none)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abs_path: Option<String>,   // resolved absolute path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<ResourceType>,  // high-level resource kind
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,         // semantic intent
    
    // Operation details (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perm_bits: Option<u32>,     // octal mode from openat, chmod, etc
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<u64>,    // size requested/transferred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<u64>,    // Δ between entry/exit when captured
    
    // Network context (May)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<NetworkInfo>,   // populated for socket syscalls
    
    // Risk analysis (May)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub risk_tags: Vec<String>,     // heuristic flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_level_kind: Option<String>,  // bucket used by Aggregator
    
    // Legacy compatibility field - TODO: Remove after transition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichment: Option<ProcessContext>,
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

/// Operation type classification
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
    pub family: String,        // "AF_INET"|"AF_INET6"|"AF_UNIX"|"AF_NETLINK"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,     // "TCP"|"UDP"|...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<String>,   // "127.0.0.1"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,      // 8000
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,  // "1.2.3.4"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,     // 443
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
    FileRead { path: PathBuf, bytes: usize },
    FileWrite { path: PathBuf, bytes: usize },
    DirectoryList { path: PathBuf, entries: usize },
    SocketConnect { addr: SocketAddr, protocol: String },
    SocketBind { addr: SocketAddr, protocol: String },
    SocketAccept { local_addr: SocketAddr, remote_addr: SocketAddr },
    ProcessSpawn { pid: u32, argv: Vec<String>, parent_pid: u32 },
    ProcessExec { argv: Vec<String> },
    ProcessExit { pid: u32, exit_code: i32 },
    SignalSend { target_pid: u32, signal: i32 },
    SignalReceive { signal: i32 },
    MemoryMap { addr: u64, size: usize, prot: String },
    MemoryUnmap { addr: u64, size: usize },
    FileOpen { path: PathBuf, flags: String },
    FileClose { path: PathBuf },
    FileStat { path: PathBuf },
    FileChmod { path: PathBuf, mode: u32 },
    FileChown { path: PathBuf, uid: u32, gid: u32 },
    Other { syscall: String, describe: String },
}
