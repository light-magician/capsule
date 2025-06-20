use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Raw syscall emitted by the parser stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub ts: u64, // microseconds since boot
    pub pid: u32,
    pub call: String, // syscall name for now
    pub args: [u64; 6],
    pub retval: i64,
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
