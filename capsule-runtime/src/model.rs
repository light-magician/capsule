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
    NetConnect { addr: SocketAddr },
    ProcessExec { argv: Vec<String> },
    Other { describe: String },
}
