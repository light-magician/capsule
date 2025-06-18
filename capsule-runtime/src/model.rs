// src/model.rs
//! Canonical data types shared by the tracer → parser → aggregator pipeline.
//!
//! * `SyscallEvent`  – lossless representation of one raw syscall.
//! * `HighLevelKind` – semantic category derived from one or more syscalls.
//! * `EventSummary`  – coalesced, human-readable audit record.
//
// All structs are `Serialize`/`Deserialize` so they can move over the wire or
// hit disk without friction.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// One line of strace, parsed just enough to keep the important bits.
///
/// The parser guarantees that every syscall line becomes exactly one
/// `SyscallEvent`, in order, with no additional interpretation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Nanoseconds since the Unix epoch.
    pub ts_ns: u64,
    /// Linux process ID that executed the syscall.
    pub pid: i32,
    /// Thread ID (may equal `pid` for single-threaded processes).
    pub tid: i32,
    /// Syscall name – e.g. `"openat"`, `"connect"`, `"execve"`.
    pub name: String,
    /// Raw argument list as printed by strace.  *Not* parsed yet.
    pub args: Vec<String>,
    /// Return value / errno / negotiated fd, exactly as shown by strace.
    pub ret: String,
}

/// Higher-level activity distilled from one or many syscalls.
///
/// Variants are intentionally verbose: Capsule’s promise is clarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum HighLevelKind {
    // ────────────────── Filesystem ──────────────────
    /// File opened for reading.
    FileRead { path: String, bytes: u64 },
    /// File created or written.
    FileWrite { path: String, bytes: u64 },
    /// File metadata queried (stat/lstat/faccess).
    FileStat { path: String },
    /// File removed (unlink/unlinkat).
    FileDelete { path: String },
    /// File renamed or moved (rename/renameat).
    FileRename { src: String, dst: String },
    /// File memory-mapped (mmap/munmap).
    FileMemMap { path: String, prot: String },

    // ────────────────── Process / Exec ──────────────────
    /// New process or thread spawned, followed by exec.
    ProcessSpawn {
        child_pid: i32,
        exec_path: String,
        argv: Vec<String>,
    },
    /// Process exited normally or via signal.
    ProcessExit { pid: i32, status: i32 },

    // ────────────────── Networking ──────────────────
    /// Outbound connection initiated (connect()).
    NetConnect { dst: SocketAddr },
    /// Inbound connection accepted (accept()).
    NetAccept { src: SocketAddr, local: SocketAddr },
    /// Socket bound (bind()).
    NetBind { local: SocketAddr },
    /// Socket set to listen (listen()).
    NetListen { local: SocketAddr },
    /// Data sent over a socket (write/send/sendto/sendmsg).
    NetSend { dst: SocketAddr, bytes: u64 },
    /// Data received from a socket (read/recv/recvfrom/recvmsg).
    NetRecv { src: SocketAddr, bytes: u64 },
    /// DNS resolution (getaddrinfo/resolve).
    DnsQuery { query: String, answers: Vec<String> },

    // ────────────────── IPC & Signals ──────────────────
    /// Wrote to pipe, FIFO, or UNIX-domain socket.
    IpcWrite { endpoint: String, bytes: u64 },
    /// Read from pipe, FIFO, or UNIX-domain socket.
    IpcRead { endpoint: String, bytes: u64 },
    /// Sent a POSIX signal.
    SignalSend { pid: i32, signo: i32 },

    // ────────────────── Memory / Privilege ──────────────────
    /// Changed memory protection on an existing mapping.
    MemProtectChange { addr: u64, len: u64, prot: String },
    /// Issued an explicitly privileged syscall (e.g. `ptrace`, `capset`).
    PrivilegedSyscall { name: String },

    // ────────────────── Fallback ──────────────────
    /// Unknown or not yet-classified activity.
    Unknown { description: String },
}

/// User-facing record written by the Aggregator.
///
/// One `EventSummary` may correspond to dozens of raw syscalls, but it should
/// read like a sentence: *“PID 1234 opened /etc/passwd for reading.”*
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    /// Timestamp of first contributing syscall (ns since epoch).
    pub ts_first: u64,
    /// Timestamp of last contributing syscall (ns since epoch).
    pub ts_last: u64,
    /// PID that initiated the activity.
    pub pid: i32,
    /// What actually happened, in human terms.
    pub kind: HighLevelKind,
}
