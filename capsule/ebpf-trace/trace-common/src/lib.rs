#![no_std]

pub mod aarch64_syscalls;

#[cfg(feature = "user")]
extern crate alloc;
#[cfg(feature = "user")]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

#[cfg(feature = "user")]
pub use aarch64_syscalls::Aarch64Syscalls;

/// This is a syscall event.
///
/// This structure is how we expect to pass syscall data
/// from kernelspace to userspace via the ring buffer
/// and is thus shared by both kernelspace and userspace.
///
/// arg0, arg1, arg2 are raw pointer values
/// TODO: expand to support more arguments.
/// phase is 0 = enter, 1 = exit
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSyscallEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub sysno: i32,
    pub arg0: u64, // raw pointer
    pub arg1: u64, // raw pointer
    pub arg2: u64, // raw pointer
    pub phase: u8, // 0=enter, 1=exit
    pub _pad: [u8; 7],
}

#[cfg(feature = "user")]
#[derive(Debug, Clone, Default)]
pub enum SyscallEnrichment {
    #[default]
    None,
    Exec {
        filename: String,
        argv: Vec<String>,
        envp: Vec<String>,
        dirfd: Option<i32>, // for execveat
        flags: Option<i32>, // for execveat
    },
    Open {
        pathname: String,
        flags: u32,
        mode: u32,
    },
    Clone {
        flags: u64,
        flags_decoded: Vec<String>,
        stack_ptr: Option<u64>,
        parent_tid_ptr: Option<u64>,
        child_tid_ptr: Option<u64>,
        tls_ptr: Option<u64>, // for clone3
    },
    Exit {
        status: i32,
        is_group: bool, // true for exit_group, false for exit
    },
    Wait {
        pid: i32,
        status_ptr: Option<u64>,
        options: u32,
        options_decoded: Vec<String>,
        rusage_ptr: Option<u64>, // for wait4
    },
    Kill {
        pid: i32,
        signal: i32,
        signal_name: String,
        is_thread: bool, // true for tkill/tgkill, false for kill
        target_tid: Option<i32>, // for tgkill
    },
    ProcessInfo {
        result: u32,
        info_type: String, // "pid", "ppid", "tid", "uid", etc.
    },
    Memory {
        addr: u64,
        length: Option<u64>,
        prot: Option<i32>,
        prot_decoded: Vec<String>,
        flags: Option<i32>,
        flags_decoded: Vec<String>,
    },
    FileIo {
        fd: i32,
        buffer_ptr: Option<u64>,
        count: Option<u64>,
        offset: Option<u64>,
        pathname: Option<String>, // for openat
        flags: Option<i32>,
        mode: Option<u32>,
    },
}

/// Enriched syscall with userspace context and human-readable information
#[cfg(feature = "user")]
#[derive(Debug, Clone)]
pub struct EnrichedSyscall {
    // Raw kernel data
    pub raw: RawSyscallEvent,

    // Syscall identification
    pub syscall_name: String,
    pub syscall_enum: Option<Aarch64Syscalls>,

    // Enriched data (populated in userspace)
    pub enrichment: SyscallEnrichment,
}

#[cfg(feature = "user")]
impl EnrichedSyscall {
    /// Create a new enriched syscall from raw data
    pub fn new(raw: RawSyscallEvent) -> Self {
        let syscall_enum = Aarch64Syscalls::from_sysno(raw.sysno);
        let syscall_name = syscall_enum
            .map(|s| s.name().to_string())
            .unwrap_or_else(|| format!("syscall_{}", raw.sysno));

        Self {
            raw,
            syscall_name,
            syscall_enum,
            enrichment: SyscallEnrichment::None,
        }
    }

    /// Check if this syscall should be enriched (is process-related)
    pub fn should_enrich(&self) -> bool {
        self.syscall_enum
            .map(|s| s.is_process_related())
            .unwrap_or(false)
    }

    /// Get the phase as human-readable string
    pub fn phase_name(&self) -> &'static str {
        match self.raw.phase {
            PHASE_ENTER => "enter",
            PHASE_EXIT => "exit",
            PHASE_TASK_EXIT => "task_exit",
            _ => "unknown",
        }
    }
}

/// Phases for ProcEvent::phase
pub const PHASE_ENTER: u8 = 0;
pub const PHASE_EXIT: u8 = 1;
pub const PHASE_TASK_EXIT: u8 = 2;

/// ProcEvent is a process related event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcEvent {
    // kernel monotonic timestamp
    pub ts_ns: u64,
    // task (thread) ID and thread group id
    pub pid: u32,
    pub tgid: u32,
    // syscall number (x86_64). For sched_exit this will be 0
    pub sysno: u32, // 0 = sys_enter, 1 = sys_exit, 2 = sched_process_exit
    pub phase: u8,
    pub _pad: [u8; 3],
}

/// scope modes (shared so userspace and kernelspace agree)
pub const MODE_ALL: u32 = 0;
pub const MODE_CGROUP: u32 = 0;