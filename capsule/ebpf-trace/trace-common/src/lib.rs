#![no_std]

#[cfg(feature = "user")]
extern crate alloc;
#[cfg(feature = "user")]
use alloc::{string::String, vec::Vec};

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
    },
}

/// Enriched syscall with userspace context
#[cfg(feature = "user")]
#[derive(Debug, Clone)]
pub struct EnrichedSyscall {
    // Raw kernel data
    pub raw: RawSyscallEvent,

    // Enriched data (populated in userspace)
    pub enrichment: SyscallEnrichment,
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
