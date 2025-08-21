#![no_std]

/// This is a syscall event.
///
/// This structure is how we expect to pass syscall data
/// from kernelspace to userspace via the ring buffer
/// and is thus shared by both kernelspace and userspace.
#[repr(C)]
pub struct Event {
    pub ktime_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub sysno: i32,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
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
