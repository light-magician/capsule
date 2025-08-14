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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcEvent {
    // kernel monotonic timestamp
    pub ts_ns: u64,
    // task (thread) ID and thread group id
    pub pid: u32,
    pub tid: u32,
    // syscall number (x86_64). For sched_exit this will be 0
    pub sysno: u32,
    // 0 = sys_enter, 1 = sys_exit, 2 = sched_process_exit
    pub phase: u8,
    pub _pad: [u8; 3],
}

/// scope modes (shared so userspace and kernelspace agree)
pub const MODE_ALL: u32 = 0;
pub const MODE_CGROUP: u32 = 0;

// Minimal process-syscall set for x86_64
#[inline(always)]
pub const fn is_process_syscall_x86_64(n: u32) -> bool {
    match n {
        56 | // clone 
        57 | // fork
        58 | // vfork
        59 | // execve
        322 | // execveat
        60 | // exit 
        231  // exit_group
        => true,
        _ => false,
    }
}
