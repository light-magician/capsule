#![no_std]

/// This is a syscall event.
///
/// This structure is how we expect to pass syscall data
/// from kernelspace to userspace via the ring buffer
/// and is thus shared by both kernelspace and userspace.
/// Kernel → userspace syscall event (ring buffer payload)
///
/// Notes on layout/portability:
/// - We use #[repr(C)] to keep a stable layout for aya ring buffer reads.
/// - Phase is a u8 for enter/exit framing and padded to maintain 8-byte alignment
///   before the first u64 arg field. This is important for all arches.
/// - Args are captured as 6 x u64 matching raw_syscalls args[0..5] (unsigned long).
///   On 64-bit Linux (aarch64/x86_64) unsigned long is 64-bit; on 32-bit it is 32-bit.
///   // TODO: If supporting 32-bit, consider an arch-specific representation or
///   //       zero-extend to u64 consistently and document truncation semantics.
#[repr(C)]
pub struct Event {
    /// Monotonic kernel timestamp (ns)
    pub ktime_ns: u64,
    /// TGID (userspace-visible PID)
    pub pid: u32,
    /// Kernel TID
    pub tid: u32,
    /// Syscall number (arch-specific)
    pub sysno: i32,
    /// Enter/Exit phase marker (see PHASE_*)
    pub phase: u8,
    /// Padding to 8-byte boundary before u64 args
    pub _pad: [u8; 3],
    /// Up to six syscall arguments (raw unsigned long values)
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
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
