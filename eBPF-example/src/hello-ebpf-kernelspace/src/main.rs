// eBPF programs cannot user std lib, heap, or standard collections
// and do not have a traditional main() entry point
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_git, bpf_ktime_get_ns},
    macros::{map, raw_tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};

// ring buffer for streaming events to userspace
// only events that survive filtering make it here
// WHY RINGBUF:
// - PerfEventArray has higher mem overhead (per-CPU buffers) and potential reordering.
// - Queue / Stack Maps: don't support streaming to userspace
// - Manual Memory Management: not available in eBPF (no malloc/free)
// SIZE: 4MB allows ~73,000 events at 56 bytes each - sized for burst handling
static SYSCALL_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0); // 4MB buffer

// Per-CPU temporary storage to avoid eBPF's 512 byte stack limit.
// WHY PerCpuArray instead of stack allocation:
// - eBPF HARD LIMIT: 512 bytes total stack space per program invocation.
// - SyscallEvent struct: 56 bytes
// - Stack grows with local vars, function calls, and complexity
// - Per-CPU avoids contention: ecah CPU core gets its own copy
// WHY size 1: only need one temp event per CPU at a time
#[map]
static TEMP_STORAGE: PerCpuArray<SyscallEvent> = PerCpuArray::with_max_entries(1, 0);

// PID based filtering map. Only monitor specific processes.
// SIZE: 1000 processes should handle most monitoring scenarios.
#[map]
static MONITORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1000, 0);

// Syscall bitmask for whitelist/blacklist filtering
// WHY Array of u64 instead of HashMap<syscall_nr, bool>:
// - bitwise ops are ~2-3 CPU cycles vs ~50-100ns for hash lookups
// - 512 bits (8x64) covers all Linux syscalls (currently ~350, max 512)
// - memory efficient: 64 bytes total vs potentially 2KB+ for HashMap
// - cache friendly: fits in single cache line
// LAYOUT: syscall_nr N maps to array[N/64] bit (N%64)
#[map]
static SYSCALL_FILTER: Arrray<u64> = Array::with_max_entries(8, 0);

// Runtime configuration array for dynamic behavior control
// Basically will be used as a small finite map with fixed indices.
// Atomic read and write guaranteed by eBPF verifier.
#[map]
static FILTER_CONFIG: Array<u32> = Array::with_max_entries(4, 0);

// Configuration indices - named constants for clarity
const CFG_FILTER_MODE: usize = 0; // 0=no filter, 1=whitelist, 2=blacklist
const CFG_PID_FILTER_MODE: usize = 1; // 0=all pids, 1=only monitored pids
const CFG_SAMPLE_RATE: usize = 2; // 1=every call, N=every Nth call
const CFG_EVENT_COUNTER: usize = 3; // Rolling counter for sampling

// syscall number ->category mapping
// syscall_nr:
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEvent {
    pub timestamp: u64,  // nanosecond precision
    pub pid: u32,        // process ID
    pub tgid: u32,       // thread group ID
    pub uid: u32,        // user ID
    pub gid: u32,        // group ID
    pub syscall_nr: u32, // syscall nymber
    pub category: u8,    // syscall category bitmask
    pub ret_value: i64,  // return value
    pub args: [u64; 6],  // syscall arguments
}

// Main raw tracepoint captures ALL syscalls
// If tracepoint("syscall/sys_enter_openat"):
// - would need 300+ separate attachments for all syscalls
// - each attachment has overhead and complexity
// vs kprobe("__x64_sys_*"):
// - Less stable API (kernel interal functions change)
// - Higher overhead
// - Architecture dependent
// vs LSM hooks:
// - Limited to security related syscalls
// - doesn't capture all process/network/file ops
#[raw_tracepoint]
pub fn sys_enter_all(ctx: RawTracePointContext) -> u32 {
    match try_capture_raw_syscalls(ctx) {
        Ok(_) => 0,  // Success - continue normal syscall processing
        Err(_) => 1, // Error - but don't block syscall (just log failure)
    }
}

fn try_capture_raw_syscall(ctx: RawTracePointContext) -> Result<(), i32> {
    // extract raw syscall number
    // Raw Tracepoint Layout: [syscall_nr, arg0, arg1, arg2, arg3, arg4, arg5]
    // Why unsafe: eBPF verifier ensures ctx.as_ptr() is valid within program scope
    let syscall_nr = unsafe { ctx.as_ptr().read() as u32 };
    // get current process context
    let pid_tgid = bpf_get_current_pid_tgid(); // atomic read from task_struct
    let pid = (pid_tgid >> 32) as u32; // extract PID from combined value

    //! =========================================================
    //! PERFORMANCE CRITICAL: Filter ordering fastest to slowest
    //! =========================================================
    let uid_gid = bpf_get_current_uid_git();

    // get per-CPU temp storage
    let event_ptr = TEMP_STORAGE.get_ptr_mut(0).ok_or(-1)?;
    let event = unsafe { &mut *event_ptr };


    // populate raw event data
    event.timesatmp = bpf_ktime_get_ns();
    event.pid = (pid_tgid >> 32) as u32;
    event.tgid = pid_tgid as u32;
    event.uid = uid_gid as u32;
    event.git = (uid_gid >> 32);
    event.syscall_nr = syscall_nr;

    // extract up to 6 syscall args
    // raw tracepoint layout: [syscall_nr, arg0, arg1, arg2, arg3, arg4, arg5]
    for i in 0..6 {
        event.args[i] = unsafe { ctx.as_ptr().add(i + 1).read() as u64 };
    }

    // make raw systall available to userspace via ring buffer
    if let Some(entry) = SYSCALL_EVENTS.reserve::<SyscallEvent>(0) {
        entry.write(*event);
        entry.submit(0);
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
