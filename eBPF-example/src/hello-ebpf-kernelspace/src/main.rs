// eBPF programs cannot user std lib, heap, or standard collections
// and do not have a traditional main() entry point
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

/// HashMap to track process ID's 1000 should be enough for now
#[map]
static PID_TRACKER: HashMap<u32, u8> = HashMap::with_max_entries(1000, 0);

// Test RingBuf for event streaming
#[map]
static EVENT_RING: RingBuf = RingBuf::with_byte_size(1024, 0);

/// Proper tracepoint approach - captures ALL syscalls via sys_enter
/// This is the CORRECT way that successful Rust eBPF programs do syscall tracing
/// Instead of raw tracepoints, use structured tracepoint access
#[tracepoint]
pub fn sys_enter_all(ctx: TracePointContext) -> u32 {
    match try_capture_syscalls(ctx) {
        Ok(_) => 0,  // Success - continue normal syscall processing
        Err(_) => 0, // Error - but don't block syscall (just log failure)
    }
}

/// PROPER syscall tracing using structured TracePointContext access
fn try_capture_syscalls(ctx: TracePointContext) -> Result<(), i32> {
    // Try to extract syscall number from TracePointContext
    // For sys_enter_openat, this should be the openat syscall (257 on x86_64)

    // Get process info using eBPF helpers (this works perfectly)
    let pid_tgid = {
        use aya_ebpf::helpers::bpf_get_current_pid_tgid;
        bpf_get_current_pid_tgid()
    };
    let pid = (pid_tgid >> 32) as u32;

    // Basic filtering - only track certain PIDs
    if pid < 100 {
        return Ok(());
    }

    // Test HashMap insert - use explicit match to avoid core::fmt
    match PID_TRACKER.insert(&pid, &1, 0) {
        Ok(_) => {}
        Err(_) => {} // Ignore errors without formatting
    }

    // Test HashMap lookup and RingBuf operations
    match unsafe { PID_TRACKER.get(&pid) } {
        Some(_) => match EVENT_RING.reserve(0u64) {
            Some(mut entry) => unsafe {
                let entry_ptr = entry.as_mut_ptr() as *mut u64;
                *entry_ptr = pid as u64;
                entry.submit(0u64);

                use aya_ebpf::helpers::bpf_printk;
                bpf_printk!(b"openat() called by PID: %d\0", pid);
            },
            None => {}
        },
        None => {}
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
