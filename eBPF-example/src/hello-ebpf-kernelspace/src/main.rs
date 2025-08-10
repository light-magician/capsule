// eBPF programs cannot user std lib, heap, or standard collections
// and do not have a traditional main() entry point
#![no_std]
#![no_main]

/// eBPF constraints:
/// - only 512 bytes of stack (or 256 if utilizing tail calls)
/// - no access to heap space and data must be written to maps
/// - cannot use the std lib in C or Rust
/// - core::fmt (formatting) may not be used and neither can traits that rely on it
///   Ex: Display or Debug
/// - as there is no heap, there is also no alloc or collections
/// - cannot panic as the eBPF VM does not support stack unwinding, or abort instruction
/// - no main function, already provided for above
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

/// HashMap to track process ID's 1000 should be enough for now
#[map(name = "PID_TRACKER")]
static mut PID_TRACKER: HashMap<u32, u8> = HashMap::with_max_entries(1000, 0);

/// A Ring (Circular) Buffer data structure for sending events from kernelspace
/// to userspace. https://en.wikipedia.org/wiki/Circular_buffer
///
/// This datastructure was chosen because of eBPF's strict memory requrements.
///
/// A first in first out datastructure.
/// When a value is read by userspace it is removed from the buffer.
///
#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0); // 16MB

// bitmap allowlist - 512 covers most arch ranges
const MAX_SYSCALLS: usize = 512;

#[repr(C)]
pub struct Event {
    pub ts_ns: u64,      // timestamp nanoseconds
    pub pid_tgid: u64,   // process ID thread group ID
    pub uid_gid: u64,    // user ID group ID
    pub syscall_id: u32, // syscall ID
    pub enter_exit: u8,  // 0 = enter, 1 = exit
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub comm: [u8; 16],
    pub retval: i64, // only valid for exits
}

#[link_section = ".rodata"]
static ALLOWLIST: [u8; MAX_SYSCALLS] = [0; MAX_SYSCALLS];

/// Capture all syscalls via sys_enter
#[tracepoint(name = "on_sys_enter", category = "raw_syscalls")]
pub fn on_sys_enter(ctx: TracePointContext) -> u32 {
    match try_enter(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_enter(ctx: TracePointContext) -> Result<(), i64> {
    // raw_syscalls:sys_enter args layout:
    // long id; unsigned long args[6];
    let id: u64 = unsafe { ctx.read_at(0)? };
    let id = id as u32;

    // early filter using allowlist
    if (id as usize) >= MAX_SYSCALLS || ALLOWLIST[id as usize] == 0 {
        return Ok(());
    }

    let mut ev = Event {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        pid_tgid: bpf_get_current_pid_tgid(),
        uid_gid: bpf_get_current_uid_gid(),
        syscall_id: id,
        enter_exit: 0,
        arg0: unsafe { ctx.read_at(8)? },
        arg1: unsafe { ctx.read_at(16)? },
        arg2: unsafe { ctx.read_at(24)? },
        arg3: unsafe { ctx.read_at(32)? },
        arg4: unsafe { ctx.read_at(40)? },
        arg5: unsafe { ctx.read_at(48)? },
        comm: [0; 16],
        retval: 0,
    };
    // aya_ebpf helper returns [u8;16]
    ev.comm = bpf_get_current_comm().unwrap_or([0; 16]);

    unsafe {
        if let Some(mut rb) = EVENTS.reserve(0) {
            // best-effort write; ignore errors to keep verifier happy
            let ptr = rb.as_mut_ptr();
            core::ptr::write(ptr as *mut Event, ev);
            rb.submit(0);
        }
    }
    Ok(())
}

#[tracepoint(name = "on_sys_exit", category = "raw_syscalls")]
pub fn on_sys_exit(ctx: TracePointContext) -> u32 {
    match try_exit(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_exit(ctx: TracePointContext) -> Result<(), i64> {
    // raw_syscalls:sys_exit args layout:
    // long id; long ret;
    let id: u64 = unsafe { ctx.read_at(0)? };
    let id = id as u32;

    if (id as usize) >= MAX_SYSCALLS || ALLOWLIST[id as usize] == 0 {
        return Ok(());
    }

    let ret: i64 = unsafe { ctx.read_at(8)? };

    let mut ev = Event {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        pid_tgid: bpf_get_current_pid_tgid(),
        uid_gid: bpf_get_current_uid_gid(),
        syscall_id: id,
        enter_exit: 1,
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
        comm: [0; 16],
        retval: ret,
    };
    ev.comm = bpf_get_current_comm().unwrap_or([0; 16]);

    unsafe {
        if let Some(mut rb) = EVENTS.reserve(0) {
            // best-effort write; ignore errors to keep verifier happy
            let ptr = rb.as_mut_ptr();
            core::ptr::write(ptr as *mut Event, ev);
            rb.submit(0);
        }
    }
    Ok(())
}

/// Your panic handler (required for compilation in no_std eBPF)
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
