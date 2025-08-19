#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{map, raw_tracepoint, tracepoint},
    maps::{ring_buf::RingBuf, HashMap},
    programs::{RawTracePointContext, TracePointContext},
    EbpfContext,
};
use trace_common::Event;

// ===== placeholder for CO-RE =====
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct task_struct {
    pub tgid: u32,
    // … rest is opaque
}

// ============================== COLLECTIONS =================================

// PIDs we are watching (root and all descendants)
#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 64, 0); // multiple of page size

/// Track watched PIDs (key=id, val=1). Userspace seeds the root PID
#[map(name = "WATCHED_PIDS")]
static mut WATCHED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// ============================= RAW TRACEPOINTS ===============================

// NOTE: to find offset run 
// cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format 
// on your kernel
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> u32 {
    unsafe {
        // ctx is struct bpf_raw_tracepoint_args*; ctx->args[0]=id, ctx->args[1]=unsigned long *args
        let base = <RawTracePointContext as EbpfContext>::as_ptr(&ctx) as *const u64;

        let id = core::ptr::read(base.add(0)) as u32;
        let args_ptr = core::ptr::read(base.add(1)) as *const u64;

        // args_ptr is a kernel pointer → must probe-read
        let a0 = bpf_probe_read_kernel(args_ptr).unwrap_or(0);
        let a1 = bpf_probe_read_kernel(args_ptr.add(1)).unwrap_or(0);
        let a2 = bpf_probe_read_kernel(args_ptr.add(2)).unwrap_or(0);

        submit_event_enter(id, a0, a1, a2);
    }
    0
}

// NOTE: to find offset run 
// cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format 
// on your kernel
#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn sys_exit(ctx: RawTracePointContext) -> u32 {
    unsafe {
        let base = <RawTracePointContext as EbpfContext>::as_ptr(&ctx) as *const u64;

        let id  = core::ptr::read(base.add(0)) as u32;  // ctx->args[0] = id
        let ret = core::ptr::read(base.add(1)) as u64;  // ctx->args[1] = return (value, not ptr)

        submit_event_exit(id, ret);
    }
    0
}

// ================================ TRACEPOINTS =================================

// sched_process_fork: parent_pid, child_pid
#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_fork(ctx: TracePointContext) -> u32 {
    unsafe {
        let (parent_pid, child_pid) = read_sched_fork_pids(&ctx);
        if WATCHED_PIDS.get(&parent_pid).is_some() {
            let _ = WATCHED_PIDS.insert(&child_pid, &1, 0);
        }
    }
    0
}

// sched_process_exit: pid
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn sched_exit(ctx: TracePointContext) -> u32 {
    unsafe {
        let pid = read_sched_exit_pid(&ctx);
        let _ = WATCHED_PIDS.remove(&pid);
    }
    0
}


// ========================== HELPERS =====================================

// NOTE: these offsets are for kernel 6.10.14-linuxkit
// For other kernels, offsets must be found with 
// cat /sys/kernel/debug/tracing/events/sched/.../format 
// and passed down by userspace. 

// =======================================================================

// raw_syscalls:sys_enter layout (x86_64):
//   id @ +8 (u64), args[0..5] @ +16,+24,+32,+40,+48,+56
#[inline(always)]
fn read_sysno_raw_enter(ctx: &TracePointContext) -> u32 {
    unsafe { ctx.read_at::<u64>(8).unwrap_or(0) as u32 }
}
#[inline(always)]
fn read_arg_raw_enter(ctx: &TracePointContext, i: u32) -> u64 {
    let base = 16u32 + i * 8;
    unsafe { ctx.read_at::<u64>(base as usize).unwrap_or(0) }
}

// raw_syscalls:sys_exit layout (x86_64):
//   id @ +8 (u64), ret @ +16 (u64)
#[inline(always)]
fn read_sysno_raw_exit(ctx: &TracePointContext) -> u32 {
    unsafe { ctx.read_at::<u64>(8).unwrap_or(0) as u32 }
}
#[inline(always)]
fn read_ret_raw_exit(ctx: &TracePointContext) -> u64 {
    unsafe { ctx.read_at::<u64>(16).unwrap_or(0) }
}

// sched:sched_process_fork
#[inline(always)]
fn read_sched_fork_pids(ctx: &TracePointContext) -> (u32, u32) {
    let parent = unsafe { ctx.read_at::<i32>(24).unwrap_or(0) } as u32;
    let child  = unsafe { ctx.read_at::<i32>(44).unwrap_or(0) } as u32;
    (parent, child)
}

#[inline(always)]
fn read_sched_exit_pid(ctx: &TracePointContext) -> u32 {
    unsafe { ctx.read_at::<i32>(24).unwrap_or(0) as u32 }
}

#[inline(always)]
unsafe fn submit_event_enter(sysno: u32, a0: u64, a1: u64, a2: u64) {
    let pid_tid = bpf_get_current_pid_tgid();
    let tgid = (pid_tid >> 32) as u32;

    //if !pid_is_watched(tgid) || !is_process_syscall_x86_64(sysno) {
    //    return;
    //}

    if let Some(mut slot) = EVENTS.reserve::<Event>(0) {
        let ev = Event {
            ktime_ns: bpf_ktime_get_ns(),
            pid:      tgid,
            tid:      pid_tid as u32,
            sysno:    sysno as i32,
            arg0:     a0,
            arg1:     a1, 
            arg2:     a2,
        };
        slot.write(ev); // fills the memory
        slot.submit(0); // submits it so that userspace can read
    }
}

#[inline(always)]
unsafe fn submit_event_exit(sysno: u32, ret: u64) {
    let pid_tid = bpf_get_current_pid_tgid();
    let tgid = (pid_tid >> 32) as u32;

    //if !pid_is_watched(tgid) || !is_process_syscall_x86_64(sysno) {
    //    return;
    //}

    if let Some(mut slot) = EVENTS.reserve::<Event>(0) {
        // For exits, store return value in arg0; arg1/arg2 = 0
        let ev = Event {
            ktime_ns: bpf_ktime_get_ns(),
            pid:      tgid,
            tid:      pid_tid as u32,
            sysno:    sysno as i32,
            arg0:     ret,
            arg1:     0,
            arg2:     0,
        };
        slot.write(ev);           
        slot.submit(0);
    }
}




// =========== BOILERPLATE ===============

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
