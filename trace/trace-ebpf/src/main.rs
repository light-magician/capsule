#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns }, 
    macros::{map, tracepoint},
    maps::ring_buf::RingBuf, 
    maps::HashMap,
    programs::TracePointContext,
};

use trace_common::Event;

// ================== MAPS =======================

// PIDs we are watching (root and all descendants)
#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 64, 0); // multiple of page size

/// Track watched PIDs (key=id, val=1). Userspace seeds the root PID
#[map(name = "WATCHED_PIDS")]
static mut WATCHED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1000, 0);


// =================== HELPERS ===================
// --- shared proc-only filter (x86_64) ---
#[inline(always)]
fn is_process_syscall_x86_64(sysno: u32) -> bool {
    // clone,fork,vfork,execve,execveat,exit,exit_group
    matches!(sysno, 56 | 57 | 58 | 59 | 322 | 60 | 231) 
}
#[inline(always)]
fn pid_is_watched(tgid: u32) -> bool {
    unsafe { WATCHED_PIDS.get(&tgid).is_some() }
}

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

// sched:sched_process_fork (x86_64 common):
//   parent_tgid @ +36 (u32), child_tgid @ +60 (u32)
#[inline(always)]
fn read_sched_fork_tgids(ctx: &TracePointContext) -> (u32, u32) {
    let parent = unsafe { ctx.read_at::<u32>(36).unwrap_or(0) };
    let child  = unsafe { ctx.read_at::<u32>(60).unwrap_or(0) };
    (parent, child)
}

// sched:sched_process_exit:
//   tgid @ +36 (u32)
#[inline(always)]
fn read_sched_exit_tgid(ctx: &TracePointContext) -> u32 {
    unsafe { ctx.read_at::<u32>(36).unwrap_or(0) }
}

///// NOTE: These offsets are going to have to be programmed for every instruction set
//#[inline(always)]
//unsafe fn submit_event(ctx: &TracePointContext) {
//    // only process syscalls we care about from the watcehd PIDs
//    let sysno: u32 = unsafe { ctx.read_at(0)}
//    let pid_tid = bpf_get_current_pid_tgid();
//    let pid = (pid_tid >> 32) as u32; // tgid
//    if !is_proc_syscall(sysno as u32) || !pid_is_watched(pid) {
//        return; // skip
//    }
//
//    // we just have the raw event, and we know how much space each
//    // field takes, so we can manually alight the Event struct fields
//    if let Some(mut e) = EVENTS.reserve::<Event>(0) {
//        let pid_tid = bpf_get_current_pid_tgid();
//        let sysno   = ctx.read_at::<i64>(0).unwrap_or_default();
//        let a0      = ctx.read_at::<u64>(8).unwrap_or_default();
//        let a1      = ctx.read_at::<u64>(16).unwrap_or_default();
//        let a2      = ctx.read_at::<u64>(24).unwrap_or_default();
//
//        // Initialize the MaybeUninit<Event> in one shot:
//        (*e).write(Event {
//            ktime_ns: bpf_ktime_get_ns(),
//            pid:      (pid_tid >> 32) as u32,
//            tid:      pid_tid as u32,
//            sysno:    sysno as i32,
//            arg0:     a0,
//            arg1:     a1,
//            arg2:     a2,
//        });
//
//        // Publish entry to ring buffer
//        e.submit(0);
//    }
//}

#[inline(always)]
unsafe fn submit_event_enter(ctx: &TracePointContext) {
    let pid_tid = bpf_get_current_pid_tgid();
    let tgid = (pid_tid >> 32) as u32;

    let sysno = read_sysno_raw_enter(ctx);
    if !pid_is_watched(tgid) || !is_process_syscall_x86_64(sysno) {
        return;
    }

    // define the args before using them
    let a0 = read_arg_raw_enter(ctx, 0);
    let a1 = read_arg_raw_enter(ctx, 1);
    let a2 = read_arg_raw_enter(ctx, 2);

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
        slot.write(ev);   // <-- this is the correct call
        slot.submit(0);
    }
}

#[inline(always)]
unsafe fn submit_event_exit(ctx: &TracePointContext) {
    let pid_tid = bpf_get_current_pid_tgid();
    let tgid = (pid_tid >> 32) as u32;

    let sysno = read_sysno_raw_exit(ctx);
    if !pid_is_watched(tgid) || !is_process_syscall_x86_64(sysno) {
        return;
    }

    if let Some(mut slot) = EVENTS.reserve::<Event>(0) {
        // For exits, store return value in arg0; arg1/arg2 = 0
        let ev = Event {
            ktime_ns: bpf_ktime_get_ns(),
            pid:      tgid,
            tid:      pid_tid as u32,
            sysno:    sysno as i32,
            arg0:     read_ret_raw_exit(ctx),
            arg1:     0,
            arg2:     0,
        };
        slot.write(ev);           
        slot.submit(0);
    }
}



// ========= TRACEPOINTS =============

// All syscalls enter
#[tracepoint(name = "tp_sys_enter_raw", category = "raw_syscalls")]
pub fn tp_sys_enter_raw(ctx: TracePointContext) -> u32 {
    unsafe { submit_event_enter(&ctx) };
    0
}

// All syscalls exit
#[tracepoint(name = "tp_sys_exit_raw", category = "raw_syscalls")]
pub fn tp_sys_exit_raw(ctx: TracePointContext) -> u32 {
    unsafe { submit_event_exit(&ctx) };
    0
}

// Track descendants
#[tracepoint(name = "tp_sched_process_fork", category = "sched")]
pub fn tp_sched_process_fork(ctx: TracePointContext) -> u32 {
    let (parent_tgid, child_tgid) = read_sched_fork_tgids(&ctx);
    unsafe {
        if WATCHED_PIDS.get(&parent_tgid).is_some() {
            let _ = WATCHED_PIDS.insert(&child_tgid, &1, 0);
        }
    }
    0
}

#[tracepoint(name = "tp_sched_process_exit", category = "sched")]
pub fn tp_sched_process_exit(ctx: TracePointContext) -> u32 {
    let tgid = read_sched_exit_tgid(&ctx);
    unsafe {
        let _ = WATCHED_PIDS.remove(&tgid);
    }
    0
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
