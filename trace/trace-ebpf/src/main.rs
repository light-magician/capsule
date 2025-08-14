#![no_std]
#![no_main]

use aya_ebpf::{helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns }, macros::{map, tracepoint}, maps::ring_buf::RingBuf, programs::TracePointContext};
use aya_log_ebpf::info;
use trace_common::Event;

#[allow(static_mut_refs)]
#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0); // 1MB must be power of two pages

#[tracepoint]
pub fn on_sys_enter(ctx: TracePointContext) -> u32 {
    unsafe { emit_enter(ctx) }.unwrap_or(0)
}

#[inline(always)]
unsafe fn emit_enter(ctx: TracePointContext) -> Result<u32, u32> {
    if let Some(mut e) = EVENTS.reserve::<Event>(0) {
        let pid_tid = bpf_get_current_pid_tgid();
        let sysno   = ctx.read_at::<i64>(0).unwrap_or_default();
        let a0      = ctx.read_at::<u64>(8).unwrap_or_default();
        let a1      = ctx.read_at::<u64>(16).unwrap_or_default();
        let a2      = ctx.read_at::<u64>(24).unwrap_or_default();

        // Initialize the MaybeUninit<Event> in one shot:
        (*e).write(Event {
            ktime_ns: bpf_ktime_get_ns(),
            pid:      (pid_tid >> 32) as u32,
            tid:      pid_tid as u32,
            sysno:    sysno as i32,
            arg0:     a0,
            arg1:     a1,
            arg2:     a2,
        });

        // Publish the entry
        e.submit(0);
    }
    Ok(0)
}

// attach: raw_syscalls/sys_exit
#[tracepoint]
pub fn on_sys_exit(_: TracePointContext) -> u32 { 0 }

#[tracepoint]
pub fn trace(ctx: TracePointContext) -> u32 {
    unsafe {
        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = pid_tgid as u32;

        let comm_buf = bpf_get_current_comm().unwrap_or([0u8; 16]);
        let mut n = 0;
        while n < comm_buf.len() && comm_buf[n] != 0 { n += 1; }
        let comm = core::str::from_utf8_unchecked(&comm_buf[..n]);

        info!(&ctx, "execve pid={} comm={}", pid, comm);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
