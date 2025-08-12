#![no_std]
#![no_main]

use aya_ebpf::{helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid }, 
    macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

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
