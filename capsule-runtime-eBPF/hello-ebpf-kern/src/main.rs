#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_printk,
    macros::tracepoint,
    programs::TracePointContext,
};

#[tracepoint]
pub fn hello(ctx: TracePointContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hello(_ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        bpf_printk!(b"Hello from eBPF! openat syscall intercepted\0");
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}