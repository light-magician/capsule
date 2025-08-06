#![no_std]
#![no_main]



#[tracepoint]
pub fn hello(ctx: TracePointContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hello(ctx: TracePointContext) -> Result<u32, u32> {
    let message = b"hello from eBPF. Syscall Intercepted\0";
    unsafe {
        bpf_trace_printk(message.as_ptr(), message.len() as u32);
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
