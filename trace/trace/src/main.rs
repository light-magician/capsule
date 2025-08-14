use anyhow::anyhow;
use aya::{maps::ring_buf::RingBuf, programs::TracePoint, Ebpf};
#[rustfmt::skip]
use log::{debug, warn};
use std::time::Duration;

use tokio::time;
use trace_common::Event;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit (needed for older kernels)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF program from embedded bytes
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/trace"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Syscall tracepoint programs
    // Load and attach `on_sys_enter`
    {
        let enter: &mut TracePoint = ebpf
            .program_mut("on_sys_enter")
            .ok_or(anyhow!("program not found: on_sys_enter"))?
            .try_into()?;
        enter.load()?;
        enter.attach("raw_syscalls", "sys_enter")?;
    } // `enter` goes out of scope here, mutable borrow released

    // Load and attach `on_sys_exit`
    {
        let exit: &mut TracePoint = ebpf
            .program_mut("on_sys_exit")
            .ok_or(anyhow!("program not found: on_sys_exit"))?
            .try_into()?;
        exit.load()?;
        exit.attach("raw_syscalls", "sys_exit")?;
    }

    // Ring buffer for events
    let mut rb = RingBuf::try_from(
        ebpf.map_mut("EVENTS")
            .ok_or(anyhow!("map not found: EVENTS"))?,
    )?;
    println!("attached: raw_syscalls:sys_enter/sys_exit");

    // Event loop
    loop {
        while let Some(bytes) = rb.next() {
            if bytes.len() == core::mem::size_of::<Event>() {
                let e = unsafe { &*(bytes.as_ptr() as *const Event) };
                println!(
                    "pid={} tid={} sysno={} a0={:#x} a1={:#x} a2={:#x}",
                    e.pid, e.tid, e.sysno, e.arg0, e.arg1, e.arg2
                );
            }
        }
        time::sleep(Duration::from_millis(5)).await;
    }
}
