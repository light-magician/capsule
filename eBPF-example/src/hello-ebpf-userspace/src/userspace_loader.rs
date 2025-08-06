/// Loads compiled eBPF bytecode into kernel
/// Attaches to sys_enter_openat tracepoint (fires when files are opened)
/// once attached, eBPF runs automatically on events
/// Userspace just waits and keeps the attachment alive

use aya::{programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    println!("🚀 Starting eBPF Hello World program...");

    // bump memory limit for eBPF maps
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("failed to remove memory limit: {}", ret);
    }
    
    // Load the compiled eBPF program
    println!("📁 Loading eBPF binary...");
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load_file("target/bpfel-unknown-none/debug/hello-kern")?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load_file("target/bpfel-unknown-none/release/hello-kern")?;
    println!("✅ eBPF binary loaded successfully");

    // initialize eBPF logger 
    println!("🔧 Initializing eBPF logger...");
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    println!("✅ eBPF logger initialized");

    // Get the tracepoint program and attach it
    println!("🔗 Loading tracepoint program...");
    let program: &mut TracePoint = bpf.program_mut("hello").unwrap().try_into()?;
    program.load()?;
    println!("✅ Tracepoint program loaded");
    
    println!("🔗 Attempting to attach to tracepoint...");
    match program.attach("syscalls", "sys_enter_openat") {
        Ok(_) => {
            println!("✅ SUCCESS: eBPF program attached to sys_enter_openat tracepoint");
            println!("Run file operations to trigger: ls, cat, touch, etc.");
            println!("Check logs: dmesg -w or cat /sys/kernel/debug/tracing/trace_pipe");
        }
        Err(e) => {
            println!("❌ FAILED to attach: {}", e);
            return Err(e.into());
        }
    }
    
    info!("Press Ctrl+C to exit...");

    // Keep the program running
    signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}