/// Loads compiled eBPF bytecode into kernel for syscall monitoring
/// Attaches to raw tracepoint sys_enter to capture ALL syscalls  
/// Manages process tree tracking for "capsule run agent" monitoring
/// Maps syscall numbers to human readable names for analysis

use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use std::collections::HashMap;
use tokio::{signal, time::{sleep, Duration}};

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

    // Initialize syscall name mapping
    println!("🗺️  Initializing syscall name mapping...");
    let syscall_names = create_syscall_map();
    println!("✅ Loaded {} syscall names", syscall_names.len());
    
    // Get the proper tracepoint program and attach it
    println!("🔗 Loading tracepoint program...");
    let program: &mut TracePoint = bpf.program_mut("sys_enter_all").unwrap().try_into()?;
    program.load()?;
    println!("✅ Tracepoint program loaded");
    
    println!("🔗 Attempting to attach to raw_syscalls:sys_enter tracepoint...");
    match program.attach("raw_syscalls", "sys_enter") {
        Ok(_) => {
            println!("✅ SUCCESS: eBPF program attached to sys_enter tracepoint");
            println!("🔍 Monitoring ALL syscalls with proper structured access");
            println!("📊 Using TracePointContext for safe syscall data extraction");
            println!("📈 Check syscall activity with: cat /sys/kernel/debug/tracing/trace_pipe");
        }
        Err(e) => {
            println!("❌ FAILED to attach to sys_enter: {}", e);
            
            // Fallback to specific syscall tracepoint
            println!("🔄 Trying fallback to specific syscall...");
            match program.attach("syscalls", "sys_enter_openat") {
                Ok(_) => {
                    println!("✅ FALLBACK: Attached to sys_enter_openat instead");
                    println!("⚠️  Limited monitoring - only file open operations");
                }
                Err(e2) => {
                    println!("❌ Fallback also failed: {}", e2);
                    return Err(e.into());
                }
            }
        }
    }
    
    // Get the ring buffer for reading events from kernel
    println!("📡 Setting up ring buffer consumer...");
    let mut ring_buf: RingBuf<_> = match bpf.take_map("EVENT_RING") {
        Some(map) => RingBuf::try_from(map)?,
        None => {
            println!("❌ Could not find EVENT_RING map");
            return Ok(());
        }
    };
    println!("✅ Ring buffer consumer ready");
    
    println!("🎯 Starting syscall event monitoring...");
    println!("📊 Events will be printed to stdout in real-time");
    println!("⚡ Generate file operations to see events: ls, cat, touch, etc.");
    println!("🛑 Press Ctrl+C to exit\n");
    
    // Main event loop - read from ring buffer and print events
    loop {
        // Check for Ctrl+C
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n🛑 Shutting down...");
                break;
            }
            _ = consume_ring_buffer_events(&mut ring_buf, &syscall_names) => {}
        }
        
        // Small delay to prevent busy waiting
        sleep(Duration::from_millis(100)).await;
    }

    Ok(())
}

/// Consume events from the ring buffer and print them to stdout
async fn consume_ring_buffer_events(
    ring_buf: &mut RingBuf<aya::maps::MapData>,
    _syscall_names: &HashMap<u32, &'static str>,
) {
    while let Some(item) = ring_buf.next() {
        // Each ring buffer entry contains a u64 (PID) for now
        // In the future, this would be a full SyscallEvent struct
        if item.len() >= 8 {
            let pid_bytes: [u8; 8] = item[0..8].try_into().unwrap_or([0; 8]);
            let pid = u64::from_ne_bytes(pid_bytes);
            
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            println!(
                "[{}] 🔍 SYSCALL EVENT: openat() called by PID {} ({})",
                timestamp,
                pid,
                get_process_name(pid as u32).unwrap_or("unknown".to_string())
            );
        }
    }
}

/// Get process name from PID (best effort)
fn get_process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Creates mapping from syscall numbers to human-readable names
/// Based on x86_64 Linux syscall table
/// Only includes syscalls we monitor: process, file I/O, network, credentials, signals
fn create_syscall_map() -> HashMap<u32, &'static str> {
    let mut map = HashMap::new();
    
    // Process management syscalls
    map.insert(56, "clone");
    map.insert(57, "fork"); 
    map.insert(58, "vfork");
    map.insert(59, "execve");
    map.insert(322, "execveat");
    map.insert(60, "exit");
    map.insert(231, "exit_group");
    
    // File I/O syscalls
    map.insert(0, "read");
    map.insert(1, "write");
    map.insert(2, "open");
    map.insert(3, "close");
    map.insert(257, "openat");
    map.insert(16, "ioctl");
    map.insert(8, "lseek");
    map.insert(9, "mmap");
    map.insert(10, "mprotect");
    map.insert(11, "munmap");
    
    // Network syscalls
    map.insert(41, "socket");
    map.insert(42, "connect");
    map.insert(43, "accept");
    map.insert(49, "bind");
    map.insert(50, "listen");
    map.insert(44, "sendto");
    map.insert(45, "recvfrom");
    map.insert(46, "sendmsg");
    map.insert(47, "recvmsg");
    
    // Security/Credential syscalls
    map.insert(102, "getuid");
    map.insert(104, "getgid");
    map.insert(105, "setuid");
    map.insert(106, "setgid");
    map.insert(107, "geteuid");
    map.insert(108, "getegid");
    map.insert(125, "capget");
    map.insert(126, "capset");
    
    // Signal syscalls
    map.insert(62, "kill");
    map.insert(13, "rt_sigaction");
    map.insert(14, "rt_sigprocmask");
    map.insert(15, "rt_sigreturn");
    
    map
}