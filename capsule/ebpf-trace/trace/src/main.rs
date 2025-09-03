use anyhow::Result;
use aya::maps::RingBuf;
use tokio::io::unix::AsyncFd;
use trace::{
    attach_tracepoints, connect_ebpf_bridge, connect_events_ringbuf, execute_cmd_and_seed_cmd_pid,
    remove_locked_mem_limit, setup_ebpf, verify_child_tracked,
};
use trace_common::{Arch, RawSyscallEvent, Sys, SyscallEnrichment, resolve_sys};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    remove_locked_mem_limit()?;

    // load BPF
    let mut ebpf = setup_ebpf()?;
    // TODO: verify that the programs are attached
    attach_tracepoints(&mut ebpf)?;

    // 1. Seed kernel map with initial PID (for eBPF filtering)
    let child_tgid = {
        let mut watched = connect_ebpf_bridge(&mut ebpf).and_then(|mut map| {
            map.insert(1, 1, 0)?;
            map.remove(&1)?;
            Ok(map)
        })?;

        // TODO: change to take actual command from program startup
        let child_tgid = execute_cmd_and_seed_cmd_pid("ls -la", &mut watched)?;
        verify_child_tracked(&mut watched, child_tgid)?;

        child_tgid
        // watched drops here - kernel map seeded, we don't need the reference anymore
    };

    // 2. Get ring buffer for reading syscall events
    let ring_buf = connect_events_ringbuf(&mut ebpf)?;
    let async_fd = AsyncFd::new(ring_buf)?;

    // 3. Start async ring buffer reading with userspace PID tracking
    read_events_async(async_fd, child_tgid).await?;

    Ok(())
}

async fn read_events_async(
    mut async_fd: AsyncFd<RingBuf<&mut aya::maps::MapData>>,
    initial_pid: u32,
) -> Result<()> {
    use std::collections::HashMap;

    println!("Starting async event reading for PID {}...", initial_pid);

    // Userspace PID tracking (this is the real process state, not just kernel filtering)
    let mut tracked_pids: HashMap<u32, String> = HashMap::new();
    tracked_pids.insert(initial_pid, "ls -la".to_string()); // Initial command

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        // Read all available events
        while let Some(item) = ring_buf.next() {
            // Cast the bytes to RawSyscallEvent
            if item.len() >= std::mem::size_of::<RawSyscallEvent>() {
                let raw_event: RawSyscallEvent =
                    unsafe { std::ptr::read(item.as_ptr() as *const RawSyscallEvent) };

                // Update userspace PID tracking based on syscalls
                update_tracked_pids(&mut tracked_pids, &raw_event);

                let arch = Arch::current();
                let sys = resolve_sys(arch, raw_event.sysno);
                let name = match sys { Sys::Unknown(_) => "unknown", _ => sys.name() };
                let phase = match raw_event.phase { 0 => "enter", 1 => "exit", _ => "?" };

                // Placeholder: no enrichment yet
                let _enrichment = SyscallEnrichment::None;

                println!(
                    "Syscall: {} ({}), pid={}, phase={}, arg0=0x{:x}, ret={} | Tracking {} PIDs",
                    name,
                    raw_event.sysno,
                    raw_event.pid,
                    phase,
                    raw_event.args[0],
                    raw_event.ret,
                    tracked_pids.len()
                );
            }
        }

        guard.clear_ready();
    }
}

fn update_tracked_pids(
    tracked_pids: &mut std::collections::HashMap<u32, String>,
    event: &RawSyscallEvent,
) {
    match event.sysno {
        // clone/clone3 syscalls - track child PID on successful exit
        220 | 435 if event.phase == 1 && event.ret > 0 && (event.ret as u64) < 0x7fffffff => {
            let child_pid = event.ret as u32;
            tracked_pids.insert(child_pid, format!("child-of-{}", event.pid));
            println!("  → Tracking new child PID: {}", child_pid);
        }
        // exit/exit_group syscalls - remove PID from tracking
        93 | 94 if event.phase == 0 => {
            tracked_pids.remove(&event.pid);
            println!("  → Stopped tracking PID: {}", event.pid);
        }
        _ => {} // Other syscalls don't affect PID tracking
    }
}
