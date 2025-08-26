use anyhow::Result;
use aya::maps::HashMap as AyaHashMap;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use trace::{
    attach_tracepoints, connect_ebpf_bridge, execute_cmd_and_seed_cmd_pid, remove_locked_mem_limit,
    setup_ebpf, verify_child_tracked,
};

#[tokio::test]
async fn test_full_process_tracking_flow() -> Result<()> {
    // Initialize environment
    env_logger::try_init().ok(); // Ignore if already initialized
    remove_locked_mem_limit()?;

    // Setup eBPF program
    let mut ebpf = setup_ebpf()?;

    // Attach all tracepoints
    attach_tracepoints(&mut ebpf)?;

    // Connect to the kernel bridge
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    // Test the bridge connection with insert/remove
    watched.insert(1, 1, 0)?;
    watched.remove(&1)?;

    // Execute the target command and seed its PID
    let child_tgid = execute_cmd_and_seed_cmd_pid("ls -la", &mut watched)?;

    // Verify the child TGID is tracked in the kernel bridge
    verify_child_tracked(&mut watched, child_tgid)?;

    println!(" Successfully tracked process {} through eBPF", child_tgid);
    Ok(())
}
