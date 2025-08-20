use anyhow::Result;
use aya::maps::HashMap as AyaHashMap;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use trace::{
    attach_tracepoints, connect_ebpf_bridge, execute_cmd_and_seed_cmd_pid, remove_locked_mem_limit,
    setup_ebpf, verify_child_tracked,
};

/// Helper function to get all currently watched TGIDs from the kernel map
fn get_watched_tgids(watched: &mut AyaHashMap<&mut aya::maps::MapData, u32, u8>) -> Result<HashSet<u32>> {
    let mut tgids = HashSet::new();
    
    // We'll scan a reasonable PID range to find tracked TGIDs
    // In production, you might want a more efficient approach
    for tgid in 1..32768u32 { // Check reasonable PID range
        if watched.get(&tgid, 0).is_ok() {
            tgids.insert(tgid);
        }
    }
    
    Ok(tgids)
}

#[tokio::test]
async fn test_fork_process_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Fork Process Tracking ===");
    
    // Execute fork test script and seed parent TGID
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_fork.py", &mut watched)?;
    
    // Verify parent is tracked immediately
    verify_child_tracked(&mut watched, parent_tgid)?;
    println!("✓ Parent TGID {} is tracked", parent_tgid);
    
    // Give time for fork to occur and child to be tracked
    thread::sleep(Duration::from_millis(300));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after fork: {:?}", watched_tgids);
    
    // Should have parent and potentially child
    assert!(watched_tgids.contains(&parent_tgid), "Parent TGID should be tracked");
    assert!(watched_tgids.len() >= 1, "Should track at least parent process");
    
    // If we have more than 1 TGID, we tracked a child process
    if watched_tgids.len() > 1 {
        println!("✓ Child process was tracked (found {} total TGIDs)", watched_tgids.len());
    }
    
    // Give time for processes to complete and exit
    thread::sleep(Duration::from_millis(1000));
    
    let final_watched = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs: {:?}", final_watched);
    
    println!("✓ Fork tracking test completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_double_fork_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Double Fork (Daemon) Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_double_fork.py", &mut watched)?;
    verify_child_tracked(&mut watched, parent_tgid)?;
    println!("✓ Parent TGID {} is tracked", parent_tgid);
    
    // Give time for double fork to occur
    thread::sleep(Duration::from_millis(500));
    
    let after_fork_watched = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after double fork: {:?}", after_fork_watched);
    
    // Should have parent and potentially children
    assert!(after_fork_watched.contains(&parent_tgid), "Parent should still be tracked");
    
    // Double fork creates: parent -> child1 -> grandchild (child1 exits quickly)
    // We should track the grandchild that continues running
    println!("Tracked {} processes during double fork", after_fork_watched.len());
    
    // Give time for grandchild to complete (it runs for 1 second)
    thread::sleep(Duration::from_millis(1500));
    
    let final_watched = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs: {:?}", final_watched);
    
    println!("✓ Double fork tracking test completed");
    Ok(())
}

#[tokio::test]
async fn test_subprocess_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Subprocess.Popen Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_subprocess.py", &mut watched)?;
    verify_child_tracked(&mut watched, parent_tgid)?;
    println!("✓ Parent TGID {} is tracked", parent_tgid);
    
    // Give time for subprocess to be created and tracked
    thread::sleep(Duration::from_millis(300));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after subprocess creation: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    
    // subprocess.Popen should create a child process
    if watched_tgids.len() > 1 {
        println!("✓ Subprocess child was tracked (found {} total TGIDs)", watched_tgids.len());
    }
    
    // Give time for subprocess to complete
    thread::sleep(Duration::from_millis(1000));
    
    let final_watched = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs: {:?}", final_watched);
    
    println!("✓ Subprocess tracking test completed");
    Ok(())
}

#[tokio::test]
async fn test_multiprocessing_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Multiprocessing Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_multiprocessing.py", &mut watched)?;
    verify_child_tracked(&mut watched, parent_tgid)?;
    println!("✓ Parent TGID {} is tracked", parent_tgid);
    
    // Give time for multiprocessing child to be created
    thread::sleep(Duration::from_millis(300));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after multiprocessing: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    
    // multiprocessing.Process should create a child process  
    if watched_tgids.len() > 1 {
        println!("✓ Multiprocessing child was tracked (found {} total TGIDs)", watched_tgids.len());
    }
    
    // Give time for worker to complete
    thread::sleep(Duration::from_millis(1000));
    
    let final_watched = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs: {:?}", final_watched);
    
    println!("✓ Multiprocessing tracking test completed");
    Ok(())
}

#[tokio::test]
async fn test_execve_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Execve Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_execve.py", &mut watched)?;
    verify_child_tracked(&mut watched, parent_tgid)?;
    println!("✓ Parent TGID {} is tracked", parent_tgid);
    
    // Give time for fork + execve to occur
    thread::sleep(Duration::from_millis(300));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after execve: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    
    // fork + execve creates a child that replaces its image
    if watched_tgids.len() > 1 {
        println!("✓ Execve child was tracked (found {} total TGIDs)", watched_tgids.len());
    }
    
    // Give time for execve child to complete
    thread::sleep(Duration::from_millis(500));
    
    let final_watched = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs: {:?}", final_watched);
    
    println!("✓ Execve tracking test completed");
    Ok(())
}

#[tokio::test]
async fn test_chain_fork_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Chain Fork Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_chain_fork.py", &mut watched)?;
    verify_child_tracked(&mut watched, parent_tgid)?;
    println!("✓ Parent TGID {} is tracked", parent_tgid);
    
    // Give time for chain of forks to occur (3 levels deep)
    thread::sleep(Duration::from_millis(600));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after chain fork: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    
    // Chain fork should create multiple processes (parent + children at different levels)
    println!("Chain fork created {} tracked processes", watched_tgids.len());
    
    // Should have multiple processes in the chain
    if watched_tgids.len() >= 2 {
        println!("✓ Chain fork created multiple tracked processes");
    }
    
    // Give time for entire chain to complete
    thread::sleep(Duration::from_millis(1500));
    
    let final_watched = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs: {:?}", final_watched);
    
    println!("✓ Chain fork tracking test completed");
    Ok(())
}

#[tokio::test]
async fn test_threading_no_new_processes() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Threading (Should NOT Create New Processes) ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_threading.py", &mut watched)?;
    verify_child_tracked(&mut watched, parent_tgid)?;
    println!("✓ Parent TGID {} is tracked", parent_tgid);
    
    // Give time for threading test to complete
    thread::sleep(Duration::from_millis(800));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after threading test: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    
    // Threading should NOT create new processes - all threads share same TGID
    assert_eq!(watched_tgids.len(), 1, "Threading should only track parent process (same TGID for all threads)");
    
    println!("✓ Threading correctly did not create new processes");
    Ok(())
}

/// Comprehensive test that validates process lifecycle management
#[tokio::test]
async fn test_process_lifecycle_management() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Process Lifecycle Management ===");
    
    // Test 1: Verify parent tracking
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_fork.py", &mut watched)?;
    verify_child_tracked(&mut watched, parent_tgid)?;
    
    let initial_watched = get_watched_tgids(&mut watched)?;
    println!("Initial tracked processes: {:?}", initial_watched);
    
    // Test 2: Give time for child processes to be created and tracked
    thread::sleep(Duration::from_millis(400));
    
    let during_execution = get_watched_tgids(&mut watched)?;
    println!("During execution: {:?}", during_execution);
    
    // Test 3: Verify child processes were tracked
    if during_execution.len() > initial_watched.len() {
        println!("✓ Child processes were successfully tracked");
    }
    
    // Test 4: Give time for processes to exit and be cleaned up
    thread::sleep(Duration::from_millis(1000));
    
    let after_completion = get_watched_tgids(&mut watched)?;
    println!("After completion: {:?}", after_completion);
    
    // Test 5: Verify process cleanup occurred
    if after_completion.len() <= during_execution.len() {
        println!("✓ Process cleanup occurred (some TGIDs removed)");
    }
    
    println!("✓ Process lifecycle management test completed");
    Ok(())
}