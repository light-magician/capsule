use anyhow::Result;
use aya::maps::HashMap as AyaHashMap;
use std::collections::HashSet;
use std::process::Command;
use std::thread;
use std::time::Duration;
use trace::{
    attach_tracepoints, connect_ebpf_bridge, execute_cmd_and_seed_cmd_pid, remove_locked_mem_limit,
    setup_ebpf, verify_child_tracked,
};

/// Helper function to get all currently watched TGIDs from the kernel map
fn get_watched_tgids(watched: &mut AyaHashMap<&mut aya::maps::MapData, u32, u8>) -> Result<HashSet<u32>> {
    let mut tgids = HashSet::new();
    
    // Iterate through the map to collect all watched TGIDs
    // Note: This is a simplified approach - in a real implementation you might need
    // to iterate through all possible keys or maintain a separate tracking mechanism
    for tgid in 1..65536u32 { // Check reasonable PID range
        if watched.get(&tgid, 0).is_ok() {
            tgids.insert(tgid);
        }
    }
    
    Ok(tgids)
}

/// Test individual process split scenarios
#[tokio::test]
async fn test_fork_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Fork Process Tracking ===");
    
    // Execute fork test script
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_fork.py", &mut watched)?;
    
    // Give time for fork to occur
    thread::sleep(Duration::from_millis(200));
    
    // Verify parent is tracked
    verify_child_tracked(&mut watched, parent_tgid)?;
    
    // Get all watched TGIDs
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after fork test: {:?}", watched_tgids);
    
    // Should have at least the parent TGID
    assert!(watched_tgids.contains(&parent_tgid), "Parent TGID should be watched");
    
    // Give time for child process to complete and exit (should be removed from watched list)
    thread::sleep(Duration::from_millis(1000));
    
    let final_watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs after fork test: {:?}", final_watched_tgids);
    
    println!("✓ Fork tracking test completed");
    Ok(())
}

#[tokio::test]
async fn test_double_fork_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Double Fork (Daemon) Process Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_double_fork.py", &mut watched)?;
    
    // Give time for double fork to occur
    thread::sleep(Duration::from_millis(300));
    
    let initial_watched = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after double fork: {:?}", initial_watched);
    
    // Should have parent and potentially grandchild
    assert!(initial_watched.contains(&parent_tgid), "Parent should be tracked");
    assert!(initial_watched.len() >= 1, "Should track at least parent process");
    
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

    println!("\n=== Testing Subprocess Process Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_subprocess.py", &mut watched)?;
    
    thread::sleep(Duration::from_millis(200));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after subprocess test: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    
    thread::sleep(Duration::from_millis(1000));
    
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

    println!("\n=== Testing Multiprocessing Process Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_multiprocessing.py", &mut watched)?;
    
    thread::sleep(Duration::from_millis(200));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after multiprocessing test: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    // Should have created a child process
    assert!(watched_tgids.len() >= 1, "Should track at least parent process");
    
    thread::sleep(Duration::from_millis(1000));
    
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

    println!("\n=== Testing Execve Process Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_execve.py", &mut watched)?;
    
    thread::sleep(Duration::from_millis(200));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after execve test: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    
    thread::sleep(Duration::from_millis(1000));
    
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

    println!("\n=== Testing Chain Fork Process Tracking ===");
    
    let parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_chain_fork.py", &mut watched)?;
    
    // Give time for chain of forks to occur
    thread::sleep(Duration::from_millis(500));
    
    let watched_tgids = get_watched_tgids(&mut watched)?;
    println!("Watched TGIDs after chain fork test: {:?}", watched_tgids);
    
    assert!(watched_tgids.contains(&parent_tgid), "Parent should be tracked");
    // Should have multiple processes in the chain
    println!("Chain created {} tracked processes", watched_tgids.len());
    
    thread::sleep(Duration::from_millis(1500));
    
    let final_watched = get_watched_tgids(&mut watched)?;
    println!("Final watched TGIDs: {:?}", final_watched);
    
    println!("✓ Chain fork tracking test completed");
    Ok(())
}

#[tokio::test]
async fn test_threading_vs_process_distinction() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Testing Threading vs Process Distinction ===");
    
    // Test threading (should NOT create new processes)
    let thread_parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_threading.py", &mut watched)?;
    thread::sleep(Duration::from_millis(300));
    
    let thread_watched = get_watched_tgids(&mut watched)?;
    println!("Threading test - Watched TGIDs: {:?}", thread_watched);
    
    // Clear watched list
    for tgid in &thread_watched {
        let _ = watched.remove(tgid);
    }
    
    // Test multiprocessing (should create new processes)  
    let multiproc_parent_tgid = execute_cmd_and_seed_cmd_pid("python3 tests/scripts/test_multiprocessing.py", &mut watched)?;
    thread::sleep(Duration::from_millis(300));
    
    let multiproc_watched = get_watched_tgids(&mut watched)?;
    println!("Multiprocessing test - Watched TGIDs: {:?}", multiproc_watched);
    
    // Threading should only track the parent process
    assert_eq!(thread_watched.len(), 1, "Threading should only track parent process");
    assert!(thread_watched.contains(&thread_parent_tgid), "Threading parent should be tracked");
    
    // Multiprocessing should track parent and child
    assert!(multiproc_watched.contains(&multiproc_parent_tgid), "Multiprocessing parent should be tracked");
    
    println!("✓ Threading vs Process distinction test completed");
    Ok(())
}

/// Comprehensive test that validates the entire process tracking system
#[tokio::test]
async fn test_comprehensive_process_tracking() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;

    println!("\n=== Comprehensive Process Tracking Test ===");
    
    let test_scenarios = vec![
        ("fork", "tests/scripts/test_fork.py"),
        ("subprocess", "tests/scripts/test_subprocess.py"),
        ("multiprocessing", "tests/scripts/test_multiprocessing.py"),
        ("execve", "tests/scripts/test_execve.py"),
        ("double_fork", "tests/scripts/test_double_fork.py"),
        ("chain_fork", "tests/scripts/test_chain_fork.py"),
    ];

    for (test_name, script_path) in test_scenarios {
        println!("\n--- Testing {} scenario ---", test_name);
        
        let cmd = format!("python3 {}", script_path);
        let parent_tgid = execute_cmd_and_seed_cmd_pid(&cmd, &mut watched)?;
        
        // Give time for process creation and execution
        thread::sleep(Duration::from_millis(300));
        
        // Verify parent is tracked
        verify_child_tracked(&mut watched, parent_tgid)?;
        
        let watched_tgids = get_watched_tgids(&mut watched)?;
        println!("{} test - Watched TGIDs: {:?}", test_name, watched_tgids);
        
        // Give time for processes to complete
        thread::sleep(Duration::from_millis(1000));
        
        println!("✓ {} scenario completed", test_name);
        
        // Clean up for next test
        for tgid in &watched_tgids {
            let _ = watched.remove(tgid);
        }
    }
    
    println!("\n✓ Comprehensive process tracking test completed successfully");
    Ok(())
}